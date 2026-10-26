from __future__ import annotations
import os, json, re
from anthropic import Anthropic

DEFAULT_MODEL = "claude-sonnet-5"
PRICING = {
    "claude-sonnet-5": {"input": 2.0, "output": 10.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-5": {"input": 5.0, "output": 25.0},
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
}


def _format_candidates(candidates) -> str:
    lines = []
    for i, c in enumerate(candidates):
        lines.append(
            f"[{i}] vuln={c.vuln.type.value} status={c.vuln.status.value} "
            f"action={c.action_type} prior_score={c.final_score:.2f} "
            f"(base={c.base_score:.2f}, failure_penalty={c.penalty:.2f})"
        )
    return "\n".join(lines)


def _parse_choice(text: str, n: int):
    """Trích {choice, reason} từ output LLM một cách bền vững.
    Thứ tự thử: (1) json.loads toàn bộ; (2) bóc JSON object bằng non-greedy;
    (3) bóc riêng số sau khóa "choice" — KHÔNG phụ thuộc reason có ký tự lạ;
    (4) số đầu tiên trong text. Trả (index, reason, parsed_ok)."""
    if not text:
        return 0, "(fallback: LLM không trả nội dung)", False
    cleaned = text.strip()
    # gỡ hàng rào code nếu LLM bọc ```json ... ```
    cleaned = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", cleaned).strip()

    # (1) cả chuỗi là JSON
    def _from_obj(obj):
        idx = int(obj.get("choice"))
        reason = str(obj.get("reason", "")).strip()
        if 0 <= idx < n:
            return idx, reason, True
        return None
    try:
        r = _from_obj(json.loads(cleaned))
        if r:
            return r
    except (ValueError, TypeError, json.JSONDecodeError):
        pass

    # (2) object JSON đầu tiên (non-greedy, bỏ qua reason dài/xuống dòng)
    m = re.search(r"\{.*?\}", cleaned, re.DOTALL)
    if m:
        try:
            r = _from_obj(json.loads(m.group(0)))
            if r:
                return r
        except (ValueError, TypeError, json.JSONDecodeError):
            pass

    # (3) bóc riêng số của khóa "choice" — bền nhất, không dính reason
    m = re.search(r'"?choice"?\s*[:=]\s*(\d+)', cleaned)
    if m:
        idx = int(m.group(1))
        if 0 <= idx < n:
            rm = re.search(r'"?reason"?\s*[:=]\s*"?(.*?)"?\s*[}\n]', cleaned, re.DOTALL)
            reason = rm.group(1).strip() if rm else cleaned[:200]
            return idx, reason, True

    # (4) số đầu tiên hợp lệ
    for tok in re.findall(r"\d+", cleaned):
        idx = int(tok)
        if 0 <= idx < n:
            return idx, cleaned[:200], True

    return 0, "(fallback: không parse được quyết định LLM, chọn ứng viên xếp hạng cao nhất)", False


class LLMClient:
    def __init__(self, model=DEFAULT_MODEL):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("Thiếu ANTHROPIC_API_KEY.")
        self.client = Anthropic(api_key=api_key)
        self.model = model
        self.total_calls = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.fallback_count = 0      # fallback do khong parse duoc output
        self.refusal_count = 0       # so luot bi safeguard tu choi (stop_reason=refusal)
        self.empty_count = 0         # so luot tra rong vi ly do khac

    def _call(self, system, user, max_tokens=500):
        """Tra ve (text, stop_reason). stop_reason == 'refusal' nghia la model
        tu choi do safeguard an toan mang -> dem rieng, KHONG coi la LLM da quyet dinh."""
        resp = self.client.messages.create(model=self.model, max_tokens=max_tokens, system=system,
                                            messages=[{"role": "user", "content": user}])
        self.total_calls += 1
        self.total_input_tokens += resp.usage.input_tokens
        self.total_output_tokens += resp.usage.output_tokens
        text = "".join(block.text for block in resp.content if block.type == "text")
        return text, getattr(resp, "stop_reason", None)

    def choose_action(self, state_summary, recent_history, candidates):
        """
        LLM TỰ RA QUYẾT ĐỊNH chọn hành động kế tiếp (Adaptive Planning).
        prior_score chỉ là một đặc trưng tham khảo; LLM được phép chọn khác nếu
        trạng thái/lịch sử/penalty thất bại cho thấy một hướng khác hợp lý hơn.
        Trả về (chosen_index:int, reasoning:str).
        """
        cand_text = _format_candidates(candidates)
        system = (
            "Ban la Planner Agent trong mot framework kiem thu xam nhap tu dong, hoat dong "
            "trong moi truong lab duoc cap phep (DVWA/Juice Shop). Nhiem vu: CHON HANH DONG "
            "KHAI THAC KE TIEP hop ly nhat de tien toi muc tieu, dua tren trang thai hien tai, "
            "lich su hanh dong va diem phat tu bo nho that bai. prior_score chi la goi y; neu "
            "mot huong khac phu hop hon voi trang thai/rang buoc tien de thi hay chon no. "
            "Chi duoc chon trong danh sach ung vien. "
            'TRA LOI DUY NHAT bang JSON: {"choice": <so_thu_tu>, "reason": "<mot cau ngan>"}'
        )
        user = (
            f"Trang thai hien tai: {state_summary}\n"
            f"Lich su gan day:\n{recent_history}\n\n"
            f"Cac ung vien hanh dong:\n{cand_text}\n\n"
            'Chon dung 1 ung vien. Chi tra JSON {"choice": i, "reason": "..."}'
        )
        # Lan 1
        out, stop = self._call(system, user, max_tokens=150)
        # Neu bi safeguard tu choi (refusal) hoac tra rong -> retry 1 lan
        if stop == "refusal" or not out.strip():
            if stop == "refusal":
                self.refusal_count += 1
            else:
                self.empty_count += 1
            out2, stop2 = self._call(system, user, max_tokens=150)
            if stop2 == "refusal" or not out2.strip():
                # Van that bai -> fallback co nhan, danh dau RO rang bước nay
                # KHONG phai do LLM quyet dinh.
                self.fallback_count += 1
                tag = "refusal an toan mang" if (stop == "refusal" or stop2 == "refusal") else "LLM tra rong"
                return 0, f"(heuristic do {tag}: chon ung vien xep hang cao nhat)"
            out = out2
        idx, reason, ok = _parse_choice(out, len(candidates))
        if not ok:
            self.fallback_count += 1
            reason = "(heuristic do khong parse duoc output LLM: chon ung vien xep hang cao nhat)"
        return idx, reason

    def interpret_recon(self, raw_finding):
        system = "Ban la Recon-Analyzer Agent. Doc recon tho, tra ve 1 cau nhan dinh."
        text, _ = self._call(system, raw_finding, max_tokens=80)
        return text

    def usage_summary(self):
        rate = PRICING.get(self.model, PRICING["claude-sonnet-5"])
        cost = (self.total_input_tokens * rate["input"] + self.total_output_tokens * rate["output"]) / 1_000_000
        return {"llm_calls": self.total_calls, "input_tokens": self.total_input_tokens,
                "output_tokens": self.total_output_tokens, "estimated_cost_usd": round(cost, 6),
                "llm_fallbacks": self.fallback_count, "llm_refusals": self.refusal_count,
                "llm_empty": self.empty_count}


class DryRunLLMClient:
    model = "dry-run"
    def __init__(self, *_, **__):
        self.total_calls = 0
        self.fallback_count = 0
        self.refusal_count = 0
        self.empty_count = 0
    def choose_action(self, state_summary, recent_history, candidates):
        # Dry-run: mo phong quyet dinh qua dung interface choose_action (khong goi API).
        self.total_calls += 1
        top = candidates[0]
        return 0, f"[DRY-RUN] chon {top.vuln.type.value} qua {top.action_type} (prior_score={top.final_score:.2f})."
    def interpret_recon(self, raw_finding):
        self.total_calls += 1
        return "[DRY-RUN] nhan dinh gia."
    def usage_summary(self):
        return {"llm_calls": self.total_calls, "input_tokens": 0, "output_tokens": 0,
                "estimated_cost_usd": 0.0, "llm_fallbacks": self.fallback_count,
                "llm_refusals": self.refusal_count, "llm_empty": self.empty_count}
