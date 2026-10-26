"""
Agent Architecture — Chương 3.5

Target-aware: DVWA và Juice Shop có cấu trúc API khác nhau (form+cookie vs
JSON+Bearer token), nên seed endpoint và lựa chọn tool wrapper đều dựa vào
state.target_name thay vì hardcode 1 kiểu duy nhất.
"""

from __future__ import annotations
from core.state import (
    PentestState, Endpoint, Vulnerability, VulnType, VulnStatus,
    PrivilegeLevel, ActionRecord,
)
from core.memory import SessionMemory, FailureMemory
from core.planner import AdaptivePlanningEngine, Candidate
from tools import wrappers as tools


class ReconAnalyzerAgent:
    def __init__(self, state: PentestState):
        self.state = state

    def discover_endpoint(self, path, method="GET", params=None):
        ep = Endpoint(url=self.state.asset.target_base_url + path, method=method, params=params or [])
        self.state.asset.add_endpoint(ep)

    def scan_with_nuclei(self, path):
        url = self.state.asset.target_base_url + path
        tools.run_nuclei(url)

    def seed_known_vuln_candidates(self, vuln_types=None) -> None:
        base = self.state.asset.target_base_url
        target = self.state.target_name

        if target == "juice_shop":
            all_seeds = {
                VulnType.AUTH_BYPASS: Vulnerability(type=VulnType.AUTH_BYPASS,
                                                      endpoint=base + "/rest/user/login", param="email"),
                VulnType.IDOR: Vulnerability(type=VulnType.IDOR,
                                               endpoint=base + "/rest/basket/{id}", param="id"),
                VulnType.SQLI: Vulnerability(type=VulnType.SQLI,
                                               endpoint=base + "/rest/user/login", param="email"),
            }
        else:
            all_seeds = {
                VulnType.AUTH_BYPASS: Vulnerability(type=VulnType.AUTH_BYPASS,
                                                      endpoint=base + "/login.php", param="username"),
                VulnType.SQLI: Vulnerability(type=VulnType.SQLI,
                                               endpoint=base + "/vulnerabilities/sqli/", param="id"),
                VulnType.IDOR: Vulnerability(type=VulnType.IDOR,
                                               endpoint=base + "/api/users/{id}", param="id"),
            }

        selected = vuln_types if vuln_types is not None else list(all_seeds.keys())
        for vt in selected:
            v = all_seeds[vt]
            # Confidence SUY RA TU PROBE THAT (thay vi gan cung 0.4): tac tu gui
            # mot HTTP request nhe toi be mat tan cong de lay bang chung truoc khi
            # dua vao VulnerabilityState. Han che da biet: danh sach endpoint cua
            # target lab (DVWA/Juice Shop) van duoc seed san (xem 3.2 Pham vi).
            v.confidence = self._probe_confidence(v)
            self.state.vulns.add(v)

    def _probe_confidence(self, v) -> float:
        """Suy confidence ban dau tu mot probe HTTP that tren be mat tan cong.
        Toi duoc + tham so xuat hien -> cao hon; khong toi duoc -> thap (nhung
        van giu lam ung vien do tin cay thap de Planner tu quyet dinh)."""
        url = v.endpoint.replace("{id}", "1")
        try:
            res = tools.http_get(url)
        except Exception:
            return 0.2  # khong probe duoc (offline) -> ung vien do tin cay thap
        if not res.success:
            return 0.15  # 4xx/5xx/khong toi duoc
        body = (res.raw or "").lower()
        conf = 0.35
        if v.param and v.param.lower() in body:
            conf += 0.15
        return round(min(conf, 0.6), 2)


class PlannerAgent:
    def __init__(self, engine: AdaptivePlanningEngine):
        self.engine = engine

    def next_action(self, state):
        return self.engine.select_action(state)

    def replan(self, state, failed, note):
        return self.engine.replan_on_failure(state, failed, note)

    def is_done(self, state) -> bool:
        return self.engine.goal_reached(state)


class ExecutionEvaluatorAgent:
    def __init__(self, state: PentestState):
        self.state = state

    def execute(self, candidate) -> ActionRecord:
        vuln = candidate.vuln
        target = self.state.target_name
        record = ActionRecord(
            action_type=candidate.action_type,
            target_vuln_id=vuln.id,
            reasoning=candidate.reasoning,
        )

        if candidate.action_type == "sqlmap_scan":
            res = tools.run_sqlmap(vuln.endpoint, vuln.param)
            record.tool_used = "sqlmap"
            if res.success:
                vuln.status = VulnStatus.CONFIRMED
                vuln.confidence = 0.8
                vuln.evidence = res.summary
            record.success = res.success
            record.result_summary = res.summary

        elif candidate.action_type == "sqlmap_exploit":
            res = tools.run_sqlmap(vuln.endpoint, vuln.param, extra_args=["--dump-all", "--batch"])
            record.tool_used = "sqlmap"
            if res.success:
                vuln.status = VulnStatus.EXPLOITED
                self.state.privilege.current_level = PrivilegeLevel.ADMIN
            record.success = res.success
            record.result_summary = res.summary

        elif candidate.action_type == "auth_bypass_probe":
            if target == "juice_shop":
                res = tools.try_auth_bypass_payloads_juiceshop(vuln.endpoint)
            else:
                res = tools.try_auth_bypass_payloads(vuln.endpoint, "username", "password")
            record.tool_used = "requests"
            if res.success:
                vuln.status = VulnStatus.EXPLOITED
                self.state.auth.is_authenticated = True
                self.state.auth.obtained_via = "sqli_login_bypass"
                self.state.privilege.current_level = PrivilegeLevel.USER
                if getattr(res, "token", None):
                    self.state.auth.session_token = res.token
                if target == "juice_shop":
                    try:
                        import json as _json
                        login_data = _json.loads(res.raw)
                        self.state.auth.own_resource_id = login_data.get("authentication", {}).get("bid")
                    except Exception:
                        self.state.auth.own_resource_id = None
            record.success = res.success
            record.result_summary = res.summary

        elif candidate.action_type == "idor_probe":
            path = vuln.endpoint.replace(self.state.asset.target_base_url, "")
            if target == "juice_shop":
                res = tools.probe_idor_juiceshop(
                    self.state.asset.target_base_url, path, id_range=range(1, 20),
                    bearer_token=self.state.auth.session_token,
                    own_basket_id=self.state.auth.own_resource_id,
                )
            else:
                res = tools.probe_idor(
                    self.state.asset.target_base_url, path, id_range=range(1, 20),
                    cookies={"session": self.state.auth.session_token} if self.state.auth.session_token else None,
                )
            record.tool_used = "requests"
            if res.success:
                vuln.status = VulnStatus.EXPLOITED
                self.state.privilege.accessible_resources.append(vuln.endpoint)
            record.success = res.success
            record.result_summary = res.summary

        else:
            record.success = False
            record.result_summary = f"Unknown action_type: {candidate.action_type}"

        self.state.history.log(record)
        self._update_graph(record)
        return record

    def _update_graph(self, record):
        prev_state_id = f"s{record.step_index}"
        next_state_id = f"s{record.step_index + 1}"
        self.state.graph.add_state_node(next_state_id, label=f"after_{record.action_type}_{'ok' if record.success else 'fail'}")
        self.state.graph.add_transition(prev_state_id, next_state_id, record)


class MemoryAgent:
    def __init__(self, session_memory: SessionMemory, failure_memory: FailureMemory):
        self.session_memory = session_memory
        self.failure_memory = failure_memory

    def update(self, state, record):
        self.session_memory.remember(record)
