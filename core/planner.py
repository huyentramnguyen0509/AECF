from __future__ import annotations
from dataclasses import dataclass
from core.state import PentestState, Vulnerability, VulnStatus, VulnType, PrivilegeLevel

@dataclass
class Candidate:
    vuln: object
    action_type: str
    base_score: float
    penalty: float = 0.0
    reasoning: str = ""
    @property
    def final_score(self):
        return max(self.base_score - self.penalty, 0.0)

class AdaptivePlanningEngine:
    def __init__(self, llm, session_memory, failure_memory):
        self.llm = llm
        self.session_memory = session_memory
        self.failure_memory = failure_memory

    def generate_candidates(self, state):
        candidates = []
        for v in state.vulns.vulns.values():
            if v.status in (VulnStatus.EXPLOITED,):
                continue
            action_type = {
                VulnType.SQLI: "sqlmap_exploit" if v.status == VulnStatus.CONFIRMED else "sqlmap_scan",
                VulnType.AUTH_BYPASS: "auth_bypass_probe",
                VulnType.IDOR: "idor_probe",
            }[v.type]
            # base_score = do tin cay (tu probe) + thuong neu da CONFIRMED + TRONG SO TAC DONG.
            # Impact lam cho cac don tac dong cao (IDOR, SQLi-exploit) tro thanh ung vien
            # canh tranh sớm — dung voi cach pentester uu tien muc tieu gia tri cao. He qua:
            # agent co the thu truoc khi tien de (session) thoa -> that bai THAT tren target
            # -> re-plan -> Failure Memory hoc de khong lap lai (do trong RQ3).
            IMPACT = {VulnType.SQLI: 0.30, VulnType.IDOR: 0.30, VulnType.AUTH_BYPASS: 0.15}
            confirmed_bonus = 0.3 if v.status == VulnStatus.CONFIRMED else 0.0
            candidates.append(Candidate(vuln=v, action_type=action_type,
                                         base_score=v.confidence + confirmed_bonus + IMPACT[v.type]))
        return candidates

    def rank_candidates(self, state, candidates):
        for c in candidates:
            ctx_sig = self._context_signature(state)
            c.penalty = self.failure_memory.penalty_for(c.vuln.type.value, c.action_type, ctx_sig)
        return sorted(candidates, key=lambda c: c.final_score, reverse=True)

    def _context_signature(self, state):
        return f"auth={state.auth.is_authenticated};priv={state.privilege.current_level.value}"

    def select_action(self, state):
        candidates = self.generate_candidates(state)
        if not candidates:
            return None
        ranked = self.rank_candidates(state, candidates)
        # LLM TU RA QUYET DINH chon trong tap ung vien (khong con chi giai thich top-1).
        # Diem tat dinh (final_score) chi la mot dac trung dua vao prompt.
        idx, reasoning = self.llm.choose_action(
            state_summary=self._context_signature(state),
            recent_history=self.session_memory.recent_context(),
            candidates=ranked,
        )
        chosen = ranked[idx]
        chosen.reasoning = reasoning
        return chosen

    def replan_on_failure(self, state, failed, note):
        ctx_sig = self._context_signature(state)
        self.failure_memory.record_failure(failed.vuln.type.value, failed.action_type, ctx_sig, note)
        failed.vuln.status = VulnStatus.FAILED
        return self.select_action(state)

    def goal_reached(self, state):
        if state.goal == "escalate_to_admin":
            return state.privilege.current_level == PrivilegeLevel.ADMIN
        if state.goal == "data_leak":
            return len(state.privilege.accessible_resources) > 0
        if state.goal == "session_hijack":
            return state.auth.is_authenticated
        return False
