from __future__ import annotations
from dataclasses import dataclass
from core.state import VulnType

@dataclass
class ScenarioSpec:
    key: str
    label: str
    vuln_types: list
    goal: str
    target_name: str

SCENARIOS = {
    "5.2.1_auth_bypass_session_hijack": ScenarioSpec(
        key="5.2.1_auth_bypass_session_hijack", label="Authentication Bypass -> Session Hijack",
        vuln_types=[VulnType.AUTH_BYPASS], goal="session_hijack", target_name="juice_shop"),
    "5.2.2_auth_bypass_idor_leak": ScenarioSpec(
        key="5.2.2_auth_bypass_idor_leak", label="Authentication Bypass -> IDOR -> Data Leak",
        vuln_types=[VulnType.AUTH_BYPASS, VulnType.IDOR], goal="data_leak", target_name="juice_shop"),
    "5.2.3_sqli_privesc": ScenarioSpec(
        key="5.2.3_sqli_privesc", label="SQL Injection -> Privilege Escalation",
        vuln_types=[VulnType.SQLI], goal="escalate_to_admin", target_name="dvwa"),
    "5.2.4_adaptive_replanning_idor_sqli": ScenarioSpec(
        key="5.2.4_adaptive_replanning_idor_sqli", label="Adaptive Re-planning (IDOR -> SQLi)",
        vuln_types=[VulnType.IDOR, VulnType.SQLI], goal="escalate_to_admin", target_name="juice_shop"),
}

def get_scenario(key):
    if key not in SCENARIOS:
        raise ValueError(f"Không có kịch bản '{key}'.")
    return SCENARIOS[key]
