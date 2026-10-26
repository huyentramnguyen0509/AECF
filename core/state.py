from __future__ import annotations
import json, uuid, datetime as dt
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import networkx as nx

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

class VulnType(str, Enum):
    SQLI = "sql_injection"
    AUTH_BYPASS = "authentication_bypass"
    IDOR = "idor_broken_access_control"

class VulnStatus(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    FAILED = "failed"

class PrivilegeLevel(str, Enum):
    NONE = "unauthenticated"
    USER = "authenticated_user"
    ADMIN = "admin"

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list = field(default_factory=list)
    tech_hints: list = field(default_factory=list)
    discovered_at: str = field(default_factory=now_iso)

@dataclass
class AssetState:
    target_base_url: str
    endpoints: dict = field(default_factory=dict)
    tech_stack: list = field(default_factory=list)
    def add_endpoint(self, ep): self.endpoints[ep.url] = ep

@dataclass
class AuthenticationState:
    is_authenticated: bool = False
    username: Optional[str] = None
    session_token: Optional[str] = None
    role: Optional[str] = None
    obtained_via: Optional[str] = None
    own_resource_id: Optional[str] = None

@dataclass
class Vulnerability:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    type: VulnType = VulnType.SQLI
    endpoint: str = ""
    param: Optional[str] = None
    status: VulnStatus = VulnStatus.CANDIDATE
    confidence: float = 0.0
    evidence: str = ""
    detected_at: str = field(default_factory=now_iso)
    resolved_at: Optional[str] = None

@dataclass
class VulnerabilityState:
    vulns: dict = field(default_factory=dict)
    def add(self, v): self.vulns[v.id] = v; return v.id
    def by_status(self, status): return [v for v in self.vulns.values() if v.status == status]

@dataclass
class PrivilegeState:
    current_level: PrivilegeLevel = PrivilegeLevel.NONE
    accessible_resources: list = field(default_factory=list)

@dataclass
class ActionRecord:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    step_index: int = 0
    action_type: str = ""
    target_vuln_id: Optional[str] = None
    tool_used: Optional[str] = None
    reasoning: str = ""
    success: Optional[bool] = None
    result_summary: str = ""
    timestamp: str = field(default_factory=now_iso)

@dataclass
class AttackHistoryState:
    actions: list = field(default_factory=list)
    def log(self, record):
        record.step_index = len(self.actions)
        self.actions.append(record)
    def failures(self): return [a for a in self.actions if a.success is False]

class AttackGraph:
    def __init__(self): self.g = nx.DiGraph()
    def add_state_node(self, state_id, label, **attrs): self.g.add_node(state_id, label=label, **attrs)
    def add_transition(self, from_state, to_state, action):
        self.g.add_edge(from_state, to_state, action_id=action.id, action_type=action.action_type,
                         success=action.success, vuln_id=action.target_vuln_id)
    def to_json(self): return nx.node_link_data(self.g)

@dataclass
class PentestState:
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_name: str = "dvwa"
    asset: AssetState = None
    auth: AuthenticationState = field(default_factory=AuthenticationState)
    vulns: VulnerabilityState = field(default_factory=VulnerabilityState)
    privilege: PrivilegeState = field(default_factory=PrivilegeState)
    history: AttackHistoryState = field(default_factory=AttackHistoryState)
    graph: AttackGraph = field(default_factory=AttackGraph)
    started_at: str = field(default_factory=now_iso)
    goal: str = "escalate_to_admin"

    def to_dict(self):
        return {
            "session_id": self.session_id, "target_name": self.target_name,
            "asset": asdict(self.asset) if self.asset else None,
            "auth": asdict(self.auth), "vulns": {k: asdict(v) for k, v in self.vulns.vulns.items()},
            "privilege": asdict(self.privilege), "history": [asdict(a) for a in self.history.actions],
            "started_at": self.started_at, "goal": self.goal, "graph": self.graph.to_json(),
        }
    def dumps(self): return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def new(cls, target_base_url, target_name="dvwa", goal="escalate_to_admin"):
        st = cls(target_name=target_name, goal=goal)
        st.asset = AssetState(target_base_url=target_base_url)
        st.graph.add_state_node("s0", label="initial_unauthenticated")
        return st
