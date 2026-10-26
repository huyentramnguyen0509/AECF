"""
Memory Mechanism (MM) — Chương 3.6

Hai loại memory đúng như scope đã chốt:
  - SessionMemory : decision + context trong CÙNG một phiên pentest hiện tại.
                    Dùng để Planner không lặp lại hành động đã thử, và để
                    Execution-Evaluator biết bước trước đã làm gì.
  - FailureMemory : tích lũy QUA NHIỀU phiên (persist ra đĩa). Ghi lại những
                    exploit đã thất bại trên loại target/vuln tương tự, để
                    Adaptive Planning Engine hạ ranking cho các action giống vậy
                    trong lần chạy sau (đây là phần đo trong ablation study —
                    Full Framework vs Planning-only-no-Memory).

Lưu trữ đơn giản bằng JSON file (đủ cho prototype). Có thể thay bằng SQLite
sau nếu cần query phức tạp hơn — interface giữ nguyên.
"""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

from core.state import ActionRecord, VulnType


@dataclass
class SessionMemoryEntry:
    step_index: int
    summary: str            # tóm tắt ngắn cho LLM context (không nhét cả state thô)
    action_type: str
    success: Optional[bool]


class SessionMemory:
    """In-memory, sống trong 1 lần chạy AECF, có thể snapshot ra JSON để debug."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.entries: list[SessionMemoryEntry] = []

    def remember(self, action: ActionRecord) -> None:
        self.entries.append(SessionMemoryEntry(
            step_index=action.step_index,
            summary=f"[{action.action_type}] target_vuln={action.target_vuln_id} -> "
                    f"{'OK' if action.success else 'FAIL' if action.success is False else 'PENDING'}: "
                    f"{action.result_summary[:160]}",
            action_type=action.action_type,
            success=action.success,
        ))

    def recent_context(self, n: int = 8) -> str:
        """Trả về context ngắn gọn để nhét vào prompt của Planner Agent."""
        tail = self.entries[-n:]
        return "\n".join(f"step {e.step_index}: {e.summary}" for e in tail) or "(chưa có hành động nào)"

    def tried_actions_on(self, vuln_id: str) -> list[SessionMemoryEntry]:
        return [e for e in self.entries if e.summary.find(vuln_id) != -1]


@dataclass
class FailurePattern:
    vuln_type: str
    action_type: str
    context_signature: str   # vd: "waf_present=true;param_type=numeric"
    fail_count: int = 1
    last_note: str = ""


class FailureMemory:
    """
    Persist qua nhiều session (khác với SessionMemory). Đây là phần được
    bật/tắt trong ablation study để đo RQ3 (đóng góp của Memory vào re-planning).
    """

    def __init__(self, path: str = "storage/failure_memory.json"):
        self.path = path
        self.patterns: dict[str, FailurePattern] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.patterns = {k: FailurePattern(**v) for k, v in raw.items()}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({k: asdict(v) for k, v in self.patterns.items()}, f, indent=2)

    def _key(self, vuln_type: str, action_type: str, context_signature: str) -> str:
        return f"{vuln_type}|{action_type}|{context_signature}"

    def record_failure(self, vuln_type: str, action_type: str, context_signature: str, note: str = "") -> None:
        key = self._key(vuln_type, action_type, context_signature)
        if key in self.patterns:
            self.patterns[key].fail_count += 1
            self.patterns[key].last_note = note
        else:
            self.patterns[key] = FailurePattern(vuln_type, action_type, context_signature, 1, note)
        self._save()

    def penalty_for(self, vuln_type: str, action_type: str, context_signature: str) -> float:
        """
        Trả về hệ số phạt (0..~0.9) dùng để trừ vào ranking score trong APE
        (xem core/planner.py: exploit ranking). Càng fail nhiều trong bối cảnh
        giống nhau -> penalty càng cao, nhưng chặn trần để không loại bỏ hẳn
        action (agent vẫn có thể thử lại nếu không còn lựa chọn khác).
        """
        key = self._key(vuln_type, action_type, context_signature)
        p = self.patterns.get(key)
        if not p:
            return 0.0
        return min(0.1 * p.fail_count, 0.9)

    def disabled_copy(self) -> "FailureMemory":
        """Dùng cho nhánh ablation 'Planning-only (không Memory)': trả về
        instance rỗng, không đọc/ghi disk, để so sánh công bằng."""
        fm = FailureMemory.__new__(FailureMemory)
        fm.path = os.devnull
        fm.patterns = {}
        fm._save = lambda: None  # no-op, không ghi gì
        return fm
