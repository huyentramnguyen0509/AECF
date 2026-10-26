"""
Storage — JSON/SQLite State Store, Chương 4.2.3

Prototype dùng JSON file per-run (đơn giản, dễ đọc lại để tính metrics
Chương 5). Có thể thay bằng SQLite sau nếu cần query chéo nhiều run
hiệu quả hơn (interface save_state/load_state giữ nguyên).
"""

from __future__ import annotations
import json
import os

from core.state import PentestState


def save_state(state: PentestState, dir_path: str = "storage/runs") -> str:
    os.makedirs(dir_path, exist_ok=True)
    out_path = os.path.join(dir_path, f"{state.session_id}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(state.dumps())
    return out_path


def load_state_dict(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
