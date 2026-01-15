# winp2/app/status_store.py
from __future__ import annotations
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, Optional

@dataclass
class LatestStatus:
    ts_iso: Optional[str] = None
    status: Optional[Dict[str, Any]] = None

class StatusStore:
    def __init__(self):
        self._lock = Lock()
        self._latest = LatestStatus()

    def update(self, ts_iso: Optional[str], status: Dict[str, Any]) -> None:
        with self._lock:
            self._latest = LatestStatus(ts_iso=ts_iso, status=status)

    def set(self, ts_iso: Optional[str], status: Dict[str, Any]) -> None:
        if ts_iso is not None:
            ts_iso = ts_iso.replace(" ", "T")
        self.update(ts_iso, status)

    def get(self) -> LatestStatus:
        with self._lock:
            return LatestStatus(ts_iso=self._latest.ts_iso,
                                status=dict(self._latest.status) if self._latest.status else None)
