from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from json import JSONDecoder, JSONDecodeError
from typing import Any, Dict, Optional

from asyncsocket import AsyncSocket
from status_store import StatusStore

JST = timezone(timedelta(hours=9))
_DEC = JSONDecoder()


def _to_iso(ts: str) -> str:
    return ts.replace(" ", "T")


def _atomic_write_json(path: str, obj: dict) -> None:
    import json, os, tempfile
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmpp = tempfile.mkstemp(prefix=".tmp_", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmpp, path)
    finally:
        try:
            if os.path.exists(tmpp):
                os.unlink(tmpp)
        except Exception:
            pass



async def run_winsocket2_server(
    path: str,
    store: StatusStore,
    dump_path: Optional[str] = None,
    log_interval_sec: float = 5.0,
    read_bytes: int = 65536,
) -> None:
    buffers: Dict[int, str] = {}
    recv = 0
    last_log = 0.0

    async def on_receive(chunk: str, writer) -> None:
        nonlocal recv, last_log

        wid = id(writer)
        buf = buffers.get(wid, "") + chunk

        while True:
            s = buf.lstrip()
            if not s:
                buffers[wid] = ""
                return

            try:
                obj, idx = _DEC.raw_decode(s)
            except JSONDecodeError:
                buffers[wid] = s
                return

            buf = s[idx:]
            buffers[wid] = buf
            recv += 1

            if not isinstance(obj, dict):
                continue

            ts = obj.get("ts") or datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")
            status = obj.get("status") or {}
            ts_iso = _to_iso(str(ts))
            if isinstance(status, dict):
                store.update(ts_iso, status)
                if dump_path:
                    _atomic_write_json(dump_path, {"ts": ts_iso, "status": status})

            now = time.time()
            if now - last_log >= log_interval_sec:
                last_log = now
                keys = list(status.keys())[:8] if isinstance(status, dict) else []
                print(f"[winp2] winsocket2 recv={recv} last_ts={ts_iso} keys={keys}")

    sock = AsyncSocket(path, mode="server", on_receive=on_receive, read_bytes=read_bytes)
    print(f"[winp2] winsocket2 server: {path}")
    await sock.start()
