# winsocket2_udpwin_bridge.py
from __future__ import annotations

import asyncio
import base64
import os
import struct
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



class UdpWinTcpSender:
    """UDPパケット上のWIN形式(1秒=1パケット)を、TCPフレームに包んで送る。
    TCPフレーム: len16(be) + payload
    payload: pkt_no, pkt_no, id_code, sec_size16(be), sec_block...
    """

    def __init__(
        self,
        host: str,
        port: int,
        id_code: int,
        start_packet_no: int = 0,
        reconnect_wait_sec: float = 2.0,
        connect_timeout_sec: float = 2.0,
        write_timeout_sec: float = 2.0,
    ) -> None:
        self.host = host
        self.port = port
        self.id_code = id_code & 0xFF
        self.pkt_no = start_packet_no & 0xFF

        self.reconnect_wait_sec = float(reconnect_wait_sec)
        self.connect_timeout_sec = float(connect_timeout_sec)
        self.write_timeout_sec = float(write_timeout_sec)

        self._writer: Optional[asyncio.StreamWriter] = None

    async def _connect_once(self) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.connect_timeout_sec,
        )
        self._writer = w
        print(f"[winp2][udpwin] tcp connected -> {(self.host, self.port)}")

    async def _connect(self) -> None:
        while True:
            try:
                await self._connect_once()
                return
            except asyncio.TimeoutError:
                print(f"[winp2][udpwin][WARN] tcp connect timeout ({self.connect_timeout_sec}s) -> retry")
            except Exception as e:
                print(f"[winp2][udpwin][WARN] tcp connect failed: {e} -> retry")
            await asyncio.sleep(self.reconnect_wait_sec)

    async def _ensure(self) -> None:
        if self._writer is None:
            await self._connect()

    async def _close(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._writer = None

    async def _try_connect_once(self) -> bool:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.connect_timeout_sec,
            )
            self._writer = w
            print(f"[winp2][udpwin] tcp connected -> {(self.host, self.port)}")
            return True
        except Exception as e:
            print(f"[winp2][udpwin][WARN] tcp connect failed: {e} -> drop")
            self._writer = None
            return False

    async def send_sec_block_best_effort(self, sec_block: bytes) -> bool:
        sec_size = len(sec_block) + 2
        payload = bytes([self.pkt_no, self.pkt_no, self.id_code]) + struct.pack(">H", sec_size) + sec_block
        frame = struct.pack(">H", len(payload)) + payload

        if self._writer is None:
            ok = await self._try_connect_once()
            if not ok:
                return False

        try:
            assert self._writer is not None
            self._writer.write(frame)
            await asyncio.wait_for(self._writer.drain(), timeout=self.write_timeout_sec)
            self.pkt_no = (self.pkt_no + 1) & 0xFF
            return True
        except Exception as e:
            print(f"[winp2][udpwin][WARN] tcp send failed: {e} -> drop")
            await self._close()
            return False


async def run_winsocket2_udpwin_bridge(
    path: str,
    store: StatusStore,
    *,
    tcp_host: str,
    tcp_port: int,
    id_code: int,
    start_packet_no: int = 0,
    reconnect_wait_sec: float = 2.0,
    connect_timeout_sec: float = 2.0,
    write_timeout_sec: float = 2.0,
    status_dump_path: Optional[str] = None,
    packet192_dump_path: Optional[str] = None,
    log_interval_sec: float = 5.0,
    read_bytes: int = 65536,
) -> None:
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass

    sender = UdpWinTcpSender(
        host=tcp_host,
        port=int(tcp_port),
        id_code=int(id_code),
        start_packet_no=int(start_packet_no),
        reconnect_wait_sec=float(reconnect_wait_sec),
        connect_timeout_sec=float(connect_timeout_sec),
        write_timeout_sec=float(write_timeout_sec),
    )

    send_q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)

    async def _sender_worker() -> None:
        while True:
            sec_block = await send_q.get()
            try:
                await sender.send_sec_block_best_effort(sec_block)
            except Exception as e:
                print(f"[winp2][udpwin][WARN] sender worker error: {e}")
            finally:
                send_q.task_done()

    asyncio.create_task(_sender_worker())

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

            try:
                if isinstance(status, dict):
                    store.update(ts_iso, status)
                    if status_dump_path:
                        _atomic_write_json(status_dump_path, {"ts": ts_iso, "status": status})
            except Exception as e:
                print(f"[winp2][WARN] store update failed: {e}")

            if packet192_dump_path:
                p192_b64 = obj.get("packet192_b64")
                if p192_b64:
                    try:
                        raw192 = base64.b64decode(p192_b64)
                        with open(packet192_dump_path, "wb") as f:
                            f.write(raw192)
                        print(f"[winp2] packet192 saved: {packet192_dump_path} (len={len(raw192)})")
                    except Exception as e:
                        print(f"[winp2][WARN] packet192 save failed: {e}")

            win1s_b64 = obj.get("win1s_b64")
            if win1s_b64:
                try:
                    raw = base64.b64decode(win1s_b64)
                    if len(raw) >= 4:
                        block_size = int.from_bytes(raw[:4], "big")
                        if 4 <= block_size <= len(raw):
                            sec_block = raw[4:block_size]
                        else:
                            sec_block = raw[4:]
                    else:
                        sec_block = raw

                    try:
                        send_q.put_nowait(sec_block)
                    except asyncio.QueueFull:
                        try:
                            _ = send_q.get_nowait()
                            send_q.task_done()
                        except Exception:
                            pass
                        try:
                            send_q.put_nowait(sec_block)
                        except Exception:
                            pass
                except Exception as e:
                    print(f"[winp2][udpwin][WARN] decode/convert failed: {e}")

            now = time.time()
            if now - last_log >= log_interval_sec:
                last_log = now
                keys = list(status.keys())[:8] if isinstance(status, dict) else []
                print(f"[winp2] winsocket2 recv={recv} last_ts={ts_iso} keys={keys}")

    sock = AsyncSocket(path, mode="server", on_receive=on_receive, read_bytes=read_bytes)
    print(f"[winp2] winsocket2+udpwin bridge listening: {path} -> tcp {tcp_host}:{tcp_port}")

    await sock.start()
