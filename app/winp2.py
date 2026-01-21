# winp2.py
from __future__ import annotations

import asyncio
import base64

import math
import os
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from json import JSONDecoder, JSONDecodeError
from typing import Any, Dict, Iterable, List, Optional, Tuple

from asyncsocket import AsyncSocket


WINP2_WINSOCKET2_PATH = "/tmp/winsocket2"


# 192byteパケット(TCP)
WINP2_PACKET192_TCP_HOST = "192.168.2.200"
WINP2_PACKET192_TCP_PORT = 4196
WINP2_PACKET192_INTERVAL_SEC = 1.0

WINP2_PACKET192_CONNECT_TIMEOUT_SEC = 0.5
WINP2_PACKET192_WRITE_TIMEOUT_SEC = 0.5
WINP2_PACKET192_RECONNECT_WAIT_SEC = 0.5

# UDP上WIN形式(1秒ブロック)をTCPで流す
WINP2_UDPWIN_DEST_HOST = "192.168.2.143"
WINP2_UDPWIN_DEST_PORT = 9100

WINP2_UDPWIN_ID_CODE = 160
WINP2_UDPWIN_START_PACKET_NO = 0

WINP2_UDPWIN_CONNECT_TIMEOUT_SEC = 0.5
WINP2_UDPWIN_WRITE_TIMEOUT_SEC = 0.5
WINP2_UDPWIN_RECONNECT_WAIT_SEC = 0.5

WINP2_LOG_INTERVAL_SEC = 5.0

JST = timezone(timedelta(hours=9))


def to_iso(ts: str) -> str:
    return ts.replace(" ", "T")


_DEC = JSONDecoder()

DATA_SECTION_LEN = 118
PACKET_LEN = 192
STX = b"\x02"
ID_SECTION = b"\xff\xff\xff\x90\x76\x31"
RESERVED_SECTION = b"\x00" * 66


class BytePos:
    NOW_START = 1
    DETECTOR_TYPE = 7
    RECORD_TYPE = 11
    VIEW_MODE = 12
    MEMORY_CARD = 13
    FAULT = 14
    PAST10_DATA = 15
    RECORDER_STATE = 16
    OP_CHANNEL = 17
    STARTTIME_INVALID = 18
    DATA_CHECK_CODE = 8
    DATA_CHECK_CODE_DATA = 9
    STARTTIME_START = 19
    SITE1_START = 25
    SITE2_START = 56
    SITE3_START = 87


def _bcd_to_int(x: int) -> int:
    return ((x >> 4) * 10) + (x & 0x0F)


def _packet192_summary(pkt: bytes) -> str:
    try:
        data_start = 1 + len(ID_SECTION)
        now_off = data_start + BytePos.NOW_START

        yy = _bcd_to_int(pkt[now_off + 0])
        mm = _bcd_to_int(pkt[now_off + 1])
        dd = _bcd_to_int(pkt[now_off + 2])
        hh = _bcd_to_int(pkt[now_off + 3])
        mi = _bcd_to_int(pkt[now_off + 4])
        ss = _bcd_to_int(pkt[now_off + 5])
        now_str = f"20{yy:02d}-{mm:02d}-{dd:02d} {hh:02d}:{mi:02d}:{ss:02d}"

        bcc_calc = sum(pkt[1:191]) & 0xFF
        bcc_pkt = pkt[191]
        bcc_ok = bcc_calc == bcc_pkt

        return f"now={now_str} bcc={bcc_pkt:02x} calc={bcc_calc:02x} ok={bcc_ok}"
    except Exception as e:
        return f"(summary_error={e})"


def _to_bcd_byte(n: int) -> int:
    n = int(n)
    if n < 0:
        n = 0
    if n > 99:
        n = 99
    return ((n // 10) << 4) | (n % 10)


def dt_to_bcd6(dt: datetime) -> List[int]:
    yy = dt.year % 100
    return [
        _to_bcd_byte(yy),
        _to_bcd_byte(dt.month),
        _to_bcd_byte(dt.day),
        _to_bcd_byte(dt.hour),
        _to_bcd_byte(dt.minute),
        _to_bcd_byte(dt.second),
    ]


def put_byte(buf: bytearray, index_0based: int, value: int) -> None:
    buf[index_0based] = value & 0xFF


def put_bytes(buf: bytearray, start_0based: int, values: Iterable[int]) -> None:
    for i, v in enumerate(values):
        put_byte(buf, start_0based + i, int(v) & 0xFF)


def _float_to_bcd_str(
    value: Optional[float], total_digits: int, decimal_places: int = 1
) -> str:
    if value is None:
        return "0" * total_digits
    val_int = int(round(float(value) * (10**decimal_places)))
    if val_int < 0:
        val_int = 0
    max_int = int("9" * total_digits)
    if val_int > max_int:
        val_int = max_int
    return f"{val_int:0{total_digits}d}"


def put_decimal_nibbles(buf: bytearray, start_0based: int, digits: str) -> int:
    nibbles = [ord(d) - 48 for d in digits]
    if len(nibbles) % 2 == 1:
        nibbles.append(0)
    out = []
    for i in range(0, len(nibbles), 2):
        out.append(((nibbles[i] & 0x0F) << 4) | (nibbles[i + 1] & 0x0F))
    put_bytes(buf, start_0based, out)
    return len(out)


@dataclass
class SiteBlock:
    site_no: int
    max_ns: float = 0.0
    max_ew: float = 0.0
    max_ud: float = 0.0
    max_hz: float = 0.0
    max_3: float = 0.0
    shindo: float = 0.0
    si: float = 0.0
    res1: float = 0.0
    res2: float = 0.0


def _zero_site(buf: bytearray, start: int):
    for i in range(31):
        put_byte(buf, start + i, 0)


def round_half_up(x: float) -> int:
    return int(math.floor(x + 0.5)) if x >= 0 else int(math.ceil(x - 0.5))


def _write_site(buf: bytearray, start: int, s: SiteBlock):
    _zero_site(buf, start)
    put_byte(buf, start + 0, s.site_no & 0xFF)
    put_decimal_nibbles(buf, start + 1, _float_to_bcd_str(s.max_ns, 6, 1))
    put_decimal_nibbles(buf, start + 4, _float_to_bcd_str(s.max_ew, 6, 1))
    put_decimal_nibbles(buf, start + 7, _float_to_bcd_str(s.max_ud, 6, 1))
    put_decimal_nibbles(buf, start + 10, _float_to_bcd_str(s.max_3, 6, 1))
    put_decimal_nibbles(buf, start + 13, _float_to_bcd_str(s.max_hz, 6, 1))
    shindo = float(s.shindo)
    rounded = round_half_up(shindo)
    put_byte(buf, start + 16, rounded & 0xFF)
    flag = 0
    if rounded in (5, 6):
        base = float(rounded)
        if shindo < base:
            flag = 1
        elif shindo >= base:
            flag = 2
    put_byte(buf, start + 17, flag)
    put_decimal_nibbles(buf, start + 18, _float_to_bcd_str(float(s.shindo), 2, 1))
    put_decimal_nibbles(buf, start + 19, _float_to_bcd_str(s.si, 6, 1))
    put_byte(buf, start + 22, 1)
    put_byte(buf, start + 23, 2)
    put_decimal_nibbles(buf, start + 24, _float_to_bcd_str(s.res1, 6, 1))
    put_decimal_nibbles(buf, start + 27, _float_to_bcd_str(s.res2, 6, 1))


def _parse_dt_any(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    try:
        if "T" in s:
            return datetime.fromisoformat(s)
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=JST)
    except Exception:
        return None


def _sites_from_status(
    status: Dict[str, Any],
) -> Tuple[Optional[datetime], Optional[datetime], List[SiteBlock]]:
    now_dt = _parse_dt_any(status.get("gps_time"))
    start_dt = _parse_dt_any(status.get("start_date"))
    pdata = status.get("pdata")
    sites: List[SiteBlock] = []
    if isinstance(pdata, list):
        for i in range(3):
            p = pdata[i] if i < len(pdata) and isinstance(pdata[i], dict) else {}
            sites.append(
                SiteBlock(
                    site_no=int(p.get("point", i + 1)),
                    shindo=float(p.get("shindo", 0) or 0),
                    si=float(p.get("si", 0) or 0),
                    max_ns=float(p.get("max_ns", 0) or 0),
                    max_ew=float(p.get("max_ew", 0) or 0),
                    max_ud=float(p.get("max_ud", 0) or 0),
                    max_hz=float(p.get("max_hz", 0) or 0),
                    max_3=float(p.get("max_3", 0) or 0),
                    res1=float(p.get("res1", 0) or 0),
                    res2=float(p.get("res2", 0) or 0),
                )
            )
    else:
        sites = [SiteBlock(site_no=1), SiteBlock(site_no=2), SiteBlock(site_no=3)]
    return now_dt, start_dt, sites


class Packet192Builder:
    def __init__(self):
        self.history: List[bytes] = []
        self._latched_start_key: Optional[str] = None
        self._latched_shindo: List[Optional[float]] = [None, None, None]
        self._latched_max_ns: List[Optional[float]] = [None, None, None]
        self._latched_max_ew: List[Optional[float]] = [None, None, None]
        self._latched_max_ud: List[Optional[float]] = [None, None, None]
        self._latched_max_3: List[Optional[float]] = [None, None, None]
        self._latched_max_hz: List[Optional[float]] = [None, None, None]

    def build_packet(self, status: Dict[str, Any], fallback_now: datetime) -> bytes:
        now_dt, start_dt, sites = _sites_from_status(status)
        start_key_raw = status.get("start_date")
        start_key = str(start_key_raw).strip() if start_key_raw else None

        if start_key != self._latched_start_key:
            self._latched_start_key = start_key
            self._latched_shindo = [None, None, None]
            self._latched_max_ns = [None, None, None]
            self._latched_max_ew = [None, None, None]
            self._latched_max_ud = [None, None, None]
            self._latched_max_3 = [None, None, None]
            self._latched_max_hz = [None, None, None]

        for i in range(min(3, len(sites))):
            cur_shindo = float(sites[i].shindo)
            if self._latched_shindo[i] is None or cur_shindo > self._latched_shindo[i]:
                self._latched_shindo[i] = cur_shindo
            sites[i].shindo = float(self._latched_shindo[i])

            cur_ns = float(sites[i].max_ns)
            if self._latched_max_ns[i] is None or cur_ns > self._latched_max_ns[i]:
                self._latched_max_ns[i] = cur_ns
            sites[i].max_ns = float(self._latched_max_ns[i])

            cur_ew = float(sites[i].max_ew)
            if self._latched_max_ew[i] is None or cur_ew > self._latched_max_ew[i]:
                self._latched_max_ew[i] = cur_ew
            sites[i].max_ew = float(self._latched_max_ew[i])

            cur_ud = float(sites[i].max_ud)
            if self._latched_max_ud[i] is None or cur_ud > self._latched_max_ud[i]:
                self._latched_max_ud[i] = cur_ud
            sites[i].max_ud = float(self._latched_max_ud[i])

            cur_3 = float(sites[i].max_3)
            if self._latched_max_3[i] is None or cur_3 > self._latched_max_3[i]:
                self._latched_max_3[i] = cur_3
            sites[i].max_3 = float(self._latched_max_3[i])

            cur_hz = float(sites[i].max_hz)
            if self._latched_max_hz[i] is None or cur_hz > self._latched_max_hz[i]:
                self._latched_max_hz[i] = cur_hz
            sites[i].max_hz = float(self._latched_max_hz[i])

        dt_now = now_dt or fallback_now
        if dt_now.tzinfo is None:
            dt_now = dt_now.replace(tzinfo=JST)

        buf = bytearray([0x00] * DATA_SECTION_LEN)
        put_bytes(buf, BytePos.NOW_START, dt_to_bcd6(dt_now))
        put_byte(buf, BytePos.DETECTOR_TYPE, 0)
        put_byte(buf, BytePos.VIEW_MODE, 1)
        put_byte(buf, BytePos.RECORD_TYPE, 1)
        put_byte(buf, BytePos.MEMORY_CARD, 0)
        put_byte(buf, BytePos.FAULT, 0)

        past10_count = min(len(self.history), 9)
        past10_valid = 0x80 if past10_count > 0 else 0x00
        put_byte(buf, BytePos.PAST10_DATA, past10_valid | (past10_count & 0x0F))
        put_byte(buf, BytePos.RECORDER_STATE, 1)
        put_byte(buf, BytePos.OP_CHANNEL, _to_bcd_byte(0))
        put_byte(buf, BytePos.DATA_CHECK_CODE, 0x01)

        if start_dt is None:
            put_byte(buf, BytePos.STARTTIME_INVALID, 0xF0)
            put_bytes(buf, BytePos.STARTTIME_START, dt_to_bcd6(dt_now))
        else:
            put_byte(buf, BytePos.STARTTIME_INVALID, 0x00)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=JST)
            put_bytes(buf, BytePos.STARTTIME_START, dt_to_bcd6(start_dt))

        _write_site(
            buf, BytePos.SITE1_START, sites[0] if len(sites) > 0 else SiteBlock(1)
        )
        _write_site(
            buf, BytePos.SITE2_START, sites[1] if len(sites) > 1 else SiteBlock(2)
        )
        _write_site(
            buf, BytePos.SITE3_START, sites[2] if len(sites) > 2 else SiteBlock(3)
        )

        current_block = bytes(buf[17:118])
        checksum = sum(sum(b) for b in self.history[-9:]) + sum(current_block)
        put_bytes(
            buf, BytePos.DATA_CHECK_CODE_DATA, [(checksum >> 8) & 0xFF, checksum & 0xFF]
        )

        buffer_for_bcc = ID_SECTION + bytes(buf) + RESERVED_SECTION
        bcc_val = sum(buffer_for_bcc) & 0xFF
        pkt = STX + buffer_for_bcc + bytes([bcc_val])
        if len(pkt) != PACKET_LEN:
            raise RuntimeError(f"packet len mismatch: {len(pkt)} != {PACKET_LEN}")

        self.history.append(current_block)
        if len(self.history) > 10:
            self.history = self.history[-10:]
        return pkt


class Packet192Connection:
    def __init__(
        self,
        dest_host: str,
        dest_port: int,
        connect_timeout_sec: float = 3.0,
        write_timeout_sec: float = 2.0,
        reconnect_wait_sec: float = 2.0,
    ):
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.connect_timeout_sec = connect_timeout_sec
        self.write_timeout_sec = write_timeout_sec
        self.reconnect_wait_sec = reconnect_wait_sec

        self._writer: Optional[asyncio.StreamWriter] = None

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
                asyncio.open_connection(self.dest_host, self.dest_port),
                timeout=self.connect_timeout_sec,
            )
            self._writer = w
            print(
                f"[winp2] packet192 tcp connected -> {(self.dest_host, self.dest_port)}"
            )
            return True
        except Exception as e:
            print(f"[winp2][packet192][WARN] tcp connect failed: {e} -> drop")
            self._writer = None
            return False

    async def send_packet(self, pkt: bytes) -> bool:
        if len(pkt) != PACKET_LEN:
            raise RuntimeError(f"packet len mismatch: {len(pkt)} != {PACKET_LEN}")

        if self._writer is None:
            ok = await self._try_connect_once()
            if not ok:
                return False

        try:
            assert self._writer is not None
            self._writer.write(pkt)
            await asyncio.wait_for(self._writer.drain(), timeout=self.write_timeout_sec)

            summary = _packet192_summary(pkt)
            hex_str = pkt.hex()
            print(
                f"[winp2][packet192] sent -> {self.dest_host}:{self.dest_port} "
                f"len={len(pkt)} {summary} hex={hex_str}"
            )
            return True
        except Exception as e:
            print(f"[winp2][WARN] packet192 send failed: {e} -> close")
            await self._close()
            return False


class UdpWinConnection:
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
                print(
                    f"[winp2][udpwin][WARN] tcp connect timeout ({self.connect_timeout_sec}s) -> retry"
                )
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
        payload = (
            bytes([self.pkt_no, self.pkt_no, self.id_code])
            + struct.pack(">H", sec_size)
            + sec_block
        )
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


async def run_bridge(
    path: str,
    *,
    tcp_host: str,
    tcp_port: int,
    id_code: int,
    start_packet_no: int = 0,
    reconnect_wait_sec: float = 0.5,
    connect_timeout_sec: float = 0.5,
    write_timeout_sec: float = 0.5,
    log_interval_sec: float = 5.0,
    read_bytes: int = 65536,
    # 192 settings
    packet192_host: str = "",
    packet192_port: int = 0,
    packet192_connect_timeout_sec: float = 0.5,
    packet192_write_timeout_sec: float = 0.5,
    packet192_reconnect_wait_sec: float = 0.5,
) -> None:
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass

    sender = UdpWinConnection(
        host=tcp_host,
        port=int(tcp_port),
        id_code=int(id_code),
        start_packet_no=int(start_packet_no),
        reconnect_wait_sec=float(reconnect_wait_sec),
        connect_timeout_sec=float(connect_timeout_sec),
        write_timeout_sec=float(write_timeout_sec),
    )

    processor = Packet192Builder()
    pusher192 = Packet192Connection(
        dest_host=packet192_host,
        dest_port=packet192_port,
        connect_timeout_sec=packet192_connect_timeout_sec,
        write_timeout_sec=packet192_write_timeout_sec,
        reconnect_wait_sec=packet192_reconnect_wait_sec,
    )

    send_q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)
    send_q_192: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)

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

    async def _sender_worker_192() -> None:
        while True:
            pkt = await send_q_192.get()
            try:
                await pusher192.send_packet(pkt)
            except Exception as e:
                print(f"[winp2][packet192][WARN] sender worker error: {e}")
            finally:
                send_q_192.task_done()

    asyncio.create_task(_sender_worker_192())

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
            ts_iso = to_iso(str(ts))

            try:
                if isinstance(status, dict):
                    try:
                        pkt = processor.build_packet(
                            status, fallback_now=datetime.now(tz=JST)
                        )
                        try:
                            send_q_192.put_nowait(pkt)
                        except asyncio.QueueFull:
                            try:
                                _ = send_q_192.get_nowait()
                                send_q_192.task_done()
                            except Exception:
                                pass
                            try:
                                send_q_192.put_nowait(pkt)
                            except Exception:
                                pass
                    except Exception as e:
                        print(f"[winp2][packet192][WARN] build/enqueue failed: {e}")

            except Exception as e:
                print(f"[winp2][WARN] status process failed: {e}")

            except Exception as e:
                print(f"[winp2][WARN] status process failed: {e}")

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

    sock = AsyncSocket(
        path, mode="server", on_receive=on_receive, read_bytes=read_bytes
    )
    print(
        f"[winp2] winsocket2+udpwin bridge listening: {path} -> tcp {tcp_host}:{tcp_port}"
    )

    await sock.start()


async def _amain() -> None:
    await run_bridge(
        WINP2_WINSOCKET2_PATH,
        tcp_host=WINP2_UDPWIN_DEST_HOST,
        tcp_port=WINP2_UDPWIN_DEST_PORT,
        id_code=WINP2_UDPWIN_ID_CODE,
        start_packet_no=WINP2_UDPWIN_START_PACKET_NO,
        reconnect_wait_sec=WINP2_UDPWIN_RECONNECT_WAIT_SEC,
        connect_timeout_sec=WINP2_UDPWIN_CONNECT_TIMEOUT_SEC,
        write_timeout_sec=WINP2_UDPWIN_WRITE_TIMEOUT_SEC,
        log_interval_sec=WINP2_LOG_INTERVAL_SEC,
        # 192 settings
        packet192_host=WINP2_PACKET192_TCP_HOST,
        packet192_port=WINP2_PACKET192_TCP_PORT,
        packet192_connect_timeout_sec=WINP2_PACKET192_CONNECT_TIMEOUT_SEC,
        packet192_write_timeout_sec=WINP2_PACKET192_WRITE_TIMEOUT_SEC,
        packet192_reconnect_wait_sec=WINP2_PACKET192_RECONNECT_WAIT_SEC,
    )


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
