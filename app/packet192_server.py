# packet192_server.py
from __future__ import annotations
import socket
import threading
import time
import math
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from status_store import StatusStore

import json

JST = timezone(timedelta(hours=9))

DATA_SECTION_LEN = 118
PACKET_LEN = 192
STX = b"\x02"
ID_SECTION = b"\xff\xff\xff\x90\x76\x31"
RESERVED_SECTION = b"\x00" * 66

def _hex_preview(b: bytes, head: int = 64, tail: int = 32) -> str:
    if len(b) <= head + tail:
        return b.hex()
    return f"{b[:head].hex()}...{b[-tail:].hex()}"

def _bcd_to_int(x: int) -> int:
    return ((x >> 4) * 10) + (x & 0x0F)

def _packet192_summary(pkt: bytes) -> str:
    try:
        data_start = 1 + len(ID_SECTION)  # STX(1) + ID_SECTION(6) の次が data_section(118)
        now_off = data_start + BytePos.NOW_START  # data_section内のNOW_START=1

        yy = _bcd_to_int(pkt[now_off + 0])
        mm = _bcd_to_int(pkt[now_off + 1])
        dd = _bcd_to_int(pkt[now_off + 2])
        hh = _bcd_to_int(pkt[now_off + 3])
        mi = _bcd_to_int(pkt[now_off + 4])
        ss = _bcd_to_int(pkt[now_off + 5])
        now_str = f"20{yy:02d}-{mm:02d}-{dd:02d} {hh:02d}:{mi:02d}:{ss:02d}"

        # BCC：build_packet() と同じ計算（pkt[1:191] の合計下位8bit）
        bcc_calc = sum(pkt[1:191]) & 0xFF
        bcc_pkt = pkt[191]
        bcc_ok = (bcc_calc == bcc_pkt)

        return f"now={now_str} bcc={bcc_pkt:02x} calc={bcc_calc:02x} ok={bcc_ok}"
    except Exception as e:
        return f"(summary_error={e})"


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

def _to_bcd_byte(n: int) -> int:
    n = int(n)
    if n < 0: n = 0
    if n > 99: n = 99
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

def _float_to_bcd_str(value: Optional[float], total_digits: int, decimal_places: int = 1) -> str:
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

    # X,Y,Z 3byteずつ（6桁 小数1位）
    put_decimal_nibbles(buf, start + 1, _float_to_bcd_str(s.max_ns, 6, 1))
    put_decimal_nibbles(buf, start + 4, _float_to_bcd_str(s.max_ew, 6, 1))
    put_decimal_nibbles(buf, start + 7, _float_to_bcd_str(s.max_ud, 6, 1))

    # 合成 / 水平
    put_decimal_nibbles(buf, start + 10, _float_to_bcd_str(s.max_3, 6, 1))
    put_decimal_nibbles(buf, start + 13, _float_to_bcd_str(s.max_hz, 6, 1))

    # 震度
    shindo = float(s.shindo)
    rounded = round_half_up(shindo)
    put_byte(buf, start + 16, rounded & 0xFF)
    flag = 0
    if rounded in (5, 6):
        base = float(rounded)  # 5.0 or 6.0
        if shindo < base:
            flag = 1
        elif shindo >= base:
            flag = 2
    put_byte(buf, start + 17, flag)
    print(f"shindo: raw={s.shindo} rounded={rounded} flag={flag}")

    # 計測震度(2桁 小数1位)
    put_decimal_nibbles(buf, start + 18, _float_to_bcd_str(float(s.shindo), 2, 1))

    # SI(6桁 小数1位)
    put_decimal_nibbles(buf, start + 19, _float_to_bcd_str(s.si, 6, 1))

    put_byte(buf, start + 22, 1)
    put_byte(buf, start + 23, 2)
    put_decimal_nibbles(buf, start + 24, _float_to_bcd_str(s.res1, 6, 1))
    put_decimal_nibbles(buf, start + 27, _float_to_bcd_str(s.res2, 6, 1))

def _parse_dt_any(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    # 例: "2026-01-08 09:15:23" / iso
    try:
        if "T" in s:
            return datetime.fromisoformat(s)
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=JST)
    except Exception:
        return None

def _sites_from_status(status: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime], List[SiteBlock]]:
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

class DataProcessor:
    def __init__(self):
        self.history: List[bytes] = []  # keep last 10 data blocks (101 bytes region)

        self._latched_start_key: Optional[str] = None
        self._latched_shindo: List[Optional[float]] = [None, None, None]

    def build_packet(self, status: Dict[str, Any], fallback_now: datetime) -> bytes:
        now_dt, start_dt, sites = _sites_from_status(status)
        
        start_key_raw = status.get("start_date")
        start_key = str(start_key_raw).strip() if start_key_raw else None

        if start_key != self._latched_start_key:
            self._latched_start_key = start_key
            self._latched_shindo = [None, None, None]
        
        for i in range(min(3, len(sites))):
            cur = float(sites[i].shindo)

            if self._latched_shindo[i] is None:
                self._latched_shindo[i] = cur
            else:
                if cur > self._latched_shindo[i]:
                    self._latched_shindo[i] = cur

            sites[i].shindo = float(self._latched_shindo[i])


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

        # past10
        past10_count = min(len(self.history), 9)
        past10_valid = 0x80 if past10_count > 0 else 0x00
        put_byte(buf, BytePos.PAST10_DATA, past10_valid | (past10_count & 0x0F))

        put_byte(buf, BytePos.RECORDER_STATE, 1)
        put_byte(buf, BytePos.OP_CHANNEL, _to_bcd_byte(0))

        # check code
        put_byte(buf, BytePos.DATA_CHECK_CODE, 0x01)

        # start time
        if start_dt is None:
            put_byte(buf, BytePos.STARTTIME_INVALID, 0xF0)
            put_bytes(buf, BytePos.STARTTIME_START, dt_to_bcd6(dt_now))
        else:
            put_byte(buf, BytePos.STARTTIME_INVALID, 0x00)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=JST)
            put_bytes(buf, BytePos.STARTTIME_START, dt_to_bcd6(start_dt))

        # sites
        _write_site(buf, BytePos.SITE1_START, sites[0] if len(sites)>0 else SiteBlock(1))
        _write_site(buf, BytePos.SITE2_START, sites[1] if len(sites)>1 else SiteBlock(2))
        _write_site(buf, BytePos.SITE3_START, sites[2] if len(sites)>2 else SiteBlock(3))

        # data_check_code_data = checksum(prev9 + current)
        current_block = bytes(buf[17:118])
        checksum = sum(sum(b) for b in self.history[-9:]) + sum(current_block)
        put_bytes(buf, BytePos.DATA_CHECK_CODE_DATA, [(checksum >> 8) & 0xFF, checksum & 0xFF])

        # build full 192
        buffer_for_bcc = ID_SECTION + bytes(buf) + RESERVED_SECTION
        bcc_val = sum(buffer_for_bcc) & 0xFF
        pkt = STX + buffer_for_bcc + bytes([bcc_val])
        if len(pkt) != PACKET_LEN:
            raise RuntimeError(f"packet len mismatch: {len(pkt)} != {PACKET_LEN}")

        # update history
        self.history.append(current_block)
        if len(self.history) > 10:
            self.history = self.history[-10:]
        return pkt

class Packet192TcpPusher:
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

        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def _close_nolock(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None

    def close(self) -> None:
        with self._lock:
            self._close_nolock()

    def _ensure_connected_nolock(self) -> None:
        if self._sock is not None:
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout_sec)
        s.connect((self.dest_host, self.dest_port))

        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        s.settimeout(self.write_timeout_sec)

        self._sock = s
        print(f"[winp2] packet192 tcp connected -> {(self.dest_host, self.dest_port)}")

    def send_packet(self, pkt: bytes) -> bool:
        if len(pkt) != PACKET_LEN:
            raise RuntimeError(f"packet len mismatch: {len(pkt)} != {PACKET_LEN}")

        with self._lock:
            try:
                self._ensure_connected_nolock()
                assert self._sock is not None
                self._sock.sendall(pkt)
                summary = _packet192_summary(pkt)
                # hex_str = _hex_preview(pkt, head=64, tail=32)
                hex_str = pkt.hex()
                print(
                    f"[winp2][packet192] sent -> {self.dest_host}:{self.dest_port} "
                    f"len={len(pkt)} {summary} hex={hex_str}"
                )
                return True
            except Exception as e:
                print(f"[winp2][WARN] packet192 send failed: {e} -> will reconnect")
                self._close_nolock()
                return False


def run_192byte_loop(
    store: StatusStore,
    dest_host: str,
    dest_port: int,
    interval_sec: float,
    connect_timeout_sec: float = 3.0,
    write_timeout_sec: float = 2.0,
    reconnect_wait_sec: float = 2.0,
):
    """
    192byteパケットを生成して、TCPクライアントとして dest_host:dest_port に送り込む。
    """
    pusher = Packet192TcpPusher(
        dest_host=dest_host,
        dest_port=dest_port,
        connect_timeout_sec=connect_timeout_sec,
        write_timeout_sec=write_timeout_sec,
        reconnect_wait_sec=reconnect_wait_sec,
    )

    proc = DataProcessor()

    next_t = time.time()

    while True:
        latest = store.get()
        status = latest.status or {}

        try:
            s = json.dumps(status, ensure_ascii=False, separators=(",", ":"))
            if len(s) > 1200:
                s = s[:1200] + "...(truncated)"
            print(f"[winp2][packet192][src] ts={latest.ts_iso} status={s}")
        except Exception as e:
            print(f"[winp2][packet192][src][WARN] status dump failed: {e}")

        pkt = proc.build_packet(status, fallback_now=datetime.now(tz=JST))

        ok = pusher.send_packet(pkt)
        if not ok:
            time.sleep(max(0.1, reconnect_wait_sec))

        next_t += max(0.05, interval_sec)
        sleep = next_t - time.time()
        if sleep > 0:
            time.sleep(sleep)
        else:
            next_t = time.time()

