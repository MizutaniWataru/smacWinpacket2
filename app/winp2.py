# winp2.py

from __future__ import annotations

import asyncio
import threading
from datetime import timezone, timedelta

from status_store import StatusStore
from packet192_server import run_192byte_loop
from winsocket2_server import run_winsocket2_server
from winsocket2_udpwin_bridge import run_winsocket2_udpwin_bridge

# winsocket2 (UNIX domain socket)
WINP2_WINSOCKET2_PATH = "/tmp/winsocket2"
WINP2_STATUS_DUMP_PATH = "/tmp/winp2_last_status.json"
WINP2_PACKET192_DUMP_PATH = "/tmp/winp2_last_packet192.bin"

# 192byteパケット(TCP)
WINP2_ENABLE_PACKET192_TCP = True
WINP2_PACKET192_TCP_HOST = "192.168.2.200"
WINP2_PACKET192_TCP_PORT = 4196
WINP2_PACKET192_INTERVAL_SEC = 1.0

WINP2_PACKET192_CONNECT_TIMEOUT_SEC = 3.0
WINP2_PACKET192_WRITE_TIMEOUT_SEC = 2.0
WINP2_PACKET192_RECONNECT_WAIT_SEC = 2.0

# UDP上WIN形式(1秒ブロック)をTCPで流す
WINP2_ENABLE_UDPWIN_TCP = True
WINP2_UDPWIN_DEST_HOST = "127.0.0.1"
WINP2_UDPWIN_DEST_PORT = 9100


WINP2_UDPWIN_ID_CODE = 160
WINP2_UDPWIN_START_PACKET_NO = 0

WINP2_UDPWIN_CONNECT_TIMEOUT_SEC = 2.0
WINP2_UDPWIN_WRITE_TIMEOUT_SEC = 2.0
WINP2_UDPWIN_RECONNECT_WAIT_SEC = 2.0

WINP2_LOG_INTERVAL_SEC = 5.0
JST = timezone(timedelta(hours=9))


# -----------------------------
# 実行
# -----------------------------

def _start_packet192_thread(store: StatusStore) -> None:
    th = threading.Thread(
        target=run_192byte_loop,
        args=(
            store,
            WINP2_PACKET192_TCP_HOST,
            WINP2_PACKET192_TCP_PORT,
            WINP2_PACKET192_INTERVAL_SEC,
            WINP2_PACKET192_CONNECT_TIMEOUT_SEC,
            WINP2_PACKET192_WRITE_TIMEOUT_SEC,
            WINP2_PACKET192_RECONNECT_WAIT_SEC,
        ),
        daemon=True,
    )
    th.start()
    print(
        f"[winp2] packet192 tcp client: dest={WINP2_PACKET192_TCP_HOST}:{WINP2_PACKET192_TCP_PORT} "
        f"interval={WINP2_PACKET192_INTERVAL_SEC}s"
    )


async def _amain(store: StatusStore) -> None:
    if WINP2_ENABLE_UDPWIN_TCP:
        await run_winsocket2_udpwin_bridge(
            WINP2_WINSOCKET2_PATH,
            store,
            tcp_host=WINP2_UDPWIN_DEST_HOST,
            tcp_port=WINP2_UDPWIN_DEST_PORT,
            id_code=WINP2_UDPWIN_ID_CODE,
            start_packet_no=WINP2_UDPWIN_START_PACKET_NO,
            reconnect_wait_sec=WINP2_UDPWIN_RECONNECT_WAIT_SEC,
            connect_timeout_sec=WINP2_UDPWIN_CONNECT_TIMEOUT_SEC,
            write_timeout_sec=WINP2_UDPWIN_WRITE_TIMEOUT_SEC,
            status_dump_path=WINP2_STATUS_DUMP_PATH,
            packet192_dump_path=WINP2_PACKET192_DUMP_PATH,
            log_interval_sec=WINP2_LOG_INTERVAL_SEC,
        )
    else:
        await run_winsocket2_server(
            WINP2_WINSOCKET2_PATH,
            store,
            dump_path=WINP2_STATUS_DUMP_PATH,
            log_interval_sec=WINP2_LOG_INTERVAL_SEC,
        )


def main() -> None:
    store = StatusStore()

    if WINP2_ENABLE_PACKET192_TCP:
        _start_packet192_thread(store)

    asyncio.run(_amain(store))


if __name__ == "__main__":
    main()
