"""Тесты сканера портов: открытый/закрытый порт, сортировка."""

import asyncio
import socket

from reconhunter.core import Target
from reconhunter.portscan import scan_ports


async def _open_listener() -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    asyncio.get_running_loop().call_later(0, asyncio.create_task, server.serve_forever())
    return server, port


def _free_port() -> int:
    """Порт, который точно никто не слушает: заняли и освободили."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


async def test_scan_finds_open_and_skips_closed():
    server, open_port = await _open_listener()
    closed_port = _free_port()

    result = await scan_ports(Target(host="127.0.0.1"), [closed_port, open_port],
                              timeout=1.0, concurrency=10)
    ports = [op.port for op in result]
    assert open_port in ports
    assert closed_port not in ports
    assert ports == sorted(ports)  # результат отсортирован
    server.close()


async def test_scan_empty_list():
    assert await scan_ports(Target(host="127.0.0.1"), []) == []
