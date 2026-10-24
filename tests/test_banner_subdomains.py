"""Тесты субдоменов (резолв) и баннеров (протокол-агностичный сбор)."""

import asyncio

from reconhunter.banner import grab_banner
from reconhunter.core import Target
from reconhunter.portscan import OpenPort
from reconhunter.subdomains import _resolves, enum_subdomains


async def test_resolves_localhost_true():
    assert await _resolves("localhost") is True


async def test_resolves_invalid_tld_false():
    # .invalid гарантированно не резолвится (RFC 2606)
    assert await _resolves("no-such-host-qwe123.invalid") is False


async def test_banner_grabbed_from_http_server(http_url):
    port = int(http_url.rsplit(":", 1)[1])
    result = await grab_banner(Target(host="127.0.0.1"), OpenPort(port=port), timeout=3.0)
    assert "HTTP/1." in result.banner


async def test_banner_closed_port_empty():
    result = await grab_banner(Target(host="127.0.0.1"), OpenPort(port=1), timeout=1.0)
    assert result.banner == ""
