"""Сбор баннеров сервисов на открытых портах."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .core import Finding, Target
from .portscan import OpenPort

HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9090}


@dataclass
class BannerResult:
    port: int
    banner: str
    version_findings: list[Finding] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.version_findings is None:
            self.version_findings = []


async def grab_banner(target: Target, op: OpenPort, timeout: float = 2.5) -> BannerResult:
    """Пробует снять приветствие сервиса или HEAD HTTP-ответа."""
    banner_text = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, op.port), timeout=timeout
        )
        if op.port in HTTP_PORTS:
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {target.host}\r\n"
                "User-Agent: ReconHunter\r\n\r\n".encode()
            )
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner_text = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass

    banner_text = " ".join(banner_text.split())[:200]
    result = BannerResult(port=op.port, banner=banner_text)

    # Утечка версии сервиса в баннере — классическая INFO/LOW находка
    first_line = banner_text.splitlines()[0] if banner_text else ""
    if any(c.isdigit() for c in first_line) and any(
        svc in first_line.lower()
        for svc in ("ssh", "ftp", "smtp", "nginx", "apache", "iis", "mysql", "redis", "jetty")
    ):
        result.version_findings.append(
            Finding(
                module="banner",
                severity="LOW",
                title=f"Порт {op.port}: баннер раскрывает версию сервиса",
                detail=first_line,
            )
        )
    return result
