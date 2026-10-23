"""Сбор баннеров сервисов на открытых портах."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .core import Finding, Target
from .portscan import OpenPort


@dataclass
class BannerResult:
    port: int
    banner: str
    version_findings: list[Finding] = field(default_factory=list)


async def grab_banner(target: Target, op: OpenPort, timeout: float = 2.5) -> BannerResult:
    """Протокол-агностичный сбор баннера: ждём приветствие сервиса,
    при тишине отправляем HTTP HEAD (работает на любом порту)."""
    banner_text = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, op.port), timeout=timeout
        )
    except Exception:
        return BannerResult(port=op.port, banner="")

    # Сервисы вроде SSH/FTP/SMTP сами присылают приветствие
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=0.8)
        banner_text = data.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Тишина — вероятно, это HTTP-сервер: здороваемся сами
    if not banner_text.strip():
        try:
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {target.host}\r\n"
                "User-Agent: ReconHunter\r\n\r\n".encode()
            )
            await writer.drain()
            data = await asyncio.wait_for(reader.read(400), timeout=timeout)
            banner_text = data.decode("utf-8", errors="replace")
        except Exception:
            pass

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    banner_text = " ".join(banner_text.split())[:200]
    result = BannerResult(port=op.port, banner=banner_text)

    # Утечка версии сервиса в баннере — классическая LOW-находка
    lowered = banner_text.lower()
    if any(c.isdigit() for c in banner_text) and any(
        svc in lowered
        for svc in ("ssh", "ftp", "smtp", "nginx", "apache", "iis", "mysql",
                    "redis", "jetty", "python", "php", "tomcat", "server:")
    ):
        result.version_findings.append(
            Finding(
                module="banner",
                severity="LOW",
                title=f"Порт {op.port}: баннер раскрывает версию сервиса",
                detail=banner_text[:120],
            )
        )
    return result
