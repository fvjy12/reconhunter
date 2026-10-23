"""Асинхронный TCP connect-сканер портов."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .core import Target


@dataclass
class OpenPort:
    port: int
    service: str = ""


SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "node/dev", 3128: "squid",
    3306: "mysql", 3389: "rdp", 5000: "upnp/flask", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb", 5985: "winrm",
    6379: "redis", 7001: "weblogic", 8000: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8090: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "sonar/minio",
    9090: "websm", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


async def _check_port(host: str, port: int, timeout: float) -> int | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def scan_ports(
    target: Target,
    ports: list[int],
    timeout: float = 2.0,
    concurrency: int = 500,
    progress=None,
) -> list[OpenPort]:
    """Сканирует порты, возвращает открытые в порядке возрастания."""
    sem = asyncio.Semaphore(concurrency)
    found: list[OpenPort] = []
    done = 0

    async def worker(port: int) -> None:
        nonlocal done
        async with sem:
            result = await _check_port(target.host, port, timeout)
        done += 1
        if progress and done % 25 == 0:
            progress(done, len(ports))
        if result is not None:
            found.append(OpenPort(port=result, service=SERVICE_HINTS.get(result, "")))

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(found, key=lambda op: op.port)
