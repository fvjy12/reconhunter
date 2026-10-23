"""Общие типы и утилиты: цели сканирования, находки, парсинг портов."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
SEVERITY_COLORS = {
    "INFO": "cyan",
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
}


@dataclass
class Finding:
    """Одна находка сканера."""

    module: str
    severity: str  # INFO / LOW / MEDIUM / HIGH
    title: str
    detail: str = ""


@dataclass
class Target:
    """Разобранная цель: хост, порт и схема (если цель — URL)."""

    host: str
    port: int | None = None
    scheme: str | None = None  # http / https, если цель задана как URL

    @property
    def is_web(self) -> bool:
        return self.scheme is not None

    @property
    def base_url(self) -> str:
        if not self.is_web:
            raise ValueError("Цель не является URL")
        port_part = f":{self.port}" if self.port not in (80, 443) else ""
        return f"{self.scheme}://{self.host}{port_part}"

    def url_for_port(self, port: int) -> str:
        scheme = "https" if port in (443, 8443) else "http"
        return f"{scheme}://{self.host}:{port}"


def parse_target(raw: str) -> Target:
    """Разбирает 'http://host:3000', 'host', 'host:8080' в Target."""
    raw = raw.strip()
    if "://" in raw:
        parts = urlparse(raw)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Неизвестная схема: {scheme}")
        port = parts.port or (443 if scheme == "https" else 80)
        return Target(host=parts.hostname, port=port, scheme=scheme)
    match = re.match(r"^([^:]+):(\d+)$", raw)
    if match:
        return Target(host=match.group(1), port=int(match.group(2)))
    return Target(host=raw)


# ~80 самых частых TCP-портов: быстрее полного скана и хватает для разведки
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 2181, 2375, 2376,
    3000, 3128, 3268, 3306, 3389, 4000, 4848, 5000, 5432, 5555, 5601, 5672,
    5900, 5901, 5984, 5985, 5986, 6379, 6443, 6660, 7001, 7077, 8000, 8008,
    8009, 8010, 8020, 8069, 8080, 8081, 8088, 8090, 8180, 8222, 8443, 8500,
    8649, 8686, 8848, 8888, 9000, 9001, 9042, 9080, 9090, 9092, 9200, 9300,
    9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 61616,
]

# Порты, на которых обычно живёт веб — по ним запускаем веб-модули
WEB_PORTS = {
    80, 443, 3000, 4000, 5000, 7001, 8000, 8008, 8010, 8020, 8069, 8080,
    8081, 8088, 8090, 8180, 8222, 8443, 8500, 8848, 9080, 9090, 9092, 9999,
    10000,
}


def parse_ports(spec: str) -> list[int]:
    """'top', '1-1024', '80,443,8080' -> список портов."""
    spec = spec.strip().lower()
    if spec in ("top", "top100", ""):
        return list(TOP_PORTS)
    if spec == "full":
        return list(range(1, 65536))
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)
