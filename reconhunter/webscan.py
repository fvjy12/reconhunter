"""Веб-разведка: robots/sitemap, чувствительные файлы, скан директорий."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import aiohttp

from .core import Finding

USER_AGENT = "ReconHunter/1.0 (authorized security scan)"

# Файлы, попадание которых почти всегда = проблема
SENSITIVE_PATHS = {
    ".git/HEAD": "HIGH",
    ".git/config": "HIGH",
    ".env": "HIGH",
    ".svn/entries": "HIGH",
    ".DS_Store": "MEDIUM",
    "server-status": "MEDIUM",
    "phpinfo.php": "MEDIUM",
    "backup.sql": "HIGH",
    "backup.zip": "HIGH",
    "db.sql": "HIGH",
    "dump.sql": "HIGH",
    ".htaccess": "LOW",
    "web.config": "MEDIUM",
    "composer.json": "LOW",
    "package.json": "INFO",
    "crossdomain.xml": "LOW",
    "admin": "INFO",
    "administrator": "INFO",
    "wp-admin": "INFO",
    "wp-login.php": "INFO",
    "manager/html": "MEDIUM",
    "console": "INFO",
    "actuator": "MEDIUM",
    "actuator/health": "MEDIUM",
    "api": "INFO",
    "swagger-ui.html": "MEDIUM",
    "swagger.json": "MEDIUM",
    "graphql": "MEDIUM",
}

STATUS_LABELS = {
    200: "доступно",
    401: "требует авторизацию",
    403: "запрещено (но существует)",
    301: "редирект (вероятно, директория)",
    302: "редирект",
    308: "редирект",
}


@dataclass
class WebFinding:
    path: str
    status: int
    severity: str
    note: str = ""


async def fetch(
    session: aiohttp.ClientSession, url: str, timeout: float = 5.0
) -> tuple[int, str]:
    """GET без редиректов; возвращает (статус, короткое тело)."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=False) as resp:
            body = (await resp.text(errors="replace"))[:4000]
            return resp.status, body
    except Exception:
        return -1, ""


def _finding_for(path: str, status: int) -> WebFinding | None:
    base = path.lstrip("/")
    if status in (200, 401, 403):
        severity = SENSITIVE_PATHS.get(base, "INFO")
        if status != 200 and severity == "INFO":
            severity = "LOW" if status == 403 else "INFO"
        return WebFinding(path="/" + base, status=status, severity=severity,
                          note=STATUS_LABELS.get(status, ""))
    if status in (301, 302, 308):
        # редирект обычно означает, что директория существует
        return WebFinding(path="/" + base, status=status, severity="LOW",
                          note=STATUS_LABELS.get(status, ""))
    return None


async def scan_web(
    base_url: str,
    wordlist: list[str] | None = None,
    timeout: float = 5.0,
    concurrency: int = 40,
    progress=None,
) -> list[WebFinding]:
    """Проверяет чувствительные пути + словарь директорий, возвращает находки.

    Плюс: вычитывает Disallow-пути из robots.txt и добавляет их в скан —
    robots.txt часто раскрывает скрытые панели."""
    findings: list[WebFinding] = []
    sem = asyncio.Semaphore(concurrency)
    done = 0

    headers = {"User-Agent": USER_AGENT}
    async with aiohttp.ClientSession(headers=headers) as session:
        robots_paths: list[str] = []
        status, body = await fetch(session, f"{base_url}/robots.txt", timeout)
        if status == 200:
            for line in body.splitlines():
                low = line.strip().lower()
                if low.startswith("disallow:") or low.startswith("allow:"):
                    path = line.split(":", 1)[1].strip().strip("/")
                    if path and "*" not in path and len(path) < 40:
                        robots_paths.append(path)

        seen: set[str] = set(SENSITIVE_PATHS)
        paths = list(SENSITIVE_PATHS)
        if wordlist:
            for p in wordlist:
                p = p.strip().lstrip("/")
                if p and not p.startswith("#") and p not in seen:
                    seen.add(p)
                    paths.append(p)
        for p in robots_paths:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        if robots_paths:
            findings.append(WebFinding(
                path="/robots.txt", status=200, severity="LOW",
                note=f"раскрывает {len(robots_paths)} скрытых путей — они добавлены в скан",
            ))
        async def worker(path: str) -> None:
            nonlocal done
            async with sem:
                status, _ = await fetch(session, f"{base_url}/{path}", timeout)
            done += 1
            if progress and done % 20 == 0:
                progress(done, len(paths))
            hit = _finding_for(path, status)
            if hit:
                findings.append(hit)

        await asyncio.gather(*(worker(p) for p in paths))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), f.path))


def findings_from_web(web_findings: list[WebFinding]) -> list[Finding]:
    """Конвертирует веб-находки в общий формат Finding."""
    out: list[Finding] = []
    for wf in web_findings:
        title = f"{wf.path} — {STATUS_LABELS.get(wf.status, str(wf.status))}"
        detail = f"HTTP {wf.status}" + (f" · {wf.note}" if wf.note else "")
        out.append(Finding(module="web", severity=wf.severity,
                           title=title, detail=detail))
    return out
