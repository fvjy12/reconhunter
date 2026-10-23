"""Определение стека технологий по заголовкам, кукам и контенту."""

from __future__ import annotations

import re

import aiohttp

from .core import Finding
from .webscan import USER_AGENT

# (куки, технология)
COOKIE_SIGNS = {
    "io": "Socket.IO (Node.js)",
    "connect.sid": "Express (Node.js)",
    "phpsessid": "PHP",
    "jsessionid": "Java / JSP",
    "asp.net_sessions": "ASP.NET",
    "rack.session": "Ruby (Rack)",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "csrftoken": "Django (вероятно)",
    "wp-settings": "WordPress",
}

# (подстрока в контенте, технология)
CONTENT_SIGNS = [
    ("owasp juice shop", "OWASP Juice Shop (учебно-уязвимое приложение)"),
    ("wp-content", "WordPress"),
    ("cdn.jsdelivr.net/npm/vue", "Vue.js"),
    ("_next/static", "Next.js (React)"),
    ("react-root", "React"),
    ("ng-app", "AngularJS"),
    ("joomla!", "Joomla"),
    ("drupal", "Drupal"),
    ("tomcat", "Apache Tomcat (вероятно)"),
]


async def fingerprint(base_url: str, timeout: float = 6.0) -> tuple[list[str], list[Finding]]:
    """Возвращает (список технологий, список находок-утечек)."""
    tech: list[str] = []
    findings: list[Finding] = []

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as resp:
            headers = resp.headers
            body = (await resp.text(errors="replace")).lower()

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    cookies = headers.get("Set-Cookie", "").lower()

    if server:
        tech.append(f"Server: {server}")
        if re.search(r"\d", server):
            findings.append(Finding(
                module="fingerprint", severity="LOW",
                title="Заголовок Server раскрывает версию ПО",
                detail=server,
            ))
    if powered:
        tech.append(f"X-Powered-By: {powered}")
        findings.append(Finding(
            module="fingerprint", severity="LOW",
            title="Заголовок X-Powered-By раскрывает технологии",
            detail=powered,
        ))

    for cookie_name, name in COOKIE_SIGNS.items():
        if cookie_name in cookies:
            tech.append(name)

    for needle, name in CONTENT_SIGNS:
        if needle in body:
            tech.append(name)

    return tech, findings
