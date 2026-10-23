"""Аудит security-заголовков HTTP-ответа."""

from __future__ import annotations

import aiohttp

from .core import Finding
from .webscan import USER_AGENT

# заголовок -> (severity если отсутствует, за что отвечает)
EXPECTED_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "защита от XSS и инъекций контента"),
    "X-Content-Type-Options": ("LOW", "запрет MIME-сниффинга"),
    "X-Frame-Options": ("LOW", "защита от clickjacking (или CSP frame-ancestors)"),
    "Referrer-Policy": ("INFO", "контроль утечки Referrer"),
    "Permissions-Policy": ("INFO", "ограничение браузерных API"),
}


async def check_headers(base_url: str, timeout: float = 6.0) -> list[Finding]:
    findings: list[Finding] = []
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as resp:
            headers = resp.headers

    csp = headers.get("Content-Security-Policy", "")
    has_frame_protection = bool(headers.get("X-Frame-Options")) or "frame-ancestors" in csp

    for header, (severity, purpose) in EXPECTED_HEADERS.items():
        if header == "X-Frame-Options":
            if not has_frame_protection:
                findings.append(Finding(module="headers", severity=severity,
                                        title=f"Отсутствует {header}",
                                        detail=f"Отвечает за {purpose}"))
            continue
        if header not in headers:
            findings.append(Finding(module="headers", severity=severity,
                                    title=f"Отсутствует {header}",
                                    detail=f"Отвечает за {purpose}"))

    if base_url.startswith("https://") and "Strict-Transport-Security" not in headers:
        findings.append(Finding(module="headers", severity="MEDIUM",
                                title="Отсутствует Strict-Transport-Security",
                                detail="HSTS заставляет браузер использовать только HTTPS"))

    # Небезопасные настройки cookie, если они есть
    for cookie_header in headers.getall("Set-Cookie", []):
        low = cookie_header.lower()
        if ("session" in low or "token" in low or low.startswith("phpsessid")
                or "jsessionid" in low) and "httponly" not in low:
            findings.append(Finding(
                module="headers", severity="MEDIUM",
                title="Cookie сессии без HttpOnly",
                detail=cookie_header.split(";")[0] + "=... (доступна из JavaScript)",
            ))
            break

    return findings
