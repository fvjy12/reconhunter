"""Аудит TLS: сертификат (срок, самоподписанность) и устаревшие протоколы."""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone

from .core import Finding


async def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float = 6.0) -> bool:
    """Пробует установить TLS-соединение с заданным контекстом."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _old_protocol_findings(host: str, port: int) -> list[Finding]:
    """Проверяет, принимает ли сервер устаревшие TLS 1.0/1.1."""
    findings: list[Finding] = []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                          ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                pass  # на старых сборках OpenSSL уровня безопасности может не быть
            if await _handshake(host, port, ctx):
                findings.append(Finding(
                    module="tls", severity="MEDIUM",
                    title=f"Поддерживается устаревший протокол {name}",
                    detail="Протокол считается небезопасным (RFC 8996), "
                           "его следует отключить на сервере",
                ))
        except Exception:
            continue
    return findings


async def check_tls(host: str, port: int = 443) -> list[Finding]:
    findings: list[Finding] = []

    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=6.0
        )
        # До обмена данными getpeercert() может кидать 'handshake not done yet'
        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5.0)
    except ssl.SSLCertVerificationError as exc:
        findings.append(Finding(
            module="tls", severity="MEDIUM",
            title="TLS-сертификат не проходит верификацию",
            detail=f"Возможен самоподписанный или неверный сертификат ({exc})",
        ))
        findings.extend(await _old_protocol_findings(host, port))
        return findings
    except Exception as exc:
        findings.append(Finding(
            module="tls", severity="INFO",
            title="TLS-соединение установить не удалось",
            detail=str(exc)[:120],
        ))
        return findings

    ssl_obj = writer.get_extra_info("ssl_object")
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    if ssl_obj is None:
        findings.extend(await _old_protocol_findings(host, port))
        return findings

    cert = ssl_obj.getpeercert()

    # Срок действия сертификата
    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(Finding(
                module="tls", severity="HIGH",
                title=f"Сертификат ПРОСРОЧЕН ({-days_left} дн. назад)",
                detail=f"Годен до: {not_after}",
            ))
        elif days_left < 14:
            findings.append(Finding(
                module="tls", severity="MEDIUM",
                title=f"Сертификат истекает через {days_left} дн.",
                detail=f"Годен до: {not_after}",
            ))
        elif days_left < 30:
            findings.append(Finding(
                module="tls", severity="LOW",
                title=f"Сертификат истекает через {days_left} дн.",
                detail=f"Годен до: {not_after}",
            ))

    # Самоподписанность: subject совпадает с issuer
    subject = tuple(cert.get("subject", ()))
    issuer = tuple(cert.get("issuer", ()))
    if subject and subject == issuer:
        findings.append(Finding(
            module="tls", severity="LOW",
            title="Самоподписанный сертификат",
        ))

    findings.extend(await _old_protocol_findings(host, port))
    return findings
