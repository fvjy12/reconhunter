"""Перебор субдоменов через DNS-резолв (словарный, пассивный к сканируемому хосту)."""

from __future__ import annotations

import asyncio
import socket


async def _resolves(host: str) -> bool:
    """True, если DNS-имя резолвится (getaddrinfo в потоке)."""
    try:
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, host, None),
            timeout=4.0,
        )
        return True
    except Exception:
        return False


async def enum_subdomains(
    domain: str,
    words: list[str],
    concurrency: int = 50,
    progress=None,
) -> list[str]:
    """Перебирает <слово>.<домен> по словарю, возвращает живые имена."""
    sem = asyncio.Semaphore(concurrency)
    found: list[str] = []
    done = 0

    async def worker(word: str) -> None:
        nonlocal done
        host = f"{word}.{domain}"
        async with sem:
            ok = await _resolves(host)
        done += 1
        if progress and done % 10 == 0:
            progress(done, len(words))
        if ok:
            found.append(host)

    await asyncio.gather(*(worker(w) for w in words))
    return sorted(found)
