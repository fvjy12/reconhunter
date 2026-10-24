"""Тесты аудита security-заголовков."""

from reconhunter.headers_check import check_headers


async def test_missing_headers_detected(http_url):
    findings = await check_headers(http_url, timeout=3.0)
    titles = " ".join(f.title for f in findings)
    assert "Content-Security-Policy" in titles
    assert "X-Content-Type-Options" in titles
    # у тестового сервера нет HTTPS и cookies — HSTS/HttpOnly не должны прилетать
    assert "Strict-Transport-Security" not in titles
    assert "HttpOnly" not in titles
