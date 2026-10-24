"""Тесты фингерпринта: точные имена кук, заголовок страницы, утечка Server."""

from reconhunter.fingerprint import fingerprint


async def test_cookie_matched_exactly(http_url_with_cookies):
    tech, _ = await fingerprint(http_url_with_cookies, timeout=3.0)
    assert any("PHP" in t for t in tech)


async def test_title_extracted(http_url_with_title):
    tech, findings = await fingerprint(http_url_with_title, timeout=3.0)
    assert any(t.startswith("Title:") for t in tech)


async def test_server_version_leak_reported(http_url):
    # python http.server отдаёт "Server: SimpleHTTP/0.6 Python/x.y.z" — версия с цифрами
    tech, findings = await fingerprint(http_url, timeout=3.0)
    assert any(f.severity == "LOW" and "Server" in f.title for f in findings)
