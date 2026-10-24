"""Общие фикстуры: локальный HTTP-сервер без внешних зависимостей."""

from __future__ import annotations

import http.server
import threading

import pytest

ROBOTS_BODY = "User-agent: *\nDisallow: /admin\nDisallow: /secret-panel\n"


def make_handler(set_cookie: str | None = None,
                 title: str | None = None) -> type[http.server.BaseHTTPRequestHandler]:
    """Генерирует обработчик с заданным поведением."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if path == "/robots.txt":
                body = ROBOTS_BODY.encode()
                self._reply(200, body, "text/plain")
            elif path in ("/.env", "/backup.zip"):
                self._reply(200, b"sensitive", "text/plain")
            elif path in ("/admin", "/secret-panel"):
                # как реальный сервер: директория редиректит на слэш
                self.send_response(301)
                self.send_header("Location", path + "/")
                self.end_headers()
            elif path in ("/admin/", "/secret-panel/"):
                self._reply(200, b"<html>panel</html>", "text/html")
            else:
                self._reply(404, b"not found", "text/plain")

        def _reply(self, code: int, body: bytes, ctype: str) -> None:
            if title:
                body = f"<html><head><title>{title}</title></head><body>x</body></html>".encode()
                ctype = "text/html"
            self.send_response(code)  # статус-строка строго до заголовков
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # тишина в консоли pytest
            pass

    return Handler


@pytest.fixture
def http_url():
    """Поднимает тестовый HTTP-сервер на свободном порту, отдаёт его базовый URL."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler())
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def http_url_with_cookies():
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), make_handler(set_cookie="PHPSESSID=abc123; path=/"))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def http_url_with_title():
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), make_handler(title="TestApp"))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
