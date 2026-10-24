"""Тесты веб-скана: чувствительные файлы, редиректы, robots.txt."""

from reconhunter.webscan import _finding_for, scan_web


class TestFindingFor:
    def test_404_skipped(self):
        assert _finding_for("whatever", 404) is None

    def test_200_sensitive_env_is_high(self):
        f = _finding_for(".env", 200)
        assert f is not None and f.severity == "HIGH"

    def test_200_unknown_path_is_info(self):
        f = _finding_for("images", 200)
        assert f is not None and f.severity == "INFO"

    def test_403_exists(self):
        f = _finding_for("admin", 403)
        assert f is not None and "существует" in f.note

    def test_301_redirect_is_low(self):
        f = _finding_for("admin", 301)
        assert f is not None and f.severity == "LOW"


class TestScanWeb:
    async def test_full_scan_against_local_server(self, http_url):
        findings = await scan_web(http_url, wordlist=None, timeout=3.0, concurrency=10)
        by_path = {f.path: f for f in findings}

        assert by_path["/.env"].severity == "HIGH"
        assert by_path["/backup.zip"].severity == "HIGH"
        # редирект на директорию ловится
        assert "/admin" in by_path
        # robots.txt раскрыл /secret-panel — путь добавился в скан
        assert "/secret-panel" in by_path
        robots = by_path.get("/robots.txt")
        assert robots is not None and "путей" in robots.note

    async def test_sorted_by_severity(self, http_url):
        findings = await scan_web(http_url, wordlist=None, timeout=3.0, concurrency=10)
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        keys = [order[f.severity] for f in findings]
        assert keys == sorted(keys)
