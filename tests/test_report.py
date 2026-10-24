"""Тесты генерации отчётов: JSON, Markdown, HTML."""

import json

from reconhunter.core import Finding
from reconhunter.report import html_report, json_report, markdown_report

FINDINGS = [
    Finding(module="web", severity="HIGH", title="/.env — доступно", detail="HTTP 200"),
    Finding(module="headers", severity="MEDIUM", title="Отсутствует CSP"),
    Finding(module="fingerprint", severity="LOW", title="Server раскрывает версию"),
]


def test_json_report_structure():
    data = json.loads(json_report("example.com", FINDINGS, ["Server: x"], ["80 — http"],
                                  ["api.example.com"]))
    assert data["tool"] == "ReconHunter"
    assert data["summary"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0}
    assert data["open_ports"] == ["80 — http"]
    assert data["subdomains"] == ["api.example.com"]
    # HIGH должен идти первым
    assert data["findings"][0]["severity"] == "HIGH"


def test_markdown_report_sections():
    md = markdown_report("example.com", FINDINGS, ["Server: x"], ["80 — http"],
                         ["api.example.com"])
    assert "## Сводка" in md
    assert "## Открытые порты" in md
    assert "## Субдомены" in md
    assert "## Технологии" in md
    assert "### [HIGH] /.env — доступно" in md


def test_html_report_contains_rows_and_cards():
    html = html_report("example.com", FINDINGS, [], [], [])
    assert "ReconHunter" in html
    assert html.count("<tr>") >= 4  # шапка + 3 находки
    assert "/.env" in html


def test_empty_sections_omitted():
    md = markdown_report("example.com", FINDINGS, [], [], [])
    assert "## Открытые порты" not in md
    assert "## Субдомены" not in md
