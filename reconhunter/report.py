"""Генерация отчётов: Markdown и standalone HTML."""

from __future__ import annotations

import html
from datetime import datetime

from . import __version__
from .core import Finding, SEVERITY_COLORS, SEVERITY_ORDER

SEVERITY_BADGE = {
    "HIGH": "#c0392b",
    "MEDIUM": "#d4ac0d",
    "LOW": "#27ae60",
    "INFO": "#2e86c1",
}


def _summary(findings: list[Finding]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))


def markdown_report(target_str: str, findings: list[Finding],
                    tech: list[str], open_ports: list[str]) -> str:
    counts = _summary(findings)
    lines = [
        "# ReconHunter — отчёт по сканированию",
        "",
        f"- **Цель:** `{target_str}`",
        f"- **Дата:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Версия:** {__version__}",
        "",
        "## Сводка",
        "",
        f"| HIGH | MEDIUM | LOW | INFO |",
        f"|---|---|---|---|",
        f"| {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} |",
        "",
    ]
    if open_ports:
        lines += ["## Открытые порты", ""] + [f"- {p}" for p in open_ports] + [""]
    if tech:
        lines += ["## Технологии", ""] + [f"- {t}" for t in tech] + [""]
    lines += ["## Находки", ""]
    for f in _sorted(findings):
        lines.append(f"### [{f.severity}] {f.title}")
        lines.append(f"*модуль: {f.module}*")
        if f.detail:
            lines.append(f"\n> {f.detail}")
        lines.append("")
    return "\n".join(lines)


def html_report(target_str: str, findings: list[Finding],
                tech: list[str], open_ports: list[str]) -> str:
    counts = _summary(findings)

    def badge(sev: str) -> str:
        color = SEVERITY_BADGE.get(sev, "#555")
        return (f'<span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:10px;font-size:12px;font-weight:bold">{sev}</span>')

    rows = ""
    for f in _sorted(findings):
        detail = f"<br><small>{html.escape(f.detail)}</small>" if f.detail else ""
        rows += (f"<tr><td>{badge(f.severity)}</td>"
                 f"<td>{html.escape(f.title)}{detail}</td>"
                 f"<td><code>{f.module}</code></td></tr>")

    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEVERITY_BADGE[k]}">'
        f'<b style="font-size:28px">{v}</b><br>{k}</div>'
        for k, v in counts.items()
    )
    ports_html = "".join(f"<li><code>{html.escape(p)}</code></li>" for p in open_ports)
    tech_html = "".join(f"<li>{html.escape(t)}</li>" for t in tech)

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>ReconHunter — {html.escape(target_str)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px auto; max-width: 900px;
         background: #0f1420; color: #e8eaf0; }}
  h1 {{ border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
  .cards {{ display: flex; gap: 16px; margin: 24px 0; }}
  .card {{ background: #1a2233; padding: 16px 24px; border-radius: 8px; text-align: center;
          flex: 1; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  td, th {{ padding: 10px 12px; border-bottom: 1px solid #2a3550; text-align: left;
           vertical-align: top; }}
  code {{ background: #1a2233; padding: 2px 6px; border-radius: 4px; }}
  small {{ color: #93a1bd; }}
  li {{ margin: 4px 0; }}
</style></head><body>
<h1>ReconHunter — отчёт</h1>
<p>Цель: <code>{html.escape(target_str)}</code><br>
   Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · v{__version__}</p>
<div class="cards">{cards}</div>
{('<h2>Открытые порты</h2><ul>' + ports_html + '</ul>') if open_ports else ''}
{('<h2>Технологии</h2><ul>' + tech_html + '</ul>') if tech else ''}
<h2>Находки</h2>
<table><tr><th>Серьёзность</th><th>Находка</th><th>Модуль</th></tr>{rows}</table>
</body></html>"""
