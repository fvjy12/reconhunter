"""CLI ReconHunter: разбор аргументов и запуск модулей."""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .banner import grab_banner
from .core import (
    Finding,
    SEVERITY_COLORS,
    Target,
    WEB_PORTS,
    is_domain,
    parse_ports,
    parse_target,
)
from .fingerprint import fingerprint
from .headers_check import check_headers
from .portscan import scan_ports
from .report import html_report, json_report, markdown_report
from .subdomains import enum_subdomains
from .tls_check import check_tls
from .webscan import findings_from_web, scan_web

BANNER = r"""
 ██████╗ ███████╗ ██████╗   ███╗   ██╗██╗   ██╗███╗   ██╗████████╗██████╗
██╔═══██╗██╔════╝██╔════╝   ████╗  ██║██║   ██║████╗  ██║╚══██╔══╝██╔══██╗
██║   ██║███████╗██║        ██╔██╗ ██║██║   ██║██╔██╗ ██║   ██║   ██████╔╝
██║   ██║╚════██║██║        ██║╚██╗██║██║   ██║██║╚██╗██║   ██║   ██╔══██╗
╚██████╔╝███████║╚██████╗██╗██║ ╚████║╚██████╔╝██║ ╚████║   ██║   ██║  ██║
 ╚═════╝ ╚══════╝ ╚═════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
        только для авторизованного тестирования · v{}
""".format(__version__)

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconhunter",
        description="Модульный разведывательный сканер для авторизованного пентеста "
                    "(лаборатории, CTF, собственные системы).",
    )
    parser.add_argument("target", help="цель: host, host:port или http://host:port")
    parser.add_argument("--ports", default="top",
                        help="порты: 'top' (по умолчанию), диапазон '1-1024', список '80,443'")
    parser.add_argument("--wordlist", default=None,
                        help="свой словарь директорий (по умолчанию wordlists/common.txt)")
    parser.add_argument("--timeout", type=float, default=2.0, help="таймаут соединения, сек")
    parser.add_argument("--concurrency", type=int, default=400, help="параллельных соединений")
    parser.add_argument("--subs", action="store_true",
                        help="перебор субдоменов по словарю (DNS, только для доменов)")
    parser.add_argument("--no-ports", action="store_true", help="не сканировать порты")
    parser.add_argument("--no-web", action="store_true", help="не запускать веб-модули")
    parser.add_argument("--format", choices=["md", "html", "json", "both"], default="both",
                        help="формат отчёта (both = md + html)")
    parser.add_argument("-o", "--output", default=None, help="базовое имя файла отчёта")
    return parser


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[dim]Находок нет.[/dim]")
        return
    table = Table(title="Находки", show_lines=False)
    table.add_column("Серьёзность", style="bold")
    table.add_column("Находка")
    table.add_column("Модуль", style="dim")
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.title, f.module)
    console.print(table)


def default_wordlist(name: str = "common.txt") -> list[str]:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "wordlists", name)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return []


async def run(args: argparse.Namespace) -> None:
    target = parse_target(args.target)
    all_findings: list[Finding] = []
    tech: list[str] = []
    port_lines: list[str] = []
    web_urls: list[str] = []
    subs_found: list[str] = []
    open_ports: list = []

    if args.subs:
        if is_domain(target.host):
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          console=console, transient=True) as progress:
                task = progress.add_task("Перебираю субдомены...", total=None)
                subs_found = await enum_subdomains(
                    target.host, default_wordlist("subdomains.txt"), concurrency=50,
                    progress=lambda done, total: progress.update(
                        task, description=f"Перебираю субдомены... {done}/{total}"),
                )
            if subs_found:
                table = Table(title=f"Живые субдомены {target.host} ({len(subs_found)})")
                for i in range(0, len(subs_found), 3):
                    table.add_row(*subs_found[i:i + 3])
                console.print(table)
            else:
                console.print("[yellow]Субдомены из словаря не нашлись.[/yellow]")
        else:
            console.print("[yellow]--subs работает только для доменов, не для IP/localhost.[/yellow]")

    if target.is_web:
        web_urls.append(target.base_url)
    else:
        if not args.no_ports:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          console=console, transient=True) as progress:
                task = progress.add_task("Сканирую порты...", total=None)
                open_ports = await scan_ports(
                    target, parse_ports(args.ports),
                    timeout=args.timeout, concurrency=args.concurrency,
                    progress=lambda done, total: progress.update(
                        task, description=f"Сканирую порты... {done}/{total}"),
                )
            if open_ports:
                table = Table(title=f"Открытые порты на {target.host}")
                table.add_column("Порт", style="bold cyan")
                table.add_column("Вероятный сервис")
                for op in open_ports:
                    table.add_row(str(op.port), op.service or "?")
                    port_lines.append(f"{op.port} — {op.service or 'неизвестно'}")
                console.print(table)

                for op in open_ports:
                    br = await grab_banner(target, op, timeout=max(args.timeout, 2.5))
                    if br.banner:
                        console.print(f"  [dim]порт {op.port}:[/dim] {br.banner[:120]}")
                    all_findings.extend(br.version_findings)

                if not args.no_web:
                    web_ports = [op.port for op in open_ports if op.port in WEB_PORTS]
                    web_urls = [target.url_for_port(p) for p in web_ports[:3]]
            else:
                console.print("[yellow]Открытых портов не найдено.[/yellow]")

    # TLS-аудит: для https-цели или если найден открытый 443-й порт
    tls_port = None
    if target.scheme == "https":
        tls_port = target.port
    elif any(op.port == 443 for op in open_ports):
        tls_port = 443
    if tls_port and not args.no_web:
        console.print(f"\n[bold blue]== TLS-аудит {target.host}:{tls_port} ==[/bold blue]")
        for f in await check_tls(target.host, tls_port):
            all_findings.append(f)
            color = SEVERITY_COLORS.get(f.severity, "white")
            console.print(f"  [{color}]{f.severity}[/{color}] {f.title}")

    if not args.no_web:
        for url in web_urls:
            console.print(f"\n[bold blue]== Веб-разведка {url} ==[/bold blue]")
            try:
                t_list, t_findings = await fingerprint(url)
                if t_list:
                    tech.extend(f"{url}: {t}" for t in t_list)
                    console.print("[green]Технологии:[/green] " + ", ".join(t_list))
                all_findings.extend(t_findings)

                all_findings.extend(await check_headers(url))

                with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                              console=console, transient=True) as progress:
                    task = progress.add_task("Сканирую директории...", total=None)
                    web_findings = await scan_web(
                        url, wordlist=default_wordlist() if not args.wordlist else _load(args.wordlist),
                        timeout=max(args.timeout, 5.0), concurrency=40,
                        progress=lambda done, total: progress.update(
                            task, description=f"Сканирую директории... {done}/{total}"),
                    )
                all_findings.extend(findings_from_web(web_findings))
            except Exception as exc:  # цель может быть не веб-сервером
                console.print(f"[yellow]Веб-модули пропущены: {exc}[/yellow]")

    console.print()
    print_findings(all_findings)

    base = args.output or f"report_{target.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs("reports", exist_ok=True)
    md_path = os.path.join("reports", base + ".md")
    html_path = os.path.join("reports", base + ".html")
    json_path = os.path.join("reports", base + ".json")
    saved: list[str] = []
    if args.format in ("md", "both"):
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(markdown_report(args.target, all_findings, tech, port_lines, subs_found))
        saved.append(f"reports/{base}.md")
    if args.format in ("html", "both"):
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_report(args.target, all_findings, tech, port_lines, subs_found))
        saved.append(f"reports/{base}.html")
    if args.format == "json":
        with open(json_path, "w", encoding="utf-8") as fh:
            fh.write(json_report(args.target, all_findings, tech, port_lines, subs_found))
        saved.append(f"reports/{base}.json")
    console.print(f"\n[green]Отчёт:[/green] " + " и ".join(saved))


def _load(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main(argv: list[str] | None = None) -> None:
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    args = build_parser().parse_args(argv)
    console.print(Panel(BANNER, style="bold blue"))
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем.[/yellow]")
        sys.exit(130)
    except ValueError as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        sys.exit(2)


if __name__ == "__main__":
    main()
