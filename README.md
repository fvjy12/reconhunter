# 🎯 ReconHunter

**Модульный разведывательный сканер для авторизованного пентеста** — порт-скан, сбор баннеров, веб-разведка, аудит security-заголовков и генерация отчётов. Python + asyncio.

> ⚠️ **Только для авторизованного тестирования:** собственные лаборатории, CTF, системы, владельцы которых дали явное разрешение. Сканирование чужих систем без разрешения — незаконно. Проект создан в образовательных целях.

[![tests](https://github.com/fvjy12/reconhunter/actions/workflows/tests.yml/badge.svg)](https://github.com/fvjy12/reconhunter/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: black-compatible](https://img.shields.io/badge/code%20style-simple-black)](https://github.com/psf/black)

## Возможности

| Модуль | Что делает |
|---|---|
| **portscan** | Асинхронный TCP connect-скан портов (топ-80 по умолчанию, свои диапазоны, `full`) |
| **banner** | Сбор баннеров сервисов на любом порту (протокол-агностично) + детект утечки версий |
| **web** | Скан директорий по словарю, поиск `.git`, `.env`, бэкапов + парсер `robots.txt` (Disallow-пути добавляются в скан) |
| **fingerprint** | Определение стека технологий по заголовкам, кукам, `<title>` и контенту |
| **headers** | Аудит security-заголовков (CSP, HSTS, X-Frame-Options, HttpOnly…) |
| **tls** | Аудит сертификата (срок, самоподписанность, верификация) и устаревших протоколов TLS 1.0/1.1 |
| **subdomains** | Перебор субдоменов по словарю через DNS (`--subs`, только для доменов) |
| **report** | Отчёты в Markdown, HTML и JSON с уровнями серьёзности находок |

## Быстрый старт

```bash
git clone https://github.com/fvjy12/reconhunter.git
cd reconhunter
pip install -r requirements.txt
```

### Запуск

```bash
# Сканировать хост целиком (порты + баннеры + веб на найденных портах)
python main.py example.com

# Только веб-разведка конкретного URL
python main.py http://example.com --no-ports

# С перебором субдоменов (DNS) и TLS-аудитом https-цели
python main.py example.com --subs

# Свой диапазон портов и словарь директорий
python main.py example.com --ports 1-1024,8080 --wordlist wordlists/common.txt

# Машинно-читаемый отчёт JSON (для пайплайнов)
python main.py example.com --format json -o my_report
```

Отчёты сохраняются в папку `reports/` (`.md` + `.html`).

## Лаборатория для теста (Docker)

В репозитории готовая `docker-compose.yml` с [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — намеренно уязвимым учебным приложением. Это **единственный легальный способ** обкатать сканер по-настоящему:

```bash
docker compose up -d          # поднимет лабу на http://localhost:3000
python main.py http://localhost:3000 --no-ports
```

## Пример вывода

```
$ python main.py http://localhost:8090 --no-ports

== Веб-разведка http://127.0.0.1:8090 ==
Технологии: Server: SimpleHTTP/0.6 Python/3.12.10

                                Находки
┌─────────────┬──────────────────────────────────────────┬─────────────┐
│ Серьёзность │ Находка                                  │ Модуль      │
├─────────────┼──────────────────────────────────────────┼─────────────┤
│ HIGH        │ /.env — доступно                         │ web         │
│ HIGH        │ /backup.zip — доступно                   │ web         │
│ MEDIUM      │ Отсутствует Content-Security-Policy      │ headers     │
│ LOW         │ Заголовок Server раскрывает версию ПО    │ fingerprint │
│ LOW         │ Отсутствует X-Content-Type-Options       │ headers     │
│ LOW         │ Отсутствует X-Frame-Options              │ headers     │
│ LOW         │ /admin — редирект (вероятно, директория) │ web         │
│ INFO        │ /robots.txt — доступно                   │ web         │
└─────────────┴──────────────────────────────────────────┴─────────────┘

Отчёт: reports/report_*.md и reports/report_*.html
```

HTML-отчёт — самодостаточная тёмная страница со сводкой и таблицей находок.

## Структура проекта

```
reconhunter/
├── main.py                  # точка входа
├── reconhunter/
│   ├── cli.py               # CLI и оркестрация модулей
│   ├── core.py              # цели, находки, парсинг портов
│   ├── portscan.py          # асинхронный сканер портов
│   ├── banner.py            # сбор баннеров
│   ├── webscan.py           # директории, чувствительные файлы, robots.txt
│   ├── fingerprint.py       # определение технологий
│   ├── headers_check.py     # аудит security-заголовков
│   ├── tls_check.py         # аудит TLS: сертификат и протоколы
│   ├── subdomains.py        # перебор субдоменов через DNS
│   └── report.py            # Markdown/HTML/JSON отчёты
├── wordlists/
│   ├── common.txt           # словарь директорий
│   └── subdomains.txt       # словарь субдоменов
└── docker-compose.yml       # лаборатория Juice Shop
```

## Что дальше (TODO)

- [ ] Проверка поддоменов на живые HTTP-сервисы (скан найденных субдоменов)
- [ ] Экспорт в SARIF
- [ ] Скрин README на реальной лабе Juice Shop

## Лицензия

MIT — см. [LICENSE](LICENSE).
