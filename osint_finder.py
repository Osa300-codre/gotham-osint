#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT-помощник: поиск публичной информации по идентификаторам.
Модули:
  site_checks.py — каталог ~430 сайтов по 20+ категориям
  scanner.py      — асинхронная проверка профилей по всем сайтам
  websearch.py    — веб-поиск упоминаний (DuckDuckGo)
  osint_finder.py — поиск по email / username / IP / домену / телефону
"""

import argparse
import asyncio
import hashlib
import json
import os
import socket
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from scanner import scan_sync
from site_checks import all_categories
from websearch import web_search
from leaks import full_leak_check, check_leakcheck
from premium import key_status, run_all, save_keys, KEY_MAP

console = Console()

# Безопасный вывод в консоль Windows (cp866/cp1251) — заменяем непечатаемые символы
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:
        pass

# Палитра в стиле Gotham
GOLD = "gold1"
DIMGOLD = "yellow4"
CYAN = "cyan"

BANNER = r"""
  ___  _  _    _    ___  _  _ ___ ___  ___
 / __|| || |  /_\  / _ \| \| | __| __|/ __|
| (_ || __ | / _ \ | (_) . . | _|| _| \__ \
 \___||_||_|/_/ \_\ \___/|\_|_|___|___|___/
"""

DISCLAIMER = (
    "ВНИМАНИЕ: Инструмент собирает только ПУБЛИЧНО доступную информацию из открытых "
    "источников. Используйте его только в законных целях (проверка собственных данных, "
    "поиск пропавших с согласия, OSINT-исследования). Не используйте для сталкинга, "
    "доксинга или нарушения приватности."
)

TIMEOUT = 12


def safe_request(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "OSINT-Finder/1.0"}, **kwargs)
        return r
    except Exception as e:
        console.print(f"[red]Ошибка запроса {url}: {e}[/red]")
        return None


# ---------------- Email ----------------
def search_email(email: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"email": email, "sources": []}
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()

    r = safe_request(f"https://www.gravatar.com/{md5}.json")
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
            entry = data.get("entry", [{}])[0]
            result["gravatar"] = {
                "found": True,
                "display_name": entry.get("displayName"),
                "profile_url": entry.get("profileUrl"),
                "about_me": entry.get("aboutMe"),
                "current_location": entry.get("currentLocation"),
                "photos": [p.get("value") for p in entry.get("photos", [])],
                "accounts": [
                    {"name": a.get("shortname"), "url": a.get("url")}
                    for a in entry.get("accounts", [])
                ],
            }
            result["sources"].append("Gravatar")
        except Exception:
            result["gravatar"] = {"found": False, "error": "не удалось разобрать ответ"}
    else:
        result["gravatar"] = {
            "found": False,
            "note": "Профиль Gravatar не найден (email не зарегистрирован или скрыт).",
        }

    try:
        domain = email.split("@")[-1]
        socket.getaddrinfo(domain, None)
        result["domain_resolves"] = True
    except Exception:
        result["domain_resolves"] = False

    r = safe_request(f"https://www.gravatar.com/avatar/{md5}?d=404&s=200")
    result["avatar"] = (f"https://www.gravatar.com/avatar/{md5}?s=200"
                        if r is not None and r.status_code == 200 else None)

    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key:
        r = safe_request(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": hibp_key, "User-Agent": "OSINT-Finder"},
        )
        if r is not None and r.status_code == 200:
            result["hibp_breaches"] = r.json()
            result["sources"].append("HaveIBeenPwned")
        elif r is not None and r.status_code == 404:
            result["hibp_breaches"] = []
        else:
            result["hibp_breaches"] = {"error": f"статус {r.status_code if r else 'нет ответа'}"}
    else:
        result["hibp_breaches"] = {"note": "Для проверки утечек задайте HIBP_API_KEY в переменных окружения."}

    # Бесплатная проверка утечек (ключ не нужен)
    try:
        result["leaks"] = full_leak_check(email, is_email=True)
        result["sources"].append("LeakCheck")
    except Exception as e:
        result["leaks"] = {"error": str(e)}

    return result


# ---------------- Username (глубокое сканирование) ----------------
def search_username(username: str, categories: Optional[List[str]] = None,
                    full: bool = True) -> Dict[str, Any]:
    """Полное сканирование username по всем сайтам из каталога."""
    if full:
        res = scan_sync(username, categories)
        return res
    return {"value": username, "note": "глубокое сканирование отключено"}


def search_username_basic(username: str) -> Dict[str, Any]:
    """Быстрая проверка по основным профилям (GitHub/GitLab/Reddit/HN)."""
    result: Dict[str, Any] = {"username": username, "profiles": []}
    checks = [
        ("GitHub", f"https://api.github.com/users/{username}"),
        ("GitLab", f"https://gitlab.com/api/v4/users?username={username}"),
        ("Reddit", f"https://www.reddit.com/user/{username}/about.json"),
        ("HackerNews", f"https://hacker-news.firebaseio.com/v0/user/{username}.json"),
    ]
    for name, url in checks:
        r = safe_request(url)
        if r is None:
            continue
        if name == "GitHub" and r.status_code == 200:
            d = r.json()
            result["profiles"].append({
                "source": "GitHub", "name": d.get("name"), "bio": d.get("bio"),
                "location": d.get("location"), "company": d.get("company"),
                "blog": d.get("blog"), "public_repos": d.get("public_repos"),
                "followers": d.get("followers"), "url": d.get("html_url"),
                "created_at": d.get("created_at"),
            })
        elif name == "GitLab" and r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and data:
                d = data[0]
                result["profiles"].append({
                    "source": "GitLab", "username": d.get("username"), "name": d.get("name"),
                    "state": d.get("state"), "avatar_url": d.get("avatar_url"),
                    "web_url": d.get("web_url"),
                })
        elif name == "Reddit" and r.status_code == 200:
            d = r.json().get("data", {})
            result["profiles"].append({
                "source": "Reddit", "name": d.get("name"),
                "link_karma": d.get("link_karma"), "comment_karma": d.get("comment_karma"),
                "created_utc": d.get("created_utc"), "is_gold": d.get("is_gold"),
            })
        elif name == "HackerNews" and r.status_code == 200 and r.text not in ("null", ""):
            d = r.json()
            result["profiles"].append({
                "source": "HackerNews", "id": d.get("id"), "karma": d.get("karma"),
                "created": d.get("created"), "about": d.get("about"),
            })
    return result


# ---------------- IP ----------------
def search_ip(ip: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ip": ip}
    r = safe_request(f"https://ipinfo.io/{ip}/json")
    if r is not None and r.status_code == 200:
        result["ipinfo"] = r.json()
    r2 = safe_request(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
    if r2 is not None and r2.status_code == 200:
        result["ip_api"] = r2.json()
    return result


# ---------------- Domain ----------------
def search_domain(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"domain": domain}
    try:
        ips = socket.gethostbyname_ex(domain)
        result["dns"] = {"hostname": ips[0], "aliases": ips[1], "addresses": ips[2]}
    except Exception as e:
        result["dns"] = {"error": str(e)}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        result["whois_raw"] = data.decode("utf-8", errors="ignore")[:2000]
    except Exception as e:
        result["whois_raw"] = f"ошибка: {e}"
    return result


# ---------------- Phone ----------------
def search_phone(phone: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"phone": phone}
    cleaned = "".join(c for c in phone if c.isdigit() or c == "+")
    result["normalized"] = cleaned
    digits = "".join(c for c in cleaned if c.isdigit())
    result["digit_count"] = len(digits)
    result["valid_length"] = 7 <= len(digits) <= 15

    country_codes = {
        "7": "Россия/Казахстан", "1": "США/Канада", "44": "Великобритания",
        "49": "Германия", "33": "Франция", "39": "Италия", "34": "Испания",
        "86": "Китай", "91": "Индия", "81": "Япония", "82": "Южная Корея",
        "90": "Турция", "972": "Израиль", "380": "Украина", "375": "Беларусь",
    }
    if cleaned.startswith("+"):
        for length in (3, 2, 1):
            cc = cleaned[1:1 + length]
            if cc in country_codes:
                result["country_code"] = cc
                result["country"] = country_codes[cc]
                break
    return result


# ---------------- Name ----------------
def search_name(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "note": ("Поиск по имени: используйте веб-поиск и проверку username-вариантов "
                 "(имя.фамилия, инициалы+фамилия и т.п.)."),
    }


def print_result(data: Dict[str, Any]):
    console.print(Panel(json.dumps(data, ensure_ascii=False, indent=2), title="Результат", border_style="cyan"))


def print_scan(result: Dict[str, Any]):
    console.print()
    console.print(f"[bold {GOLD}]НАЙДЕНО ПРОФИЛЕЙ:[/bold {GOLD}] [bold white]{result['found_count']}[/bold white]  "
                  f"[{DIMGOLD}]проверено {result['total_checked']} · не найдено {result['not_found_count']} · "
                  f"не подтверждено {result['unknown_count']}[/{DIMGOLD}]")
    for cat, items in result.get("by_category", {}).items():
        console.print(f"\n  [bold {GOLD}]{cat.upper()}[/bold {GOLD}]")
        for it in items:
            console.print(f"    [green]+[/green] {it['site']:<22} [{DIMGOLD}]{it['url']}[/{DIMGOLD}]")


def print_banner():
    console.print(f"[bold {GOLD}]{BANNER}[/bold {GOLD}]")
    console.print(f"  [{DIMGOLD}]OSINT-помощник · публичные данные · 506 сайтов · 21 категория[/{DIMGOLD}]\n")


def main():
    parser = argparse.ArgumentParser(description="OSINT-помощник (публичные данные)")
    parser.add_argument("--email", action="append", default=[], help="Email для поиска")
    parser.add_argument("--username", action="append", default=[], help="Username для поиска")
    parser.add_argument("--ip", action="append", default=[], help="IP-адрес")
    parser.add_argument("--domain", action="append", default=[], help="Домен")
    parser.add_argument("--phone", action="append", default=[], help="Телефон")
    parser.add_argument("--name", action="append", default=[], help="Имя")
    parser.add_argument("--search", action="append", default=[], help="Веб-поиск точной фразы")
    parser.add_argument("--leaks", action="append", default=[],
                        help="Проверка утечек (email/телефон/логин) — бесплатно, без ключа")
    parser.add_argument("--premium", action="append", default=[],
                        help="Запуск всех подключённых платных сервисов (email/телефон/логин)")
    parser.add_argument("--keys", action="store_true", help="Показать статус платных ключей")
    parser.add_argument("--set-key", action="append", default=[], metavar="NAME=VALUE",
                        help="Сохранить ключ (напр. HIBP_API_KEY=abc123)")
    parser.add_argument("--categories", default="", help="Категории через запятую (см. --list-cats)")
    parser.add_argument("--list-cats", action="store_true", help="Показать категории сайтов")
    parser.add_argument("--quick", action="store_true", help="Быстрая проверка username вместо глубокой")
    parser.add_argument("--output", help="Файл для сохранения JSON-отчёта")
    parser.add_argument("--json", action="store_true", help="Вывести результат в JSON (без оформления)")
    parser.add_argument("--yes", action="store_true", help="Пропустить подтверждение")
    args = parser.parse_args()

    if args.list_cats:
        console.print(Panel(", ".join(all_categories()), title="Категории", border_style=GOLD))
        return

    if args.keys:
        rows = []
        for s in key_status():
            mark = f"[green]{s['masked']}[/green]" if s["active"] else f"[{DIMGOLD}]не задан[/{DIMGOLD}]"
            rows.append(f"  {s['service']:<18} {mark:<24} {s['price']:<42} {s['url']}")
        console.print(Panel("\n".join(rows), title="Платные сервисы", border_style=GOLD))
        return

    if args.set_key:
        new = {}
        for kv in args.set_key:
            if "=" in kv:
                k, v = kv.split("=", 1)
                k = k.strip().upper()
                if k in KEY_MAP:
                    new[k] = v.strip()
                else:
                    console.print(f"[red]Неизвестный ключ: {k}. Доступны: {', '.join(KEY_MAP)}[/red]")
        if new:
            save_keys(new)
            console.print(f"[green]Сохранено в osint_keys.json: {', '.join(new)}[/green]")
        return

    console.print(Panel(DISCLAIMER, title="Этическое предупреждение", border_style="yellow"))
    print_banner()

    if not args.yes:
        ans = console.input("Продолжить? [y/N]: ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
            console.print("Отменено.")
            sys.exit(0)

    cats = [c.strip() for c in args.categories.split(",") if c.strip()] or None

    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [],
    }

    for e in args.email:
        r = search_email(e)
        report["results"].append({"type": "email", "data": r})
        print_result(r)
    for u in args.username:
        r = (search_username_basic(u) if args.quick else search_username(u, cats))
        report["results"].append({"type": "username", "data": r})
        if args.quick:
            print_result(r)
        else:
            print_scan(r)

    for ip in args.ip:
        r = search_ip(ip)
        report["results"].append({"type": "ip", "data": r})
        print_result(r)
    for d in args.domain:
        r = search_domain(d)
        report["results"].append({"type": "domain", "data": r})
        print_result(r)
    for p in args.phone:
        r = search_phone(p)
        report["results"].append({"type": "phone", "data": r})
        print_result(r)
    for n in args.name:
        r = search_name(n)
        report["results"].append({"type": "name", "data": r})
        print_result(r)
    for s in args.search:
        r = web_search(s)
        report["results"].append({"type": "web_search", "data": r})
        console.print(Panel(json.dumps(r, ensure_ascii=False, indent=2), title="Веб-поиск", border_style="magenta"))
    for lv in args.leaks:
        r = full_leak_check(lv.strip(), is_email=("@" in lv))
        report["results"].append({"type": "leaks", "data": r})
        lc = r.get("leakcheck", {})
        console.print(Panel(json.dumps(r, ensure_ascii=False, indent=2),
                            title=f"Утечки: {lv}", border_style="red"))
        console.print(f"[bold red]Записей в утечках: {lc.get('found')}[/bold red] "
                      f"| источников: {lc.get('source_count', 0)} "
                      f"| утекли данные: {', '.join(lc.get('leaked_field_labels') or [])}")
    for pv in args.premium:
        r = run_all(pv.strip())
        report["results"].append({"type": "premium", "data": r})
        console.print(Panel(json.dumps(r, ensure_ascii=False, indent=2),
                            title=f"Премиум-сервисы: {pv}", border_style="yellow"))

    if not any([args.email, args.username, args.ip, args.domain, args.phone, args.name, args.search, args.leaks]):
        console.print("[yellow]Не указаны данные. Используйте --help.[/yellow]")
        console.print("Пример: python osint_finder.py --username octocat --yes")
        console.print("Пример: python osint_finder.py --email test@example.com --yes")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        console.print(f"[{GOLD}]Отчёт сохранён:[/bold {GOLD}] {args.output}")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
