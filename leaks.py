#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка публичных утечек данных.
Использует БЕСПЛАТНЫЕ открытые API — ключ не требуется:
  * LeakCheck  (leakcheck.io/api/public)  — email / username / phone / IP
  * HudsonRock (cavalier.hudsonrock.com)   — заражения инфостилерами
Дополнительно, если задан HIBP_API_KEY — проверка через Have I Been Pwned.
"""

import os
import re
from typing import Any, Dict, List, Optional

import requests

TIMEOUT = 25
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
    "Accept": "application/json, text/plain, */*",
}

# Поля, которые чаще всего утекают (для наглядности в отчёте)
FIELD_LABELS = {
    "password": "пароли",
    "password_hash": "хэши паролей",
    "phone": "телефоны",
    "mobile_phone": "мобильные телефоны",
    "address": "адреса",
    "ip": "IP-адреса",
    "ip1": "IP-адреса",
    "ip2": "IP-адреса",
    "email": "email",
    "email2": "email",
    "name": "имена",
    "username": "логины",
    "login": "логины",
    "first_name": "имена",
    "last_name": "фамилии",
    "birthday": "даты рождения",
    "dob": "даты рождения",
    "gender": "пол",
    "ssn": "номера соц. страхования",
    "credit_card": "банковские карты",
    "company_name": "места работы",
    "job_title": "должности",
    "country": "страны",
    "city": "города",
    "state": "регионы",
    "zip": "индексы",
    "origin": "источники регистрации",
    "id": "идентификаторы",
    "profile_name": "имена профилей",
    "middle_name": "отчества",
}


def _get(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
    except Exception:
        return None


def check_leakcheck(value: str) -> Dict[str, Any]:
    """Основной бесплатный источник: количество утечек, поля, названия источников."""
    out: Dict[str, Any] = {"value": value, "found": None, "sources": [], "fields": [], "error": None}
    r = _get(f"https://leakcheck.io/api/public?check={value}")
    if r is None:
        out["error"] = "LeakCheck недоступен"
        return out
    if r.status_code != 200:
        out["error"] = f"LeakCheck: HTTP {r.status_code}"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = "LeakCheck: не удалось разобрать ответ"
        return out

    out["found"] = d.get("found")
    out["fields"] = d.get("fields") or []
    srcs = d.get("sources") or []
    out["sources"] = [
        {"name": s.get("name"), "date": s.get("date") or "не указана"}
        for s in srcs if isinstance(s, dict)
    ]
    out["source_count"] = len(out["sources"])
    out["leaked_field_labels"] = [
        FIELD_LABELS.get(f, f) for f in out["fields"]
    ]
    out["source"] = "LeakCheck (бесплатно)"
    return out


def check_xposedornot(email: str) -> Dict[str, Any]:
    """XposedOrNot — бесплатный API (792 утечки, 11.6 млрд записей), без ключа.

    Отдаёт: список утечек с описаниями, типы утеканных данных, риск-скор,
    стойкость паролей, отрасль. Лимит: 2 запроса/сек с одного IP.
    """
    import time as _time

    out: Dict[str, Any] = {"email": email, "active": True, "breaches": [],
                           "summary": None, "risk": None, "passwords_strength": None,
                           "error": None}
    h = {"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
         "Accept": "application/json, text/plain, */*",
         "Referer": "https://xposedornot.com/"}

    r = None
    for attempt in range(3):
        try:
            r = requests.get("https://api.xposedornot.com/v1/breach-analytics",
                             params={"email": email}, headers=h, timeout=TIMEOUT)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
            return out
        if r.status_code != 429:
            break
        import time as _t
        _t.sleep(4 + attempt * 4)   # лимит 2 req/sec + часовые/дневные капы

    if r is None:
        out["error"] = "XposedOrNot недоступен"
        return out
    if r.status_code == 429:
        out["error"] = ("лимит запросов XposedOrNot исчерпан (2/сек, есть часовой и "
                         "дневной кап) — повторите позже")
        return out
    if r.status_code != 200:
        out["error"] = f"XposedOrNot: HTTP {r.status_code}"
        return out

    try:
        d = r.json()
    except Exception:
        out["error"] = "не удалось разобрать ответ"
        return out

    summary = d.get("BreachesSummary") or {}
    out["summary"] = summary.get("site")
    out["breaches"] = [b.get("breach") for b in
                       ((d.get("ExposedBreaches") or {}).get("breaches_details") or [])
                       if isinstance(b, dict)]
    out["breach_details"] = [
        {"name": b.get("breach"), "domain": b.get("domain"),
         "details": (b.get("details") or "")[:400]}
        for b in ((d.get("ExposedBreaches") or {}).get("breaches_details") or [])
        if isinstance(b, dict)]
    bm = d.get("BreachMetrics") or {}
    risk = bm.get("risk") or []
    if risk:
        out["risk"] = risk[0]
    out["passwords_strength"] = bm.get("passwords_strength")
    out["industries"] = bm.get("industry")
    out["found"] = bool(out["breaches"])
    return out


def check_infostealer(email: str) -> Dict[str, Any]:
    """Hudson Rock: был ли компьютер заражён инфостилером (утечки ОС)."""
    out: Dict[str, Any] = {"email": email, "infected": None, "error": None}
    r = _get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}")
    if r is None:
        out["error"] = "Hudson Rock недоступен"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = "Hudson Rock: не удалось разобрать ответ"
        return out

    if d.get("message"):
        # {"message": "This email address is not associated with..."} и т.п.
        msg = str(d.get("message"))
        out["infected"] = "infected" in msg.lower() and "not associated" not in msg.lower()
        out["message"] = msg
        return out

    out["infected"] = bool(d.get("stealer"))
    out["data"] = {
        "date_compromised": d.get("date_compromised"),
        "computer_name": d.get("computer_name"),
        "os": d.get("os"),
        "ip": d.get("ip"),
        "credentials": d.get("credentials"),
        "family": d.get("family"),
        "url": d.get("url"),
    }
    return out


def check_hibp(email: str) -> Dict[str, Any]:
    """Have I Been Pwned — требует платный API-ключ (HIBP_API_KEY)."""
    out: Dict[str, Any] = {"email": email, "available": False, "breaches": [], "error": None}
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        out["error"] = "Не задан HIBP_API_KEY (бесплатная проверка уже работает через LeakCheck)"
        return out
    r = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
             headers={"hibp-api-key": key, "User-Agent": "OSINT-Finder"})
    if r is None:
        out["error"] = "HIBP недоступен"
        return out
    if r.status_code == 404:
        out["available"] = True
        out["breaches"] = []
        out["message"] = "Утечек не найдено"
        return out
    if r.status_code == 200:
        out["available"] = True
        out["breaches"] = r.json()
        return out
    out["error"] = f"HIBP: HTTP {r.status_code}"
    return out


def full_leak_check(value: str, is_email: bool = False) -> Dict[str, Any]:
    """Полная проверка: LeakCheck + Hudson Rock + HIBP (если есть ключ)."""
    out: Dict[str, Any] = {
        "value": value,
        "leakcheck": check_leakcheck(value),
        "hibp": check_hibp(value) if is_email else {"error": "HIBP работает только с email"},
    }
    if is_email:
        out["infostealer"] = check_infostealer(value)
    return out
