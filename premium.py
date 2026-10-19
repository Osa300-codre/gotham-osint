#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Платные/расширенные источники. Каждый сервис активируется автоматически,
если соответствующий ключ найден (в .env, в переменных окружения или
в локальном файле osint_keys.json рядом с программой).

СЕРВИСЫ И ЦЕНЫ (актуально на 2026):
  HIBP_API_KEY      haveibeenpwned.com    ~$3.50/мес  — базы утечек по email
  HUNTER_API_KEY    hunter.io             50 кредитов/мес бесплатно, далее $34-49/мес
  DEHASHED_API_KEY  dehashed.com          $3 за 100 кредитов — поиск по ЛЮБОМУ термину
  SERPER_API_KEY    serper.dev            2500 запросов бесплатно, далее $0.30-1 / 1000
  NUMVERIFY_API_KEY numverify.com         100 проверок/мес бесплатно, далее $19.99/мес
  EPIEOS_API_KEY    epieos.com            €29.99/мес — обратный поиск по 14+ сайтам
  CONTUR_API_KEY    contour.one           — поиск людей по имени/фото
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "osint_keys.json")
TIMEOUT = 25
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")


# ---------------------------------------------------------------------------
# Хранилище ключей
# ---------------------------------------------------------------------------
KEY_MAP = {
    "HIBP_API_KEY": {
        "service": "Have I Been Pwned",
        "env": "HIBP_API_KEY",
        "url": "https://haveibeenpwned.com",
        "price": "~$3.50/мес",
        "free": False,
        "what": "Проверка email по 1046+ базам утечек (пароли, токены, утечки данных)",
    },
    "HUNTER_API_KEY": {
        "service": "Hunter.io",
        "env": "HUNTER_API_KEY",
        "url": "https://hunter.io",
        "price": "50 кредитов/мес бесплатно, $34/мес за 2000",
        "free": True,
        "what": "Поиск всех email компании по домену + проверка валидности email",
    },
    "DEHASHED_API_KEY": {
        "service": "DeHashed",
        "env": "DEHASHED_API_KEY",
        "url": "https://dehashed.com",
        "price": "$3 за 100 кредитов",
        "free": False,
        "what": "Мощный поиск по утечкам: email, телефон, логин, IP, имя, пароль",
    },
    "SERPER_API_KEY": {
        "service": "Serper.dev",
        "env": "SERPER_API_KEY",
        "url": "https://serper.dev",
        "price": "2500 запросов бесплатно, далее $0.30-1 за 1000",
        "free": True,
        "what": "Настоящий поиск Google (быстрее и глубже, чем DuckDuckGo)",
    },
    "NUMVERIFY_API_KEY": {
        "service": "Numverify",
        "env": "NUMVERIFY_API_KEY",
        "url": "https://numverify.com",
        "price": "100 проверок/мес бесплатно, $19.99/мес за 1000",
        "free": True,
        "what": "Проверка телефона: страна, оператор, тип линии (обычный/виртуальный)",
    },
    "EPIEOS_API_KEY": {
        "service": "Epieos",
        "env": "EPIEOS_API_KEY",
        "url": "https://epieos.com",
        "price": "€29.99/мес (Osinter)",
        "free": False,
        "what": "Обратный поиск email/телефона по 14+ сайтам (LinkedIn, Twitter и др.)",
    },
    "CONTUR_API_KEY": {
        "service": "Contour",
        "env": "CONTUR_API_KEY",
        "url": "https://contour.one",
        "price": "бесплатный тариф ограничен",
        "free": True,
        "what": "Поиск людей по имени, фото и контактам",
    },
    "XON_API_KEY": {
        "service": "xonAPI+ (XposedOrNot)",
        "env": "XON_API_KEY",
        "url": "https://plus.xposedornot.com/pricing",
        "price": "$9/мес — оплата картой (Visa/MC/PayPal)",
        "free": True,
        "what": "Расширенный доступ к 792 утечкам / 11.6 млрд записей + домены и пасты",
    },
    "REVEALER_API_KEY": {
        "service": "Revealer.us",
        "env": "REVEALER_API_KEY",
        "url": "https://revealer.us/pricing",
        "price": "$12.99/мес (Starter), $29.99/мес с API — оплата картой",
        "free": False,
        "what": "Поиск по 800+ платформам, breach lookup, people reveal, API",
    },
}


def _load_file_keys() -> Dict[str, str]:
    try:
        with open(KEYS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if v}
    except Exception:
        return {}


def save_keys(keys: Dict[str, str]) -> bool:
    """Сохраняет ключи в osint_keys.json рядом с программой."""
    try:
        clean = {k: v.strip() for k, v in keys.items() if v and v.strip()}
        with open(KEYS_FILE, "w", encoding="utf-8") as f:
            json.dump(clean, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def get_key(name: str) -> Optional[str]:
    """Ищет ключ: файл osint_keys.json -> переменная окружения."""
    v = _load_file_keys().get(name)
    if v:
        return v
    return os.environ.get(name) or None


def key_status() -> List[Dict[str, Any]]:
    """Статус по каждому поддерживаемому сервису."""
    out = []
    for name, meta in KEY_MAP.items():
        key = get_key(name)
        out.append({
            "env": name,
            "service": meta["service"],
            "active": bool(key),
            "masked": (key[:6] + "..." + key[-4:]) if key and len(key) > 12 else ("задан" if key else ""),
            "url": meta["url"],
            "price": meta["price"],
            "free_tier": meta["free"],
            "what": meta["what"],
        })
    return out


def _req(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA}, **kwargs)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Реализации
# ---------------------------------------------------------------------------
def hibp_breaches(email: str) -> Dict[str, Any]:
    """Have I Been Pwned: список утечек по email."""
    key = get_key("HIBP_API_KEY")
    out: Dict[str, Any] = {"email": email, "active": bool(key), "breaches": [], "error": None}
    if not key:
        out["error"] = "Нет ключа HIBP_API_KEY"
        return out
    r = _req(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
             headers={"hibp-api-key": key, "User-Agent": UA})
    if r is None:
        out["error"] = "HIBP недоступен"
        return out
    if r.status_code == 404:
        out["breaches"] = []
        out["message"] = "Утечек не найдено"
        return out
    if r.status_code == 200:
        try:
            out["breaches"] = r.json()
        except Exception:
            out["error"] = "не удалось разобрать ответ"
        return out
    out["error"] = f"HTTP {r.status_code}"
    return out


def hunter_lookup(email: str) -> Dict[str, Any]:
    """Hunter.io: валидность email + данные о домене."""
    key = get_key("HUNTER_API_KEY")
    out: Dict[str, Any] = {"email": email, "active": bool(key), "error": None}
    if not key:
        out["error"] = "Нет ключа HUNTER_API_KEY"
        return out
    r = _req(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={key}")
    if r is None:
        out["error"] = "Hunter.io недоступен"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = f"HTTP {r.status_code}"
        return out
    out["data"] = d.get("data", {})
    out["status"] = d.get("status")
    return out


def hunter_domain_emails(domain: str, limit: int = 50) -> Dict[str, Any]:
    """Hunter.io: все email сотрудников компании по домену."""
    key = get_key("HUNTER_API_KEY")
    out: Dict[str, Any] = {"domain": domain, "active": bool(key), "emails": [], "error": None}
    if not key:
        out["error"] = "Нет ключа HUNTER_API_KEY"
        return out
    r = _req(f"https://api.hunter.io/v2/domain-search?domain={domain}"
             f"&limit={limit}&api_key={key}")
    if r is None:
        out["error"] = "Hunter.io недоступен"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = f"HTTP {r.status_code}"
        return out
    data = d.get("data", {}) or {}
    out["emails"] = [{
        "email": e.get("email"),
        "name": e.get("full_name") or " ".join(filter(None, [e.get("first_name"), e.get("last_name")])),
        "position": e.get("position"),
        "department": e.get("department"),
    } for e in (data.get("emails") or [])]
    out["organization"] = data.get("organization")
    return out


def dehashed_search(query: str) -> Dict[str, Any]:
    """DeHashed: поиск по любому термину (email:, phone:, username:, ip:)."""
    key = get_key("DEHASHED_API_KEY")
    out: Dict[str, Any] = {"query": query, "active": bool(key), "results": [], "error": None}
    if not key:
        out["error"] = "Нет ключа DEHASHED_API_KEY"
        return out
    r = _req(f"https://api.dehashed.com/search?query={query}", headers={"Authorization": f"Basic {key}"})
    if r is None:
        out["error"] = "DeHashed недоступен"
        return out
    if r.status_code in (401, 402):
        out["error"] = f"DeHashed: {r.status_code} (нужны кредиты)"
        return out
    if r.status_code != 200:
        out["error"] = f"HTTP {r.status_code}"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = "не удалось разобрать ответ"
        return out
    out["total"] = d.get("total")
    out["results"] = d.get("entries", [])
    return out


def serper_search(query: str, limit: int = 25) -> Dict[str, Any]:
    """Serper.dev: поиск через Google (быстро, точно, с цитатами).

    ВНИМАНИЕ: на бесплатных тарифах параметр "num" запрещён (400),
    поэтому отправляем только "q". Некоторые query-паттерны тоже
    блокируются — при ошибке повторяем запрос без кавычек.
    """
    key = get_key("SERPER_API_KEY")
    out: Dict[str, Any] = {"query": query, "active": bool(key), "results": [], "error": None}
    if not key:
        out["error"] = "Нет ключа SERPER_API_KEY"
        return out

    def _post(q: str):
        return requests.post("https://google.serper.dev/search", json={"q": q},
                              headers={"X-API-KEY": key, "Content-Type": "application/json"},
                              timeout=TIMEOUT)

    r = None
    for attempt in range(3):
        try:
            r = _post(query)
        except Exception:
            out["error"] = "Serper недоступен"
            return out
        if r.status_code != 429:
            break
        time.sleep(1.5 * (attempt + 1))   # лимит 5 запросов/сек

    if r is None:
        out["error"] = "Serper недоступен"
        return out

    # Бесплатный тариф запрещает часть query-паттернов — упрощаем и повторяем
    if r.status_code == 400:
        try:
            fallback = query.replace('"', "").strip()
            r2 = _post(fallback)
            if r2.status_code == 200:
                out["note"] = "Кавычки в запросе не поддерживаются бесплатным тарифом — запрос упрощён"
                r = r2
        except Exception:
            pass

    if r.status_code != 200:
        try:
            err = r.json().get("message", "")
        except Exception:
            err = ""
        out["error"] = f"Serper: HTTP {r.status_code} {err}".strip()
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = "не удалось разобрать ответ"
        return out
    for item in (d.get("organic") or []):
        out["results"].append({
            "title": item.get("title"),
            "url": item.get("link"),
            "snippet": item.get("snippet"),
            "date": item.get("date"),
        })
    out["total"] = len(out["results"])
    out["credits_left"] = d.get("credits")
    return out


def numverify_phone(phone: str) -> Dict[str, Any]:
    """Numverify: страна, оператор, тип телефонной линии."""
    key = get_key("NUMVERIFY_API_KEY")
    out: Dict[str, Any] = {"phone": phone, "active": bool(key), "error": None}
    if not key:
        out["error"] = "Нет ключа NUMVERIFY_API_KEY"
        return out
    r = _req(f"http://apilayer.net/api/validate?access_key={key}&number={phone}")
    if r is None:
        out["error"] = "Numverify недоступен"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = f"HTTP {r.status_code}"
        return out
    if not d.get("valid"):
        out["error"] = d.get("error", {}).get("info", "невалидный номер")
        return out
    out["data"] = {
        "country": d.get("country_name"),
        "country_code": d.get("country_code"),
        "location": d.get("location"),
        "carrier": d.get("carrier"),
        "line_type": d.get("line_type"),
        "valid": d.get("valid"),
    }
    return out


def epieos_reverse(value: str) -> Dict[str, Any]:
    """Epieos: обратный поиск email/телефона по соцсетям."""
    key = get_key("EPIEOS_API_KEY")
    out: Dict[str, Any] = {"value": value, "active": bool(key), "error": None}
    if not key:
        out["error"] = "Нет ключа EPIEOS_API_KEY"
        return out
    try:
        r = requests.post("https://epieos.com/api/search",
                          json={"query": value},
                          headers={"Authorization": key, "Content-Type": "application/json"},
                          timeout=TIMEOUT)
    except Exception:
        out["error"] = "Epieos недоступен"
        return out
    if r.status_code != 200:
        out["error"] = f"HTTP {r.status_code}"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = "не удалось разобрать ответ"
        return out
    out["data"] = d
    return out


def contour_search(name: str) -> Dict[str, Any]:
    """Contour: поиск людей по имени."""
    key = get_key("CONTUR_API_KEY")
    out: Dict[str, Any] = {"name": name, "active": bool(key), "people": [], "error": None}
    if not key:
        out["error"] = "Нет ключа CONTUR_API_KEY"
        return out
    r = _req(f"https://api.contour.one/v1/search?query={name}&api_key={key}")
    if r is None:
        out["error"] = "Contour недоступен"
        return out
    try:
        d = r.json()
    except Exception:
        out["error"] = f"HTTP {r.status_code}"
        return out
    out["people"] = d.get("people", d if isinstance(d, list) else [])
    return out


def run_all(value: str, kind: str = "auto") -> Dict[str, Any]:
    """Запускает все активные платные сервисы по значению."""
    if kind == "auto":
        if "@" in value:
            kind = "email"
        elif value.replace("+", "").replace("-", "").replace(" ", "").isdigit():
            kind = "phone"
        else:
            kind = "username"

    out: Dict[str, Any] = {"value": value, "kind": kind, "services": {}}
    if kind == "email":
        out["services"]["hibp"] = hibp_breaches(value)
        out["services"]["hunter"] = hunter_lookup(value)
        out["services"]["epieos"] = epieos_reverse(value)
    elif kind == "phone":
        out["services"]["numverify"] = numverify_phone(value)
        out["services"]["epieos"] = epieos_reverse(value)
    else:
        out["services"]["dehashed"] = dehashed_search(f"username:{value}")
        out["services"]["epieos"] = epieos_reverse(value)
    out["services"]["serper"] = serper_search(f'"{value}"')
    return out
