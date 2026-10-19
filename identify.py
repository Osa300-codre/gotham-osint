#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Точный поиск по конкретным идентификаторам:
  * Telegram username
  * Email
  * Ссылка на профиль ВК
  * Номер телефона

Используются только публичные источники. Часть данных (профиль ВК)
получается через текстовый рендер r.jina.ai, т.к. обычный HTML VK
содержит только оболочку страницы.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from leaks import check_leakcheck, check_infostealer, check_hibp
from websearch import web_search

TIMEOUT = 25
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"}

JINA = "https://r.jina.ai/"


def _get(url: str, timeout: int = TIMEOUT, **kw) -> Optional[requests.Response]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, **kw)
        # jina.ai иногда отдаёт windows-1251 без charset — читаем как utf-8
        if "jina.ai" in url and not r.encoding:
            r.encoding = "utf-8"
        return r
    except Exception:
        return None


def _similar(a: str, b: str) -> bool:
    """Похожи ли две строки (кириллический/латинский дубль одного слова)."""
    la = [c for c in a.lower() if c.isalpha()]
    lb = [c for c in b.lower() if c.isalpha()]
    if not la or not lb:
        return False
    if abs(len(la) - len(lb)) > 2:
        return False
    common = len(set(la) & set(lb))
    return common >= max(2, int(min(len(la), len(lb)) * 0.45))


def _is_translit(cyr: str, lat: str) -> bool:
    """Одна строка — кириллица, другая — латиница той же длины (дубль города)."""
    def has_cyr(s):
        return any("\u0400" <= c <= "\u04FF" for c in s)
    def has_lat(s):
        return any("a" <= c.lower() <= "z" for c in s)
    a, b = cyr, lat
    if has_cyr(a) and has_lat(b) and not has_cyr(b):
        a, b = b, a
    if not (has_cyr(a) and has_lat(b) and not has_cyr(b)):
        return False
    return abs(len(re.sub(r"[^A-Za-zА-Яа-я]", "", a)) -
               len(re.sub(r"[^A-Za-zА-Яа-я]", "", b))) <= 3


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


# ===========================================================================
#  TELEGRAM
# ===========================================================================
def search_telegram(username: str) -> Dict[str, Any]:
    """Полное досье по Telegram-аккаунту."""
    u = username.strip().lstrip("@").split("/")[-1].split("?")[0]
    out: Dict[str, Any] = {
        "input": username,
        "username": u,
        "profile_url": f"https://t.me/{u}",
        "exists": False,
        "profile": {},
        "leaks": None,
        "mentions": [],
        "errors": [],
    }

    r = _get(f"https://t.me/{u}")
    if r is None:
        out["errors"].append("t.me недоступен")
        return out
    html = r.text

    if "tgme_page_title" in html:
        out["exists"] = True

    def meta(prop: str) -> Optional[str]:
        m = re.search(rf'<meta[^>]+property="{re.escape(prop)}"[^>]*content="([^"]*)"', html, re.I)
        return _text(m.group(1)) if m else None

    title = re.search(r'<div class="tgme_page_title">(.*?)</div>', html, re.S)
    extra = re.search(r'<div class="tgme_page_extra">(.*?)</div>', html, re.S)
    desc = re.search(r'<div class="tgme_page_description">(.*?)</div>', html, re.S)
    icon = re.search(r'<div class="tgme_page_icon[^"]*"[^>]*style="background-image:url\((.*?)\)', html, re.S)

    prof = {
        "name": _text(title.group(1)) if title else (meta("og:title") or ""),
        "bio": _text(desc.group(1)) if desc else (meta("og:description") or ""),
        "avatar": meta("og:image"),
        "subscribers": _text(extra.group(1)) if extra else "",
        "page_title": meta("og:title") or "",
    }
    if prof["name"].startswith("Telegram: "):
        prof["name"] = prof["name"][9:].replace(f"View @{u}", "").replace(f"Contact @{u}", "").strip()
    out["profile"] = {k: v for k, v in prof.items() if v}

    # Утечки по логину
    lk = check_leakcheck(u)
    out["leaks"] = {"found": lk.get("found"), "sources": lk.get("sources", []),
                    "fields": lk.get("leaked_field_labels", [])}

    # Упоминания в интернете
    try:
        web = web_search(f'"{u}" telegram', limit=12)
        out["mentions"] = [{"title": m.get("title"), "url": m.get("url"),
                            "snippet": m.get("snippet"), "domain": m.get("domain")}
                           for m in web.get("results", [])]
    except Exception as e:
        out["errors"].append(f"веб-поиск: {e}")

    return out


# ===========================================================================
#  EMAIL
# ===========================================================================
def search_email_detailed(email: str) -> Dict[str, Any]:
    """Полное досье по email."""
    em = email.strip().lower()
    out: Dict[str, Any] = {
        "input": email,
        "email": em,
        "domain": em.split("@")[-1] if "@" in em else "",
        "gravatar": {},
        "leaks": {},
        "infostealer": {},
        "hibp": {},
        "mentions": [],
        "errors": [],
    }

    # --- Gravatar ---
    import hashlib
    md5 = hashlib.md5(em.encode()).hexdigest()
    r = _get(f"https://www.gravatar.com/{md5}.json")
    if r is not None and r.status_code == 200:
        try:
            entry = (r.json().get("entry") or [{}])[0]
            out["gravatar"] = {
                "found": True,
                "name": entry.get("displayName"),
                "about": entry.get("aboutMe"),
                "location": entry.get("currentLocation"),
                "profile_url": entry.get("profileUrl"),
                "accounts": [{"name": a.get("shortname"), "url": a.get("url")}
                             for a in (entry.get("accounts") or [])],
                "avatar": (entry.get("photos") or [{}])[0].get("value"),
            }
        except Exception:
            out["gravatar"] = {"found": False}
    else:
        out["gravatar"] = {"found": False, "note": "профиль Gravatar не найден"}

    # --- Утечки ---
    try:
        lc = check_leakcheck(em)
        out["leaks"] = {
            "found": lc.get("found"),
            "source_count": lc.get("source_count"),
            "fields": lc.get("leaked_field_labels", []),
            "sources": lc.get("sources", []),
        }
    except Exception as e:
        out["errors"].append(f"LeakCheck: {e}")

    try:
        out["infostealer"] = check_infostealer(em)
    except Exception as e:
        out["errors"].append(f"Hudson Rock: {e}")

    try:
        out["hibp"] = check_hibp(em)
    except Exception as e:
        out["errors"].append(f"HIBP: {e}")

    # --- Упоминания в интернете ---
    try:
        web = web_search(f'"{em}"', limit=20)
        out["mentions"] = [{"title": m.get("title"), "url": m.get("url"),
                            "snippet": m.get("snippet"), "domain": m.get("domain")}
                           for m in web.get("results", [])]
    except Exception as e:
        out["errors"].append(f"веб-поиск: {e}")

    return out


# ===========================================================================
#  ВК
# ===========================================================================
VK_RE = re.compile(r"(?:vk\.com|vk\.ru|m\.vk\.com|dvk\.com)(?:/[^/]+)?/([A-Za-z0-9_.]{2,64})", re.I)


def parse_vk_link(link: str) -> Dict[str, Any]:
    """Извлекает screen_name / id из ссылки ВК."""
    raw = link.strip()
    out: Dict[str, Any] = {"input": raw, "screen_name": None, "numeric_id": None}

    m = re.match(r"^(?:https?://)?(?:www\.|m\.)?(vk\.com|vk\.ru|dvk\.com)(?:/|$)(.*)$",
                 raw, re.I)
    if m:
        out["host"] = m.group(1).lower()
        path = m.group(2).strip("/")
    else:
        path = raw.strip("/")

    if not path:
        return out

    parts = [seg for seg in path.split("/") if seg]
    if not parts:
        return out

    # очищаем query/fragment
    seg = parts[0].split("?")[0].split("#")[0]
    if re.match(r"^(id|public|club|event|app|group|album|video|photo|post|wall)\d+$", seg, re.I):
        out["numeric_id"] = seg
        out["screen_name"] = None
    else:
        out["screen_name"] = seg
    return out


def _parse_vk_markdown(md: str, screen_name: str) -> Dict[str, Any]:
    """Достаёт имя, город, статус и аватар из markdown-рендера ВК."""
    prof: Dict[str, Any] = {}

    m = re.search(r"^Title:\s*(.+?)\s*(?:\||$)", md, re.M)
    if m:
        title = m.group(1).strip()
        if title and "|" not in title and title.lower() != "vk":
            prof["name"] = re.sub(r":\s*Posts$", "", title).strip()

    m = re.search(r"^##\s*@([A-Za-z0-9_.]+)", md, re.M)
    if m:
        prof["screen_name"] = m.group(1)

    m = re.search(r"^##\s+(.+?)\s*$", md, re.M)
    if m and "name" not in prof:
        prof["name"] = m.group(1).strip()

    # аватар
    m = re.search(r"!\[Image 1\]\((https?://[^)]+)\)", md)
    if m:
        prof["avatar"] = m.group(1)

    # Разбираем блок заголовка: ## @name, ## Имя, город, работа/город, статус
    lines = [l.strip() for l in md.splitlines()]
    idx = None
    for i, line in enumerate(lines):
        if line.startswith("##") and screen_name and screen_name in line:
            idx = i
            break

    stop_words = {"follow", "posts", "videos", "photos", "music", "games", "friends",
                  "search", "actions", "verified", "more", "settings", "friendship",
                  "audio", "groups", "vkontakte", "people", "friends", "notifications",
                  "messages", "likes", "comments", "reposts", "market", "services",
                  "help", "exit", "exit1", "exit2"}
    if idx is not None:
        tail = []
        for line in lines[idx + 1:]:
            if line.startswith("* * *"):
                break
            if not line:
                continue
            if line.startswith("!["):
                continue
            tail.append(line)

        plain_tail = []
        for t in tail:
            t2 = re.sub(r"!\[.*?\]\(.*?\)", "", t)
            t2 = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t2)
            t2 = re.sub(r"^#+\s*", "", t2).strip()
            if not t2 or t2.lower() in stop_words or t2.startswith("http"):
                continue
            if t2.startswith("@") and screen_name and t2[1:] == screen_name:
                continue
            plain_tail.append(t2)

        if plain_tail:
            if "name" not in prof:
                prof["name"] = plain_tail[0]
            # убираем дубли (кириллическая и латинская версия одного города)
            uniq = []
            for t in plain_tail[1:]:
                if any(_similar(t, u) or _is_translit(t, u) for u in uniq):
                    continue
                uniq.append(t)
            if uniq:
                prof["city"] = uniq[0]
            if len(uniq) > 1:
                prof["work"] = uniq[1]

    # Статус — самый длинный текстовый абзац
    body = md.split("* * *", 1)[-1] if "* * *" in md else md
    body = re.sub(r"!\[.*?\]\(.*?\)", "", body)
    body = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", body)
    paras = [re.sub(r"\s+", " ", p).strip() for p in body.split("\n\n")]
    paras = [p for p in paras if len(p) > 30 and not p.startswith(("Title:", "URL Source:"))]
    if paras:
        prof["status"] = paras[0][:300]

    return prof


def search_vk(link: str) -> Dict[str, Any]:
    """Полное досье по профилю ВК."""
    parsed = parse_vk_link(link)
    screen = parsed.get("screen_name")
    num = parsed.get("numeric_id")
    out: Dict[str, Any] = {
        "input": link,
        "parsed": parsed,
        "profile_url": (f"https://vk.com/{screen}" if screen else
                        (f"https://vk.com/{num}" if num else None)),
        "profile": {},
        "leaks": None,
        "mentions": [],
        "errors": [],
    }

    if not screen and not num:
        out["errors"].append("Не удалось распознать ссылку ВК")
        return out

    # --- Профиль через текстовый рендер (m.vk.com отдаёт больше данных) ---
    screen = screen or ""
    for cand in ([f"https://m.vk.com/{screen}", f"https://vk.com/{screen}"] if screen
                 else [f"https://vk.com/{num}"]):
        r = _get(JINA + cand, timeout=45)
        if r is not None and r.status_code == 200 and len(r.text) > 150:
            prof = _parse_vk_markdown(r.text, screen)
            if prof.get("name"):
                prof["found"] = True
                prof["source"] = cand
                out["profile"] = prof
                break
    if not out["profile"]:
        out["errors"].append("Профиль ВК не удалось получить (анти-бот или нет доступа)")

    # --- Утечки по screen_name / id ---
    key = screen or num
    try:
        lk = check_leakcheck(key)
        out["leaks"] = {"found": lk.get("found"), "sources": lk.get("sources", []),
                        "fields": lk.get("leaked_field_labels", [])}
    except Exception as e:
        out["errors"].append(f"LeakCheck: {e}")

    # --- Упоминания ---
    try:
        q = f'"{screen}" site:vk.com' if screen else f'"vk.com/{num}"'
        web = web_search(q, limit=15)
        out["mentions"] = [{"title": m.get("title"), "url": m.get("url"),
                            "snippet": m.get("snippet"), "domain": m.get("domain")}
                           for m in web.get("results", [])]
    except Exception as e:
        out["errors"].append(f"веб-поиск: {e}")

    return out


# ===========================================================================
#  ТЕЛЕФОН
# ===========================================================================
COUNTRY_PREFIX = {
    "7": ("Россия / Казахстан", "+7"),
    "1": ("США / Канада", "+1"),
    "44": ("Великобритания", "+44"),
    "49": ("Германия", "+49"),
    "33": ("Франция", "+33"),
    "39": ("Италия", "+39"),
    "34": ("Испания", "+34"),
    "380": ("Украина", "+380"),
    "375": ("Беларусь", "+375"),
    "374": ("Армения", "+374"),
    "994": ("Азербайджан", "+994"),
    "995": ("Грузия", "+995"),
    "998": ("Узбекистан", "+998"),
    "996": ("Киргизия", "+996"),
    "992": ("Таджикистан", "+992"),
    "993": ("Туркменистан", "+993"),
    "48": ("Польша", "+48"),
    "31": ("Нидерланды", "+31"),
    "46": ("Швеция", "+46"),
    "47": ("Норвегия", "+47"),
    "45": ("Дания", "+45"),
    "358": ("Финляндия", "+358"),
    "420": ("Чехия", "+420"),
    "30": ("Греция", "+30"),
    "351": ("Португалия", "+351"),
    "54": ("Аргентина", "+54"),
    "55": ("Бразилия", "+55"),
    "52": ("Мексика", "+52"),
    "1": ("США / Канада", "+1"),
    "61": ("Австралия", "+61"),
    "81": ("Япония", "+81"),
    "82": ("Южная Корея", "+82"),
    "86": ("Китай", "+86"),
    "91": ("Индия", "+91"),
    "880": ("Бангладеш", "+880"),
    "92": ("Пакистан", "+92"),
    "66": ("Таиланд", "+66"),
    "84": ("Вьетнам", "+84"),
    "62": ("Индонезия", "+62"),
    "60": ("Малайзия", "+60"),
    "63": ("Филиппины", "+63"),
    "90": ("Турция", "+90"),
    "972": ("Израиль", "+972"),
    "971": ("ОАЭ", "+971"),
    "966": ("Саудовская Аравия", "+966"),
    "20": ("Египет", "+20"),
    "27": ("ЮАР", "+27"),
    "234": ("Нигерия", "+234"),
    "254": ("Кения", "+254"),
    "212": ("Марокко", "+212"),
    "213": ("Алжир", "+213"),
    "961": ("Ливан", "+961"),
    "964": ("Ирак", "+964"),
    "98": ("Иран", "+98"),
    "90": ("Турция", "+90"),
}


def normalize_phone(phone: str) -> Dict[str, Any]:
    """Нормализует номер и определяет страну по префиксу."""
    raw = phone.strip()
    plus = raw.startswith("+")
    digits = re.sub(r"\D", "", raw)
    out: Dict[str, Any] = {"input": raw, "digits": digits, "valid_length": 7 <= len(digits) <= 15}

    if plus:
        best = None
        for length in (3, 2, 1):
            cc = digits[:length]
            if cc in COUNTRY_PREFIX:
                best = (cc, COUNTRY_PREFIX[cc][0])
                break
        if best:
            out["country_code"] = best[0]
            out["country"] = best[1]
            out["e164"] = "+" + digits
        else:
            out["e164"] = "+" + digits
    else:
        out["e164"] = "+" + digits
        out["note"] = "номер без '+' — код страны определён предположительно"
        # пытаемся определить страну по префиксу
        for length in (3, 2, 1):
            cc = digits[:length]
            if cc in COUNTRY_PREFIX:
                out["country_code"] = cc
                out["country"] = COUNTRY_PREFIX[cc][0]
                break

    # Россия: 8XXXXXXXXXX -> +7
    if len(digits) == 11 and digits.startswith("8"):
        out["e164"] = "+7" + digits[1:]
        out["country_code"] = "7"
        out["country"] = "Россия"
    return out


def search_phone_deep(phone: str) -> Dict[str, Any]:
    """Полное досье по номеру телефона."""
    norm = normalize_phone(phone)
    out: Dict[str, Any] = {
        "input": phone,
        "normalized": norm,
        "operator": {},
        "leaks": {},
        "mentions": [],
        "linked": [],
        "errors": [],
    }

    digits = norm["digits"]

    # --- Оператор и тип линии (numverify, если есть ключ) ---
    try:
        from premium import numverify_phone
        nv = numverify_phone(digits)
        if nv.get("active") and nv.get("data"):
            out["operator"] = nv["data"]
        elif nv.get("error"):
            out["operator"] = {"note": nv["error"]}
    except Exception as e:
        out["errors"].append(f"Numverify: {e}")

    # --- Утечки по номеру ---
    try:
        lk = check_leakcheck(digits)
        out["leaks"] = {
            "found": lk.get("found"),
            "source_count": lk.get("source_count"),
            "fields": lk.get("leaked_field_labels", []),
            "sources": lk.get("sources", []),
        }
    except Exception as e:
        out["errors"].append(f"LeakCheck: {e}")

    # --- Упоминания в интернете ---
    variants = {digits}
    if norm.get("e164"):
        variants.add(norm["e164"].lstrip("+"))
    try:
        web = web_search(f'"{digits}"', limit=20)
        out["mentions"] = [{"title": m.get("title"), "url": m.get("url"),
                            "snippet": m.get("snippet"), "domain": m.get("domain")}
                           for m in web.get("results", [])]
    except Exception as e:
        out["errors"].append(f"веб-поиск: {e}")

    # --- Связанные аккаунты (Avito, VK и др. по номеру) ---
    for label, url_tpl in [
        ("Avito (по номеру)", "https://www.avito.ru/sankt-peterburg?q={}"),
        ("ВКонтакте (поиск)", "https://vk.com/people?do_search&query={}"),
    ]:
        try:
            r = _get(url_tpl.format(digits), timeout=12)
            if r is not None and r.status_code == 200:
                out["linked"].append({"source": label, "url": url_tpl.format(digits),
                                      "status": "проверьте вручную"})
        except Exception:
            pass

    return out


# ===========================================================================
#  Универсальная точка входа
# ===========================================================================
def identify(value: str) -> Dict[str, Any]:
    """Определяет тип значения и запускает соответствующий поиск."""
    v = value.strip()
    if not v:
        return {"error": "пустое значение"}

    if "@" in v and "." in v.split("@")[-1]:
        kind = "email"
    elif re.match(r"^(https?://)?(www\.)?(m\.)?(vk\.com|vk\.ru|dvk\.com)/", v, re.I) or \
            re.match(r"^(vk\.com|vk\.ru)/", v, re.I):
        kind = "vk"
    elif re.match(r"^(https?://)?(www\.)?t\.me/", v, re.I) or v.startswith("@"):
        kind = "telegram"
    elif re.fullmatch(r"[+\-\s()\d]{7,25}", v) and len(re.sub(r"\D", "", v)) >= 7:
        # телефон: важно считать ВСЕ цифры, а не только идущие подряд
        # ("8 999 123-45-67" — цифры идут группами по 3)
        kind = "phone"
    else:
        kind = "telegram" if v.isascii() else "unknown"

    if kind == "email":
        return {"kind": kind, "result": search_email_detailed(v)}
    if kind == "vk":
        return {"kind": kind, "result": search_vk(v)}
    if kind == "phone":
        return {"kind": kind, "result": search_phone_deep(v)}
    if kind == "telegram":
        return {"kind": kind, "result": search_telegram(v)}
    return {"kind": "unknown", "error": "не удалось определить тип значения"}
