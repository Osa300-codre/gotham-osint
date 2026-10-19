#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Асинхронный движок проверки профилей по множеству сайтов.

Правила детекции (строго по убыванию приоритета):
  1) HTTP 404/410                      -> профиля НЕТ (железный признак)
  2) редирект на /login                -> профиля НЕТ
  3) type=any + success-маркер найден  -> профиль ЕСТЬ
  4) type=message + error-маркер найден-> профиля НЕТ
  5) username найден в <title>/<h1>/og:title/og:description -> профиль ЕСТЬ
  6) type=none / страница без признаков -> НЕИЗВЕСТНО (требует ручной проверки)

ВАЖНО: og:url НЕ используется — он всегда содержит подставленный username
и даёт ложные срабатывания.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

import aiohttp

from site_checks import get_sites, get_api_sites, all_categories, PROFILE_LINKS

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

CONCURRENCY = 30
TIMEOUT = 10

_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script.*?</script>", re.S | re.I)
_WS_RE = re.compile(r"\s+")

# Заголовки страниц-заглушек, которые встречаются у несуществующих профилей
GENERIC_TITLES = {
    "", "instagram", "tiktok - make your day", "facebook", "pinterest",
    "reddit", "youtube", "twitter", "x", "vkontakte", "ok",
}

# JSON-поля, которые сайты встраивают в HTML только для существующих профилей.
# Это самый надёжный сигнал: у несуществующих профилей этих полей нет.
JSON_KEYS = ("username", "uniqueId", "screen_name", "user_name", "login", "nickname",
             "profile_nickname", "userName", "authorName")

# microdata-поля (Schema.org), которые есть только у существующих профилей
MICRO_KEYS = ("additionalName", "alternateName", "name")


def _strip(text: str) -> str:
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", text)).strip().lower()


def _decode_entities(text: str) -> str:
    import html as html_mod
    return html_mod.unescape(text)


def _signals(html: str) -> Dict[str, str]:
    """Извлекает значимые поля страницы (без og:url!)."""
    out: Dict[str, str] = {}

    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    out["title"] = _decode_entities(_strip(m.group(1))) if m else ""

    for prop in ("og:title", "og:description", "twitter:title", "twitter:description", "description"):
        mm = re.search(
            rf'<meta[^>]+(?:property|name)\s*=\s*["\']{re.escape(prop)}["\'][^>]*content\s*=\s*["\']([^"\']*)["\']',
            html, re.S | re.I)
        if not mm:
            mm = re.search(
                rf'<meta[^>]+content\s*=\s*["\']([^"\']*)["\'][^>]*(?:property|name)\s*=\s*["\']{re.escape(prop)}["\']',
                html, re.S | re.I)
        if mm:
            out[prop] = _decode_entities(_strip(mm.group(1)))

    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I)
    out["h1"] = _decode_entities(_strip(m.group(1))) if m else ""

    return out


def _mentions(text: str, value: str) -> bool:
    v = value.lower().strip().lstrip("@")
    if len(v) < 3:
        return False
    if v in text:
        return True
    if "@" in v:
        local = v.split("@")[0]
        if len(local) >= 4 and local in text:
            return True
    return False


def _signal_hit(signals: Dict[str, str], value: str) -> bool:
    """Проверяет упоминание username только в осмысленных полях."""
    for key in ("title", "h1", "og:title", "og:description",
                "twitter:title", "twitter:description", "description"):
        val = signals.get(key, "")
        if not val:
            continue
        if val in GENERIC_TITLES:
            continue
        if _mentions(val, value):
            return True
    return False


def _json_hit(html: str, value: str) -> bool:
    """Ищет username в JSON-полях встроенных в HTML."""
    v = value.lower().strip().lstrip("@")
    if len(v) < 3:
        return False
    for key in JSON_KEYS:
        # "username":"value"
        pat = re.compile(rf'"{key}"\s*:\s*"([^"]*)"', re.I)
        for m in pat.finditer(html):
            if m.group(1).lower() == v:
                return True
    # itemprop="additionalName">value<
    for key in MICRO_KEYS:
        pat = re.compile(rf'itemprop\s*=\s*["\']{key}["\'][^>]*>\s*([^<]{{1,60}})', re.I)
        for m in pat.finditer(html):
            if v in m.group(1).strip().lower():
                return True
    return False


def _api_verify(body: str, check: str, field: str, value: str) -> Optional[bool]:
    """Проверяет ответ API. True = профиль есть, False = нет, None = неизвестно."""
    import json as _json

    v = value.lower().strip().lstrip("@")
    text = body.strip()

    if check == "xml_profile":
        if "<profile>" in text:
            return True
        if "<error>" in text.lower() or "<response><error" in text.lower():
            return False
        return None

    if check == "text_nonempty":
        if not text or text == "null":
            return False
        return True

    try:
        data = _json.loads(text)
    except Exception:
        return None

    if check == "json_field":
        if not isinstance(data, dict):
            return None
        if field and field in data:
            val = str(data[field])
            if val.lower() == v:
                return True
            # числовые id (напр. player_id) — принимаем как признак наличия
            if field in ("player_id", "id") and val.isdigit():
                return True
        if "message" in data and "not found" in str(data.get("message", "")).lower():
            return False
        if data.get("code") == 0 and "not found" in str(data.get("message", "")).lower():
            return False
        return None

    if check == "json_list":
        if isinstance(data, list):
            if not data:
                return False
            first = data[0]
            if isinstance(first, dict):
                key = field or "username"
                if str(first.get(key, "")).lower() == v:
                    return True
            return True
        if isinstance(data, dict) and "message" in data:
            return False
        return None

    if check == "json_nonempty":
        if isinstance(data, dict):
            if not data:
                return False
            if "message" in data and "not found" in str(data.get("message", "")).lower():
                return False
            return True
        if isinstance(data, list):
            return bool(data)
        return None

    if check == "html_title":
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        if not m:
            return None
        title = _strip(_decode_entities(m.group(1)))
        if title in GENERIC_TITLES:
            return None
        if _mentions(title, value):
            return True
        return None

    return None


async def _check_api(session: aiohttp.ClientSession, site: Dict[str, Any], value: str) -> Dict[str, Any]:
    url = site["url"].format(value)
    entry = {"site": site["name"], "category": site["category"], "url": url}
    # Ссылка на профиль (для API-источников она читаемее)
    tmpl = PROFILE_LINKS.get(site["name"])
    entry["profile_url"] = tmpl.format(value) if tmpl else url
    try:
        async with session.get(url, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
            entry["status"] = resp.status
            if resp.status in (404, 410):
                entry["found"] = False
                entry["note"] = f"HTTP {resp.status}"
                return entry
            try:
                body = await resp.text(errors="ignore")
            except Exception:
                body = ""
            res = _api_verify(body, site.get("marker") or "", site.get("field") or "", value)
            if res is None:
                entry["found"] = None
                entry["note"] = f"HTTP {resp.status} (не подтверждено)"
            else:
                entry["found"] = res
                if not res:
                    entry["note"] = f"HTTP {resp.status} — профиля нет"
            return entry
    except asyncio.TimeoutError:
        entry["found"] = None
        entry["note"] = "таймаут"
        return entry
    except Exception as e:
        entry["found"] = None
        entry["note"] = f"ошибка: {type(e).__name__}"
        return entry


async def _check_site(session: aiohttp.ClientSession, site: Dict[str, Any], value: str) -> Dict[str, Any]:
    if site.get("type") == "api":
        return await _check_api(session, site, value)
    url = site["url"].format(value)
    entry = {"site": site["name"], "category": site["category"], "url": url}
    typ = site["type"]
    marker = (site["marker"] or "").lower()

    try:
        async with session.get(url, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
            entry["status"] = resp.status
            final = str(resp.url).rstrip("/").lower()

            if final.endswith(("/login", "/signin", "/sign-in", "/account/login", "/auth")):
                entry["found"] = False
                entry["note"] = "редирект на логин"
                return entry

            # 1) железный признак отсутствия
            if resp.status in (404, 410):
                entry["found"] = False
                entry["note"] = f"HTTP {resp.status}"
                return entry

            if typ == "none":
                entry["found"] = None
                entry["note"] = f"HTTP {resp.status} (нужна ручная проверка)"
                return entry

            try:
                html = await resp.text(errors="ignore")
            except Exception:
                html = ""

            if not html:
                entry["found"] = None
                entry["note"] = "пустой ответ"
                return entry

            # 3) success-маркер
            if typ == "any":
                if marker and marker in html.lower():
                    entry["found"] = True
                else:
                    entry["found"] = None
                    entry["note"] = "маркер не найден"
                return entry

            # 4) error-маркер
            if typ == "message" and marker and marker in html.lower():
                entry["found"] = False
                entry["note"] = "маркер отсутствия"
                return entry

            # 5) username в осмысленных полях или в JSON
            if resp.status == 200:
                signals = _signals(html)
                if _signal_hit(signals, value) or _json_hit(html, value):
                    entry["found"] = True
                    return entry
                title = signals.get("title", "")
                if title in GENERIC_TITLES:
                    entry["found"] = None
                    entry["note"] = "заглушка / анти-бот"
                else:
                    entry["found"] = None
                    entry["note"] = f"username не в заголовке (title={title[:40]!r})"
                return entry

            entry["found"] = None
            entry["note"] = f"HTTP {resp.status}"
            return entry
    except asyncio.TimeoutError:
        entry["found"] = None
        entry["note"] = "таймаут"
        return entry
    except Exception as e:
        entry["found"] = None
        entry["note"] = f"ошибка: {type(e).__name__}"
        return entry


async def scan(value: str, categories: Optional[List[str]] = None,
               sites: Optional[List[Dict[str, Any]]] = None,
               include_api: bool = True) -> Dict[str, Any]:
    """Проверяет value (username/email/phone) по всем подходящим сайтам."""
    if sites is not None:
        targets = list(sites)
    else:
        targets = get_sites(categories)
        if include_api:
            targets = targets + get_api_sites(categories)
    targets = [s for s in targets if "{}" in s["url"]]
    # Дедупликация по имени сайта: приоритет у API-варианта (точнее)
    by_name: Dict[str, Dict[str, Any]] = {}
    for s in targets:
        prev = by_name.get(s["name"])
        if prev is None:
            by_name[s["name"]] = s
        elif prev.get("type") != "api" and s.get("type") == "api":
            by_name[s["name"]] = s
    targets = list(by_name.values())
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False, force_close=False)
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
    }
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [_check_site(session, s, value) for s in targets]
        results = await asyncio.gather(*tasks)

    found = [r for r in results if r.get("found") is True]
    not_found = [r for r in results if r.get("found") is False]
    unknown = [r for r in results if r.get("found") is None]

    for r in found:
        if r.get("profile_url"):
            r["url"] = r["profile_url"]

    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for r in found:
        by_cat.setdefault(r["category"], []).append(r)

    return {
        "value": value,
        "total_checked": len(results),
        "found_count": len(found),
        "not_found_count": len(not_found),
        "unknown_count": len(unknown),
        "found": sorted(found, key=lambda r: (r["category"], r["site"])),
        "by_category": {k: v for k, v in sorted(by_cat.items())},
        "errors": [{"site": r["site"], "note": r.get("note")} for r in unknown],
    }


def scan_sync(value: str, categories: Optional[List[str]] = None) -> Dict[str, Any]:
    return asyncio.run(scan(value, categories))
