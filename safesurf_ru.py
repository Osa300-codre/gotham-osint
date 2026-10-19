#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Safe Surf (chk.safe-surf.ru) — сервис проверки утечек от НКЦКИ/ФСТЭК (РФ).

Российский государственный сервис: агрегирует данные об утечках,
опубликованные в открытом доступе. Бесплатный, полностью на русском языке,
работает с российскими пользователями без VPN.

Возвращает число совпадений по email / логину / номеру телефона.
"""

import re
from typing import Any, Dict

import requests

TIMEOUT = 25
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

BASE = "https://chk.safe-surf.ru/"

SESSID_PATTERNS = (
    r'name="sessid"[^>]*value="([0-9a-fA-F]{16,})"',
    r'value="([0-9a-fA-F]{16,})"[^>]*name="sessid"',
    r'bitrix_sessid[^0-9a-fA-F]+([0-9a-fA-F]{16,})',
)

MATCHES_PATTERNS = (
    r"(\d+)\s+[Сс]овпадени",
    r"[Оо]бнаружено\s+совпадений[^0-9]{0,10}(\d+)",
    r"Результат[^0-9]{0,20}(\d+)",
)


def _detect_entity(value: str) -> str:
    digits = re.sub(r"[^0-9]", "", value)
    if "@" in value and "." in value.split("@")[-1]:
        return "email"
    if digits.isdigit() and len(digits) >= 7:
        return "phone"
    return "login"


def _find_sessid(html: str):
    for pat in SESSID_PATTERNS:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return None


def _find_matches(text: str):
    for pat in MATCHES_PATTERNS:
        m = re.search(pat, text)
        if m:
            try:
                return int(m.group(1))
            except (ValueError, IndexError):
                continue
    return None


def check(value: str, entity: str = "auto") -> Dict[str, Any]:
    """Проверяет значение в базе Safe Surf (НКЦКИ).

    Возвращает: {"matches": int|None, "found": bool|None, "entity": str,
                 "summary": str, "error": str|None}
    """
    val = (value or "").strip()
    ent = entity if entity != "auto" else _detect_entity(val)

    result: Dict[str, Any] = {
        "value": val,
        "entity": ent,
        "active": True,
        "matches": None,
        "found": None,
        "summary": None,
        "error": None,
    }

    if not val:
        result["error"] = "пустое значение"
        return result

    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8",
        "Referer": BASE,
    }

    try:
        session = requests.Session()
        page = session.get(BASE, headers=headers, timeout=TIMEOUT)
        sessid = _find_sessid(page.text)
        if not sessid:
            result["error"] = "не удалось получить идентификатор сессии (sessid)"
            return result

        response = session.post(
            BASE,
            data={"sessid": sessid, "query": val, "entity": ent},
            headers=headers,
            timeout=TIMEOUT,
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", response.text))
    count = _find_matches(plain)

    if count is None:
        result["error"] = "не удалось разобрать ответ сервиса"
        return result

    result["matches"] = count
    result["found"] = count > 0
    result["summary"] = ("Совпадений не обнаружено" if count == 0
                          else f"Обнаружено совпадений: {count}")
    return result
