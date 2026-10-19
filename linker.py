#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Связывание площадок: как понять, что два профиля на разных сайтах —
это один человек.

Методы:
  * хеш аватара (dHash, 64 бит) — картинка та же, даже если пережата/обрезана;
  * хеш точных байтов аватара — картинка та же файл;
  * пересечение контактов — один и тот же e-mail/телефон/ник в разных профилях;
  * отпечаток ника — одинаковый ник + совпадающий аватар/био;
  * общие домены в био — «мой сайт» на двух площадках;
  * нормализованные ФИО (транслитерация, порядок частей).

Каждое правило возвращает (уверенность, доказательство) — их можно
комбинировать и складывать в базе знаний (knowledge.py).
"""

import hashlib
import io
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np
    from PIL import Image
    _HAS_IMG = True
except Exception:  # pragma: no cover
    _HAS_IMG = False

TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}

STOP_NAMES = {"и", "в", "на", "с", "г", "к", "о", "у", "а", "ы", "э", "ю", "я"}


def translit(s: str) -> str:
    out = []
    for ch in (s or "").lower():
        out.append(TRANSLIT.get(ch, ch))
    return "".join(out)


PATRONYMIC_RE = re.compile(r"(ович|евич|овна|евна|ична|инична|ична|увич)$", re.I)


def name_key(name: str) -> str:
    """Нормализованный ключ ФИО: без отчеств, без порядка частей."""
    if not name:
        return ""
    parts = [p for p in re.split(r"[^0-9A-Za-zА-Яа-яЁё]+", name) if p]
    words = []
    for p in parts:
        if PATRONYMIC_RE.search(p):
            continue
        low = translit(p)
        if low in STOP_NAMES:
            continue
        words.append(low)
    if not words:
        return ""
    return "".join(sorted(words))


def name_similarity(a: str, b: str) -> float:
    ka, kb = name_key(a), name_key(b)
    if not ka or not kb:
        return 0.0
    if ka == kb:
        return 1.0
    sa, sb = set(ka), set(kb)
    inter = len(sa & sb)
    if not inter:
        return 0.0
    return inter / max(len(sa), len(sb))


def hash_bytes(url: str, timeout: int = 12) -> Optional[str]:
    """Точный sha256 файла аватара."""
    if not url or not url.startswith("http"):
        return None
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0"})
        if r.status_code != 200 or len(r.content) < 100:
            return None
        return hashlib.sha256(r.content).hexdigest()
    except Exception:
        return None


def dhash(url: str, timeout: int = 12) -> Optional[str]:
    """Перцептивный хеш (dHash 8x9 -> 64 бит) — устойчив к пережатию."""
    if not _HAS_IMG or not url or not url.startswith("http"):
        return None
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0"})
        if r.status_code != 200 or len(r.content) < 100:
            return None
        img = Image.open(io.BytesIO(r.content)).convert("L").resize((9, 8))
        a = np.asarray(img, dtype=np.int16)
        diff = a[:, 1:] > a[:, :-1]
        bits = "".join("1" if b else "0" for b in diff.flatten())
        return f"{int(bits, 2):016x}"
    except Exception:
        return None


def hamming(a: Optional[str], b: Optional[str]) -> Optional[int]:
    if not a or not b:
        return None
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except Exception:
        return None


def avatar_match(a_url: str, b_url: str) -> Tuple[float, str]:
    """Сравнение аватаров: (уверенность, доказательство)."""
    if not a_url or not b_url:
        return 0.0, ""
    ha, hb = hash_bytes(a_url), hash_bytes(b_url)
    if ha and hb:
        if ha == hb:
            return 0.9, "файл аватара идентичен"
    da, db = dhash(a_url), dhash(b_url)
    if da and db:
        dist = hamming(da, db)
        if dist is not None and dist <= 6:
            return 0.8, f"перцептивный хеш аватара совпал (расстояние {dist})"
        if dist is not None and dist <= 12:
            return 0.6, f"похожие аватары (расстояние {dist})"
    return 0.0, ""


DOMAIN_RE = re.compile(r"https?://([a-z0-9.\-]+\.[a-z]{2,})", re.I)


def domains_of(text: str) -> Set[str]:
    if not text:
        return set()
    out = set()
    for d in DOMAIN_RE.findall(text):
        d = d.lower()
        if d.startswith("www."):
            d = d[4:]
        if d in ("vk.com", "t.me", "telegram.org", "facebook.com", "twitter.com",
                 "x.com", "instagram.com", "youtube.com", "google.com",
                 "yandex.ru", "microsoft.com", "apple.com", "github.com"):
            continue
        if "." in d:
            out.add(d)
    return out


def contact_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Общие контакты двух профилей: [(тип, значение)]."""
    found: List[Tuple[str, str]] = []
    for key in ("emails", "phones"):
        sa = {str(x).lower() for x in (a.get(key) or [])}
        sb = {str(x).lower() for x in (b.get(key) or [])}
        for v in sa & sb:
            found.append((key, v))
    ua = {str(x).lower() for x in (a.get("usernames") or [])}
    ub = {str(x).lower() for x in (b.get("usernames") or [])}
    for v in ua & ub:
        found.append(("usernames", v))
    return found


def link_profiles(a: Dict[str, Any], b: Dict[str, Any]) -> List[Tuple[float, str]]:
    """Все правила связывания для пары профилей."""
    rules: List[Tuple[float, str]] = []

    # 1) общие контакты — самый сильный сигнал
    for typ, val in contact_overlap(a, b):
        conf = 0.95 if typ == "emails" else (0.92 if typ == "phones" else 0.8)
        rules.append((conf, f"общий {typ[:-1]}: {val}"))

    # 2) аватар
    conf, why = avatar_match(a.get("avatar", ""), b.get("avatar", ""))
    if conf:
        rules.append((conf, why))

    # 3) ФИО
    if a.get("name") and b.get("name"):
        sim = name_similarity(a["name"], b["name"])
        if sim >= 0.85:
            rules.append((min(0.85, 0.4 + sim * 0.45),
                          f"совпадение имени «{a['name']}» / «{b['name']}»"))

    # 4) общие домены в био/ссылках
    da = domains_of((a.get("bio") or "") + " " + " ".join(a.get("links") or []))
    db = domains_of((b.get("bio") or "") + " " + " ".join(b.get("links") or []))
    for d in sorted(da & db):
        rules.append((0.75, f"общий домен в профилях: {d}"))

    # 5) одинаковый ник на разных площадках + совпадение аватара/био
    ua = (a.get("ident_value") or "").lower()
    ub = (b.get("ident_value") or "").lower()
    if ua and ua == ub and a.get("platform") != b.get("platform"):
        rules.append((0.6, f"одинаковый ник «{ua}» на разных площадках"))

    return rules


def merge_rules(rules: List[Tuple[float, str]]) -> Tuple[float, List[str]]:
    """Объединяет правила: берёт максимум, но несколько независимых — усиливают."""
    if not rules:
        return 0.0, []
    rules = sorted(rules, key=lambda x: -x[0])
    top = rules[0][0]
    reasons = [r[1] for r in rules]
    bonus = 0.05 * min(3, len(rules) - 1)
    return min(1.0, round(top + bonus, 2)), reasons
