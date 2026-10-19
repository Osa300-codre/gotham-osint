#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Мультикоррелятор: сводит НЕСКОЛЬКО идентификаторов в одно досье.

Вход (любая комбинация):
    телефон, e-mail, ник в Telegram, ссылка на VK, username, ФИО.

Зачем: «Досье» в osint_web работает с одним значением за раз. Здесь несколько
идентификаторов проверяются параллельно, а затем связываются между собой:
совпадение имени, e-mail в био, username == local-part почты, перекрёстные
ссылки «профиль → профиль» и общие аватары дают граф с весами уверенности
и кластеры «вероятно один человек».

Выход: JSON, Markdown, HTML-граф + блок «ЛИЧНОСТЬ» (ФИО, адреса, города,
ссылки на соцсети) и оценка экспозиции 0–100 с рекомендациями по защите.

Переиспользует существующие модули проекта:
    identify.py — Telegram / VK / email / phone разбор
    dossier.py  — ФИО, адреса, утечки, web-доказательства
    personal.py — персональные dorks
    scanner.py  — скан username по 500+ сайтам
"""

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.panel import Panel
except Exception:  # pragma: no cover
    class Console:  # type: ignore
        def print(self, *a, **k):
            print(*a)

    def Panel(*a, **k):  # type: ignore
        return "\n".join(str(x) for x in a)

console = Console()
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

from person_resolve import build_identity_summary, clean_links, social_links
from linker import link_profiles, merge_rules

DISCLAIMER = (
    "Инструмент показывает, что о человеке уже известно из открытых источников "
    "и из утечек. Применяйте к своим данным или к субъекту, на которого есть "
    "согласие/санкция. Доксинг и сталкинг запрещены (152-ФЗ, 137 УК РФ, GDPR)."
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d[\s\-().]*){9,17}\d")
VK_RE = re.compile(r"(?:https?://)?(?:www\.)?(?:vk\.com|vk\.ru|m\.vk\.com)/([A-Za-z0-9_\.]{2,64})", re.I)
TELEGRAM_RE = re.compile(r"(?:https?://)?(?:t|telegram)\.me/(?:s/)?@?([A-Za-z0-9_]{4,32})", re.I)

PALETTE = {
    "phone": "#e94560", "email": "#0f9d58", "telegram": "#2aabee",
    "vk": "#0077ff", "username": "#f5a623", "name": "#9b59b6",
    "profile": "#34495e",
}


# ---------------------------------------------------------------- утилиты

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm_text(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[«»\"'’`]+", "", s)
    s = re.sub(r"[^0-9a-zа-яё]+", " ", s, flags=re.I)
    return re.sub(r"\s+", " ", s).strip()


def tokens(s: str) -> Set[str]:
    return {t for t in norm_text(s).split() if len(t) > 1}


def name_match(a: str, b: str) -> float:
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    inter = ta & tb
    if not inter:
        return 0.0
    return len(inter) / max(len(ta), len(tb))


def _bio_links(bio: str) -> List[str]:
    """Ссылки из описания профиля (сайт, канал, соцсеть)."""
    if not bio:
        return []
    urls = re.findall(r"https?://[^\s<>\"')\]]+", bio)
    return clean_links(urls)


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return ""


# ---------------------------------------------------------------- идентификаторы

@dataclass
class Ident:
    type: str          # phone | email | telegram | vk | username | name
    value: str
    source: str = "input"
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value.lower()}"


def parse_vk_slug(value: str) -> Optional[str]:
    m = VK_RE.search(value.strip())
    if m:
        return m.group(1).split("?")[0].split("/")[0]
    v = value.strip()
    if re.fullmatch(r"(id\d+|[A-Za-z0-9_.]{2,64})", v):
        return v
    return None


def parse_tg_handle(value: str) -> Optional[str]:
    v = value.strip()
    m = TELEGRAM_RE.search(v)
    if m:
        return m.group(1)
    v2 = v.lstrip("@")
    if re.fullmatch(r"[A-Za-z0-9_]{4,32}", v2):
        return v2
    return None


def username_variants(base: str) -> List[str]:
    raw = base.strip().lstrip("@")
    parts = [p for p in re.split(r"[._\-\s]+", raw) if p]
    out: List[str] = []

    def add(v: str):
        v = v.strip().lower()
        if v and len(v) >= 3 and v not in out:
            out.append(v)

    add(raw)
    add("".join(parts))
    if len(parts) >= 2:
        add(f"{parts[0]}_{parts[1]}")
        add(f"{parts[0]}{parts[1]}")
        add(f"{parts[0][0]}{parts[1]}")
        add(f"{parts[-1]}{parts[0]}")
    return out[:8]


def build_idents(phone: List[str], email: List[str], telegram: List[str],
                 vk: List[str], username: List[str], name: List[str]) -> List[Ident]:
    out: List[Ident] = []
    seen: Set[str] = set()

    def push(t: str, v: str, source: str = "input", meta: Optional[Dict[str, Any]] = None):
        v = (v or "").strip()
        if not v:
            return
        i = Ident(t, v, source, meta or {})
        if i.key in seen:
            return
        seen.add(i.key)
        out.append(i)

    for p in phone:
        push("phone", p)
    for e in email:
        push("email", e.lower())
    for t in telegram:
        h = parse_tg_handle(t)
        if h:
            push("telegram", h)
    for v in vk:
        s = parse_vk_slug(v)
        if s:
            push("vk", s)
    for u in username:
        push("username", u.lstrip("@").lower())
    for n in name:
        push("name", n.strip())

    # производные username-варианты (для быстрой проверки в Telegram/VK)
    derived: List[str] = []
    existing_values = {i.value.lower() for i in out}
    for i in list(out):
        base = ""
        if i.type == "email":
            base = i.value.split("@")[0]
        elif i.type in ("username", "telegram", "vk", "name"):
            base = re.sub(r"[^A-Za-z0-9А-Яа-яЁё._\-\s]", "", i.value)
        if not base:
            continue
        for v in username_variants(base):
            # не дублируем уже заданные значения (telegram:durov == username:durov)
            if v in existing_values or v in derived:
                continue
            if any(x.type == "username" and x.value == v for x in out):
                continue
            derived.append(v)
    for d in derived[:8]:
        push("username", d, "derived")
    return out


# ---------------------------------------------------------------- сбор данных

def collect(idents: List[Ident], deep: bool = False, pages: int = 15,
            log: Optional[Any] = None) -> Dict[str, Any]:
    """Опрашивает площадки по каждому идентификатору."""
    say = log or (lambda *a, **k: None)
    from identify import (search_telegram, search_vk, search_email_detailed,
                          search_phone_deep)

    raw: Dict[str, Any] = {}
    profiles: List[Dict[str, Any]] = []
    dossiers: Dict[str, Any] = {}

    for i in idents:
        if i.type == "telegram":
            r = search_telegram(i.value)
            raw[i.key] = r
            p = r.get("profile") or {}
            if r.get("exists") and p:
                profiles.append({
                    "platform": "Telegram", "url": r.get("profile_url"),
                    "ident_type": "telegram", "ident_value": i.value,
                    "name": p.get("name") or "", "bio": p.get("bio") or "",
                    "avatar": p.get("avatar") or "",
                    "links": _bio_links(p.get("bio") or ""),
                    "emails": sorted({e.lower() for e in
                                      EMAIL_RE.findall(p.get("bio") or "")}),
                    "phones": sorted({re.sub(r"\D", "", m) for m in
                                      PHONE_RE.findall(p.get("bio") or "")
                                      if len(re.sub(r"\D", "", m)) >= 10}),
                    "extra": {k: v for k, v in p.items()
                              if k not in ("name", "bio", "avatar")},
                })
                say(f"+ Telegram {i.value}: {p.get('name')}")
        elif i.type == "vk":
            r = search_vk(i.value)
            raw[i.key] = r
            p = r.get("profile") or {}
            if p:
                links = [l for l in (p.get("links") or []) if l.startswith("http")]
                prof_links = clean_links(links)
                profiles.append({
                    "platform": "VK", "url": r.get("profile_url"),
                    "ident_type": "vk", "ident_value": i.value,
                    "name": p.get("name") or "", "bio": p.get("status") or "",
                    "avatar": p.get("avatar") or "",
                    "links": prof_links, "emails": [], "phones": [],
                    "extra": {k: v for k, v in p.items()
                              if k not in ("name", "bio", "avatar", "links")},
                })
                say(f"+ VK {i.value}: {p.get('name')}"
                    + (f" ({p.get('city')})" if p.get("city") else ""))
        elif i.type == "email":
            r = search_email_detailed(i.value)
            raw[i.key] = r
            g = r.get("gravatar") or {}
            if g.get("found"):
                profiles.append({
                    "platform": "Gravatar", "url": g.get("profile_url") or "",
                    "ident_type": "email", "ident_value": i.value,
                    "name": g.get("name") or "", "bio": g.get("about") or "",
                    "avatar": g.get("avatar") or "",
                    "links": [a.get("url") for a in (g.get("accounts") or []) if a.get("url")],
                    "emails": [], "phones": [],
                    "extra": {"location": g.get("location") or ""},
                })
                say(f"+ Gravatar {i.value}: {g.get('name')}")
        elif i.type == "phone":
            r = search_phone_deep(i.value)
            raw[i.key] = r
            say(f"* телефон {i.value}: {r.get('normalized', {}).get('country', '')}")
        elif i.type == "username":
            say(f"… username {i.value}")

    # --- скан username по каталогу сайтов
    scans: Dict[str, Any] = {}
    if deep:
        from scanner import scan_sync
        for i in idents:
            if i.type != "username":
                continue
            say(f"→ скан {i.value}")
            scans[i.value] = scan_sync(i.value)
            for it in scans[i.value].get("found", []):
                profiles.append({
                    "platform": it.get("site", "Web"), "url": it.get("url"),
                    "ident_type": "username", "ident_value": i.value,
                    "name": "", "bio": "", "avatar": "",
                    "links": [], "emails": [], "phones": [],
                    "extra": {"category": it.get("category", "")},
                })

    # --- досье по «якорным» значениям (ФИО, адреса, утечки).
    #     Для username/Telegram/VK досье бессмысленно (там нет e-mail/телефона),
    #     эти площадки уже разобраны через identify.py.
    from dossier import build_dossier
    for i in idents:
        if i.type not in ("phone", "email"):
            continue
        say(f"→ досье {i.value}")
        try:
            dossiers[i.key] = build_dossier(i.value)
        except Exception as e:
            dossiers[i.key] = {"error": f"{type(e).__name__}: {e}"}

    # --- обход найденных профилей ради e-mail/телефонов/ссылок
    extra_pages: List[Dict[str, Any]] = []
    if pages > 0:
        import requests
        from concurrent.futures import ThreadPoolExecutor
        urls = []
        for sc in scans.values():
            for it in sc.get("found", []):
                u = it.get("url") or ""
                if u.startswith("http"):
                    urls.append(u)
        urls = list(dict.fromkeys(urls))[:pages]
        if urls:
            say(f"→ обход {len(urls)} страниц")

            def grab(u: str) -> Dict[str, Any]:
                try:
                    r = requests.get(u, timeout=12, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                                      "Chrome/122.0.0.0 Safari/537.36"})
                    if r.status_code != 200:
                        return {"url": u, "status": r.status_code}
                    html = r.text
                    text = re.sub(r"<[^>]+>", " ", html)
                    h = set(EMAIL_RE.findall(text))
                    ph = {re.sub(r"\D", "", m) for m in PHONE_RE.findall(text)}
                    og = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]*'
                                   r'content=["\']([^"\']+)', html, re.I)
                    return {"url": u, "status": 200,
                            "emails": sorted({x.lower() for x in h}),
                            "phones": sorted({p for p in ph if len(p) >= 10}),
                            "links": clean_links(re.findall(
                                r'href=["\']([^"\']+)["\']', html, re.I))[:40],
                            "avatar": og.group(1) if og else "",
                            "title": (re.search(r"<title[^>]*>(.*?)</title>",
                                                html, re.S | re.I).group(1).strip()
                                      if re.search(r"<title[^>]*>(.*?)</title>",
                                                   html, re.S | re.I) else ""),
                            "text": re.sub(r"\s+", " ", text)[:20000]}
                except Exception as e:
                    return {"url": u, "status": 0, "error": str(e)}

            with ThreadPoolExecutor(max_workers=8) as ex:
                extra_pages = list(ex.map(grab, urls))

    # --- обогащаем профили данными с их страниц (контакты, аватар, ссылки)
    by_url = {}
    for p in profiles:
        if p.get("url"):
            by_url[p["url"].rstrip("/")] = p
    for pg in extra_pages:
        p = by_url.get(str(pg.get("url", "")).rstrip("/"))
        if not p:
            continue
        p["emails"] = sorted(set(p.get("emails") or []) | set(pg.get("emails") or []))
        p["phones"] = sorted(set(p.get("phones") or []) | set(pg.get("phones") or []))
        p["links"] = sorted(set(p.get("links") or []) | set(pg.get("links") or []))
        if not p.get("avatar") and pg.get("avatar"):
            p["avatar"] = pg["avatar"]
        if not p.get("name") and pg.get("title"):
            p["name"] = pg["title"][:60]
        p.setdefault("usernames", [])
        if p.get("ident_value"):
            p["usernames"] = sorted(set(p["usernames"]) | {p["ident_value"]})

    return {"raw": raw, "profiles": profiles, "dossiers": dossiers,
            "scans": scans, "extra_pages": extra_pages}


# ---------------------------------------------------------------- корреляция

@dataclass
class Edge:
    a: str
    b: str
    confidence: float
    reasons: List[str] = field(default_factory=list)


class DSU:
    def __init__(self):
        self.p: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def correlate(idents: List[Ident], profiles: List[Dict[str, Any]],
              dossiers: Dict[str, Any], extra_pages: List[Dict[str, Any]],
              raw: Dict[str, Any]) -> Tuple[List[Edge], List[List[str]]]:
    edges: List[Edge] = []

    def add(a: str, b: str, conf: float, reason: str):
        if a == b:
            return
        for e in edges:
            if {e.a, e.b} == {a, b}:
                e.confidence = max(e.confidence, conf)
                if reason not in e.reasons:
                    e.reasons.append(reason)
                return
        edges.append(Edge(a, b, conf, [reason]))

    # 1) совпадение значений между типами (telegram == username и т.п.)
    by_val: Dict[str, List[Ident]] = {}
    for i in idents:
        by_val.setdefault(i.value.lower(), []).append(i)
    for val, group in by_val.items():
        for x in range(len(group)):
            for y in range(x + 1, len(group)):
                a, b = group[x], group[y]
                add(a.key, b.key, 0.9,
                    f"совпадает значение «{val}» ({a.type}/{b.type})")

    # 2) username == local-part e-mail
    emails = {i.value.lower(): i for i in idents if i.type == "email"}
    users = {i.value.lower(): i for i in idents if i.type == "username"}
    for ev, ei in emails.items():
        for uv, ui in users.items():
            if uv == ev.split("@")[0]:
                add(ei.key, ui.key, 0.85, "username совпадает с local-part e-mail")

    # 3) e-mail / телефон, найденные на странице профиля
    prof_by_url = {p.get("url"): p for p in profiles}
    for pg in extra_pages:
        p = prof_by_url.get(pg.get("url"))
        if not p:
            continue
        key = f"{p['platform']}:{p.get('ident_value') or p.get('url')}"
        for em in (pg.get("emails") or []):
            for i in idents:
                if i.type == "email" and i.value.lower() == em.lower():
                    add(i.key, key, 0.95, "e-mail найден на странице профиля")
                elif i.type == "username" and i.value.lower() == em.split("@")[0]:
                    add(i.key, key, 0.7,
                        "username = local-part e-mail, найденного на профиле")
        for ph in (pg.get("phones") or []):
            for i in idents:
                if i.type == "phone" and re.sub(r"\D", "", i.value) == ph:
                    add(i.key, key, 0.9, "телефон найден на странице профиля")

    # 4) перекрёстные ссылки между профилями
    node_keys = {f"{p['platform']}:{p.get('ident_value') or p.get('url')}": p
                 for p in profiles}
    for a_key, a in node_keys.items():
        for lk in (a.get("links") or []):
            h = host_of(lk)
            for b_key, b in node_keys.items():
                if b_key == a_key:
                    continue
                bh = host_of(b.get("url") or "")
                if bh and h == bh:
                    add(a_key, b_key, 0.8, f"ссылка на {b['platform']} в профиле")
                elif b.get("ident_value") and b["ident_value"].lower() in lk.lower():
                    add(a_key, b_key, 0.75, f"прямая ссылка на профиль {b['ident_value']}")

    # 5) совпадение отображаемых имён
    named = [p for p in profiles if p.get("name")]
    for x in range(len(named)):
        for y in range(x + 1, len(named)):
            a, b = named[x], named[y]
            ka = f"{a['platform']}:{a.get('ident_value') or a.get('url')}"
            kb = f"{b['platform']}:{b.get('ident_value') or b.get('url')}"
            sc = name_match(a["name"], b["name"])
            if sc >= 0.5:
                add(ka, kb, min(0.85, 0.4 + sc * 0.5),
                    f"совпадение имени «{a['name']}» / «{b['name']}»")

    # 5b) полное связывание площадок: контакты, аватар, домены, ник
    for x in range(len(profiles)):
        for y in range(x + 1, len(profiles)):
            a, b = profiles[x], profiles[y]
            ka = f"{a['platform']}:{a.get('ident_value') or a.get('url')}"
            kb = f"{b['platform']}:{b.get('ident_value') or b.get('url')}"
            rules = link_profiles(a, b)
            if not rules:
                continue
            conf, reasons = merge_rules(rules)
            if conf >= 0.5:
                add(ka, kb, conf, "; ".join(reasons))

    # 6) общие контакты из досье: если два идентификатора дали один e-mail/телефон
    contact_map: Dict[str, List[str]] = {}
    for key, d in dossiers.items():
        if not isinstance(d, dict):
            continue
        for em in ((d.get("contacts") or {}).get("emails") or []):
            contact_map.setdefault("email:" + em.lower(), []).append(key)
        for ph in ((d.get("contacts") or {}).get("phones") or []):
            contact_map.setdefault("phone:" + re.sub(r"\D", "", ph), []).append(key)
    for shared, keys in contact_map.items():
        for x in range(len(keys)):
            for y in range(x + 1, len(keys)):
                add(keys[x], keys[y], 0.8, f"общий контакт {shared}")

    # 7) совпадение аватаров
    for x in range(len(profiles)):
        for y in range(x + 1, len(profiles)):
            a, b = profiles[x], profiles[y]
            if a.get("avatar") and b.get("avatar"):
                if a["avatar"].split("?")[0] == b["avatar"].split("?")[0]:
                    add(f"{a['platform']}:{a.get('ident_value') or a.get('url')}",
                        f"{b['platform']}:{b.get('ident_value') or b.get('url')}",
                        0.65, "одинаковый аватар")

    dsu = DSU()
    for i in idents:
        dsu.find(i.key)
    for k in node_keys:
        dsu.find(k)
    for e in edges:
        dsu.union(e.a, e.b)
    groups: Dict[str, List[str]] = {}
    for k in list(dsu.p.keys()):
        groups.setdefault(dsu.find(k), []).append(k)
    clusters = [sorted(v) for v in groups.values() if len(v) > 1]
    clusters.sort(key=len, reverse=True)
    return edges, clusters


# ---------------------------------------------------------------- отчёт

def risk_level(score: int) -> str:
    if score >= 70:
        return "высокий"
    if score >= 40:
        return "средний"
    if score > 0:
        return "низкий"
    return "минимальный"


def recommendations(score: int) -> List[str]:
    recs = [
        "Смените пароли (e-mail, мессенджеры, банки) и включите 2FA везде.",
        "Отключите публичный профиль Gravatar для основного e-mail.",
        "Проверьте, не утекли ли прежние пароли — смените их повторно.",
        "Уберите телефон, адрес и дату рождения из открытых профилей.",
        "Telegram: включите «Скрыть номер телефона».",
        "VK: проверьте приватность и запретите индексацию в поиске.",
        "Заведите отдельный e-mail для регистраций.",
    ]
    if score >= 70:
        recs.insert(0, "Риск высокий: смените пароли немедленно и заведите "
                       "новый e-mail/номер для публичных сервисов.")
    return recs


def collect_identity(idents: List[Ident], profiles: List[Dict[str, Any]],
                     dossiers: Dict[str, Any], raw: Dict[str, Any],
                     extra_pages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Сводит ФИО / адреса / города / соцсети / утечки по всем идентификаторам."""
    ident_values = [i.value for i in idents if i.type != "name"]

    # данные из досье: ФИО, адреса, города, контакты
    names: Dict[str, Dict[str, Any]] = {}
    addrs: Dict[str, Dict[str, Any]] = {}
    cities: Dict[str, Dict[str, Any]] = {}
    leak_fields: Set[str] = set()
    leak_sources: List[str] = []
    leak_records = 0

    def put(bucket: Dict[str, Dict[str, Any]], value: str, source: str,
            conf: float, **extra):
        value = (value or "").strip()
        if not value:
            return
        k = value.lower()
        if k in bucket:
            e = bucket[k]
            e["confidence"] = max(e["confidence"], conf)
            if source not in e["sources"]:
                e["sources"].append(source)
            return
        bucket[k] = {"value": value, "confidence": conf, "sources": [source], **extra}

    for key, d in dossiers.items():
        if not isinstance(d, dict) or d.get("error"):
            continue
        ident = d.get("value") or key
        for n in (d.get("identity") or {}).get("full_name") or []:
            put(names, n, ident, 0.6, kind="ФИО")
        for n in (d.get("identity") or {}).get("first_name") or []:
            put(names, n, ident, 0.35, kind="имя")
        for a in (d.get("locations") or {}).get("address") or []:
            put(addrs, a, ident, 0.6, kind="адрес")
        for c in (d.get("locations") or {}).get("city") or []:
            put(cities, c, ident, 0.55)
        for reg in (d.get("locations") or {}).get("region") or []:
            put(cities, reg, ident, 0.4)
        br = d.get("breaches") or {}
        if br.get("count"):
            leak_records = max(leak_records, br.get("count") or 0)
            leak_fields.update(br.get("fields") or [])
            for s in (br.get("sources") or [])[:20]:
                nm = s.get("name") if isinstance(s, dict) else str(s)
                dt = s.get("date") if isinstance(s, dict) else ""
                leak_sources.append(f"{nm} ({dt})" if dt else str(nm))
        # web-доказательства: извлечённые значения
        for ev in (d.get("web_evidence") or []):
            ex = ev.get("extracted") or {}
            for n in ex.get("names") or []:
                put(names, n, ev.get("url") or ev.get("domain") or "веб", 0.45, kind="ФИО")
            for a in ex.get("addresses") or []:
                put(addrs, a, ev.get("url") or ev.get("domain") or "веб", 0.4, kind="адрес")
            for c in ex.get("cities") or []:
                put(cities, c, ev.get("url") or ev.get("domain") or "веб", 0.35)

    # из identify-профилей
    jobs: Dict[str, Dict[str, Any]] = {}
    for p in profiles:
        if p.get("name"):
            put(names, p["name"], p["platform"], 0.7, kind="ФИО")
        loc = (p.get("extra") or {}).get("location") or (p.get("extra") or {}).get("city")
        if loc:
            put(cities, loc, p["platform"], 0.6)
        work = (p.get("extra") or {}).get("work")
        if work:
            put(jobs, work, p["platform"], 0.5)

    # слой разбора: e-mail/телефон в выдаче поиска, соцссылки
    pages_for_resolve = [{"url": pg.get("url", ""), "text": pg.get("text", ""),
                           "title": pg.get("title", ""),
                           "source": pg.get("url", "")} for pg in extra_pages]

    # упоминания из поиска по каждому идентификатору — источник ФИО/адресов
    mentions_all: List[Dict[str, Any]] = []
    for key, r in raw.items():
        if isinstance(r, dict):
            for m in (r.get("mentions") or []):
                mm = dict(m)
                mm["_key"] = key
                mentions_all.append(mm)

    try:
        detail = build_identity_summary(
            identifiers=ident_values,
            profiles=profiles,
            pages=pages_for_resolve,
            email_analysis={"mentions": mentions_all},
            phone_analysis={"mentions": [],
                            "meta": (raw.get(next((k for k in raw if k.startswith("phone:")), ""), {})
                                     or {}).get("normalized", {})},
            leaks={},
        )
    except Exception:
        detail = {"full_names": [], "addresses": [], "cities": [],
                  "social_links": [], "leak_exposure": {}}

    for n in detail.get("full_names") or []:
        put(names, n["value"], ", ".join(n.get("sources") or ["веб"]),
            n.get("confidence", 0.4), kind="ФИО")
    for a in detail.get("addresses") or []:
        put(addrs, a["value"], ", ".join(a.get("sources") or ["веб"]),
            a.get("confidence", 0.4), kind="адрес")
    for c in detail.get("cities") or []:
        put(cities, c["value"], ", ".join(c.get("sources") or ["веб"]),
            c.get("confidence", 0.3))

    # соцсети
    all_links: List[str] = []
    for p in profiles:
        all_links += list(p.get("links") or [])
    for pg in extra_pages:
        all_links += list(pg.get("links") or [])
    socials = social_links(all_links)

    return {
        "full_names": sorted(names.values(), key=lambda x: -x["confidence"]),
        "addresses": sorted(addrs.values(), key=lambda x: -x["confidence"]),
        "cities": sorted(cities.values(), key=lambda x: -x["confidence"]),
        "jobs": sorted(jobs.values(), key=lambda x: -x["confidence"]),
        "social_links": socials,
        "leak_exposure": {
            "records": leak_records,
            "fields": sorted(leak_fields),
            "sources": leak_sources[:40],
        },
        "detail": detail,
    }


def build_report(idents: List[Ident], data: Dict[str, Any],
                 edges: List[Edge], clusters: List[List[str]],
                 identity: Dict[str, Any]) -> Dict[str, Any]:
    profiles = data["profiles"]
    risk = 0
    reasons: List[str] = []

    for key, d in (data.get("dossiers") or {}).items():
        if not isinstance(d, dict):
            continue
        br = d.get("breaches") or {}
        if br.get("count"):
            risk += 25
            reasons.append(f"{d.get('value')}: {br.get('count')} записей в утечках")
        if (d.get("personal") or {}).get("infected"):
            risk += 20
            reasons.append(f"{d.get('value')}: компьютер заражён инфостилером")
    for p in profiles:
        if p["platform"] == "Gravatar":
            risk += 12
            reasons.append("публичный профиль Gravatar по e-mail")
        if p.get("name"):
            risk += 6
            reasons.append("имя публикуется в профилях")
    if identity["addresses"]:
        risk += 12
        reasons.append("адреса видны в открытых источниках")
    if len(profiles) >= 5:
        risk += 10
        reasons.append(f"много связанных профилей ({len(profiles)})")
    if identity["leak_exposure"]["records"]:
        risk += 10
        reasons.append("идентификаторы засветились в утечках")
    risk = min(100, risk)

    return {
        "generated_at": now_iso(),
        "tool": "Gotham OSINT — мультикоррелятор (correlator.py)",
        "notice": DISCLAIMER,
        "identifiers": [dict(type=i.type, value=i.value, source=i.source,
                             key=i.key, meta=i.meta) for i in idents],
        "profiles": profiles,
        "identity": identity,
        "correlation": {
            "edges": [dict(a=e.a, b=e.b, confidence=e.confidence, reasons=e.reasons)
                      for e in edges],
            "clusters": clusters,
        },
        "username_scans": {k: {"found_count": v.get("found_count", 0),
                               "total_checked": v.get("total_checked", 0),
                               "found": v.get("found", [])}
                           for k, v in (data.get("scans") or {}).items()},
        "risk": {"score": risk, "level": risk_level(risk), "reasons": reasons},
        "recommendations": recommendations(risk),
    }


# ---------------------------------------------------------------- HTML-граф

def render_graph_html(rep: Dict[str, Any]) -> str:
    import math

    nodes: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def push(key: str, label: str, kind: str):
        if key in seen:
            return
        seen.add(key)
        nodes.append({"id": key, "label": label, "kind": kind})

    for i in rep["identifiers"]:
        push(i["key"], i["value"], i["type"])
    for p in rep["profiles"]:
        push(f"{p['platform']}:{p.get('ident_value') or p.get('url')}",
             f"{p['platform']}\n{p.get('name') or p.get('ident_value') or ''}",
             "profile")

    clusters = rep["correlation"]["clusters"] or [[n["id"] for n in nodes]]
    placed: Set[str] = set()
    for ci, cl in enumerate(clusters):
        members = [n for n in nodes if n["id"] in cl and n["id"] not in placed]
        if not members:
            continue
        cx = 220 + (ci % 3) * 460
        cy = 170 + (ci // 3) * 380
        for k, n in enumerate(members):
            ang = 2 * math.pi * k / max(1, len(members))
            r = 165 if k else 0
            n["x"] = cx + r * math.cos(ang)
            n["y"] = cy + r * math.sin(ang)
            placed.add(n["id"])
    for n in nodes:
        if "x" not in n:
            n["x"], n["y"] = 1500, 760

    svg = ['<svg viewBox="0 0 1700 900" width="100%" height="900" '
           'xmlns="http://www.w3.org/2000/svg">']
    for e in rep["correlation"]["edges"]:
        a = next((n for n in nodes if n["id"] == e["a"]), None)
        b = next((n for n in nodes if n["id"] == e["b"]), None)
        if not a or not b:
            continue
        w = 1 + e["confidence"] * 4
        op = 0.2 + e["confidence"] * 0.6
        svg.append(f'<line x1="{a["x"]:.0f}" y1="{a["y"]:.0f}" x2="{b["x"]:.0f}" '
                   f'y2="{b["y"]:.0f}" stroke="#7f8c8d" stroke-width="{w:.1f}" '
                   f'opacity="{op:.2f}"/>')
        mx, my = (a["x"] + b["x"]) / 2, (a["y"] + b["y"]) / 2
        svg.append(f'<text x="{mx:.0f}" y="{my:.0f}" font-size="10" fill="#9aa5b1" '
                   f'text-anchor="middle">{e["confidence"]:.2f}</text>')
    for n in nodes:
        col = PALETTE.get(n["kind"], "#55606e")
        lines = str(n["label"]).split("\n")[:3]
        h = 22 + 13 * len(lines)
        svg.append(f'<g><rect x="{n["x"]-95:.0f}" y="{n["y"]-h/2:.0f}" width="190" '
                   f'height="{h}" rx="8" fill="#111927" stroke="{col}" stroke-width="1.5"/>')
        for li, ln in enumerate(lines):
            svg.append(f'<text x="{n["x"]:.0f}" y="{n["y"]-h/2+16+li*13:.0f}" '
                       f'font-size="11" fill="#e8edf7" text-anchor="middle" '
                       f'font-family="Inter,Arial">{ln[:26]}</text>')
        svg.append('</g>')
    svg.append("</svg>")

    legend = " ".join(f'<span class="lg"><i style="background:{c}"></i>{k}</span>'
                      for k, c in PALETTE.items())
    edges_rows = "".join(
        f"<tr><td>{e['a'][:26]}</td><td>&rarr;</td><td>{e['b'][:26]}</td>"
        f"<td>{e['confidence']:.2f}</td><td>{'; '.join(e['reasons'])[:70]}</td></tr>"
        for e in rep["correlation"]["edges"])
    recs = "".join(f"<li>{x}</li>" for x in rep["recommendations"])
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<title>Граф связей — Gotham OSINT</title>
<style>
 body{{margin:0;background:#05070b;color:#e8edf7;font-family:Inter,Segoe UI,Arial,sans-serif}}
 header{{padding:14px 22px;border-bottom:1px solid #1e2a3f;display:flex;gap:22px;
        align-items:center;flex-wrap:wrap}}
 h1{{font-size:16px;margin:0;letter-spacing:.6px;text-transform:uppercase}}
 .lg{{font-size:12px;color:#8494ad;display:inline-flex;align-items:center;gap:6px;margin-right:12px}}
 .lg i{{width:11px;height:11px;border-radius:3px;display:inline-block}}
 .risk{{font-size:12px;padding:4px 12px;border-radius:20px;background:#0d131f;
       border:1px solid #2a3a56;color:#f5c542}}
 .wrap{{display:grid;grid-template-columns:1fr 380px}}
 svg{{display:block}}
 aside{{padding:16px 18px;border-left:1px solid #1e2a3f;max-height:900px;overflow:auto}}
 h2{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#5a6a83;margin:16px 0 8px}}
 table{{width:100%;border-collapse:collapse;font-size:11px}}
 td{{padding:4px 6px;border-bottom:1px solid #111927;vertical-align:top}}
 ul{{font-size:11px;line-height:1.6;color:#b9c2cc;padding-left:16px}}
</style></head><body>
<header><h1>Граф связей · Gotham OSINT</h1>
<span class="risk">Экспозиция: {rep['risk']['score']}/100 — {rep['risk']['level']}</span>
<div>{legend}</div></header>
<div class="wrap"><div>{''.join(svg)}</div><aside>
<h2>Связи ({len(rep['correlation']['edges'])})</h2>
<table>{edges_rows}</table>
<h2>Рекомендации</h2><ul>{recs}</ul></aside></div></body></html>"""


def render_markdown(rep: Dict[str, Any]) -> str:
    L: List[str] = []
    L.append("# Мультикоррелятор — отчёт\n")
    L.append(f"_Сформировано: {rep['generated_at']}_\n")
    L.append(f"> {rep['notice']}\n")
    r = rep["risk"]
    L.append(f"## Оценка экспозиции: {r['score']}/100 ({r['level']})\n")
    for x in r["reasons"] or ["явных признаков утечки не обнаружено"]:
        L.append(f"- {x}")

    L.append("\n## Идентификаторы\n")
    for i in rep["identifiers"]:
        L.append(f"- **{i['type']}**: `{i['value']}` ({i['source']})")

    ident = rep["identity"]
    L.append("\n## ЛИЧНОСТЬ\n")
    L.append("### ФИО\n")
    if ident["full_names"]:
        L.append("| Значение | Уверенность | Источники |")
        L.append("|---|---|---|")
        for n in ident["full_names"][:30]:
            L.append(f"| {n['value']} | {n['confidence']:.2f} | "
                     f"{', '.join(n['sources'])} |")
    else:
        L.append("_Не найдено._")

    L.append("\n### Адреса\n")
    if ident["addresses"]:
        L.append("| Значение | Уверенность | Источники |")
        L.append("|---|---|---|")
        for a in ident["addresses"][:30]:
            L.append(f"| {a['value']} | {a['confidence']:.2f} | "
                     f"{', '.join(a['sources'])} |")
    else:
        L.append("_Не найдено._")

    if ident["cities"]:
        L.append("\n**Города/регионы:** " + ", ".join(
            f"{c['value']} ({c['confidence']:.2f})" for c in ident["cities"][:15]))
    if ident.get("jobs"):
        L.append("\n**Места работы:** " + ", ".join(
            f"{j['value']} ({j['confidence']:.2f})" for j in ident["jobs"][:10]))

    L.append("\n### Ссылки на соцсети\n")
    if ident["social_links"]:
        L.append("| Площадка | Ссылка |")
        L.append("|---|---|")
        for s in ident["social_links"][:50]:
            L.append(f"| {s['platform']} | {s['url']} |")
    else:
        L.append("_Не найдено._")

    lex = ident["leak_exposure"]
    if lex.get("records") or lex.get("fields"):
        L.append("\n### Экспозиция в утечках\n")
        L.append(f"- Записей: {lex.get('records')}")
        L.append(f"- Поля: {', '.join(lex.get('fields') or []) or '—'}")
        for s in (lex.get("sources") or [])[:15]:
            L.append(f"  - {s}")

    L.append("\n## Профили\n")
    if rep["profiles"]:
        L.append("| Площадка | Имя | Ссылка |")
        L.append("|---|---|---|")
        for p in rep["profiles"][:60]:
            L.append(f"| {p['platform']} | {p.get('name') or '—'} | {p.get('url') or ''} |")
    else:
        L.append("_Не найдены._")

    L.append("\n## Граф связей\n")
    if rep["correlation"]["edges"]:
        L.append("| A | B | Уверенность | Основание |")
        L.append("|---|---|---|---|")
        for e in rep["correlation"]["edges"]:
            L.append(f"| {e['a']} | {e['b']} | {e['confidence']:.2f} | "
                     f"{'; '.join(e['reasons'])} |")
    else:
        L.append("_Связей не найдено._")
    if rep["correlation"]["clusters"]:
        L.append("\n### Кластеры (вероятно один человек)\n")
        for c in rep["correlation"]["clusters"]:
            L.append(f"- {len(c)} узлов: " + ", ".join(c))

    L.append("\n## Рекомендации\n")
    for x in rep["recommendations"]:
        L.append(f"1. {x}")
    return "\n".join(L)


# ---------------------------------------------------------------- движок

def correlate_all(phone: Optional[List[str]] = None,
                  email: Optional[List[str]] = None,
                  telegram: Optional[List[str]] = None,
                  vk: Optional[List[str]] = None,
                  username: Optional[List[str]] = None,
                  name: Optional[List[str]] = None,
                  deep: bool = False,
                  pages: int = 15,
                  log: Optional[Any] = None) -> Dict[str, Any]:
    say = log or (lambda *a, **k: None)
    idents = build_idents(phone or [], email or [], telegram or [], vk or [],
                          username or [], name or [])
    if not idents:
        return {"error": "не передано ни одного идентификатора"}
    say(f"Идентификаторов: {len(idents)}")

    data = collect(idents, deep=deep, pages=pages, log=log)
    edges, clusters = correlate(idents, data["profiles"], data["dossiers"],
                                data["extra_pages"], data["raw"])
    identity = collect_identity(idents, data["profiles"], data["dossiers"],
                                 data["raw"], data["extra_pages"])
    rep = build_report(idents, data, edges, clusters, identity)

    # ---------- накопительная база знаний ----------
    try:
        from knowledge import KnowledgeBase
        kb = KnowledgeBase()
        rep["knowledge"] = kb.ingest(rep)
        rep["knowledge"]["stats"] = kb.stats()

        # ранее подтверждённые связи получают вес из базы
        known = kb.known_links()
        prof_keys = {f"{p.get('platform')}:{p.get('ident_value') or p.get('url')}"
                     for p in rep.get("profiles") or []}

        def kb_key(endpoint: str) -> str:
            if endpoint in prof_keys:
                return "profile:" + endpoint.lower()
            return endpoint.lower()

        for e in rep["correlation"]["edges"]:
            k = "|".join(sorted([kb_key(e["a"]), kb_key(e["b"])]))
            info = known.get(k)
            if info and info.get("sightings", 0) > 1:
                e["kb_confirmed"] = True
                e["kb_sightings"] = info["sightings"]
                e["confidence"] = round(min(1.0, e["confidence"] + 0.05), 2)
            else:
                e["kb_confirmed"] = False

        rep["knowledge"]["note"] = (
            "Результаты складываются в osint_kb.sqlite: с каждым запуском "
            "связи и атрибуты накапливаются, повторные подтверждения "
            "повышают уверенность.")
        kb.close()
    except Exception as e:
        rep["knowledge"] = {"error": f"{type(e).__name__}: {e}"}

    return rep


# ---------------------------------------------------------------- CLI

def main():
    import argparse

    ap = argparse.ArgumentParser(
        description="Мультикоррелятор: несколько идентификаторов -> одно досье + граф.")
    ap.add_argument("--phone", action="append", default=[])
    ap.add_argument("--email", action="append", default=[])
    ap.add_argument("--telegram", action="append", default=[])
    ap.add_argument("--vk", action="append", default=[])
    ap.add_argument("--username", action="append", default=[])
    ap.add_argument("--name", action="append", default=[])
    ap.add_argument("--deep", action="store_true", help="скан username по 500+ сайтам")
    ap.add_argument("--pages", type=int, default=15)
    ap.add_argument("--output", default="correlation_report.json")
    ap.add_argument("--md", default="correlation_report.md")
    ap.add_argument("--graph", default="correlation_graph.html")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    if not any([args.phone, args.email, args.telegram, args.vk, args.username, args.name]):
        ap.print_help()
        return

    console.print(Panel(DISCLAIMER, title="Назначение", border_style="yellow"))
    if not args.yes:
        ans = console.input("Продолжить? [y/N]: ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
            console.print("Отменено.")
            return

    rep = correlate_all(phone=args.phone, email=args.email, telegram=args.telegram,
                        vk=args.vk, username=args.username, name=args.name,
                        deep=args.deep, pages=args.pages,
                        log=lambda m: console.print(f"[cyan]→[/cyan] {m}"))

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    with open(args.md, "w", encoding="utf-8") as f:
        f.write(render_markdown(rep))
    with open(args.graph, "w", encoding="utf-8") as f:
        f.write(render_graph_html(rep))

    console.print(Panel(
        f"Экспозиция: [bold]{rep['risk']['score']}/100[/bold] ({rep['risk']['level']})\n"
        f"Профилей: {len(rep['profiles'])} · Связей: {len(rep['correlation']['edges'])} · "
        f"Кластеров: {len(rep['correlation']['clusters'])}\n"
        f"Отчёты: {args.output}, {args.md}, {args.graph}",
        title="Готово", border_style="cyan"))

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
