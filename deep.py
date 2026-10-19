#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Глубокое исследование: рекурсивный обход графа связей.

Логика:
  seed (любой идентификатор)
    -> находим профиль/данные
    -> извлекаем из них новые идентификаторы (ники, email, телефон, ФИО,
       ссылки, фото, город, домен)
    -> каждый новый идентификатор — новая ветка
    -> повторяем до max_depth

На выходе: граф (узлы + рёбра), слои поиска и сводка по найденному.
Все данные — публичные.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from identify import (search_telegram, search_email_detailed, search_vk,
                       search_phone_deep)
from personal import extract_personal, personal_dorks, phone_variants

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"}

# --- идентификаторы в тексте ---
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+7|8|7)[\s\-\(]?\d{3}[\s\-\)]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")
HANDLE_RE = re.compile(r"(?:@|https?://(?:www\.)?(?:t\.me|telegram\.me|github\.com|gitlab\.com|"
                       r"vk\.com|vk\.ru|instagram\.com|twitter\.com|x\.com|youtube\.com|"
                       r"ok\.ru|pikabu\.ru|habr\.com|medium\.com|dev\.to)/)"
                       r"([A-Za-z0-9_.\-]{3,40})")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9\-]+\.)+(?:com|net|org|ru|io|me|info|biz|dev|app|xyz|"
                       r"site|online|shop|club|pro|store|blog|edu|gov|co|uk|de|fr|ua|kz|by))\b",
                       re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]{6,120}")
TG_RE = re.compile(r"(?:https?://)?t\.me/(?!\+)([A-Za-z0-9_]{4,40})")
PHOTO_RE = re.compile(r"https?://[^\s\"'<>\\)]{5,200}\.(?:jpg|jpeg|png|webp|gif)", re.I)

STOP_HANDLES = {"login", "logout", "signin", "signup", "register", "search", "about",
                "privacy", "terms", "help", "support", "share", "share.php", "index",
                "home", "profile", "settings", "feed", "hashtag", "post", "posts",
                "watch", "video", "videos", "photo", "photos", "status", "explore",
                "catalog", "news", "blog", "docs", "wiki", "api", "app", "www",
                "telegram", "twitter", "facebook", "instagram", "youtube", "tiktok",
                "reddit", "medium", "behance", "dribbble", "pinterest", "spotify",
                # css/html-мусор
                "context", "font-face", "keyframes", "media", "type", "display",
                "background", "border", "margin", "padding", "color", "width",
                "height", "position", "content", "template", "variable", "value",
                "function", "return", "import", "export", "default", "public",
                "class", "false", "true", "null", "undefined", "object", "string",
                "number", "boolean", "const", "let", "var", "async", "await",
                "this", "self", "window", "document", "console", "error", "warning"}

# Технические домены — контакты человека сюда не попадают
TECH_DOMAINS = {"sentry.io", "sentry-cdn.com", "w3.org", "example.com", "example.org",
                 "localhost", "schema.org", "gstatic.com", "googleapis.com",
                 "cloudflare.com", "jquery.com", "bootstrapcdn.com", "yandex.net",
                 "mail.ru", "localhost.localdomain", "no-reply", "noreply",
                 "sentry.wixpress.com", "facebook.net", "doubleclick.net",
                 "googletagmanager.com", "google-analytics.com", "yastatic.net",
                 "fonts.googleapis.com", "cdn.jsdelivr.net", "unpkg.com"}

# Мусорные URL (ресурсы страницы, а не профили)
BAD_URL_RE = re.compile(
    r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|map)(\?|$)|"
    r"/(s3|static|assets?|bundles?|favicon|img|images?|fonts?)/|"
    r"w3\.org|schema\.org|googleapis|gstatic|doubleclick|googletagmanager",
    re.I)


NOT_NAMES = {
    "сша", "россия", "европа", "америка", "мир", "мирa", "город", "область",
    "край", "район", "улица", "дом", "квартира", "индекс", "телефон", "почта",
    "выбор", "поиск", "результат", "страница", "профиль", "вход", "выход",
    "регистрация", "назад", "далее", "главная", "новости", "статьи", "форум",
    "услуги", "объявления", "работа", "вакансии", "резюме", "каталог",
    "паспорт", "долг", "счет", "счёт", "карта", "банк", "заказ", "доставка",
}


def _looks_like_name(value: str) -> bool:
    """Отсеивает мусор: «США», «Штаты Висконсин», «Павел Дуров (фальшивый)»."""
    v = (value or "").strip()
    if not v or len(v) > 34:
        return False
    low = v.lower()
    if low in NOT_NAMES:
        return False
    if any(low.startswith(n) for n in NOT_NAMES):
        return False
    if "(" in v or ")" in v or "«" in v or "»" in v:
        return False
    parts = v.split()
    if not (2 <= len(parts) <= 3):
        return False
    for p in parts:
        core = p.rstrip(".")
        if len(core) < 2 or len(core) > 16:
            return False
        if not all(ch.isalpha() for ch in core):
            return False
        if not core[0].isupper():
            return False
    return True


class DeepResearch:
    """Рекурсивное OSINT-исследование с построением графа связей."""

    def __init__(self, seed: str, kind: str = "auto", max_depth: int = 2,
                 max_nodes: int = 80, scan_categories: Optional[List[str]] = None,
                 fetch_pages: int = 18):
        self.seed = seed.strip()
        self.kind = kind
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.fetch_pages = fetch_pages
        self.scan_categories = scan_categories or [
            "social", "messenger", "dev", "code", "professional", "workplace",
            "creative", "media", "files", "market", "work", "education",
            "professional", "startup", "business", "registry",
        ]
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, str]] = []
        self.layers: List[Dict[str, Any]] = []
        self._seen: Set[str] = set()
        self._edge_seen: Set[Tuple[str, str]] = set()

    # ---------- граф ----------
    def _node_id(self, kind: str, value: str) -> str:
        return f"{kind}:{value.lower()}"

    def add_node(self, kind: str, value: str, source: str,
                 extra: Optional[Dict[str, Any]] = None) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        nid = self._node_id(kind, value)
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid, "kind": kind, "value": value,
                "sources": [source] if source else [],
                "meta": extra or {},
            }
        else:
            if source and source not in self.nodes[nid]["sources"]:
                self.nodes[nid]["sources"].append(source)
            if extra:
                self.nodes[nid]["meta"].update({k: v for k, v in extra.items()
                                                if v and k not in self.nodes[nid]["meta"]})
        return nid

    def add_edge(self, src: str, dst: str, relation: str) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        self.edges.append({"from": src, "to": dst, "relation": relation})

    # ---------- извлечение идентификаторов ----------
    def extract_ids(self, text: str) -> Dict[str, List[str]]:
        text = text or ""
        emails = set()
        for m in EMAIL_RE.findall(text):
            low = m.lower()
            dom = low.split("@")[-1]
            if dom in TECH_DOMAINS or any(d in dom for d in ("sentry", "no-reply",
                                                             "noreply", "w3.org")):
                continue
            if len(low.split("@")[0]) > 30:      # хеш-подобные идентификаторы
                continue
            emails.add(low)
        phones = set()
        for m in PHONE_RE.findall(text):
            d = re.sub(r"\D", "", m)
            if len(d) == 11 and d.startswith("8"):
                d = "7" + d[1:]
            if len(d) == 10:
                d = "7" + d
            if len(d) == 11:
                phones.add("+" + d)
        handles = set()
        for m in HANDLE_RE.findall(text):
            h = m.strip(".").lower()
            if not h or h in STOP_HANDLES or len(h) < 4:
                continue
            if "." in h and not re.fullmatch(r"[a-z0-9_]+", h):
                continue          # это домен, а не ник
            handles.add(h)
        for m in TG_RE.findall(text):
            h = m.lower()
            if h and h not in STOP_HANDLES and len(h) >= 4 and "." not in h:
                handles.add(h)
        domains = {m.lower() for m in DOMAIN_RE.findall(text)
                   if m.lower() not in TECH_DOMAINS
                   and not any(d in m.lower() for d in ("sentry", "no-reply", "w3.org"))}
        urls = {m.rstrip(".,);") for m in URL_RE.findall(text)
                if not BAD_URL_RE.search(m)
                and not re.search(r"https?://(www\.)?(api|dw|images?|static|css|cdn|mail|ftp|"
                                  r"ns\d|www\d)\.", m, re.I)}
        photos = {m for m in PHOTO_RE.findall(text)}
        fio = extract_personal(text)
        names = [n for n in fio.get("names", []) if _looks_like_name(n)]
        return {
            "email": sorted(emails)[:15],
            "phone": sorted(phones)[:10],
            "username": sorted(handles)[:25],
            "domain": sorted(domains)[:12],
            "url": sorted(urls)[:20],
            "photo": sorted(photos)[:8],
            "name": names[:6],
            "address": fio.get("addresses", [])[:6],
            "city": fio.get("cities", [])[:6],
            "birth_date": fio.get("birth_dates", [])[:4],
        }

    # ---------- сбор страницы ----------
    def fetch_page(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            r = requests.get(url, headers=HEADERS, timeout=12, allow_redirects=True)
            if r.status_code != 200 or not r.text:
                return None
            html = r.text
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
            if m:
                title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1))).strip()[:160]
            desc = ""
            for prop in ("og:description", "description", "og:title"):
                mm = re.search(rf'<meta[^>]+(?:property|name)="{prop}"[^>]*content="([^"]*)"',
                               html, re.I)
                if mm:
                    desc = re.sub(r"\s+", " ", mm.group(1)).strip()[:300]
                    break
            return {"url": url, "title": title, "desc": desc, "text": html[:120000]}
        except Exception:
            return None

    # ---------- ядро ----------
    async def run(self) -> Dict[str, Any]:
        seed_kind = self.kind
        if seed_kind == "auto":
            seed_kind = self._detect_kind(self.seed)
        self.kind = seed_kind

        start = self.add_node(seed_kind, self.seed, "ввод")
        frontier: List[Tuple[str, str, int]] = [(self.seed, seed_kind, 0)]

        while frontier:
            value, kind, depth = frontier.pop(0)
            if depth > self.max_depth or len(self.nodes) >= self.max_nodes:
                continue
            key = (kind, value.lower())
            if key in self._seen:
                continue
            self._seen.add(key)

            found = await self._investigate(value, kind, depth)
            layer = {
                "depth": depth, "query": value, "kind": kind,
                "new_nodes": len(found.get("new_ids", [])),
                "sources": found.get("sources", []),
                "details": found.get("details", {}),
            }
            self.layers.append(layer)

            for nk, nv, rel in found.get("new_ids", []):
                nid = self.add_node(nk, nv, f"{kind}:{value}")
                self.add_edge(start if depth == 0 else self._node_id(kind, value),
                              nid, rel)
                if len(self.nodes) < self.max_nodes:
                    frontier.append((nv, nk, depth + 1))

        return self._report()

    def _detect_kind(self, v: str) -> str:
        if "@" in v and "." in v.split("@")[-1]:
            return "email"
        if re.match(r"^(https?://)?(www\.)?(m\.)?(vk\.com|vk\.ru)/", v, re.I):
            return "vk"
        if re.match(r"^(https?://)?(www\.)?t\.me/", v, re.I) or v.startswith("@"):
            return "telegram"
        if re.fullmatch(r"[+\-\s()\d]{7,25}", v) and len(re.sub(r"\D", "", v)) >= 7:
            return "phone"
        return "username"

    async def _investigate(self, value: str, kind: str, depth: int) -> Dict[str, Any]:
        """Ищет данные по идентификатору и возвращает новые идентификаторы."""
        new_ids: List[Tuple[str, str, str]] = []
        sources: List[str] = []
        details: Dict[str, Any] = {}

        def add(kind_new: str, vals: List[str], rel: str):
            for x in vals:
                if not x:
                    continue
                if kind_new == "username" and x.lower() in STOP_HANDLES:
                    continue
                if kind_new == "url":
                    # узел-ссылка оставляем только если в ней есть сам идентификатор
                    core = value.lower().lstrip("@")
                    if core and core not in x.lower():
                        continue
                new_ids.append((kind_new, x, rel))

        if kind == "telegram":
            try:
                tg = search_telegram(value)
                sources.append("Telegram")
                p = tg.get("profile", {})
                details["telegram"] = p
                if p.get("name"):
                    add("name", [p["name"]], "имя в Telegram")
                if p.get("bio"):
                    ids = self.extract_ids(p["bio"])
                    add("email", ids["email"], "в bio Telegram")
                    add("phone", ids["phone"], "в bio Telegram")
                    add("username", ids["username"], "ссылка в bio")
                    add("url", ids["url"], "ссылка в bio")
                    add("domain", ids["domain"], "домен в bio")
                if p.get("avatar"):
                    details["avatar"] = p["avatar"]
                    add("photo", [p["avatar"]], "аватар Telegram")
                lk = tg.get("leaks") or {}
                if lk.get("found"):
                    details["breaches"] = lk.get("found")
                    sources.append("утечки")
            except Exception:
                pass

        elif kind == "email":
            try:
                em = search_email_detailed(value)
                sources.append("email-источники")
                g = em.get("gravatar", {}) or {}
                details["gravatar"] = g
                if g.get("name"):
                    add("name", [g["name"]], "Gravatar")
                for acc in (g.get("accounts") or []):
                    if acc.get("name"):
                        add("username", [acc["name"]], "связь в Gravatar")
                lk = em.get("leaks", {}) or {}
                if lk.get("found"):
                    details["breaches"] = lk.get("found")
                    sources.append("утечки")
            except Exception:
                pass

        elif kind == "phone":
            try:
                ph = search_phone_deep(value)
                sources.append("телефонные источники")
                details["phone"] = ph.get("normalized")
                op = ph.get("operator") or {}
                if op.get("carrier"):
                    details["operator"] = op.get("carrier")
                lk = ph.get("leaks", {}) or {}
                if lk.get("found"):
                    details["breaches"] = lk.get("found")
            except Exception:
                pass

        elif kind == "vk":
            try:
                vk = search_vk(value)
                sources.append("ВКонтакте")
                p = vk.get("profile", {}) or {}
                details["vk"] = p
                if p.get("name"):
                    add("name", [p["name"]], "имя в ВК")
                if p.get("city"):
                    add("city", [p["city"]], "город в ВК")
                if p.get("status"):
                    ids = self.extract_ids(p["status"])
                    add("email", ids["email"], "в статусе ВК")
                    add("phone", ids["phone"], "в статусе ВК")
                    add("username", ids["username"], "ссылка в статусе ВК")
            except Exception:
                pass

        # --- сканер соцсетей по username ---
        if kind in ("username", "telegram", "name"):
            try:
                from scanner import scan as _scan
                cands = [value] if kind == "username" else []
                if kind == "telegram":
                    cands = [value.lstrip("@")]
                for un in cands[:2]:
                    sc = await _scan(un, self.scan_categories)
                    if sc.get("found_count"):
                        details.setdefault("profiles", []).extend(
                            [{"site": f["site"], "url": f["url"]} for f in sc["found"]])
                        sources.append("сканер 800+ сайтов")
                        # тянем контакты с найденных страниц
                        for page in await self._collect_contacts(sc["found"]):
                            ids = self.extract_ids(page.get("text", "") + " " +
                                                 page.get("desc", "") + " " +
                                                 page.get("title", ""))
                            add("email", ids["email"], f"в профиле {page['site']}")
                            add("phone", ids["phone"], f"в профиле {page['site']}")
                            add("username", ids["username"], f"в профиле {page['site']}")
                            add("name", ids["name"], f"в профиле {page['site']}")
                            add("url", ids["url"], f"в профиле {page['site']}")
            except Exception:
                pass

        # --- веб-поиск (dorks) ---
        if kind in ("username", "phone", "email", "name", "telegram"):
            try:
                dkind = "phone" if kind == "phone" else "email"
                dk = personal_dorks(value if dkind == "email" else value, dkind)
                details["web_hits"] = len(dk.get("results", []))
                sources.append("веб-поиск")
                for r in dk.get("results", [])[:12]:
                    ids = self.extract_ids((r.get("title") or "") + " " +
                                           (r.get("snippet") or ""))
                    add("email", ids["email"], "в найденной странице")
                    add("phone", ids["phone"], "в найденной странице")
                    add("username", ids["username"], "в найденной странице")
                    add("name", ids["name"], "в найденной странице")
            except Exception:
                pass

        return {"new_ids": new_ids, "sources": sources, "details": details}

    async def _collect_contacts(self, found: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Загружает найденные профили и вытаскивает из них контакты."""
        out = []
        sem = asyncio.Semaphore(8)

        async def one(item):
            async with sem:
                page = await asyncio.to_thread(self.fetch_page, item["url"])
                if page:
                    page["site"] = item.get("site", "")
                    return page
                return None

        for res in await asyncio.gather(*[one(i) for i in found[:self.fetch_pages]]):
            if res:
                out.append(res)
        return out

    def _report(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for n in self.nodes.values():
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
        return {
            "seed": {"value": self.seed, "kind": self.kind},
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "by_kind": by_kind,
                "depth_reached": max((l["depth"] for l in self.layers), default=0),
            },
            "layers": self.layers,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }


async def deep_research(seed: str, kind: str = "auto", max_depth: int = 2,
                        max_nodes: int = 80) -> Dict[str, Any]:
    return await DeepResearch(seed, kind, max_depth, max_nodes).run()
