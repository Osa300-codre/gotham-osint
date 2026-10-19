#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Веб-поиск упоминаний.
Приоритет источников:
  1) Serper.dev (Google) — если задан ключ (стабильно, без блокировок)
  2) DuckDuckGo HTML — бесплатный запасной вариант (с ретраями и ротацией UA)
"""

import random
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]


def _headers() -> Dict[str, str]:
    h = dict(BASE_HEADERS)
    h["User-Agent"] = random.choice(USER_AGENTS)
    return h


def _clean_url(url: str) -> str:
    if "duckduckgo.com/l/" in url:
        qs = parse_qs(urlparse(url).query)
        if "uddg" in qs:
            return unquote(qs["uddg"][0])
    return url


def _snippet(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:400]


def _serper(query: str, limit: int) -> Optional[Dict[str, Any]]:
    """Поиск через Serper.dev (Google)."""
    try:
        from premium import serper_search
    except Exception:
        return None
    try:
        r = serper_search(query, limit)
    except Exception:
        return None
    if not r.get("active") or not r.get("results"):
        return None
    return {
        "query": query,
        "engine": "Google (Serper.dev)",
        "count": len(r["results"]),
        "results": [{
            "title": x.get("title"),
            "url": x.get("url"),
            "snippet": x.get("snippet") or "",
            "domain": (urlparse(x["url"]).netloc if x.get("url") else ""),
            "date": x.get("date"),
        } for x in r["results"]],
        "error": None,
    }


def _ddg(query: str, limit: int, retries: int = 3) -> Dict[str, Any]:
    """Поиск через DuckDuckGo HTML с ретраями."""
    out: Dict[str, Any] = {"query": query, "engine": "DuckDuckGo", "count": 0,
                           "results": [], "error": None}
    for attempt in range(retries):
        try:
            r = requests.post("https://html.duckduckgo.com/html/", data={"q": query},
                              headers=_headers(), timeout=25)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
            time.sleep(1.5 * (attempt + 1))
            continue

        if r.status_code == 200 and "result__a" in r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            seen = set()
            for block in soup.select("div.result, div.web-result"):
                a = block.select_one("a.result__a")
                sn = block.select_one(".result__snippet")
                if not a:
                    continue
                url = _clean_url(a.get("href", ""))
                if not url or url in seen:
                    continue
                seen.add(url)
                out["results"].append({
                    "title": a.get_text(" ", strip=True),
                    "url": url,
                    "snippet": _snippet(sn.get_text(" ", strip=True)) if sn else "",
                    "domain": urlparse(url).netloc,
                })
                if len(out["results"]) >= limit:
                    break
            out["count"] = len(out["results"])
            if out["count"]:
                return out

        # 202 = анти-бот челлендж — ждём и пробуем снова
        out["error"] = f"DuckDuckGo: HTTP {r.status_code}"
        time.sleep(2.5 + attempt * 2)
    return out


def web_search(query: str, limit: int = 25, site_filter: Optional[str] = None) -> Dict[str, Any]:
    """Ищет в интернете страницы, где встречается query."""
    q = f'"{query}"'
    if site_filter:
        q = f'"{query}" site:{site_filter}'

    res = _serper(q, limit)
    if res:
        return res
    return _ddg(q, limit)


def mentions_by_site(query: str, limit: int = 40) -> Dict[str, Any]:
    """Ищет упоминания запроса и группирует по домену."""
    res = web_search(query, limit=limit)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for r in res.get("results", []):
        grouped.setdefault(r["domain"], []).append(r)
    res["grouped"] = grouped
    res["domains"] = sorted(grouped.keys())
    return res
