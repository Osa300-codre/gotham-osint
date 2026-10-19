#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Веб-поиск через DuckDuckGo HTML: находит упоминания email/имени/телефона в интернете."""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
}

# Известные трекеры, которые редиректят — очищаем URL
TRACKERS = ("duckduckgo.com/l/?uddg=", "duckduckgo.com/y.js?", "ad_doubleclick.net",
            "google.com/url?", "yandex.ru/clck/")


def _clean_url(url: str) -> str:
    if "duckduckgo.com/l/" in url:
        qs = parse_qs(urlparse(url).query)
        if "uddg" in qs:
            return unquote(qs["uddg"][0])
    for t in TRACKERS:
        if t in url and "uddg" not in url:
            return url
    return url


def _snippet(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:400]


def web_search(query: str, limit: int = 25, site_filter: Optional[str] = None) -> Dict[str, Any]:
    """Ищет в интернете страницы, где встречается query."""
    q = query
    if site_filter:
        q = f'"{query}" site:{site_filter}'
    else:
        q = f'"{query}"'

    out: Dict[str, Any] = {"query": query, "results": [], "error": None}
    try:
        r = requests.post("https://html.duckduckgo.com/html/", data={"q": q},
                          headers=HEADERS, timeout=25)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    if r.status_code != 200:
        out["error"] = f"HTTP {r.status_code}"
        return out

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

    if not out["results"]:
        for a in soup.select("a.result__a"):
            url = _clean_url(a.get("href", ""))
            if not url or url in seen:
                continue
            seen.add(url)
            out["results"].append({
                "title": a.get_text(" ", strip=True),
                "url": url,
                "snippet": "",
                "domain": urlparse(url).netloc,
            })
            if len(out["results"]) >= limit:
                break

    out["count"] = len(out["results"])
    return out


def mentions_by_site(query: str, limit: int = 40) -> Dict[str, Any]:
    """Ищет упоминания запроса и группирует по домену."""
    res = web_search(query, limit=limit)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for r in res.get("results", []):
        grouped.setdefault(r["domain"], []).append(r)
    res["grouped"] = grouped
    res["domains"] = sorted(grouped.keys())
    return res
