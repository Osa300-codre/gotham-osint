#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Интерактивная карта нитей OSINT: центральный узел -> расходящиеся ветви
к категориям источников. Визуализация в стиле «OSINT Catalog»:
тонкие кривые Безье, буллеты справа, клик по ветви раскрывает состав.
"""

import html
from typing import Any, Dict, List, Tuple

BRANCH_COLOR = {
    "social": "#f5c542", "messenger": "#f5c542", "dev": "#4aa8ff",
    "code": "#4aa8ff", "work": "#3ddc84", "workplace": "#3ddc84",
    "professional": "#3ddc84", "business": "#3ddc84", "market": "#ff9f43",
    "wallet": "#ff9f43", "transport": "#ff6b6b", "travel": "#ff6b6b",
    "food": "#ff6b6b", "threat": "#ff5c5c", "network": "#ff5c5c",
    "domains": "#a78bfa", "geo": "#22d3ee", "maps": "#22d3ee",
    "media": "#f472b6", "files": "#f472b6", "mail": "#facc15",
    "email": "#facc15", "phone": "#facc15", "health": "#34d399",
    "education": "#34d399", "creative": "#c084fc", "startup": "#c084fc",
    "cloud": "#94a3b8", "forum": "#94a3b8", "monitoring": "#94a3b8",
    "search": "#e2e8f0", "archive": "#e2e8f0", "dating": "#fb7185",
}

# Порядок ветвей — как на референсном изображении
BRANCH_ORDER = [
    "Поиск и мониторинг", "Люди и контакты", "Соцсети и мессенджеры",
    "Домены, сеть и угрозы", "Гео и объекты", "Медиа и файлы",
    "Реестры и бизнес", "Рабочая среда", "OPSEC и обучение",
    "Код и репозитории", "Промпты / скиллы", "Дорки", "Порты",
]

# Соответствие русских названий категорий -> внутренние категории site_checks
CAT_ALIASES = {
    "Поиск и мониторинг": ["search", "monitoring", "archive"],
    "Люди и контакты": ["professional", "phone", "email", "health", "dating"],
    "Соцсети и мессенджеры": ["social", "messenger", "workplace"],
    "Домены, сеть и угрозы": ["domains", "network", "threat", "mail", "cloud"],
    "Гео и объекты": ["geo", "maps", "transport", "travel"],
    "Медиа и файлы": ["media", "files", "creative"],
    "Реестры и бизнес": ["business", "market", "wallet", "startup"],
    "Рабочая среда": ["work", "education", "food", "forum"],
    "OPSEC и обучение": ["email", "monitoring", "search"],
    "Код и репозитории": ["code", "dev", "dev"],
    "Промпты / скиллы": ["code", "dev", "creative"],
    "Дорки": ["search", "email", "phone", "social"],
    "Порты": ["network", "threat", "domains"],
}


def _load():
    """Собирает категории и сайты из site_checks."""
    sites_by_cat: Dict[str, List[Tuple[str, str]]] = {}
    try:
        import site_checks as SC
        for name, cat, url, _t, _m in SC.SITES:
            sites_by_cat.setdefault(cat, []).append((name, url))
        for name, cat, url, _chk, _f in SC.API_SITES:
            sites_by_cat.setdefault(cat, []).append((name + " (API)", url))
    except Exception:
        pass
    return sites_by_cat


# Ресурсы из каталога, которых нет в site_checks — ими наполняются «узкие» ветви
CATALOG_FOR_BRANCH = {
    "OPSEC и обучение": ["OPSEC и обучение"],
    "Промпты / скиллы": ["Промпты и скиллы", "Код и репозитории"],
    "Дорки": ["Дорки"],
    "Порты": ["Порты"],
    "Поиск и мониторинг": ["Поиск и мониторинг"],
}


def _catalog_tools() -> Dict[str, List[Tuple[str, str]]]:
    """Инструменты из catalog.py, сгруппированные по названию категории."""
    out: Dict[str, List[Tuple[str, str]]] = {}
    try:
        import catalog as CAT
        for cat in CAT.CATEGORIES:
            out.setdefault(cat["name"], []).extend(
                [(n, u) for n, u, _d in cat["tools"]])
    except Exception:
        pass
    return out


def build_branches() -> List[Dict[str, Any]]:
    """Возвращает список ветвей: название, цвет, сайты, количество.

    Каждый источник попадает ровно в одну ветвь — иначе счётчики
    переоценивают размер каталога.
    """
    sites_by_cat = _load()
    cat_tools = _catalog_tools()
    out: List[Dict[str, Any]] = []
    used_cats: set = set()
    used_sites: set = set()
    for title in BRANCH_ORDER:
        items: List[Tuple[str, str]] = []
        for cat in CAT_ALIASES.get(title, []):
            for s in sites_by_cat.get(cat, []):
                if s in used_sites:
                    continue
                used_sites.add(s)
                items.append(s)
            used_cats.add(cat)
        # добираем инструментами из каталога
        for cname in CATALOG_FOR_BRANCH.get(title, []):
            for s in cat_tools.get(cname, []):
                if s in used_sites:
                    continue
                used_sites.add(s)
                items.append(s)
        out.append({
            "title": title,
            "color": BRANCH_COLOR.get(CAT_ALIASES.get(title, [""])[0], "#8b93a7"),
            "items": items,
            "count": len(items),
        })
    # оставшиеся категории — в отдельную ветку
    rest: List[Tuple[str, str]] = []
    for cat, items in sites_by_cat.items():
        if cat in used_cats:
            continue
        for s in items:
            if s in used_sites:
                continue
            used_sites.add(s)
            rest.append(s)
    if rest:
        out.append({"title": "Прочие источники", "color": "#64748b",
                    "items": rest, "count": len(rest)})
    return out


def render_svg(branches: List[Dict[str, Any]]) -> str:
    """Рисует дерево нитей (SVG) в стиле референса."""
    n = len(branches)
    row_h = 40
    top = 22
    height = max(380, top * 2 + row_h * (n - 1))
    cx, cy = 300, height / 2
    x_end = 690
    label_x = 720

    paths = []
    dots = []
    labels = []
    for i, b in enumerate(branches):
        y = top + i * row_h
        if y > height - top:
            y = height - top
        # плавная кривая Безье: от центра веером к каждой ветви
        dx = (x_end - cx) * 0.55
        paths.append(
            f'<path d="M {cx},{cy} C {cx+dx},{cy} {x_end-dx},{y} {x_end},{y}" '
            f'fill="none" stroke="{b["color"]}" stroke-width="1.1" opacity="0.34"/>')
        dots.append(f'<circle cx="{x_end}" cy="{y}" r="2.6" fill="{b["color"]}" opacity="0.85"/>')
        labels.append(
            f'<g class="branch" data-cat="{html.escape(b["title"])}" tabindex="0">'
            f'<text x="{label_x}" y="{y+5}" fill="#cfd6e4" font-size="16" '
            f'font-family="Inter,Segoe UI,sans-serif" style="cursor:pointer">'
            f'{html.escape(b["title"])}'
            f'<tspan fill="#f5c542" font-size="13" dx="8"> {b["count"]}</tspan>'
            f'</text></g>')

    return (
        f'<svg viewBox="0 0 1180 {height}" width="100%" height="{height}" '
        f'style="max-height:78vh" preserveAspectRatio="xMidYMin meet">'
        f'<defs><radialGradient id="coreGlow">'
        f'<stop offset="0%" stop-color="#f5c542" stop-opacity="0.9"/>'
        f'<stop offset="100%" stop-color="#f5c542" stop-opacity="0"/></radialGradient></defs>'
        f'<circle cx="{cx}" cy="{cy}" r="70" fill="url(#coreGlow)" opacity="0.18"/>'
        + "".join(paths) + "".join(dots) + "".join(labels) +
        f'<circle cx="{cx}" cy="{cy}" r="4" fill="#f5c542"/>'
        # эмблема-иконка слева от названия (летучая мышь)
        f'<g transform="translate({cx-300},{cy-15}) scale(0.62)" fill="#f5c542">'
        f'<path d="M50 6c-5 6-12 8-20 7-6-1-12-5-18-9-2 8-4 14-10 20 6 0 10 2 13 5 4-1 8-1 12 1 4-1 8-1 12 1 4-2 8-2 12-1 3-3 7-5 13-5-6-6-8-12-10-20-6 4-12 8-18 9-8 1-15-1-20-7z"/>'
        f'</g>'
        f'<text x="{cx-248}" y="{cy-2}" fill="#e8edf7" font-size="21" font-weight="700" '
        f'font-family="Bebas Neue,Oswald,Impact,sans-serif" letter-spacing="1">GOTHAM OSINT</text>'
        f'<text x="{cx-248}" y="{cy+20}" fill="#8494ad" font-size="12" '
        f'font-family="Inter,sans-serif">'
        f'{sum(b["count"] for b in branches)} источников · {len(branches)} нитей</text>'
        f'</svg>'
    )


def render_detail(branches: List[Dict[str, Any]]) -> str:
    """Блоки с составом каждой ветви."""
    out = []
    for b in branches:
        rows = "".join(
            f"<tr><td><b>{html.escape(n)}</b></td>"
            f"<td><a href='{html.escape(u)}' target='_blank'>{html.escape(u)}</a></td></tr>"
            for n, u in b["items"][:400])
        out.append(
            f"<details class='branch-detail' data-cat='{html.escape(b['title'])}'>"
            f"<summary><span style='color:{b['color']}'>●</span> "
            f"<b>{html.escape(b['title'])}</b> "
            f"<span class='count'>{b['count']}</span></summary>"
            f"<div class='tablewrap'><table><thead><tr><th>Источник</th><th>Ссылка</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></details>")
    return "".join(out)
