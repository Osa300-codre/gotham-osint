#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Паутина источников: центральный узел -> узлы-переплетения -> нити категорий ->
конкретные источники на концах.

Оформление: монохромная «сталь + золото», структурные пунктирные кольца,
плавное затухание нитей от центра, никакого визуального шума.
"""

import html
import math
from typing import Any, Dict, List, Tuple

# Приглушённая палитра: сталь для линий, золото для акцентов
INK = "#3c4a60"
INK_SOFT = "#4d5d78"
NODE = "#64748b"
GOLD = "#e8b23a"
GOLD_SOFT = "#b98f2c"
TEXT = "#dde5f1"
MUTED = "#8a97ab"

BRANCH_ORDER = [
    "Поиск и мониторинг", "Люди и контакты", "Соцсети и мессенджеры",
    "Домены, сеть и угрозы", "Гео и объекты", "Медиа и файлы",
    "Реестры и бизнес", "Рабочая среда", "OPSEC и обучение",
    "Код и репозитории", "Промпты / скиллы", "Дорки", "Порты",
]

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
    "Код и репозитории": ["code", "dev"],
    "Промпты / скиллы": ["code", "dev", "creative"],
    "Дорки": ["search", "email", "phone", "social"],
    "Порты": ["network", "threat", "domains"],
}

CATALOG_FOR_BRANCH = {
    "OPSEC и обучение": ["OPSEC и обучение"],
    "Промпты / скиллы": ["Промпты и скиллы", "Код и репозитории"],
    "Дорки": ["Дорки"],
    "Порты": ["Порты"],
    "Поиск и мониторинг": ["Поиск и мониторинг"],
}

LEAF_COUNT = 3
LEAF_LINE = 21
THREAD_STEP = LEAF_COUNT * LEAF_LINE + 46


def _load() -> Dict[str, List[Tuple[str, str]]]:
    sites_by_cat: Dict[str, List[Tuple[str, str]]] = {}

    def fix(url: str) -> str:
        # в каталоге URL-шаблоны содержат плейсхолдер {} — подставляем пример
        return url.replace("{}", "username") if "{}" in url else url

    try:
        import site_checks as SC
        for name, cat, url, _t, _m in SC.SITES:
            sites_by_cat.setdefault(cat, []).append((name, fix(url)))
        for name, cat, url, _chk, _f in SC.API_SITES:
            sites_by_cat.setdefault(cat, []).append((name + " (API)", fix(url)))
    except Exception:
        pass
    return sites_by_cat


def _catalog_tools() -> Dict[str, List[Tuple[str, str]]]:
    out: Dict[str, List[Tuple[str, str]]] = {}
    try:
        import catalog as CAT
        for cat in CAT.CATEGORIES:
            out.setdefault(cat["name"], []).extend(
                [(n, u.replace("{}", "username")) for n, u, _d in cat["tools"]])
    except Exception:
        pass
    return out


def build_branches() -> List[Dict[str, Any]]:
    """Ветви с источниками (каждый источник — ровно в одной ветви)."""
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
        for cname in CATALOG_FOR_BRANCH.get(title, []):
            for s in cat_tools.get(cname, []):
                if s in used_sites:
                    continue
                used_sites.add(s)
                items.append(s)
        out.append({"title": title, "items": items, "count": len(items)})
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
        out.append({"title": "Прочие источники", "items": rest, "count": len(rest)})
    return out


# ==========================================================================
#  Геометрия
# ==========================================================================
def _catmull_rom(points: List[Tuple[float, float]], tension: float = 1.0) -> str:
    if len(points) < 2:
        return ""
    d = f"M {points[0][0]:.1f},{points[0][1]:.1f}"
    p = [points[0]] + list(points) + [points[-1]]
    for i in range(len(p) - 3):
        p0, p1, p2, p3 = p[i], p[i + 1], p[i + 2], p[i + 3]
        c1 = (p1[0] + (p2[0] - p0[0]) / 6.0 * tension,
              p1[1] + (p2[1] - p0[1]) / 6.0 * tension)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6.0 * tension,
              p2[1] - (p3[1] - p1[1]) / 6.0 * tension)
        d += (f" C {c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}")
    return d


def _rings(cx: float, cy: float) -> List[List[Tuple[float, float]]]:
    """Три эллиптических кольца узлов-переплетения."""
    rings: List[List[Tuple[float, float]]] = []
    specs = [(105, 5, 0.0), (205, 8, 0.42), (310, 11, 0.85)]
    for radius, count, phase in specs:
        pts = []
        for i in range(count):
            a = phase + 2 * math.pi * i / count
            pts.append((cx + radius * 0.72 * math.cos(a),
                        cy + radius * 0.56 * math.sin(a)))
        rings.append(pts)
    return rings


def render_svg(branches: List[Dict[str, Any]]) -> str:
    """Паутина источников: центр -> узлы-переплетения -> нити -> источники."""
    n = len(branches)
    top = 78
    # высота учитывает хвост источников последней нити
    height = top + (n - 1) * THREAD_STEP + 52 + LEAF_COUNT * LEAF_LINE + 34
    cx, cy = 250, height / 2
    end_x = 570
    leaf_x = 594

    rings = _rings(cx, cy)
    r1, r2, r3 = rings

    parts: List[str] = []
    defs: List[str] = []
    labels: List[str] = []
    leaves: List[str] = []
    ndots: List[str] = []

    # --- структурные кольца (пунктирные эллипсы) ---
    for i, (rx, ry) in enumerate([(76, 59), (148, 115), (223, 174)], start=1):
        parts.append(
            f'<ellipse cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" fill="none" '
            f'stroke="{INK}" stroke-width="0.8" stroke-dasharray="2 7" opacity="0.75"/>')

    # --- нити: центр -> узлы -> категория (с градиентом) ---
    for i, b in enumerate(branches):
        gid = f"g{i}"
        defs.append(
            f'<linearGradient id="{gid}" x1="{cx}" y1="{cy}" x2="{end_x}" y2="{cy}" '
            f'gradientUnits="userSpaceOnUse">'
            f'<stop offset="0%" stop-color="{GOLD}" stop-opacity="0.06"/>'
            f'<stop offset="45%" stop-color="{INK_SOFT}" stop-opacity="0.55"/>'
            f'<stop offset="100%" stop-color="{GOLD_SOFT}" stop-opacity="0.9"/>'
            f'</linearGradient>')
        y_target = top + i * THREAD_STEP
        end = (float(end_x), y_target)
        j1 = r1[i % len(r1)]
        j2 = r2[(i * 2) % len(r2)]
        j3 = r3[(i * 3) % len(r3)]
        pts = [(cx, cy), j1, j2, j3, end]
        parts.append(f'<path d="{_catmull_rom(pts, 1.0)}" fill="none" '
                     f'stroke="url(#{gid})" stroke-width="1.5" stroke-linecap="round"/>')

        ndots.append(f'<circle cx="{end[0]}" cy="{end[1]}" r="4" fill="{GOLD}"/>')
        ndots.append(f'<circle cx="{end[0]}" cy="{end[1]}" r="8" fill="{GOLD}" opacity="0.14"/>')
        labels.append(
            f'<g class="branch" data-cat="{html.escape(b["title"])}" tabindex="0">'
            f'<text x="{end[0] + 16}" y="{end[1] + 6}" fill="{TEXT}" font-size="23" '
            f'font-family="Inter,Segoe UI,sans-serif" style="cursor:pointer">'
            f'{html.escape(b["title"])}</text>'
            f'<text x="{end[0] + 16}" y="{end[1] + 26}" fill="{GOLD_SOFT}" font-size="18" '
            f'font-family="Inter,sans-serif">{b["count"]} источников</text>'
            f'</g>')

        # конкретные источники на конце нитки
        for k, (sname, surl) in enumerate(b["items"][:LEAF_COUNT]):
            ly = end[1] + 48 + k * LEAF_LINE
            if ly > height - 12:
                break
            leaves.append(
                f'<a class="leaf" href="{html.escape(surl)}" target="_blank" '
                f'data-title="{html.escape(sname)}" data-url="{html.escape(surl)}" '
                f'data-thread="{html.escape(b["title"])}">'
                f'<title>{html.escape(sname)}</title>'
                f'<circle cx="{leaf_x - 10}" cy="{ly - 5}" r="2.6" fill="{NODE}"/>'
                f'<text x="{leaf_x}" y="{ly}" fill="{MUTED}" font-size="17" '
                f'font-family="Inter,sans-serif">{html.escape(sname[:26])}</text></a>')

    # --- узлы-переплетения: каждому соответствует конкретный источник ---
    pool: List[Tuple[str, str, str]] = []   # (название, url, нить)
    for b in branches:
        for sname, surl in b["items"][:6]:
            pool.append((sname, surl, b["title"]))
    if not pool:
        pool = [("Gotham OSINT", "https://github.com/Osa300-codre/gotham-osint", "ядро")]

    node_usage: Dict[Tuple[float, float], int] = {}
    for i, b in enumerate(branches):
        for pt in (r1[i % len(r1)], r2[(i * 2) % len(r2)], r3[(i * 3) % len(r3)]):
            key = (round(pt[0], 1), round(pt[1], 1))
            node_usage[key] = node_usage.get(key, 0) + 1

    ndots: List[str] = []
    for ring_idx, ring in enumerate(rings):
        for pt in ring:
            key = (round(pt[0], 1), round(pt[1], 1))
            sname, surl, thread = pool[(hash(key) + ring_idx * 7) % len(pool)]
            threads = node_usage.get(key, 1)
            ndots.append(
                f'<g class="node" data-title="{html.escape(sname)}" '
                f'data-url="{html.escape(surl)}" data-thread="{html.escape(thread)}" '
                f'data-count="{threads}">'
                f'<title>{html.escape(sname)} — {html.escape(thread)}</title>'
                f'<circle cx="{pt[0]:.1f}" cy="{pt[1]:.1f}" r="3.2" '
                f'fill="{INK_SOFT}" stroke="#0a0d13" stroke-width="1"/>'
                f'<circle cx="{pt[0]:.1f}" cy="{pt[1]:.1f}" r="7" fill="none" '
                f'stroke="{GOLD}" stroke-width="1" opacity="0" class="node-halo"/>'
                f'</g>')

    # --- ядро ---
    total = sum(b["count"] for b in branches)
    core = (f'<circle cx="{cx}" cy="{cy}" r="92" fill="url(#coreGlow)"/>'
            f'<circle cx="{cx}" cy="{cy}" r="9" fill="{GOLD}"/>'
            f'<circle cx="{cx}" cy="{cy}" r="17" fill="none" stroke="{GOLD}" '
            f'stroke-width="1" opacity="0.35"/>'
            f'<text x="{cx}" y="{cy-32}" fill="{TEXT}" font-size="25" font-weight="700" '
            f'text-anchor="middle" letter-spacing="1.2" '
            f'font-family="Bebas Neue,Oswald,Impact,sans-serif">GOTHAM OSINT</text>'
            f'<text x="{cx}" y="{cy+40}" fill="{MUTED}" font-size="14" text-anchor="middle" '
            f'font-family="Inter,sans-serif">{total} источников · {len(branches)} нитей</text>')

    # --- легенда в свободной зоне слева снизу ---
    ly0 = height - 104
    legend = [
        (f'<circle cx="{cx-176}" cy="{ly0}" r="6" fill="{GOLD}"/>',
         "категория (нить)"),
        (f'<circle cx="{cx-176}" cy="{ly0+26}" r="3.2" fill="{INK_SOFT}" '
         f'stroke="#0a0d13" stroke-width="1"/>',
         "узел переплетения"),
        (f'<circle cx="{cx-176}" cy="{ly0+52}" r="2.6" fill="{NODE}"/>',
         "конкретный источник"),
    ]
    lsvg = []
    for i, (shape, text) in enumerate(legend):
        lsvg.append(shape)
        lsvg.append(f'<text x="{cx-162}" y="{ly0 + 5 + i * 26}" fill="{MUTED}" '
                    f'font-size="14" font-family="Inter,sans-serif">{text}</text>')

    return (
        f'<svg viewBox="0 0 900 {height:.0f}" preserveAspectRatio="xMidYMin meet">'
        f'<defs>'
        f'<radialGradient id="coreGlow">'
        f'<stop offset="0%" stop-color="{GOLD}" stop-opacity="0.22"/>'
        f'<stop offset="60%" stop-color="{GOLD}" stop-opacity="0.05"/>'
        f'<stop offset="100%" stop-color="{GOLD}" stop-opacity="0"/></radialGradient>'
        + "".join(defs) +
        f'</defs>'
        + "".join(parts) + "".join(ndots) + "".join(labels) + "".join(leaves)
        + "".join(lsvg) + core +
        f'</svg>'
    )


def render_detail(branches: List[Dict[str, Any]]) -> str:
    """Раскрывающиеся составы ветвей."""
    out = []
    for b in branches:
        rows = "".join(
            f"<tr><td><b>{html.escape(n)}</b></td>"
            f"<td><a href='{html.escape(u)}' target='_blank'>{html.escape(u)}</a></td></tr>"
            for n, u in b["items"][:400])
        out.append(
            f"<details class='bdetail' data-cat='{html.escape(b['title'])}'>"
            f"<summary><span style='color:{GOLD}'>●</span> "
            f"<b>{html.escape(b['title'])}</b> "
            f"<span class='count'>{b['count']}</span></summary>"
            f"<div class='wrap'><table class='tbl'><thead><tr><th>Источник</th><th>Ссылка</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></details>")
    return "".join(out)
