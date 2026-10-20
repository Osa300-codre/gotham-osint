#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Паутина источников: центральный узел -> узлы-переплетения -> нити категорий ->
конкретные источники на концах. Нити переплетаются в середине (общие узлы
и перекрёстные связи между кольцами), образуя сеть.
"""

import html
import math
from typing import Any, Dict, List, Tuple

BRANCH_COLOR = {
    "social": "#e8b23a", "messenger": "#e8b23a", "dev": "#4a9fe8",
    "code": "#4a9fe8", "work": "#3ecf8e", "workplace": "#3ecf8e",
    "professional": "#3ecf8e", "business": "#3ecf8e", "market": "#e8a13a",
    "wallet": "#e8a13a", "transport": "#ef5b5b", "travel": "#ef5b5b",
    "food": "#ef5b5b", "threat": "#ef5b5b", "network": "#ef5b5b",
    "domains": "#a78bfa", "geo": "#22d3ee", "maps": "#22d3ee",
    "media": "#f472b6", "files": "#f472b6", "mail": "#f0c040",
    "email": "#f0c040", "phone": "#f0c040", "health": "#34d399",
    "education": "#34d399", "creative": "#c084fc", "startup": "#c084fc",
    "cloud": "#94a3b8", "forum": "#94a3b8", "monitoring": "#94a3b8",
    "search": "#dde5f1", "archive": "#dde5f1", "dating": "#fb7185",
}

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

# Сколько конкретных источников показывать на конце нитки
LEAF_COUNT = 3
# Вертикальный шаг между нитями: источники одной нити не должны наезжать
# на подпись следующей
LEAF_LINE = 19
THREAD_STEP = LEAF_COUNT * LEAF_LINE + 40


def _load() -> Dict[str, List[Tuple[str, str]]]:
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


def _catalog_tools() -> Dict[str, List[Tuple[str, str]]]:
    out: Dict[str, List[Tuple[str, str]]] = {}
    try:
        import catalog as CAT
        for cat in CAT.CATEGORIES:
            out.setdefault(cat["name"], []).extend([(n, u) for n, u, _d in cat["tools"]])
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
        out.append({
            "title": title,
            "color": BRANCH_COLOR.get(CAT_ALIASES.get(title, [""])[0], "#8b93a7"),
            "items": items,
            "count": len(items),
        })
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


# ==========================================================================
#  Геометрия паутины
# ==========================================================================
def _catmull_rom(points: List[Tuple[float, float]], tension: float = 1.0) -> str:
    """Плавная кривая через точки (Catmull-Rom -> кубический Bezier)."""
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
    """Кольца узлов-переплетения: три эллиптических кольца, узлы разнесены по кругу.

    Эллипс (сплюснутый по X) нужен, чтобы паутина не вылезала левее центра.
    """
    rings: List[List[Tuple[float, float]]] = []
    specs = [(120, 6, 0.0), (225, 9, 0.38), (340, 12, 0.75)]
    for radius, count, phase in specs:
        pts = []
        for i in range(count):
            a = phase + 2 * math.pi * i / count
            pts.append((cx + radius * 0.66 * math.cos(a),
                        cy + radius * 0.5 * math.sin(a)))
        rings.append(pts)
    return rings


def render_svg(branches: List[Dict[str, Any]]) -> str:
    """Паутина: центр -> узлы-переплетения -> нити -> конкретные источники."""
    n = len(branches)
    top = 70
    height = top * 2 + THREAD_STEP * (n - 1)
    cx, cy = 185, height / 2
    end_x = 610
    leaf_x = 636

    rings = _rings(cx, cy)
    r1, r2, r3 = rings

    paths: List[str] = []
    dots: List[str] = []
    jdots: List[str] = []
    labels: List[str] = []
    leaves: List[str] = []
    webs: List[str] = []

    # --- перекрёстные связи между кольцами (эффект сплетения) ---
    for a_ring, b_ring in ((r1, r2), (r2, r3)):
        for i, a in enumerate(a_ring):
            b = b_ring[(i * 3 + 2) % len(b_ring)]
            webs.append(
                f'<path d="{_catmull_rom([a, ((a[0]+b[0])/2, (a[1]+b[1])/2), b], 1.0)}" '
                f'fill="none" stroke="#39445a" stroke-width="0.7" opacity="0.55"/>')
    # хорды внутри колец
    for ring in rings:
        for i in range(len(ring)):
            a = ring[i]
            b = ring[(i + 1) % len(ring)]
            webs.append(
                f'<path d="{_catmull_rom([a, b], 1.0)}" fill="none" '
                f'stroke="#2a3646" stroke-width="0.6" opacity="0.5"/>')

    # --- нити: центр -> узлы колец -> категория ---
    for i, b in enumerate(branches):
        color = b["color"]
        y_target = top + i * THREAD_STEP
        end = (float(end_x), y_target)

        j1 = r1[i % len(r1)]
        j2 = r2[(i * 2) % len(r2)]
        j3 = r3[(i * 3) % len(r3)]
        pts = [(cx, cy), j1, j2, j3, end]
        paths.append(f'<path d="{_catmull_rom(pts, 1.0)}" fill="none" '
                     f'stroke="{color}" stroke-width="1.2" opacity="0.6"/>')

        dots.append(f'<circle cx="{end[0]}" cy="{end[1]}" r="3.6" fill="{color}"/>')
        labels.append(
            f'<g class="branch" data-cat="{html.escape(b["title"])}" tabindex="0">'
            f'<text x="{end[0] + 14}" y="{end[1] + 6}" fill="#dde5f1" font-size="23" '
            f'font-family="Inter,Segoe UI,sans-serif" style="cursor:pointer">'
            f'{html.escape(b["title"])}'
            f'<tspan fill="{color}" font-size="19" dx="8">{b["count"]}</tspan>'
            f'</text></g>')

        # конкретные источники на конце нитки
        picks = b["items"][:LEAF_COUNT]
        for k, (sname, surl) in enumerate(picks):
            ly = end[1] + 22 + k * LEAF_LINE
            if ly > height - 10:
                break
            leaves.append(
                f'<a href="{html.escape(surl)}" target="_blank">'
                f'<circle cx="{leaf_x - 9}" cy="{ly - 4.5}" r="2.4" fill="{color}" opacity="0.75"/>'
                f'<text x="{leaf_x}" y="{ly}" fill="#8494ad" font-size="17" '
                f'font-family="Inter,sans-serif">{html.escape(sname[:26])}</text></a>')

    # --- узлы-переплетения ---
    for ring in rings:
        for pt in ring:
            jdots.append(f'<circle cx="{pt[0]:.1f}" cy="{pt[1]:.1f}" r="2.2" '
                         f'fill="#5b6982" opacity="0.85"/>')

    # --- центральный узел ---
    core = (f'<circle cx="{cx}" cy="{cy}" r="44" fill="url(#coreGlow)" opacity="0.20"/>'
            f'<circle cx="{cx}" cy="{cy}" r="5.5" fill="#e8b23a"/>'
            f'<text x="{cx-186}" y="{cy-4}" fill="#e8edf7" font-size="21" font-weight="700" '
            f'font-family="Bebas Neue,Oswald,Impact,sans-serif" letter-spacing="1">GOTHAM OSINT</text>'
            f'<text x="{cx-186}" y="{cy+17}" fill="#8494ad" font-size="12" '
            f'font-family="Inter,sans-serif">'
            f'{sum(b["count"] for b in branches)} источников · {len(branches)} нитей</text>')

    return (
        f'<svg viewBox="0 0 900 {height:.0f}" '
        f'preserveAspectRatio="xMidYMin meet">'
        f'<defs><radialGradient id="coreGlow">'
        f'<stop offset="0%" stop-color="#e8b23a" stop-opacity="0.85"/>'
        f'<stop offset="100%" stop-color="#e8b23a" stop-opacity="0"/></radialGradient></defs>'
        + "".join(webs) + "".join(paths) + "".join(jdots) + "".join(dots)
        + "".join(labels) + "".join(leaves) + core +
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
            f"<summary><span style='color:{b['color']}'>●</span> "
            f"<b>{html.escape(b['title'])}</b> "
            f"<span class='count'>{b['count']}</span></summary>"
            f"<div class='wrap'><table class='tbl'><thead><tr><th>Источник</th><th>Ссылка</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></details>")
    return "".join(out)
