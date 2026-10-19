#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gotham OSINT — веб-интерфейс.

Разделы:
  1. Сканирование      — проверка username по всем площадкам каталога
  2. Досье             — полные данные о человеке (email / телефон / ФИО / ВК / Telegram)
  3. Глубокое исслед.  — граф связей с рекурсивным обходом
  4. Источники         — карта нитей, каталог ресурсов, база знаний
  5. Инструменты       — утечки, веб-поиск, IP/домен, корреляция
  6. Ключи             — управление API-ключами
"""

import io
import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from osint_finder import (
    search_email, search_username_basic, search_ip, search_domain,
    search_phone, search_name, DISCLAIMER,
)
from scanner import scan
from site_checks import all_categories
from websearch import web_search
from leaks import full_leak_check, check_xposedornot
import safesurf_ru
from premium import (
    key_status, save_keys, KEY_MAP, serper_search,
    hunter_domain_emails, dehashed_search, numverify_phone,
)
from identify import (
    identify, search_telegram, search_email_detailed,
    search_vk, search_phone_deep,
)
from dossier import build_dossier
from deep import deep_research
from threads_map import build_branches, render_svg, render_detail

app = FastAPI(title="Gotham OSINT")

SECTIONS = [
    ("scan", "Сканирование", "Проверка username по всем площадкам"),
    ("dossier", "Досье", "Данные о человеке по любому идентификатору"),
    ("deep", "Глубокое исследование", "Граф связей с рекурсивным обходом"),
    ("sources", "Источники", "Карта нитей, каталог ресурсов, база знаний"),
    ("tools", "Инструменты", "Утечки, веб-поиск, IP и домен, корреляция"),
    ("keys", "Ключи", "Подключение платных API-сервисов"),
]

# ==========================================================================
#  CSS
# ==========================================================================
CSS = """
:root{
  --bg:#0a0d13; --bg-2:#0e131c; --panel:#111823; --panel-2:#151d2a;
  --line:#1e2735; --line-2:#2a3646;
  --text:#dde5f1; --text-2:#9aa7ba; --text-3:#6b7789;
  --accent:#e8b23a; --accent-2:#f2c55c; --accent-dim:rgba(232,178,58,.10);
  --ok:#3ecf8e; --warn:#e8a13a; --bad:#ef5b5b; --info:#4a9fe8;
  --r:6px; --r-s:4px;
  --mono:'JetBrains Mono','Cascadia Code',Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
  background:var(--bg); color:var(--text); font-size:14px; line-height:1.55;
  -webkit-font-smoothing:antialiased;
}
a{color:var(--info);text-decoration:none}
a:hover{text-decoration:underline}
code,.mono{font-family:var(--mono)}

/* ---- каркас ---- */
.app{display:flex;min-height:100vh}
.side{
  width:252px;flex:0 0 252px;background:var(--bg-2);
  border-right:1px solid var(--line);display:flex;flex-direction:column;
  position:sticky;top:0;height:100vh;
}
.brand{padding:20px 20px 16px;border-bottom:1px solid var(--line)}
.brand h1{font-size:17px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--text)}
.brand .mark{display:inline-block;width:9px;height:9px;background:var(--accent);
  transform:rotate(45deg);margin-right:9px;vertical-align:1px}
.brand .ver{font-size:11px;color:var(--text-3);margin-top:5px;letter-spacing:.04em}
.nav{padding:12px 10px;flex:1;overflow-y:auto}
.nav a{
  display:flex;flex-direction:column;gap:1px;padding:9px 12px;border-radius:var(--r);
  color:var(--text-2);text-decoration:none;margin-bottom:2px;border-left:2px solid transparent;
}
.nav a:hover{background:var(--panel);color:var(--text);text-decoration:none}
.nav a.on{background:var(--panel-2);color:var(--text);border-left-color:var(--accent)}
.nav a .t{font-size:13.5px;font-weight:600}
.nav a .d{font-size:11px;color:var(--text-3)}
.nav a.on .d{color:var(--text-2)}
.side-foot{padding:14px 20px;border-top:1px solid var(--line);font-size:11px;color:var(--text-3);
  font-family:var(--mono);line-height:1.8}
.side-foot b{color:var(--accent);font-weight:600}

.main{flex:1;min-width:0;padding:26px 30px 70px;max-width:1400px}
.head{margin-bottom:20px;padding-bottom:14px;border-bottom:1px solid var(--line)}
.head h2{font-size:21px;font-weight:700;letter-spacing:.01em}
.head p{color:var(--text-2);font-size:13px;margin-top:3px}
.crumb{font-size:11px;color:var(--text-3);text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}

/* ---- карточки/статистика ---- */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:12px 14px}
.card b{display:block;font-size:24px;font-weight:700;line-height:1.2}
.card span{font-size:10.5px;color:var(--text-3);text-transform:uppercase;letter-spacing:.07em}
.card.ok b{color:var(--ok)} .card.warn b{color:var(--warn)} .card.bad b{color:var(--bad)}
.card.acc b{color:var(--accent)}

/* ---- формы ---- */
.box{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;margin-bottom:18px}
label{display:block;font-size:11px;letter-spacing:.07em;text-transform:uppercase;
  color:var(--text-3);margin:12px 0 5px;font-weight:600}
label:first-child{margin-top:0}
input,select,textarea{
  width:100%;padding:9px 11px;background:var(--bg);border:1px solid var(--line-2);
  border-radius:var(--r-s);color:var(--text);font-size:13.5px;font-family:var(--mono);
}
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
input::placeholder{color:var(--text-3)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
.hint{font-size:12px;color:var(--text-3);margin-top:7px;line-height:1.6}
button,.btn{
  display:inline-block;padding:9px 18px;background:var(--accent);color:#12161d;border:none;
  border-radius:var(--r-s);font-size:12.5px;font-weight:700;letter-spacing:.05em;
  text-transform:uppercase;cursor:pointer;font-family:inherit;transition:.15s;
}
button:hover{background:var(--accent-2)}
button.ghost,.btn.ghost{background:transparent;color:var(--text-2);border:1px solid var(--line-2)}
button.ghost:hover,.btn.ghost:hover{background:var(--panel);color:var(--text)}
button:disabled{opacity:.5;cursor:default}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}

/* ---- таблицы ---- */
.tbl{width:100%;border-collapse:collapse;font-size:13px;border:1px solid var(--line);
  border-radius:var(--r);overflow:hidden}
.tbl th{background:var(--panel-2);color:var(--text-2);text-align:left;padding:9px 12px;
  font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;
  border-bottom:1px solid var(--line)}
.tbl td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(232,178,58,.035)}
.wrap{overflow-x:auto}

/* ---- теги ---- */
.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10.5px;font-weight:600;
  letter-spacing:.04em;text-transform:uppercase;border:1px solid}
.tag.acc{color:var(--accent);border-color:rgba(232,178,58,.35);background:var(--accent-dim)}
.tag.ok{color:var(--ok);border-color:rgba(62,207,142,.35);background:rgba(62,207,142,.08)}
.tag.bad{color:var(--bad);border-color:rgba(239,91,91,.35);background:rgba(239,91,91,.08)}
.tag.dim{color:var(--text-3);border-color:var(--line-2)}
.tags{display:flex;flex-wrap:wrap;gap:5px}

/* ---- блоки результатов ---- */
.kv{width:100%;border-collapse:collapse;font-size:13px}
.kv td{padding:7px 0;border-bottom:1px solid var(--line);vertical-align:top}
.kv td:first-child{width:210px;color:var(--text-3);font-size:12px}
.kv tr:last-child td{border-bottom:none}
.kv b{font-weight:600;color:var(--text);word-break:break-word}
.panel{border:1px solid var(--line);border-radius:var(--r);background:var(--panel);
  padding:14px 16px;margin:12px 0}
.panel h4{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-2);
  margin-bottom:9px;display:flex;align-items:center;gap:9px}
details{border:1px solid var(--line);border-radius:var(--r);background:var(--panel);margin:8px 0}
details summary{cursor:pointer;padding:10px 14px;font-size:13px;color:var(--text-2);
  list-style:none;display:flex;align-items:center;gap:8px}
details summary::-webkit-details-marker{display:none}
details summary::before{content:'+';color:var(--accent);font-family:var(--mono)}
details[open] summary::before{content:'−'}
details[open] summary{border-bottom:1px solid var(--line);color:var(--text)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:var(--r-s);padding:13px;
  overflow:auto;font-family:var(--mono);font-size:12px;line-height:1.6;color:#a9d6b5;max-height:520px}
.alert{display:flex;gap:10px;padding:11px 14px;border-radius:var(--r);margin-bottom:16px;
  background:rgba(232,161,58,.07);border:1px solid rgba(232,161,58,.28);font-size:12.5px;color:#e7cd9d}
.alert svg{flex:0 0 16px;margin-top:2px}
.empty{padding:26px;text-align:center;color:var(--text-3);font-size:13px}
.busy{display:flex;align-items:center;gap:10px;padding:30px;justify-content:center;color:var(--text-2);font-size:13px}
.spin{width:14px;height:14px;border:2px solid var(--line-2);border-top-color:var(--accent);
  border-radius:50%;animation:sp .8s linear infinite;display:inline-block}
@keyframes sp{to{transform:rotate(360deg)}}

/* ---- под-разделы инструментов ---- */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin-bottom:16px;flex-wrap:wrap}
.tabs a{padding:8px 15px;font-size:12.5px;color:var(--text-3);text-decoration:none;
  border-bottom:2px solid transparent;font-weight:600}
.tabs a:hover{color:var(--text);text-decoration:none}
.tabs a.on{color:var(--accent);border-bottom-color:var(--accent)}

/* ---- карта нитей ---- */
.mapwrap{border:1px solid var(--line);border-radius:var(--r);background:var(--panel);
  padding:14px;margin:12px 0}
.mapwrap svg{display:block;margin:0 auto;width:100%;height:auto}
.mapwrap .branch text{cursor:pointer;transition:.15s}
.mapwrap .branch:hover text{fill:var(--accent)}
.bdetail{border:1px solid var(--line);border-radius:var(--r);background:var(--panel);margin:6px 0}
.bdetail summary{cursor:pointer;padding:9px 13px;font-size:13px;display:flex;align-items:center;gap:8px}
.bdetail summary::-webkit-details-marker{display:none}
.bdetail summary .count{margin-left:auto}

@media(max-width:900px){
  .app{flex-direction:column}
  .side{width:100%;flex:none;height:auto;position:static;border-right:none;border-bottom:1px solid var(--line)}
  .nav{display:flex;flex-wrap:wrap;gap:4px}
  .nav a{border-left:none;border-bottom:2px solid transparent;flex:1 1 150px}
  .nav a.on{border-left:none;border-bottom-color:var(--accent)}
  .main{padding:18px 16px 50px}
  .row2,.row3{grid-template-columns:1fr}
}
"""

# ==========================================================================
#  HTML
# ==========================================================================
HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gotham OSINT</title>
<link rel="icon" href="/favicon.ico" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0a0d13">
<meta name="description" content="Поиск публичной информации по username, email, телефону и домену.">
<style>__CSS__</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">
      <h1><span class="mark"></span>Gotham OSINT</h1>
      <div class="ver">v1.0 &middot; __NSITES__ источников</div>
    </div>
    <nav class="nav">__NAV__</nav>
    <div class="side-foot">
      СЕРВЕР <b>127.0.0.1:8765</b><br>
      ИСТОЧНИКОВ <b>__NSITES__</b> &middot; КЛЮЧЕЙ <b>__NKEYS__</b>
    </div>
  </aside>
  <main class="main">
    <div class="head">
      <div class="crumb">__CRUMB__</div>
      <h2>__TITLE__</h2>
      <p>__DESC__</p>
    </div>
    __BODY__
  </main>
</div>
<script>__JS__</script>
</body>
</html>
"""

JS = """
document.querySelectorAll('.tabs a, .nav a').forEach(function(a){
  a.addEventListener('click', function(e){
    if (a.getAttribute('href') && a.getAttribute('href').startsWith('#')) {
      e.preventDefault();
      var t = document.querySelector(a.getAttribute('href'));
      if (t) t.scrollIntoView({behavior:'smooth'});
    }
  });
});
function busy(id, text){
  var el = document.getElementById(id);
  if (el) el.innerHTML = '<div class="busy"><span class="spin"></span>' + (text||'Обработка...') + '</div>';
}
document.querySelectorAll('form[data-busy]').forEach(function(f){
  f.addEventListener('submit', function(){
    var t = f.getAttribute('data-busy');
    busy(t, f.getAttribute('data-msg') || 'Обработка...');
  });
});
document.addEventListener('click', function(e){
  var c = e.target.closest('[data-copy]');
  if (c) { navigator.clipboard.writeText(c.dataset.copy).then(function(){ toast('Скопировано'); }); return; }
  var d = e.target.closest('[data-download]');
  if (d) {
    var b = new Blob([d.dataset.download], {type:'application/json'});
    var a = document.createElement('a'); a.href = URL.createObjectURL(b);
    a.download = 'osint-report.json'; a.click(); toast('Файл сохранён'); return;
  }
  var g = e.target.closest('.branch');
  if (g) {
    var cat = g.getAttribute('data-cat');
    var det = document.querySelector(".bdetail[data-cat='" + cat.replace(/'/g,"\\\\'") + "']");
    if (det) { det.open = true; det.scrollIntoView({behavior:'smooth', block:'center'}); }
  }
});
function toast(msg){
  var t = document.createElement('div');
  t.textContent = msg;
  t.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#e8b23a;color:#12161d;'+
    'padding:9px 16px;border-radius:4px;font-size:12.5px;font-weight:700;z-index:99';
  document.body.appendChild(t); setTimeout(function(){ t.remove(); }, 1900);
}
"""


def _esc(v) -> str:
    import html as _h
    return _h.escape(str(v), quote=True)


def _nav(active: str) -> str:
    out = []
    for key, title, desc in SECTIONS:
        cls = " class=\"on\"" if key == active else ""
        out.append(f'<a href="/?s={key}"{cls}><span class="t">{_esc(title)}</span>'
                   f'<span class="d">{_esc(desc)}</span></a>')
    return "\n".join(out)


def _stats(items) -> str:
    cells = []
    for value, label, kind in items:
        c = f"card {kind}" if kind else "card"
        cells.append(f'<div class="{c}"><b>{_esc(value)}</b><span>{_esc(label)}</span></div>')
    return '<div class="grid">' + "".join(cells) + "</div>"


def _table(headers, rows) -> str:
    if not rows:
        return '<div class="empty">Ничего не найдено</div>'
    th = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="wrap"><table class="tbl"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>'


def _kv(rows) -> str:
    trs = []
    for label, value in rows:
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, list):
            body = "".join(f'<span class="tag acc" style="margin:1px 4px 1px 0">{_esc(v)}</span>' for v in value[:40])
            if not body:
                continue
        else:
            body = f"<b>{_esc(value)}</b>"
        trs.append(f"<tr><td>{_esc(label)}</td><td>{body}</td></tr>")
    if not trs:
        return '<div class="empty">Данных не найдено</div>'
    return '<table class="kv">' + "".join(trs) + "</table>"


def _page(section: str = "scan", body: str = "", title: str = "", desc: str = "",
          crumb: str = "") -> str:
    meta = {k: (t, d) for k, t, d in SECTIONS}
    t, d = meta.get(section, ("Gotham OSINT", ""))
    nkeys = sum(1 for s in key_status() if s["active"])
    try:
        from threads_map import build_branches
        nsites = sum(b["count"] for b in build_branches())
    except Exception:
        nsites = 0
    if not nsites:
        try:
            import site_checks as SC
            nsites = len(SC.SITES) + len(SC.API_SITES)
        except Exception:
            nsites = 0
    return (HTML.replace("__CSS__", CSS)
                .replace("__JS__", JS)
                .replace("__NAV__", _nav(section))
                .replace("__NSITES__", str(nsites))
                .replace("__NKEYS__", str(nkeys))
                .replace("__CRUMB__", _esc(crumb or t))
                .replace("__TITLE__", _esc(title or t))
                .replace("__DESC__", _esc(desc or d))
                .replace("__BODY__", body))


# ==========================================================================
#  Раздел: Сканирование
# ==========================================================================
CHIP_CSS = """
.chip{padding:4px 10px;border:1px solid var(--line-2);border-radius:3px;font-size:11.5px;
  color:var(--text-3);cursor:pointer;user-select:none;margin:2px 3px 2px 0;display:inline-block}
.chip:hover{border-color:var(--accent);color:var(--text)}
.chip.on{background:var(--accent-dim);border-color:var(--accent);color:var(--accent)}
"""

CHIP_JS = """
document.querySelectorAll('.chip').forEach(function(c){c.addEventListener('click',function(){
  c.classList.toggle('on');
  var sel=[];document.querySelectorAll('.chip.on').forEach(function(x){sel.push(x.dataset.c)});
  document.getElementById('cats-val').value=sel.join(',');
});});
"""


def _scan_section(value: str = "", cats: List[str] = None) -> str:
    chips = "".join(
        f'<span class="chip" data-c="{_esc(c)}">{_esc(c)}</span>'
        for c in all_categories())
    val = _esc(value)
    return (
        '<div class="box">'
        '<form method="post" action="/scan" data-busy="scan-out" '
        'data-msg="Проверяем площадки каталога...">'
        '<label>Username / ник</label>'
        f'<input name="value" value="{val}" placeholder="octocat" required>'
        '<label>Категории площадок (пусто — все)</label>'
        f'<div class="tags" id="cats">{chips}</div>'
        '<input type="hidden" name="cats" id="cats-val" value="">'
        '<div class="actions">'
        '<button type="submit">Запустить проверку</button>'
        '<a class="btn ghost" href="/?s=sources">Карта источников</a>'
        '</div>'
        '<div class="hint">Проверяется наличие профиля на всех площадках каталога. '
        'Займёт 10–30 секунд.</div>'
        '</form></div>'
        f'<div id="scan-out">{_scan_out(value, cats)}</div>'
        f'<style>{CHIP_CSS}</style>'
        f'<script>{CHIP_JS}</script>'
    )


def _scan_out(value: str, cats: Optional[List[str]]) -> str:
    if not value:
        return ""
    res = scan_sync_safe(value, cats)
    rows = []
    for cat, items in (res.get("by_category") or {}).items():
        for it in items:
            rows.append([f'<span class="tag acc">{_esc(cat)}</span>', f"<b>{_esc(it['site'])}</b>",
                         f"<a href='{_esc(it['url'])}' target='_blank'>{_esc(it['url'])}</a>"])
    body = _stats([
        (res.get("found_count", 0), "профилей найдено", "ok"),
        (res.get("total_checked", 0), "сайтов проверено", ""),
        (res.get("not_found_count", 0), "не найдено", "bad"),
        (res.get("unknown_count", 0), "не подтверждено", "warn"),
    ])
    body += '<div class="panel"><h4>Найденные профили</h4>' + _table(
        ["Категория", "Площадка", "Ссылка"], rows) + "</div>"
    body += "<details><summary>Полный отчёт (JSON)</summary><pre>" + _esc(
        json.dumps(res, ensure_ascii=False, indent=2)) + "</pre></details>"
    return body


def scan_sync_safe(value: str, cats: Optional[List[str]]) -> Dict[str, Any]:
    import asyncio
    from scanner import scan as _scan
    return asyncio.run(_scan(value, cats))


# ==========================================================================
#  Раздел: Досье
# ==========================================================================
def _dossier_section() -> str:
    return """
<div class="box">
  <form method="post" action="/dossier" data-busy="dos-out" data-msg="Собираем досье, это займёт до минуты...">
    <div class="row2">
      <div>
        <label>Идентификатор</label>
        <input name="value" placeholder="ivanov@example.com / +79991234567 / durov / https://vk.com/durov" required>
      </div>
      <div>
        <label>Тип данных</label>
        <select name="kind">
          <option value="auto">Определить автоматически</option>
          <option value="email">Email</option>
          <option value="phone">Номер телефона</option>
          <option value="telegram">Telegram username</option>
          <option value="vk">Ссылка ВКонтакте</option>
          <option value="name">ФИО или имя</option>
          <option value="username">Username</option>
        </select>
      </div>
    </div>
    <div class="actions"><button type="submit">Собрать досье</button></div>
    <div class="hint">
      Проверяются: базы утечек (LeakCheck, XposedOrNot, НКЦКИ), профиль Gravatar,
      коммиты GitHub (настоящее ФИО), владелец номера, ФИО и адрес из открытых страниц,
      все профили на площадках каталога по найденным никам.
    </div>
  </form>
</div>
<div id="dos-out"></div>
"""


def _dossier_out(value: str, kind: str) -> str:
    if not value:
        return ""
    if kind == "auto":
        kind = identify(value).get("kind", "auto")
    if kind == "phone":
        kind = "phone"
    if kind in ("email", "phone"):
        d = build_dossier(value, kind)
        p = d.get("personal") or {}
        idn, loc, con = d["identity"], d["locations"], d["contacts"]
        body = _stats([
            (d["breaches"].get("count", 0), "записей в утечках", "bad"),
            (len(d["breaches"].get("sources") or []), "источников утечек", ""),
            (len(p.get("names") or []), "имён найдено", "ok"),
            (len(p.get("addresses") or []), "адресов", "acc"),
        ])
        rows = []
        for k, v in (d.get("checked") or {}).get("counts", {}).items():
            rows.append([_esc(k), f"<b>{_esc(v)}</b>"])
        body += ('<div class="panel"><h4>Установленные сведения</h4>' + _kv([
            ("ФИО / имя", idn.get("full_name")),
            ("Дата рождения", idn.get("birth_date")),
            ("Пол", idn.get("gender")),
            ("Адрес проживания", loc.get("address")),
            ("Город", loc.get("city")),
            ("Регион", loc.get("region")),
            ("Район", loc.get("district")),
            ("Индекс", loc.get("zip")),
            ("Страна", loc.get("country")),
            ("Телефоны", con.get("phones")),
            ("Email", con.get("emails")),
            ("Логины", con.get("usernames")),
        ]) + "</div>")
        body += ('<div class="panel"><h4>Что было проверено</h4>' +
                 _table(["Источник", "Результат"], rows) + "</div>")
        ev = []
        for e in (p.get("evidence") or [])[:40]:
            ex = e.get("extracted") or {}
            tags = "".join(f'<span class="tag dim" style="margin:1px 3px 1px 0">{_esc(k)}: {_esc(v)}</span>'
                           for k, v in ex.items())
            link = (f"<a href='{_esc(e.get('url'))}' target='_blank'>{_esc(e.get('source'))}</a>"
                    if e.get("url") else _esc(e.get("source")))
            ev.append([link, _esc((e.get("detail") or "")[:220]), tags])
        body += ('<details"><summary>Доказательства — откуда взяты данные</summary>' +
                 _table(["Источник", "Фрагмент", "Извлечено"], ev) + "</details>")
        body += "<details><summary>Полный отчёт (JSON)</summary><pre>" + _esc(
            json.dumps(d, ensure_ascii=False, indent=2)) + "</pre></details>"
        return body

    # профили: Telegram / ВК / ФИО / username
    if kind == "telegram":
        r = search_telegram(value)
        pr = r.get("profile") or {}
        body = _stats([(1 if r.get("exists") else 0, "аккаунт найден", "ok"),
                        (len(pr.get("subscribers") or ""), "подписчиков", ""),
                        (r.get("leaks", {}).get("found", 0), "в утечках", "bad")])
        body += ('<div class="panel"><h4>Профиль Telegram</h4>' + _kv([
            ("Имя", pr.get("name")), ("Описание", pr.get("bio")),
            ("Подписчики", pr.get("subscribers")), ("Ссылка", r.get("profile_url")),
        ]) + "</div>")
        srcs = [(s.get("name"), s.get("date")) for s in (r.get("leaks") or {}).get("sources", [])]
        body += ('<details"><summary>Источники утечек (' + str(len(srcs)) + ")</summary>" +
                 _table(["Сервис", "Дата"], srcs) + "</details>")
        ment = [(f"<a href='{_esc(m.get('url'))}' target='_blank'>{_esc(m.get('title'))}</a>",
                 _esc(m.get("domain")), _esc((m.get("snippet") or "")[:160]))
                for m in (r.get("mentions") or [])[:30]]
        body += ('<details"><summary>Упоминания в интернете (' + str(len(ment)) + ")</summary>" +
                 _table(["Заголовок", "Домен", "Фрагмент"], ment) + "</details>")
        body += "<details><summary>Полный отчёт (JSON)</summary><pre>" + _esc(
            json.dumps(r, ensure_ascii=False, indent=2)) + "</pre></details>"
        return body

    if kind == "vk":
        r = search_vk(value)
        pr = r.get("profile") or {}
        body = _stats([(1 if pr else 0, "профиль получен", "ok"),
                        (len(r.get("mentions") or []), "упоминаний", ""),
                        ((r.get("leaks") or {}).get("found", 0), "в утечках", "bad")])
        body += ('<div class="panel"><h4>Профиль ВКонтакте</h4>' + _kv([
            ("Имя", pr.get("name")), ("Ник", pr.get("screen_name")),
            ("Город", pr.get("city")), ("Работа", pr.get("work")),
            ("Статус", pr.get("status")), ("Ссылка", r.get("profile_url")),
        ]) + "</div>")
        body += "<details><summary>Полный отчёт (JSON)</summary><pre>" + _esc(
            json.dumps(r, ensure_ascii=False, indent=2)) + "</pre></details>"
        return body

    # ФИО / username — сканер + веб
    res = scan_sync_safe(value, ["social", "messenger", "dev", "professional",
                                 "workplace", "creative", "media", "market"])
    rows = []
    for cat, items in (res.get("by_category") or {}).items():
        for it in items:
            rows.append([f'<span class="tag acc">{_esc(cat)}</span>',
                         f"<b>{_esc(it['site'])}</b>",
                         f"<a href='{_esc(it['url'])}' target='_blank'>{_esc(it['url'])}</a>"])
    body = _stats([(res.get("found_count", 0), "профилей найдено", "ok"),
                    (res.get("total_checked", 0), "сайтов проверено", "")])
    body += '<div class="panel"><h4>Найденные профили</h4>' + _table(
        ["Категория", "Площадка", "Ссылка"], rows) + "</div>"
    body += "<details><summary>Полный отчёт (JSON)</summary><pre>" + _esc(
        json.dumps(res, ensure_ascii=False, indent=2)) + "</pre></details>"
    return body


# ==========================================================================
#  Раздел: Глубокое исследование
# ==========================================================================
def _deep_section() -> str:
    return """
<div class="box">
  <form method="post" action="/deep" data-busy="deep-out" data-msg="Исследуем граф связей, это займёт до нескольких минут...">
    <div class="row2">
      <div>
        <label>Точка входа</label>
        <input name="seed" placeholder="durov / ivanov@example.com / +79991234567" required>
      </div>
      <div>
        <label>Тип</label>
        <select name="kind">
          <option value="auto">Определить автоматически</option>
          <option value="telegram">Telegram</option>
          <option value="username">Username</option>
          <option value="email">Email</option>
          <option value="phone">Телефон</option>
          <option value="vk">ВКонтакте</option>
          <option value="name">ФИО</option>
        </select>
      </div>
    </div>
    <label>Глубина обхода: <span id="dv">2</span></label>
    <input type="range" id="depth" name="depth" min="1" max="3" value="2"
           oninput="document.getElementById('dv').textContent=this.value">
    <div class="actions"><button type="submit">Запустить исследование</button></div>
    <div class="hint">
      Глубина 1 — прямые связи (30–60 сек), 2 — с ветвлением (1–3 мин), 3 — максимум (5–10 мин).
      Из каждого профиля извлекаются ники, email, телефоны, ФИО, фото и ссылки — и поиск продолжается.
    </div>
  </form>
</div>
<div id="deep-out"></div>
"""


def _deep_out(seed: str, kind: str, depth: int) -> str:
    import asyncio
    res = asyncio.run(asyncio.wait_for(
        deep_research(seed, kind, max_depth=depth, max_nodes=120), timeout=900))
    sm = res.get("summary", {})
    body = _stats([
        (sm.get("total_nodes", 0), "узлов графа", "ok"),
        (sm.get("total_edges", 0), "связей", ""),
        (len(res.get("layers", [])), "источников опрошено", "acc"),
        (sm.get("depth_reached", 0), "глубина", ""),
    ])
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for n in res.get("nodes", []):
        groups.setdefault(n["kind"], []).append(n)
    blocks = []
    for k, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        tags = "".join(
            f'<span class="tag dim" style="margin:1px 3px 1px 0" '
            f'title="{_esc(", ".join(n["sources"])[:120])}">{_esc(n["value"][:46])}</span>'
            for n in items[:80])
        blocks.append(f'<div class="panel"><h4>{_esc(k)} <span class="tag acc">{len(items)}</span></h4>'
                      f'<div class="tags">{tags}</div></div>')
    body += "".join(blocks)
    lrows = [[l["depth"], f'<span class="tag acc">{_esc(l["kind"])}</span>',
               _esc(str(l["query"])[:40]), f"<b>{l['new_nodes']}</b>",
               _esc(", ".join(l.get("sources", []))[:90])] for l in res.get("layers", [])]
    body += ('<div class="panel"><h4>Слои исследования</h4>' +
             _table(["Глубина", "Тип", "Запрос", "Новых связей", "Источники"], lrows) + "</div>")
    erows = [[_esc(e["from"][:44]), _esc(e["relation"]), _esc(e["to"][:44])]
             for e in res.get("edges", [])[:150]]
    body += ('<details"><summary>Связи (' + str(len(res.get("edges", []))) + ")</summary>" +
             _table(["Откуда", "Связь", "Куда"], erows) + "</details>")
    body += "<details><summary>Полный граф (JSON)</summary><pre>" + _esc(
        json.dumps(res, ensure_ascii=False, indent=2)) + "</pre></details>"
    return body


# ==========================================================================
#  Раздел: Источники
# ==========================================================================
def _sources_section() -> str:
    branches = build_branches()
    total = sum(b["count"] for b in branches)
    map_html = (f'<div class="mapwrap">{render_svg(branches)}</div>')
    details = render_detail(branches)
    return f"""
<div class="grid">
  <div class="card acc"><b>{total}</b><span>источников</span></div>
  <div class="card"><b>{len(branches)}</b><span>нитей</span></div>
  <div class="card"><b>{len(all_categories())}</b><span>категорий</span></div>
</div>
{map_html}
{details}
"""


# ==========================================================================
#  Раздел: Инструменты
# ==========================================================================
TOOL_TABS = [("leaks", "Утечки"), ("web", "Веб-поиск"),
             ("net", "IP и домен"), ("corr", "Корреляция")]


def _tools_section(tab: str = "leaks") -> str:
    tabs = "".join(
        f'<a href="/?s=tools&t={k}" class="{"on" if k == tab else ""}">{_esc(t)}</a>'
        for k, t in TOOL_TABS)
    head = f'<div class="tabs">{tabs}</div>'
    if tab == "leaks":
        return head + """
<div class="box">
  <form method="post" action="/tools-leaks" data-busy="tool-out" data-msg="Проверяем базы утечек...">
    <label>Email, телефон или логин</label>
    <input name="value" placeholder="ivanov@example.com" required>
    <div class="actions"><button type="submit">Проверить</button></div>
    <div class="hint">LeakCheck, XposedOrNot (11.6 млрд записей) и Safe Surf / НКЦКИ — бесплатно, без ключей.</div>
  </form>
</div>
<div id="tool-out"></div>
"""
    if tab == "web":
        return head + """
<div class="box">
  <form method="post" action="/tools-web" data-busy="tool-out" data-msg="Ищем в Google...">
    <label>Точная фраза</label>
    <input name="query" placeholder="&quot;ivanov@example.com&quot;" required>
    <div class="actions"><button type="submit">Искать</button></div>
    <div class="hint">Через Serper.dev (Google). При наличии ключа — точнее и быстрее.</div>
  </form>
</div>
<div id="tool-out"></div>
"""
    if tab == "net":
        return head + """
<div class="box">
  <form method="post" action="/tools-net" data-busy="tool-out" data-msg="Собираем данные...">
    <div class="row2">
      <div><label>IP-адрес</label><input name="ip" placeholder="8.8.8.8"></div>
      <div><label>Домен</label><input name="domain" placeholder="example.com"></div>
    </div>
    <div class="row2">
      <div><label>Телефон</label><input name="phone" placeholder="+79991234567"></div>
      <div><label>ФИО</label><input name="name" placeholder="Иван Иванов"></div>
    </div>
    <div class="actions"><button type="submit">Проверить</button></div>
  </form>
</div>
<div id="tool-out"></div>
"""
    return head + """
<div class="box">
  <form method="post" action="/tools-corr" data-busy="tool-out" data-msg="Сопоставляем профили...">
    <label>Имя или ник для корреляции</label>
    <input name="value" placeholder="Pavel Durov" required>
    <div class="actions"><button type="submit">Сопоставить</button></div>
    <div class="hint">Сопоставление аккаунтов по имени, нику и фото (perceptual hash).</div>
  </form>
</div>
<div id="tool-out"></div>
"""


# ==========================================================================
#  Раздел: Ключи
# ==========================================================================
def _keys_section() -> str:
    rows = []
    for s in key_status():
        state = ('<span class="tag ok">подключён</span>' if s["active"]
                 else '<span class="tag dim">не задан</span>')
        key = _esc(s["masked"]) if s["active"] else "—"
        rows.append([f"<b>{_esc(s['service'])}</b><br><span class='hint'>{_esc(s['env'])}</span>",
                     state, f"<code>{key}</code>",
                     f"<a href='{_esc(s['url'])}' target='_blank'>{_esc(s['url'])}</a><br>"
                     f"<span class='hint'>{_esc(s['price'])}</span>"])
    fields = []
    for name, meta in KEY_MAP.items():
        badge = ('<span class="tag ok">free tier</span>' if meta["free"] else "")
        fields.append(
            f'<label>{_esc(meta["service"])} — <code>{_esc(name)}</code> {badge}</label>'
            f'<input name="{_esc(name)}" placeholder="{_esc(meta["price"])}" autocomplete="off">'
            f'<div class="hint">{_esc(meta["what"])}</div>')
    return f"""
<div class="box">
  <form method="post" action="/keys">
    {"".join(fields)}
    <div class="actions"><button type="submit">Сохранить ключи</button></div>
    <div class="hint">Ключи сохраняются в osint_keys.json рядом с программой и подхватываются автоматически.</div>
  </form>
</div>
<div class="panel"><h4>Статус сервисов</h4>{_table(["Сервис", "Статус", "Ключ", "Тариф"], rows)}</div>
"""


# ==========================================================================
#  Роуты
# ==========================================================================
@app.get("/", response_class=HTMLResponse)
def index(s: str = "scan", t: str = "leaks"):
    if s == "scan":
        body = _scan_section()
    elif s == "dossier":
        body = _dossier_section()
    elif s == "deep":
        body = _deep_section()
    elif s == "sources":
        body = _sources_section()
    elif s == "tools":
        body = _tools_section(t)
    elif s == "keys":
        body = _keys_section()
    else:
        body = _scan_section()
    return _page(s, body)


@app.post("/scan", response_class=HTMLResponse)
def scan_route(value: str = Form(...), cats: str = Form("")):
    sel = [c.strip() for c in cats.split(",") if c.strip()] or None
    body = _scan_out(value.strip(), sel)
    return _page("scan", _scan_section(value) + body)


@app.post("/dossier", response_class=HTMLResponse)
def dossier_route(value: str = Form(...), kind: str = Form("auto")):
    body = _dossier_section() + _dossier_out(value.strip(), kind)
    return _page("dossier", body)


@app.post("/deep", response_class=HTMLResponse)
def deep_route(seed: str = Form(...), kind: str = Form("auto"), depth: str = Form("2")):
    try:
        d = max(1, min(int(depth), 3))
    except Exception:
        d = 2
    body = _deep_section() + _deep_out(seed.strip(), kind, d)
    return _page("deep", body)


@app.post("/tools-leaks", response_class=HTMLResponse)
def tools_leaks(value: str = Form(...)):
    v = value.strip()
    res = full_leak_check(v, is_email=("@" in v))
    lc = res.get("leakcheck", {})
    xon = check_xposedornot(v) if "@" in v else None
    ss = safesurf_ru.check(v)
    rows = [
        ["LeakCheck", f"<b>{lc.get('found', 0)}</b>",
         _esc(", ".join(lc.get("leaked_field_labels", [])[:25]))],
        ["XposedOrNot", f"<b>{len(xon.get('breaches', [])) if xon else 0}</b>",
         _esc(", ".join(xon.get("breaches", [])[:25]) if xon else "— только для email")],
        ["Safe Surf / НКЦКИ", f"<b>{ss.get('matches', '—')}</b>", _esc(ss.get("summary") or "")],
    ]
    srcs = [(s.get("name"), s.get("date")) for s in (lc.get("sources") or [])[:60]]
    body = _tools_section("leaks") + _stats([
        (lc.get("found", 0), "записей в утечках", "bad"),
        (len(srcs), "источников", ""),
        (len(lc.get("leaked_field_labels", [])), "типов данных", "warn"),
    ])
    body += ('<div class="panel"><h4>Сводка по базам</h4>' +
             _table(["База", "Записей", "Какие данные утекли"], rows) + "</div>")
    body += ('<details><summary>Источники утечек (' + str(len(srcs)) + ")</summary>" +
             _table(["Сервис", "Дата"], srcs) + "</details>")
    body += "<details><summary>Полный отчёт (JSON)</summary><pre>" + _esc(
        json.dumps(res, ensure_ascii=False, indent=2)) + "</pre></details>"
    return _page("tools", body)


@app.post("/tools-web", response_class=HTMLResponse)
def tools_web(query: str = Form(...)):
    q = query.strip()
    sp = serper_search(q, limit=25)
    if sp.get("active") and sp.get("results"):
        rows = [(f"<a href='{_esc(r['url'])}' target='_blank'>{_esc(r.get('title'))}</a>",
                 _esc(r.get("domain")), _esc((r.get("snippet") or "")[:180]))
                for r in sp["results"]]
        engine = "Google / Serper.dev"
    else:
        res = web_search(q, limit=25)
        rows = [(f"<a href='{_esc(r['url'])}' target='_blank'>{_esc(r.get('title'))}</a>",
                 _esc(r.get("domain")), _esc((r.get("snippet") or "")[:180]))
                for r in res.get("results", [])]
        engine = "DuckDuckGo"
    body = _tools_section("web") + _stats([(len(rows), "результатов", "ok"),
                                           (engine, "источник", "")])
    body += '<div class="panel"><h4>Результаты</h4>' + _table(
        ["Заголовок", "Домен", "Фрагмент"], rows) + "</div>"
    return _page("tools", body)


@app.post("/tools-net", response_class=HTMLResponse)
def tools_net(ip: str = Form(""), domain: str = Form(""),
              phone: str = Form(""), name: str = Form("")):
    out: Dict[str, Any] = {}
    if ip.strip():
        out["IP"] = search_ip(ip.strip())
    if domain.strip():
        out["Домен"] = search_domain(domain.strip())
    if phone.strip():
        out["Телефон"] = search_phone(phone.strip())
    if name.strip():
        out["ФИО"] = search_name(name.strip())
    body = _tools_section("net")
    if out:
        body += ('<div class="panel"><h4>Собранные данные</h4>' +
                 _table(["Раздел", "Данные"],
                        [[k, f"<pre style='max-height:340px'>{_esc(json.dumps(v, ensure_ascii=False, indent=2))}</pre>"]
                         for k, v in out.items()]) + "</div>")
    return _page("tools", body)


@app.post("/tools-corr", response_class=HTMLResponse)
def tools_corr(value: str = Form(...)):
    v = value.strip()
    body = _tools_section("corr")
    try:
        from correlator import username_variants, name_match
        variants = username_variants(v)
        body += _stats([(len(variants), "вариантов ника", "acc"), (1, "введён запрос", "")])
        body += ('<div class="panel"><h4>Варианты написания ника</h4><div class="tags">' +
                 "".join(f'<span class="tag acc" style="margin:2px 4px 2px 0">{_esc(x)}</span>'
                         for x in variants) + "</div></div>")
    except Exception as e:
        body += f'<div class="panel"><h4>Ошибка</h4><pre>{_esc(str(e))}</pre></div>'
    return _page("tools", body)


@app.post("/keys", response_class=HTMLResponse)
async def keys_route(request: Request):
    form = await request.form()
    current = {s["env"]: s for s in key_status()}
    keys = {}
    for name in KEY_MAP:
        v = (form.get(name) or "").strip()
        if not v:
            continue
        st = current.get(name, {})
        if st.get("active") and v == st.get("masked"):
            continue
        keys[name] = v
    if keys:
        save_keys(keys)
    body = _keys_section()
    body = ('<div class="panel"><h4>Сохранено</h4>'
            + ("<p>Ключи сохранены в osint_keys.json и подхвачены автоматически.</p>" if keys
               else "<p>Новые ключи не заданы.</p>") + "</div>") + body
    return _page("keys", body)


@app.get("/api/scan", response_class=JSONResponse)
async def api_scan(value: str, cats: str = ""):
    sel = [c.strip() for c in cats.split(",") if c.strip()] or None
    return JSONResponse(await scan(value, sel))


# ==========================================================================
#  Статика / PWA
# ==========================================================================
@app.get("/favicon.ico")
def favicon():
    from fastapi.responses import Response
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
           '<rect width="100" height="100" rx="14" fill="#0a0d13"/>'
           '<path d="M50 26 L74 38 L74 62 L50 74 L26 62 L26 38 Z" fill="#e8b23a"/></svg>')
    return Response(svg, media_type="image/svg+xml")


@app.get("/manifest.json")
def manifest():
    from fastapi.responses import Response
    import json as _j
    data = {
        "name": "Gotham OSINT",
        "short_name": "Gotham OSINT",
        "description": "Поиск публичной информации по username, email, телефону и домену",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": "#0a0d13",
        "theme_color": "#0a0d13",
        "lang": "ru",
        "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}],
        "shortcuts": [
            {"name": "Сканирование", "url": "/?s=scan"},
            {"name": "Досье", "url": "/?s=dossier"},
            {"name": "Источники", "url": "/?s=sources"},
        ],
    }
    return Response(_j.dumps(data, ensure_ascii=False), media_type="application/manifest+json")


@app.get("/icon.svg")
def icon():
    from fastapi.responses import Response
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
           '<rect width="512" height="512" rx="110" fill="#0a0d13"/>'
           '<path d="M256 133 L373 197 L373 315 L256 379 L139 315 L139 197 Z" fill="#e8b23a"/>'
           '<path d="M256 186 L314 216 L314 276 L256 306 L198 276 L198 216 Z" fill="#0a0d13"/></svg>')
    return Response(svg, media_type="image/svg+xml")


@app.get("/sw.js")
def service_worker():
    from fastapi.responses import Response
    sw = """
const CACHE='gotham-osint-v1';
const CORE=['/','/manifest.json','/icon.svg','/favicon.ico'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const u=new URL(e.request.url);
  if(u.origin!==location.origin)return;
  if(u.pathname.startsWith('/api/'))return;
  e.respondWith(fetch(e.request).then(r=>{const cp=r.clone();caches.open(CACHE).then(c=>c.put(e.request,cp)).catch(()=>{});return r;}).catch(()=>caches.match(e.request).then(r=>r||caches.match('/'))));
});
"""
    return Response(sw, media_type="application/javascript",
                    headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8765"))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"[Gotham OSINT] http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
