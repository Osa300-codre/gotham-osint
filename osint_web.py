#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Веб-интерфейс OSINT-помощника — стиль Gotham."""

import html
import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from osint_finder import (
    search_email,
    search_username_basic,
    search_ip,
    search_domain,
    search_phone,
    search_name,
    DISCLAIMER,
)
from scanner import scan
from site_checks import all_categories
from websearch import web_search
from leaks import full_leak_check, check_xposedornot
import safesurf_ru
from premium import (
    key_status, save_keys, KEY_MAP, serper_search,
    hunter_domain_emails, dehashed_search,
)
from identify import (
    identify, search_telegram, search_email_detailed,
    search_vk, search_phone_deep,
)
from dossier import build_dossier

app = FastAPI(title="Gotham OSINT")

CATS = all_categories()

# --------------------------------------------------------------------------
# CSS — стиль Gotham: тёмный, угловатый, золото + чёрное
# --------------------------------------------------------------------------
CSS = """
:root{
  --bg:#05070b; --bg2:#0a0e16; --panel:#0d131f; --panel2:#111927;
  --line:#1e2a3f; --line2:#2a3a56;
  --gold:#f5c542; --gold2:#ffd979; --gold-dim:#8a6f1e;
  --text:#e8edf7; --muted:#8494ad; --dim:#5a6a83;
  --ok:#3ddc84; --warn:#f5a623; --bad:#ff5c5c; --info:#4aa8ff;
  --glow:0 0 0 1px rgba(245,197,66,.18), 0 8px 40px rgba(0,0,0,.6);
  --f-display:'Bebas Neue','Oswald','Impact','Arial Narrow',sans-serif;
  --f-body:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
  --f-mono:'JetBrains Mono','Cascadia Code','Consolas',monospace;
  --clip:polygon(0 0,calc(100% - 14px) 0,100% 14px,100% 100%,14px 100%,0 calc(100% - 14px));
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:var(--f-body); background:var(--bg); color:var(--text);
  min-height:100vh; overflow-x:hidden; position:relative;
  background-image:
    radial-gradient(1200px 600px at 50% -10%, rgba(245,197,66,.07), transparent 60%),
    radial-gradient(800px 500px at 100% 0%, rgba(74,168,255,.05), transparent 60%),
    linear-gradient(180deg,#05070b 0%,#070b12 40%,#05070b 100%);
}
body::before{
  content:''; position:fixed; inset:0; pointer-events:none; z-index:1;
  background:repeating-linear-gradient(0deg,rgba(255,255,255,.014) 0 1px,transparent 1px 3px);
  mix-blend-mode:overlay;
}
body::after{
  content:''; position:fixed; inset:0; pointer-events:none; z-index:1;
  background:radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,.75) 100%);
}
.wrap{max-width:1280px;margin:0 auto;padding:0 20px 60px;position:relative;z-index:2}

/* ---------- HEADER ---------- */
header{
  position:relative; padding:34px 0 26px; margin-bottom:24px;
  border-bottom:1px solid var(--line); overflow:hidden;
}
header::after{
  content:''; position:absolute; left:0; right:0; bottom:-1px; height:2px;
  background:linear-gradient(90deg,transparent,var(--gold),transparent);
  opacity:.55;
}
.bat-signal{
  position:absolute; top:-140px; left:50%; transform:translateX(-50%);
  width:520px; height:520px; pointer-events:none; opacity:.14;
  background:radial-gradient(circle,var(--gold) 0%,rgba(245,197,66,.16) 32%,transparent 66%);
  animation:signal 6s ease-in-out infinite;
}
@keyframes signal{0%,100%{opacity:.08;transform:translateX(-50%) scale(.9)}50%{opacity:.2;transform:translateX(-50%) scale(1.06)}}
.brand{display:flex;align-items:center;gap:20px;position:relative;z-index:3}
.emblem{
  width:74px;height:74px;flex:0 0 74px;display:grid;place-items:center;
  background:radial-gradient(circle at 50% 42%,#ffd979 0%,var(--gold) 42%,#8a6f1e 100%);
  clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);
  box-shadow:0 0 34px rgba(245,197,66,.45);
}
.emblem svg{width:56px;height:34px;fill:#05070b}
h1{
  font-family:var(--f-display); font-size:46px; line-height:.95; letter-spacing:3px;
  text-transform:uppercase; color:var(--gold2);
  text-shadow:0 0 26px rgba(245,197,66,.35);
}
.brand .subtitle{
  font-size:12px; letter-spacing:3.5px; text-transform:uppercase;
  color:var(--muted); margin-top:6px; font-weight:600;
  display:inline-block; padding-bottom:2px;
  border-bottom:1px solid var(--line2);
}
.hdr-right{margin-left:auto;text-align:right;font-family:var(--f-mono);font-size:11.5px;color:var(--dim);line-height:1.8}
.hdr-right b{color:var(--gold);font-weight:600}
.skyline{position:absolute;left:0;right:0;bottom:0;height:90px;opacity:.16;pointer-events:none;z-index:2}

/* ---------- ALERT ---------- */
.alert{
  display:flex;gap:12px;align-items:flex-start;padding:13px 16px;margin-bottom:22px;
  background:linear-gradient(90deg,rgba(245,166,35,.10),rgba(245,166,35,.02));
  border:1px solid rgba(245,166,35,.28);border-left:3px solid var(--warn);
  font-size:13px;color:#f0d9a8;clip-path:var(--clip);
}
.alert svg{flex:0 0 18px;margin-top:1px}

/* ---------- TABS ---------- */
.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:18px;background:var(--panel);
  padding:5px;clip-path:var(--clip);border:1px solid var(--line)}
.tab{
  padding:11px 16px;border:1px solid transparent;cursor:pointer;font-size:12.5px;
  font-weight:600;letter-spacing:.3px;color:var(--muted);text-transform:uppercase;
  transition:.18s;position:relative;user-select:none;display:flex;align-items:center;gap:7px;
  white-space:nowrap;
}
.tab svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8}
.tab:hover{color:var(--text);background:rgba(245,197,66,.06)}
.tab.active{
  color:#05070b;background:linear-gradient(180deg,var(--gold2),var(--gold));
  clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px));
  box-shadow:0 0 22px rgba(245,197,66,.3);
}

/* ---------- PANEL ---------- */
.panel{display:none;background:linear-gradient(180deg,var(--panel),var(--bg2));
  border:1px solid var(--line);padding:24px;clip-path:var(--clip);box-shadow:var(--glow)}
.panel.active{display:block;animation:fade .28s ease}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.panel-title{font-family:var(--f-display);font-size:26px;letter-spacing:2px;color:var(--gold);
  text-transform:uppercase;margin-bottom:4px}
.panel-sub{font-size:13px;color:var(--muted);margin-bottom:22px}

/* ---------- FORM ---------- */
label{display:block;font-size:11px;letter-spacing:1.6px;text-transform:uppercase;
  color:var(--muted);margin:16px 0 7px;font-weight:700}
input,select,textarea{
  width:100%;padding:13px 15px;border-radius:0;font-size:14.5px;
  background:rgba(0,0,0,.42);border:1px solid var(--line2);color:var(--text);
  font-family:var(--f-mono);transition:.18s;
}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--gold);
  box-shadow:0 0 0 3px rgba(245,197,66,.12);background:rgba(0,0,0,.6)}
input::placeholder{color:var(--dim)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.hint{font-size:12px;color:var(--dim);margin-top:7px;line-height:1.6}
button{
  margin-top:20px;padding:14px 26px;border:none;cursor:pointer;font-size:14px;
  font-weight:800;letter-spacing:1.6px;text-transform:uppercase;font-family:var(--f-body);
  background:linear-gradient(180deg,var(--gold2),var(--gold));color:#05070b;
  clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px));
  transition:.18s;position:relative;overflow:hidden;
}
button:hover{filter:brightness(1.12);box-shadow:0 0 30px rgba(245,197,66,.4)}
button:active{transform:translateY(1px)}
button.ghost{background:transparent;color:var(--gold);border:1px solid var(--gold-dim)}
button.ghost:hover{background:rgba(245,197,66,.1);box-shadow:none}
button.mini{margin:0;padding:7px 12px;font-size:11px;letter-spacing:.8px}
.btn-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

/* ---------- CHIPS ---------- */
.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:10px}
.chip{
  background:rgba(0,0,0,.4);border:1px solid var(--line2);padding:6px 13px;
  font-size:12px;cursor:pointer;color:var(--muted);transition:.16s;user-select:none;
  clip-path:polygon(0 0,calc(100% - 7px) 0,100% 7px,100% 100%,7px 100%,0 calc(100% - 7px));
}
.chip:hover{border-color:var(--gold-dim);color:var(--text)}
.chip.on{background:rgba(245,197,66,.16);border-color:var(--gold);color:var(--gold2);font-weight:600}

/* ---------- STATS ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:20px 0}
.stat{background:linear-gradient(180deg,rgba(245,197,66,.07),rgba(0,0,0,.25));
  border:1px solid var(--line);padding:15px 17px;position:relative;overflow:hidden;
  clip-path:polygon(0 0,calc(100% - 11px) 0,100% 11px,100% 100%,11px 100%,0 calc(100% - 11px))}
.stat::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--gold);opacity:.65}
.stat b{display:block;font-family:var(--f-display);font-size:36px;line-height:1;color:var(--gold2)}
.stat span{font-size:10.5px;letter-spacing:1.4px;text-transform:uppercase;color:var(--muted);margin-top:5px;display:block}
.stat.ok b{color:var(--ok)} .stat.ok::before{background:var(--ok)}
.stat.bad b{color:var(--bad)} .stat.bad::before{background:var(--bad)}
.stat.warn b{color:var(--warn)} .stat.warn::before{background:var(--warn)}

/* ---------- TABLE ---------- */
h3{font-family:var(--f-display);font-size:19px;letter-spacing:2px;color:var(--gold);
  text-transform:uppercase;margin:28px 0 12px;padding-bottom:9px;
  border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px}
h3 .count{font-family:var(--f-mono);font-size:12px;color:var(--muted);
  background:rgba(245,197,66,.1);padding:2px 9px;border:1px solid var(--line2)}
.tablewrap{border:1px solid var(--line);overflow-x:auto;background:rgba(0,0,0,.25)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{background:rgba(245,197,66,.08);color:var(--gold);text-align:left;padding:11px 14px;
  font-size:10.5px;letter-spacing:1.4px;text-transform:uppercase;font-weight:700;
  border-bottom:1px solid var(--line2);white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid rgba(30,42,63,.6);vertical-align:top}
tr:hover td{background:rgba(245,197,66,.045)}
tr:last-child td{border-bottom:none}
a{color:var(--info);text-decoration:none;word-break:break-all}
a:hover{color:var(--gold2);text-decoration:underline}
.tag{display:inline-block;padding:3px 9px;font-size:10.5px;font-weight:700;letter-spacing:.6px;
  text-transform:uppercase;border:1px solid;white-space:nowrap}
.tag.cat{color:var(--gold);border-color:var(--gold-dim);background:rgba(245,197,66,.08)}
.tag.ok{color:var(--ok);border-color:rgba(61,220,132,.45);background:rgba(61,220,132,.1)}
.tag.warn{color:var(--warn);border-color:rgba(245,166,35,.45);background:rgba(245,166,35,.1)}
.tag.bad{color:var(--bad);border-color:rgba(255,92,92,.45);background:rgba(255,92,92,.1)}
.tag.dim{color:var(--muted);border-color:var(--line2);background:rgba(0,0,0,.3)}

/* ---------- MISC ---------- */
pre{background:#03050a;border:1px solid var(--line);padding:16px;overflow-x:auto;
  font-family:var(--f-mono);font-size:12px;line-height:1.65;color:#8fe3a8;margin:0;
  max-height:520px;overflow-y:auto}
pre::-webkit-scrollbar{width:9px;height:9px}
pre::-webkit-scrollbar-thumb{background:var(--line2)}
pre::-webkit-scrollbar-track{background:#03050a}
details{margin-top:14px;border:1px solid var(--line);background:rgba(0,0,0,.22)}
summary{cursor:pointer;padding:12px 15px;font-size:13px;color:var(--muted);user-select:none;
  list-style:none;display:flex;align-items:center;gap:9px}
summary::-webkit-details-marker{display:none}
summary::before{content:'▸';color:var(--gold);transition:.2s;font-size:15px}
details[open] summary::before{transform:rotate(90deg)}
details[open] summary{border-bottom:1px solid var(--line);color:var(--text)}
details ul{margin:0;padding:14px 20px 14px 40px;font-size:12.5px;color:var(--muted);max-height:340px;overflow-y:auto}
details li{margin-bottom:5px;line-height:1.5}
.loading{text-align:center;padding:52px 20px;color:var(--muted);font-size:14px}
.bat-loader{
  width:46px;height:46px;margin:0 auto 18px;background:var(--gold);
  clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);
  animation:pulse 1.1s ease-in-out infinite;
}
@keyframes pulse{0%,100%{transform:scale(.82) rotate(-4deg);opacity:.55}50%{transform:scale(1.06) rotate(4deg);opacity:1}}
.empty{text-align:center;padding:38px;color:var(--dim);font-size:13.5px}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:16px 0}
.toolbar input{max-width:300px;margin:0}
.spacer{flex:1}
.kbd{font-family:var(--f-mono);font-size:11px;background:rgba(245,197,66,.12);
  border:1px solid var(--gold-dim);padding:1px 6px;color:var(--gold)}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:#03050a}
::-webkit-scrollbar-thumb{background:var(--line2)}
::-webkit-scrollbar-thumb:hover{background:var(--gold-dim)}
.toast{position:fixed;bottom:24px;right:24px;background:var(--gold);color:#05070b;
  padding:12px 20px;font-weight:700;font-size:13px;z-index:100;
  clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px));
  box-shadow:0 8px 34px rgba(0,0,0,.6);animation:slide .25s ease}
@keyframes slide{from{transform:translateX(120%);opacity:0}to{transform:none;opacity:1}}
@media(max-width:820px){
  .row,.row3{grid-template-columns:1fr}
  h1{font-size:32px} .brand{gap:14px} .emblem{width:56px;height:56px;flex:0 0 56px}
  .hdr-right{display:none} .panel{padding:18px}
}
"""

# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------
ICONS = {
    "scan": '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>',
    "mail": '<svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16"/><path d="M2 6l10 7 10-7"/></svg>',
    "leak": '<svg viewBox="0 0 24 24"><path d="M12 2s7 7.5 7 13a7 7 0 01-14 0c0-5.5 7-13 7-13z"/></svg>',
    "key": '<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v2"/></svg>',
    "globe": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 010 18a15 15 0 010-18z"/></svg>',
    "shield": '<svg viewBox="0 0 24 24"><path d="M12 2l8 3v7c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V5z"/></svg>',
    "target": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1"/></svg>',
}

BAT_EMBLEM = '''<svg viewBox="0 0 100 60"><path d="M50 6c-5 6-12 8-20 7-6-1-12-5-18-9-2 8-4 14-10 20 6 0 10 2 13 5 4-1 8-1 12 1 4-1 8-1 12 1 4-2 8-2 12-1 4-2 8-2 12 1 3-3 7-5 13-5-6-6-8-12-10-20-6 4-12 8-18 9-8 1-15-1-20-7z"/></svg>'''

SKYLINE = '''<svg class="skyline" viewBox="0 0 1440 90" preserveAspectRatio="none">
<path fill="#0a0e16" d="M0 90V62h24V38h18v52h14V48h26v42h18V28h22v62h16V54h30v36h12V20h16v70h20V44h26v46h14V34h20v56h18V50h28v40h16V24h24v66h20V46h22v44h16V36h26v54h20V56h24v34h14V30h18v60h22V42h24v48h16V52h26v38h18V36h22v54h16V26h20v64h24V48h22v42h14V34h26v56h18V50h24v40h16V44h28v46h20V30h18v60h24V52h26v38h14V40h22v50h20V56h26v34h18V34h20v56h22V46h24v44h16V38h28v52h20V58h24v32h16V44h22v46h20V30h18v60h26V50h22v40h20V40h20v50h24V56h24v34h18V46h26v44h20V36h18v54h24V54h22v36h20V44h24v46h20V38h16v52h24V60h20v30h24V50h22v40h26V42h20v48h16V56h24v34h20V46h22v44h18V38h20v52h26V54h20v36h22V60h18v30h26V48h20v42h22V56h24v34h18V42h20v48h22V52h20v38h24V60h26v30h20V48h22v42h18V56h26v34h22V44h20v46h24V58h18v32h30V62h20v28h40V90z"/>
</svg>'''

HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GOTHAM OSINT &mdash; поиск публичных данных</title>
<link rel="icon" href="/favicon.ico" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon.svg">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#f5c542">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Gotham OSINT">
<meta name="description" content="Поиск публичной информации по username, email, телефону, IP и домену. 506 сайтов, проверка утечек, веб-поиск.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>__CSS__</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="bat-signal"></div>
  __SKYLINE__
  <div class="brand">
    <div class="emblem">__EMBLEM__</div>
    <div>
      <h1>Gotham OSINT</h1>
      <div class="subtitle">Поиск публичных данных &middot; 500+ источников</div>
    </div>
    <div class="hdr-right">
      СЕРВЕР: <b>127.0.0.1:8765</b><br>
      САЙТОВ В КАТАЛОГЕ: <b>506</b><br>
      АКТИВНЫХ КЛЮЧЕЙ: <b>__NKEYS__</b>
    </div>
  </div>
</header>

<div class="alert">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>
  <div><b>Этическое предупреждение.</b> __DISCLAIMER__</div>
</div>

<div class="tabs" id="tabs">
  <div class="tab active" data-t="tab-scan">__ICO_SCAN__Сканирование</div>
  <div class="tab" data-t="tab-email">__ICO_MAIL__Email</div>
  <div class="tab" data-t="tab-leaks">__ICO_LEAK__Утечки</div>
  <div class="tab" data-t="tab-exact">__ICO_TARGET__Точный поиск</div>
  <div class="tab" data-t="tab-dossier">__ICO_SHIELD__Досье</div>
  <div class="tab" data-t="tab-web">__ICO_GLOBE__Веб-поиск</div>
  <div class="tab" data-t="tab-keys">__ICO_KEY__Ключи</div>
  <div class="tab" data-t="tab-other">__ICO_TARGET__IP / домен / тел.</div>
</div>

<!-- ===== SCAN ===== -->
<div class="panel active" id="tab-scan">
  <div class="panel-title">Сканирование профилей</div>
  <div class="panel-sub">Проверка username по 506 сайтам в 21 категории. Занимает 10&ndash;30 секунд.</div>
  <form method="post" action="/scan" id="scanform">
    <label>Username / идентификатор</label>
    <input name="value" id="scanvalue" placeholder="octocat" required>
    <label>Категории сайтов <span class="hint" style="display:inline">(пусто &mdash; все)</span></label>
    <div class="chips" id="chips">__CATS__</div>
    <input type="hidden" name="cats" id="cats" value="">
    <div class="btn-row">
      <button type="submit">Начать сканирование</button>
      <button type="button" class="ghost" id="randscan">Случайный пример</button>
    </div>
  </form>
  <div id="scan-result"></div>
</div>

<!-- ===== EMAIL ===== -->
<div class="panel" id="tab-email">
  <div class="panel-title">Разбор email</div>
  <div class="panel-sub">Gravatar-профиль, домен, утечки, упоминания в Google, сотрудники компании (Hunter.io).</div>
  <form method="post" action="/email">
    <label>Email</label>
    <input name="email" placeholder="ivanov@example.com" required>
    <button type="submit">Исследовать email</button>
  </form>
  <div id="email-result"></div>
</div>

<!-- ===== LEAKS ===== -->
<div class="panel" id="tab-leaks">
  <div class="panel-title">Проверка утечек</div>
  <div class="panel-sub">Бесплатно, без ключей: LeakCheck + Hudson Rock (инфостилеры). HIBP подключается при наличии ключа.</div>
  <form method="post" action="/leaks">
    <label>Email, телефон, логин или IP</label>
    <input name="value" placeholder="ivanov@example.com" required>
    <label>HIBP API-ключ <span class="hint" style="display:inline">(необязательно)</span></label>
    <input name="hibp_key" placeholder="оставьте пустым &mdash; LeakCheck работает бесплатно">
    <button type="submit">Проверить утечки</button>
  </form>
  <div id="leaks-result"></div>
</div>

<!-- ===== WEB ===== -->
<div class="panel" id="tab-exact">
  <div class="panel-title">Точный поиск</div>
  <div class="panel-sub">Досье по конкретному идентификатору: Telegram, email, ссылка ВК или номер телефона.</div>

  <form method="post" action="/exact" id="exactform">
    <div class="row3">
      <div>
        <label>Telegram username</label>
        <input name="telegram" placeholder="durov">
      </div>
      <div>
        <label>Email</label>
        <input name="email" placeholder="ivanov@example.com">
      </div>
      <div>
        <label>Ссылка ВК</label>
        <input name="vk" placeholder="https://vk.com/durov">
      </div>
    </div>
    <div class="row3" style="margin-top:14px">
      <div>
        <label>Телефон</label>
        <input name="phone" placeholder="+79991234567">
      </div>
      <div style="grid-column: span 2; display:flex; align-items:flex-end">
        <button type="submit" style="width:100%">Собрать досье</button>
      </div>
    </div>
    <div class="hint">Заполните любое из полей — можно несколько сразу. Тип определяется автоматически.</div>
  </form>
  <div id="exact-result"></div>
</div>

<div class="panel" id="tab-dossier">
  <div class="panel-title">Досье</div>
  <div class="panel-sub">Максимум доступных публичных данных по email или телефону: ФИО, дата рождения, адрес, контакты, утечки, связанные аккаунты.</div>

  <form method="post" action="/dossier" id="dossierform">
    <div class="row">
      <div>
        <label>Email или номер телефона</label>
        <input name="value" placeholder="ivanov@example.com или +7 999 123-45-67" required>
      </div>
      <div style="display:flex;align-items:flex-end">
        <button type="submit" style="width:100%">Собрать досье</button>
      </div>
    </div>
    <div class="hint">
      Номер можно вводить в <b>любом формате</b> — <b>+79991234567</b>, <b>8 999 123-45-67</b>,
      <b>89991234567</b>: программа сама подберёт все варианты записи и найдёт объявления.
      Проверяются базы утечек (LeakCheck, XposedOrNot, НКЦКИ), ФИО и адрес с открытых страниц,
      владелец номера и все профили в 506 соцсетях. Сбор занимает 20–40 секунд.
    </div>
  </form>
  <div id="dossier-result"></div>
</div>

<div class="panel" id="tab-web">
  <div class="panel-title">Веб-поиск</div>
  <div class="panel-sub">Поиск точных фраз через Google (Serper.dev) с автоматическим откатом на DuckDuckGo.</div>
  <form method="post" action="/web">
    <label>Точная фраза</label>
    <input name="query" placeholder="&quot;ivanov@example.com&quot;" required>
    <button type="submit">Искать</button>
  </form>
  <div id="web-result"></div>
</div>

<!-- ===== KEYS ===== -->
<div class="panel" id="tab-keys">
  <div class="panel-title">Ключи и премиум</div>
  <div class="panel-sub">Вставьте ключи &mdash; они сохранятся в <b>osint_keys.json</b> и подхватятся автоматически.</div>
  <form method="post" action="/keys" id="keysform">
    __KEYFIELDS__
    <button type="submit">Сохранить ключи</button>
  </form>
  <div id="keys-result"></div>
  <h3>Статус сервисов</h3>
  __KEYTABLE__
  <h3>Возможности и цены</h3>
  __KEYINFO__
</div>

<!-- ===== OTHER ===== -->
<div class="panel" id="tab-other">
  <div class="panel-title">IP, домен, телефон, имя</div>
  <div class="panel-sub">Геолокация и провайдер по IP, DNS и WHOIS по домену, страна и тип линии по телефону.</div>
  <form method="post" action="/other">
    <div class="row">
      <div><label>IP-адрес</label><input name="ip" placeholder="8.8.8.8"></div>
      <div><label>Домен</label><input name="domain" placeholder="example.com"></div>
    </div>
    <div class="row">
      <div><label>Телефон</label><input name="phone" placeholder="+79991234567"></div>
      <div><label>Имя</label><input name="name" placeholder="Иван Иванов"></div>
    </div>
    <button type="submit">Исследовать</button>
  </form>
  <div id="other-result"></div>
</div>

</div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];

/* --- TABS --- */
$$('.tab').forEach(t=>t.addEventListener('click',()=>{
  $$('.tab').forEach(x=>x.classList.remove('active'));
  $$('.panel').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  document.getElementById(t.dataset.t).classList.add('active');
  history.replaceState(null,'','#'+t.dataset.t);
}));
if(location.hash){const p=document.getElementById(location.hash.slice(1));
  if(p){const t=$$('.tab').find(x=>x.dataset.t===location.hash.slice(1)); if(t)t.click();}}

/* --- CHIPS --- */
$$('#chips .chip').forEach(c=>c.addEventListener('click',()=>{
  c.classList.toggle('on');
  $('#cats').value=$$('#chips .chip.on').map(e=>e.dataset.c).join(',');
}));

/* --- TOAST --- */
function toast(msg){const t=document.createElement('div');t.className='toast';t.textContent=msg;
  document.body.appendChild(t);setTimeout(()=>t.remove(),2200);}

/* --- COPY / EXPORT --- */
document.addEventListener('click',e=>{
  const c=e.target.closest('[data-copy]');
  if(c){navigator.clipboard.writeText(c.dataset.copy).then(()=>toast('Скопировано в буфер'));return;}
  const d=e.target.closest('[data-download]');
  if(d){
    const blob=new Blob([d.dataset.download],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(blob);
    a.download='osint-report.json';a.click();toast('Отчёт сохранён');return;}
  const v=e.target.closest('[data-csv]');
  if(v){downloadCsv();return;}
});

/* --- CSV EXPORT (из видимой таблицы) --- */
function downloadCsv(){
  const tbl=document.querySelector('#scan-result table');
  if(!tbl){toast('Сначала выполните сканирование');return;}
  const rows=[['категория','сайт','ссылка']];
  tbl.querySelectorAll('tbody tr').forEach(r=>{
    const td=r.querySelectorAll('td');
    if(td.length>=3)rows.push([td[0].innerText.trim(),td[1].innerText.trim(),td[2].innerText.trim()]);
  });
  const csv=rows.map(r=>r.map(c=>'"'+c.replace(/"/g,'""')+'"').join(';')).join('\\n');
  const blob=new Blob(['\\ufeff'+csv],{type:'text/csv;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='osint-profiles.csv';a.click();toast('CSV сохранён');
}

/* --- FILTER TABLE --- */
function initFilter(root){
  root.querySelectorAll('.tablewrap table').forEach(tbl=>{
    const wrap=tbl.closest('.tablewrap');
    if(wrap.dataset.filtered)return;
    wrap.dataset.filtered='1';
    if(tbl.querySelectorAll('tbody tr').length<6)return;
    const bar=document.createElement('div');bar.className='toolbar';
    bar.innerHTML='<input placeholder="&#128269; Фильтр по названию или домену..."><span class="spacer"></span>';
    wrap.parentNode.insertBefore(bar,wrap);
    const inp=bar.querySelector('input');
    inp.addEventListener('input',()=>{
      const q=inp.value.toLowerCase();
      let n=0;const rows=tbl.querySelectorAll('tbody tr');
      rows.forEach(r=>{const ok=!q||r.textContent.toLowerCase().includes(q);r.style.display=ok?'':'none';if(ok)n++;});
      bar.querySelector('.spacer').textContent=q?(n+' / '+rows.length+' строк'):'';
    });
  });
}

/* --- LOADING --- */
function showLoading(target,text){
  document.getElementById(target).innerHTML=
    '<div class="loading"><div class="bat-loader"></div>'+text+'</div>';
}

/* --- FORMS --- */
$('#scanform').addEventListener('submit',()=>showLoading('scan-result','Перепроверяем 506 сайтов &mdash; это займёт 10&ndash;30 секунд'));
$('#scanform').addEventListener('submit',e=>{
  const v=$('#scanvalue').value.trim();
  if(!v){e.preventDefault();toast('Введите username');}
});
document.querySelector('#tab-email form').addEventListener('submit',()=>showLoading('email-result','Анализируем email...'));
document.querySelector('#tab-leaks form').addEventListener('submit',()=>showLoading('leaks-result','Проверяем базы утечек...'));
document.querySelector('#tab-exact form').addEventListener('submit',()=>showLoading('exact-result','Собираем досье...'));
document.querySelector('#tab-dossier form').addEventListener('submit',()=>showLoading('dossier-result','Собираем полное досье... Это может занять до минуты...'));
document.querySelector('#tab-web form').addEventListener('submit',()=>showLoading('web-result','Ищем в Google...'));
document.querySelector('#tab-other form').addEventListener('submit',()=>showLoading('other-result','Собираем данные...'));

/* --- RANDOM EXAMPLES --- */
$('#randscan').addEventListener('click',()=>{
  const ex=['torvalds','durov','spez','gaben','hikaru','ph_piter','trainwreckstv','flickr','chris','twitch','satyam','destufft'];
  const v=ex[Math.floor(Math.random()*ex.length)];
  $('#scanvalue').value=v;toast('Пример: '+v);
});

/* --- INIT FILTERS AFTER CONTENT LOAD --- */
function refreshFilters(){initFilter(document);}
window.addEventListener('load',refreshFilters);
new MutationObserver(()=>refreshFilters()).observe(document.body,{childList:true,subtree:true});

/* --- KEYBOARD --- */
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();$('#scanvalue').focus();}
  if(e.key>='1'&&e.key<='6'&&document.activeElement.tagName!=='INPUT'){
    const t=$$('.tab')[+e.key-1]; if(t)t.click();
  }
});

/* --- PWA: регистрация service worker + install prompt --- */
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js').catch(()=>{});
}
let deferredPrompt=null;
window.addEventListener('beforeinstallprompt',e=>{
  e.preventDefault(); deferredPrompt=e;
  const btn=document.createElement('button');
  btn.className='ghost'; btn.style.cssText='margin:14px 0 0;width:auto;display:block';
  btn.textContent='Установить как приложение';
  btn.onclick=async()=>{deferredPrompt.prompt();await deferredPrompt.userChoice;deferredPrompt=null;btn.remove();};
  document.querySelector('#tab-scan .btn-row').appendChild(btn);
});
window.addEventListener('appinstalled',()=>console.log('Gotham OSINT установлен'));
</script>
</body>
</html>
"""


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _cats_html() -> str:
    return "\n".join(f'<span class="chip" data-c="{c}">{c}</span>' for c in CATS)


def _keyfields_html() -> str:
    rows = []
    current = {s["env"]: s for s in key_status()}
    for name, meta in KEY_MAP.items():
        badge = " <span class='tag ok'>free tier</span>" if meta["free"] else ""
        st = current.get(name, {})
        if st.get("active"):
            val = f"<input name='{name}' value='{_esc(st['masked'])}' autocomplete='off'>"
            hint = (f"<div class='hint'><span class='tag ok'>подключён</span> "
                    f"{_esc(meta['what'])}</div>")
        else:
            val = f"<input name='{name}' placeholder='{_esc(meta['price'])}' autocomplete='off'>"
            hint = f"<div class='hint'>{_esc(meta['what'])}</div>"
        rows.append(
            f"<label>{meta['service']} &mdash; <span style='text-transform:none;color:var(--gold)'>{name}</span>{badge}</label>"
            f"{val}{hint}")
    return "\n".join(rows)


def _keytable_html() -> str:
    rows = ""
    for s in key_status():
        badge = "<span class='tag ok'>подключён</span>" if s["active"] else "<span class='tag dim'>не задан</span>"
        key = _esc(s["masked"]) if s["active"] else "&mdash;"
        rows += (f"<tr><td><b>{_esc(s['service'])}</b><br><span class='hint'>{_esc(s['env'])}</span></td>"
                 f"<td>{badge}</td><td><code>{key}</code></td>"
                 f"<td><a href='{_esc(s['url'])}' target='_blank'>купить</a><br>"
                 f"<span class='hint'>{_esc(s['price'])}</span></td></tr>")
    return (f"<div class='tablewrap'><table><thead><tr><th>Сервис</th><th>Статус</th>"
            f"<th>Ключ</th><th>Цена / ссылка</th></tr></thead><tbody>{rows}</tbody></table></div>")


def _keyinfo_html() -> str:
    rows = ""
    for name, meta in KEY_MAP.items():
        rows += (f"<tr><td><b>{_esc(meta['service'])}</b></td><td>{_esc(meta['what'])}</td>"
                 f"<td>{_esc(meta['price'])}</td>"
                 f"<td><a href='{_esc(meta['url'])}' target='_blank'>купить</a></td></tr>")
    return (f"<div class='tablewrap'><table><thead><tr><th>Сервис</th><th>Возможности</th>"
            f"<th>Цена</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>")


def _page(active: str = "tab-scan") -> str:
    nkeys = sum(1 for s in key_status() if s["active"])
    h = (HTML.replace("__CSS__", CSS)
            .replace("__SKYLINE__", SKYLINE)
            .replace("__EMBLEM__", BAT_EMBLEM)
            .replace("__DISCLAIMER__", DISCLAIMER)
            .replace("__CATS__", _cats_html())
            .replace("__KEYFIELDS__", _keyfields_html())
            .replace("__KEYTABLE__", _keytable_html())
            .replace("__KEYINFO__", _keyinfo_html())
            .replace("__NKEYS__", str(nkeys)))
    for k, v in ICONS.items():
        h = h.replace(f"__ICO_{k.upper()}__", v)
    # Активируем нужную вкладку
    h = h.replace('class="tab active" data-t="tab-scan"', 'class="tab" data-t="tab-scan"')
    h = h.replace('class="panel active" id="tab-scan"', 'class="panel" id="tab-scan"')
    h = h.replace(f'class="tab" data-t="{active}"', f'class="tab active" data-t="{active}"')
    h = h.replace(f'class="panel" id="{active}"', f'class="panel active" id="{active}"')
    return h


def _jblock(data) -> str:
    return f"<pre>{_esc(json.dumps(data, ensure_ascii=False, indent=2))}</pre>"


def _toolbar(payload, name="osint-report.json") -> str:
    return (f"<div class='toolbar'>"
            f"<button class='mini ghost' data-copy=\"{_esc(json.dumps(payload, ensure_ascii=False, indent=2))}\">Копировать JSON</button>"
            f"<button class='mini ghost' data-download=\"{_esc(json.dumps(payload, ensure_ascii=False, indent=2))}\">Скачать отчёт</button>"
            f"<button class='mini ghost' data-csv=\"1\">Скачать CSV</button>"
            f"<span class='spacer'></span></div>")


def _csv_rows(res: Dict) -> str:
    """Формирует CSV по найденным профилям."""
    import csv
    import io as _io
    buf = _io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["категория", "сайт", "ссылка", "статус"])
    for cat, items in (res.get("by_category") or {}).items():
        for it in items:
            w.writerow([cat, it.get("site", ""), it.get("url", ""), "найден"])
    for e in (res.get("errors") or []):
        w.writerow(["", e.get("site", ""), "", f"не подтверждено: {e.get('note','')}"])
    return buf.getvalue()


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/favicon.ico")
def favicon():
    from fastapi.responses import Response
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
           '<polygon points="50,2 88,25 88,75 50,98 12,75 12,25" fill="#f5c542"/>'
           '<path d="M50 26c-4 5-9 6-15 5-5-1-9-4-14-7-1 6-3 10-7 14 4 0 7 1 9 4 3-1 6-1 9 1 3-1 6-1 9 1 3-2 6-2 9-1 3-2 6-2 9 1 2-3 5-4 9-4-4-4-6-8-7-14-5 3-9 6-14 7-6 1-11 0-15-5z" '
           'fill="#05070b"/></svg>')
    return Response(svg, media_type="image/svg+xml")


def _static_file(name: str, media_type: str):
    from fastapi.responses import Response
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return Response("", media_type=media_type, status_code=404)
    return Response(data, media_type=media_type)


@app.get("/manifest.json")
def manifest():
    return _static_file("manifest.json", "application/manifest+json")


@app.get("/icon.svg")
def icon():
    return _static_file("icon.svg", "image/svg+xml")


@app.get("/sw.js")
def service_worker():
    from fastapi.responses import Response
    sw = """
const CACHE='gotham-osint-v1';
const CORE=['/','/manifest.json','/icon.svg','/favicon.ico'];
self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate',e=>{
  e.waitUntil(caches.keys().then(k=>Promise.all(
    k.filter(x=>x!==CACHE).map(x=>caches.delete(x))
  )).then(()=>self.clients.claim()));
});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const url=new URL(e.request.url);
  if(url.origin!==location.origin)return;
  if(url.pathname.startsWith('/api/'))return;
  e.respondWith(
    fetch(e.request).then(r=>{
      const cp=r.clone();
      caches.open(CACHE).then(c=>c.put(e.request,cp)).catch(()=>{});
      return r;
    }).catch(()=>caches.match(e.request).then(r=>r||caches.match('/')))
  );
});
"""
    return Response(sw, media_type="application/javascript",
                    headers={"Cache-Control": "no-cache"})


@app.get("/", response_class=HTMLResponse)
def index():
    return _page()


@app.post("/scan", response_class=HTMLResponse)
async def scan_route(value: str = Form(...), cats: str = Form("")):
    sel = [c.strip() for c in cats.split(",") if c.strip()] or None
    res = await scan(value.strip(), sel)

    rows = ""
    for cat, items in res.get("by_category", {}).items():
        for it in items:
            rows += (f"<tr><td><span class='tag cat'>{_esc(cat)}</span></td>"
                     f"<td><b>{_esc(it['site'])}</b></td>"
                     f"<td><a href='{_esc(it['url'])}' target='_blank'>{_esc(it['url'])}</a></td></tr>")

    unknown = ""
    if res.get("errors"):
        items = "".join(f"<li><b>{_esc(e['site'])}</b> &mdash; {_esc(e.get('note',''))}</li>"
                        for e in res["errors"])
        unknown = ("<details><summary>Не подтверждено автоматически "
                   f"({len(res['errors'])} шт.) &mdash; откройте список</summary><ul>{items}</ul></details>")

    cat_summary = "".join(
        f"<span class='chip on' style='cursor:default'>{_esc(cat)}: {len(items)}</span>"
        for cat, items in (res.get("by_category") or {}).items())

    body = f"""
    <div class="stats">
      <div class="stat ok"><b>{res['found_count']}</b><span>профилей найдено</span></div>
      <div class="stat"><b>{res['total_checked']}</b><span>сайтов проверено</span></div>
      <div class="stat bad"><b>{res['not_found_count']}</b><span>не найдено</span></div>
      <div class="stat warn"><b>{res['unknown_count']}</b><span>не подтверждено</span></div>
    </div>
    {_toolbar(res)}
    <h3>Найденные профили <span class="count">{res['found_count']}</span></h3>
    <div class="tablewrap"><table><thead><tr><th>Категория</th><th>Сайт</th><th>Ссылка</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="3" class="empty">Профилей не найдено</td></tr>'}</tbody></table></div>
    {unknown}
    <h3>Сводка по категориям</h3>
    <div class="chips">{cat_summary}</div>
    <h3>Полный отчёт</h3>
    {_jblock(res)}
    """
    return _page("tab-scan").replace('<div id="scan-result"></div>', f'<div id="scan-result">{body}</div>')


@app.post("/email", response_class=HTMLResponse)
def email_route(email: str = Form(...)):
    em = email.strip()
    res = search_email(em)
    web = web_search(em, limit=20)
    wrows = "".join(
        f"<tr><td><a href='{_esc(r['url'])}' target='_blank'>{_esc(r['title'])}</a></td>"
        f"<td>{_esc(r['domain'])}</td><td>{_esc(r['snippet'])}</td></tr>" for r in web.get("results", []))

    prem = ""
    domain = em.split("@")[-1] if "@" in em else ""
    h = hunter_domain_emails(domain) if domain else {"active": False, "emails": []}
    if h.get("active"):
        hrows = "".join(
            f"<tr><td><b>{_esc(e.get('name') or '-')}</b></td><td>{_esc(e.get('email'))}</td>"
            f"<td>{_esc(e.get('position') or '')}</td><td>{_esc(e.get('department') or '')}</td></tr>"
            for e in h.get("emails", []))
        prem += (f"<h3>Hunter.io &mdash; сотрудники домена {domain} "
                 f"<span class='count'>{len(h.get('emails', []))}</span></h3>"
                 f"<div class='tablewrap'><table><thead><tr><th>Имя</th><th>Email</th>"
                 f"<th>Должность</th><th>Отдел</th></tr></thead><tbody>{hrows}</tbody></table></div>")

    d = dehashed_search(f"email:{em}")
    if d.get("active") and d.get("results"):
        drows = "".join(
            f"<tr><td>{_esc((e.get('_source') or {}).get('name','-'))}</td>"
            f"<td>{_esc(((e.get('_source') or {}).get('date') or ['-'])[0] if (e.get('_source') or {}).get('date') else '-')}</td>"
            f"<td>{_esc(', '.join(sorted(e.keys())[:8]))}</td></tr>" for e in d["results"][:40])
        prem += (f"<h3>DeHashed &mdash; записи утечек <span class='count'>{d.get('total', 0)}</span></h3>"
                 f"<div class='tablewrap'><table><thead><tr><th>Источник</th><th>Дата</th>"
                 f"<th>Поля</th></tr></thead><tbody>{drows}</tbody></table></div>")

    body = f"""
    <h3>Досье по email</h3>
    {_jblock(res)}
    {prem}
    <h3>Упоминания в интернете <span class="count">{web.get('count', 0)}</span></h3>
    <div class="tablewrap"><table><thead><tr><th>Заголовок</th><th>Домен</th><th>Фрагмент</th></tr></thead>
    <tbody>{wrows or '<tr><td colspan="3" class="empty">Упоминаний не найдено</td></tr>'}</tbody></table></div>
    """
    return _page("tab-email").replace('<div id="email-result"></div>', f'<div id="email-result">{body}</div>')


@app.post("/leaks", response_class=HTMLResponse)
def leaks_route(value: str = Form(...), hibp_key: str = Form("")):
    import os as _os
    if hibp_key.strip():
        _os.environ["HIBP_API_KEY"] = hibp_key.strip()
    v = value.strip()
    res = full_leak_check(v, is_email=("@" in v))
    lc = res.get("leakcheck", {})
    found = lc.get("found")

    # XposedOrNot — бесплатный источник (11.6 млрд записей, без ключа)
    xon = None
    if "@" in v:
        try:
            xon = check_xposedornot(v)
        except Exception:
            xon = None

    # Safe Surf (НКЦКИ, РФ) — российский сервис, бесплатно
    ss = None
    try:
        ss = safesurf_ru.check(v)
    except Exception:
        ss = None

    ss_block = ""
    if ss and ss.get("matches") is not None:
        ok = ss["matches"] > 0
        ss_block = (
            f"<div class='stats'>"
            f"<div class='stat {'bad' if ok else 'ok'}'><b>{ss['matches']}</b>"
            f"<span>совпадений в базе НКЦКИ</span></div></div>"
            f"<h3>Safe Surf / НКЦКИ (РФ)</h3>"
            f"<p class='hint'>{_esc(ss.get('summary', ''))} &mdash; "
            f"тип поиска: {_esc(ss.get('entity', ''))}</p>")

    srows = "".join(
        f"<tr><td><b>{_esc(s.get('name'))}</b></td><td>{_esc(s.get('date'))}</td></tr>"
        for s in (lc.get("sources") or []))
    fl = lc.get("leaked_field_labels") or []

    xon_block = ""
    if xon and xon.get("breaches"):
        xrows = "".join(f"<tr><td><b>{_esc(b)}</b></td></tr>" for b in xon["breaches"])
        risk = xon.get("risk") or {}
        xon_block = (
            f"<div class='stats'><div class='stat bad'><b>{len(xon['breaches'])}</b>"
            f"<span>утечек (XposedOrNot)</span></div>"
            f"<div class='stat'><b>{_esc(risk.get('risk_label', '—'))}</b>"
            f"<span>риск-скор {_esc(risk.get('risk_score', '—'))}</span></div></div>"
            f"<h3>Утечки по XposedOrNot <span class='count'>{len(xon['breaches'])}</span></h3>"
            f"<div class='tablewrap'><table><thead><tr><th>Сервис</th></tr></thead>"
            f"<tbody>{xrows}</tbody></table></div>")

    if found:
        summary = (f"<div class='stats'>"
                   f"<div class='stat bad'><b>{found}</b><span>записей в утечках</span></div>"
                   f"<div class='stat warn'><b>{lc.get('source_count', 0)}</b><span>источников</span></div>"
                   f"<div class='stat'><b>{len(fl)}</b><span>типов данных</span></div></div>"
                   f"<p class='hint'>Утекли данные: <b style='color:var(--bad)'>{_esc(', '.join(fl))}</b></p>")
    elif found == 0:
        summary = "<div class='stats'><div class='stat ok'><b>0</b><span>утечек не найдено</span></div></div>"
    else:
        summary = f"<p class='hint' style='color:var(--bad)'>{_esc(lc.get('error') or 'нет данных')}</p>"

    body = f"""
    {summary}
    {xon_block}
    {ss_block}
    {_toolbar(res)}
    <h3>Источники утечек <span class="count">{lc.get('source_count', 0)}</span></h3>
    <div class="tablewrap"><table><thead><tr><th>Сервис / сайт</th><th>Дата</th></tr></thead>
    <tbody>{srows or '<tr><td colspan="2" class="empty">Утечек не найдено</td></tr>'}</tbody></table></div>
    <h3>Полный отчёт</h3>
    {_jblock(res)}
    """
    return _page("tab-leaks").replace('<div id="leaks-result"></div>', f'<div id="leaks-result">{body}</div>')


@app.post("/exact", response_class=HTMLResponse)
def exact_route(telegram: str = Form(""), email: str = Form(""),
                vk: str = Form(""), phone: str = Form("")):
    blocks = []

    if telegram.strip():
        r = search_telegram(telegram.strip())
        p = r.get("profile", {})
        lk = r.get("leaks", {}) or {}
        avatar = (f"<img src='{_esc(p.get('avatar'))}' style='width:64px;height:64px;"
                  f"border-radius:8px;border:1px solid var(--line2)'>") if p.get("avatar") else ""
        meta_rows = "".join(
            f"<tr><td style='width:150px;color:var(--muted)'>{_esc(k)}</td><td><b>{_esc(v)}</b></td></tr>"
            for k, v in [("Имя", p.get("name")), ("Описание", p.get("bio")),
                         ("Подписчики", p.get("subscribers")),
                         ("Ссылка", p.get("profile_url"))] if v)
        blocks.append(
            f"<h3>Telegram <span class='count'>@{_esc(r.get('username'))}</span></h3>"
            f"<div style='display:flex;gap:16px;align-items:flex-start'>"
            f"<div>{avatar}</div><div style='flex:1'><table><tbody>{meta_rows}</tbody></table></div></div>"
            f"{_leaks_block(lk)}"
            f"{_mentions_block(r.get('mentions') or [])}"
            f"<details><summary>Полный отчёт</summary>{_jblock(r)}</details>")

    if email.strip():
        r = search_email_detailed(email.strip())
        g = r.get("gravatar", {}) or {}
        lk = r.get("leaks", {}) or {}
        gv = g.get("found")
        meta_rows = "".join(
            f"<tr><td style='width:150px;color:var(--muted)'>{_esc(k)}</td><td><b>{_esc(v)}</b></td></tr>"
            for k, v in [("Профиль Gravatar", g.get("profile_url") or ("не найден" if not gv else "")),
                         ("Имя", g.get("name")), ("Описание", g.get("about")),
                         ("Локация", g.get("location")),
                         ("Домен", r.get("domain"))] if v)
        accounts = ""
        if g.get("accounts"):
            links = "".join(f"<li><a href='{_esc(a.get('url'))}' target='_blank'>{_esc(a.get('name'))}</a></li>"
                            for a in g["accounts"] if a.get("url"))
            accounts = f"<tr><td style='width:150px;color:var(--muted'>Связи</td><td><ul style='margin-left:16px'>{links}</ul></td></tr>"
        blocks.append(
            f"<h3>Email <span class='count'>{_esc(r.get('email'))}</span></h3>"
            f"<table><tbody>{meta_rows}{accounts}</tbody></table>"
            f"{_leaks_block(lk)}"
            f"{_mentions_block(r.get('mentions') or [])}"
            f"<details><summary>Полный отчёт</summary>{_jblock(r)}</details>")

    if vk.strip():
        r = search_vk(vk.strip())
        p = r.get("profile", {}) or {}
        lk = r.get("leaks", {}) or {}
        avatar = (f"<img src='{_esc(p.get('avatar'))}' style='width:64px;height:64px;"
                  f"border-radius:8px;border:1px solid var(--line2)'>") if p.get("avatar") else ""
        meta_rows = "".join(
            f"<tr><td style='width:150px;color:var(--muted)'>{_esc(k)}</td><td><b>{_esc(v)}</b></td></tr>"
            for k, v in [("Имя", p.get("name")), ("Ник", p.get("screen_name")),
                         ("Город", p.get("city")), ("Работа", p.get("work")),
                         ("Статус", (p.get("status") or "")[:200]),
                         ("Ссылка", r.get("profile_url"))] if v)
        blocks.append(
            f"<h3>ВКонтакте <span class='count'>{_esc(r.get('profile_url') or '')}</span></h3>"
            f"<div style='display:flex;gap:16px;align-items:flex-start'>"
            f"<div>{avatar}</div><div style='flex:1'><table><tbody>{meta_rows}</tbody></table></div></div>"
            f"{_leaks_block(lk)}"
            f"{_mentions_block(r.get('mentions') or [])}"
            f"<details><summary>Полный отчёт</summary>{_jblock(r)}</details>")

    if phone.strip():
        r = search_phone_deep(phone.strip())
        n = r.get("normalized", {}) or {}
        op = r.get("operator", {}) or {}
        lk = r.get("leaks", {}) or {}
        meta_rows = "".join(
            f"<tr><td style='width:150px;color:var(--muted)'>{_esc(k)}</td><td><b>{_esc(v)}</b></td></tr>"
            for k, v in [("Нормализован", n.get("e164")), ("Страна", n.get("country")),
                         ("Оператор", op.get("carrier")), ("Тип линии", op.get("line_type")),
                         ("Локация", op.get("location"))] if v)
        blocks.append(
            f"<h3>Телефон <span class='count'>{_esc(r.get('input'))}</span></h3>"
            f"<table><tbody>{meta_rows}</tbody></table>"
            f"{_leaks_block(lk)}"
            f"{_mentions_block(r.get('mentions') or [])}"
            f"<details><summary>Полный отчёт</summary>{_jblock(r)}</details>")

    if not blocks:
        blocks.append('<p class="hint">Заполните хотя бы одно поле.</p>')

    body = "".join(blocks)
    return _page("tab-exact").replace('<div id="exact-result"></div>', f'<div id="exact-result">{body}</div>')


def _leaks_block(lk: Dict[str, Any]) -> str:
    """Блок с данными об утечках."""
    if not lk:
        return ""
    found = lk.get("found")
    if found in (None, 0):
        return ('<div class="stats"><div class="stat ok"><b>0</b>'
                '<span>утечек не найдено</span></div></div>')
    srcs = lk.get("sources") or []
    rows = "".join(f"<tr><td><b>{_esc(s.get('name'))}</b></td><td>{_esc(s.get('date'))}</td></tr>"
                   for s in srcs[:60])
    fields = lk.get("fields") or lk.get("leaked_field_labels") or []
    fld = f'<p class="hint">Утекли данные: <b style="color:var(--bad)">{_esc(", ".join(fields))}</b></p>' if fields else ""
    return (f'<div class="stats"><div class="stat bad"><b>{found}</b><span>записей в утечках</span></div>'
            f'<div class="stat warn"><b>{lk.get("source_count", len(srcs))}</b><span>источников</span></div></div>'
            f'{fld}'
            f'<details><summary>Источники утечек ({len(srcs)})</summary>'
            f'<div class="tablewrap"><table><thead><tr><th>Сервис</th><th>Дата</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></details>')


def _mentions_block(mentions: List[Dict[str, Any]]) -> str:
    """Блок с упоминаниями в интернете."""
    if not mentions:
        return ""
    rows = "".join(
        f"<tr><td><a href='{_esc(m.get('url'))}' target='_blank'>{_esc(m.get('title'))}</a></td>"
        f"<td>{_esc(m.get('domain'))}</td><td>{_esc((m.get('snippet') or '')[:150])}</td></tr>"
        for m in mentions if m.get("url"))
    return (f'<h3>Упоминания в интернете <span class="count">{len(mentions)}</span></h3>'
            f'<div class="tablewrap"><table><thead><tr><th>Заголовок</th><th>Домен</th>'
            f'<th>Фрагмент</th></tr></thead><tbody>{rows}</tbody></table></div>')


@app.post("/dossier", response_class=HTMLResponse)
def dossier_route(value: str = Form(...)):
    d = build_dossier(value.strip())
    sm = d.get("summary", {})
    idn, loc, con, br = d["identity"], d["locations"], d["contacts"], d["breaches"]

    def chips(vals):
        if not vals:
            return '<span class="hint">— не найдено —</span>'
        return "".join(f"<span class='tag cat' style='margin:2px 3px 2px 0'>{_esc(v)}</span>"
                       for v in vals[:25])

    def field(label, vals, badge=""):
        return (f"<tr><td style='width:190px;color:var(--muted)'>{_esc(label)}</td>"
                f"<td>{chips(vals)}{badge}</td></tr>")

    srcs = "".join(f"<span class='tag ok' style='margin:2px 3px 2px 0'>{_esc(s)}</span>"
                   for s in d.get("sources_used", []))

    ev_rows = ""
    for e in (d.get("profiles", {}).get("web_extractions") or [])[:20]:
        ex = e.get("extracted", {})
        chips_ex = "".join(f"<span class='tag cat' style='margin:1px 2px 1px 0'>{_esc(k)}: {_esc(v)}</span>"
                           for k, v in ex.items())
        ev_rows += (f"<tr><td><a href='{_esc(e.get('url'))}' target='_blank'>"
                    f"{_esc(e.get('title') or '')}</a><br>"
                    f"<span class='hint'>{_esc(e.get('snippet') or '')[:150]}</span></td>"
                    f"<td>{chips_ex}</td></tr>")

    br_rows = "".join(
        f"<tr><td><b>{_esc(s.get('name'))}</b></td><td>{_esc(s.get('date'))}</td></tr>"
        for s in (br.get("sources") or [])[:60])

    accounts = ""
    acc = d.get("profiles", {}).get("accounts") or {}
    if acc:
        rows = "".join(
            f"<tr><td><b>{_esc(un)}</b></td><td>"
            + "".join(f"<a href='{_esc(i.get('url'))}' target='_blank'>{_esc(i.get('site'))}</a> "
                      for i in items) + "</td></tr>"
            for un, items in acc.items())
        accounts = (f"<h3>Связанные аккаунты <span class='count'>{sum(len(v) for v in acc.values())}</span></h3>"
                    f"<div class='tablewrap'><table><thead><tr><th>Логин</th><th>Площадки</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table></div>")

    ident = d.get("profiles", {}).get("infostealer")
    ident_block = ""
    if ident:
        rows = "".join(f"<tr><td style='width:190px;color:var(--muted)'>{_esc(k)}</td><td><b>{_esc(v)}</b></td></tr>"
                       for k, v in ident.items() if v)
        ident_block = (f"<h3>Заражение инфостилером</h3>"
                       f"<table><tbody>{rows}</tbody></table>")

    # ---------------- ЛИЧНЫЕ ДАННЫЕ ----------------
    per = d.get("personal") or {}
    # Дополняем сводку данными из личного блока (найдены в открытых источниках)
    if per and not per.get("error"):
        if not idn["full_name"] and per.get("names"):
            idn["full_name"] = list(per["names"])
        if not idn["birth_date"] and per.get("birth_dates"):
            idn["birth_date"] = list(per["birth_dates"])
        if not idn["gender"] and per.get("genders"):
            idn["gender"] = list(per["genders"])
        if not loc["address"] and per.get("addresses"):
            loc["address"] = list(per["addresses"])
        if not loc["city"] and per.get("cities"):
            loc["city"] = list(per["cities"])
        if not loc["district"] and per.get("districts"):
            loc["district"] = list(per["districts"])
        if not loc["zip"] and per.get("zips"):
            loc["zip"] = list(per["zips"])
        if not con["usernames"] and per.get("usernames"):
            con["usernames"] = list(per["usernames"])
    personal_block = ""
    if per and not per.get("error"):
        def plist(vals, empty="— не найдено —"):
            if not vals:
                return f"<span class='hint'>{_esc(empty)}</span>"
            return "".join(f"<span class='tag cat' style='margin:2px 3px 2px 0'>{_esc(v)}</span>"
                           for v in vals[:25])

        srows = ""
        sp = per.get("social_profiles") or {}
        items = sp.items() if isinstance(sp, dict) else []
        for un, lst in items:
            if isinstance(lst, list):
                for it in lst:
                    srows += (f"<tr><td><b>{_esc(it.get('site'))}</b><br>"
                              f"<span class='hint'>{_esc(it.get('category',''))}</span></td>"
                              f"<td><span class='hint'>логин: {_esc(un)}</span></td>"
                              f"<td><a href='{_esc(it.get('url'))}' target='_blank'>{_esc(it.get('url'))}</a></td></tr>")
        for it in (sp if isinstance(sp, list) else []):
            srows += (f"<tr><td><b>{_esc(it.get('site'))}</b></td><td></td>"
                      f"<td><a href='{_esc(it.get('url'))}' target='_blank'>{_esc(it.get('url'))}</a></td></tr>")

        erows = ""
        for e in (per.get("evidence") or [])[:30]:
            ex = e.get("extracted") or {}
            exchips = "".join(f"<span class='tag cat' style='margin:1px 2px 1px 0'>{_esc(k)}: {_esc(val)}</span>"
                              for k, val in ex.items())
            link = (f"<a href='{_esc(e.get('url'))}' target='_blank'>{_esc(e.get('source'))}</a>"
                    if e.get("url") else _esc(e.get("source")))
            erows += (f"<tr><td>{link}</td><td>{_esc((e.get('detail') or '')[:220])}</td>"
                      f"<td>{exchips}</td></tr>")

        personal_block = f"""
        <h3>🕵️ Личные данные</h3>
        <div class="stats">
          <div class="stat ok"><b>{len(per.get('names') or [])}</b><span>имён / ФИО</span></div>
          <div class="stat"><b>{len(per.get('addresses') or [])}</b><span>адресов</span></div>
          <div class="stat"><b>{len(per.get('cities') or [])}</b><span>городов</span></div>
          <div class="stat"><b>{len(per.get('usernames') or [])}</b><span>логинов</span></div>
          <div class="stat"><b>{len(per.get('birth_dates') or [])}</b><span>дат рождения</span></div>
          <div class="stat"><b>{len(per.get('genders') or [])}</b><span>пол</span></div>
          <div class="stat"><b>{len(per.get('districts') or [])}</b><span>районов</span></div>
          <div class="stat"><b>{len(per.get('zips') or [])}</b><span>индексов</span></div>
        </div>
        <table><tbody>
          <tr><td style='width:190px;color:var(--muted)'>ФИО / имя</td><td>{plist(per.get('names'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Владелец номера</td><td>{plist([per.get('phone_owner')] if per.get('phone_owner') else [])}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Дата рождения</td><td>{plist(per.get('birth_dates'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Пол</td><td>{plist(per.get('genders'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Адрес проживания</td><td>{plist(per.get('addresses'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Город</td><td>{plist(per.get('cities'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Район</td><td>{plist(per.get('districts'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Индекс</td><td>{plist(per.get('zips'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Оператор связи</td><td>{plist(per.get('operators'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Логины</td><td>{plist(per.get('usernames'))}</td></tr>
          <tr><td style='width:190px;color:var(--muted)'>Источники</td><td>{plist(per.get('sources'))}</td></tr>
        </tbody></table>
        <h3>Все соцсети и профили <span class="count">{srows.count('<tr>')}</span></h3>
        <div class="tablewrap"><table><thead><tr><th>Сайт</th><th>Логин</th><th>Ссылка</th></tr></thead>
        <tbody>{srows or '<tr><td colspan="3" class="empty">Профили не найдены</td></tr>'}</tbody></table></div>
        <h3>Доказательства (откуда взяты данные)</h3>
        <div class="tablewrap"><table><thead><tr><th>Источник</th><th>Фрагмент</th><th>Извлечено</th></tr></thead>
        <tbody>{erows or '<tr><td colspan="3" class="empty">—</td></tr>'}</tbody></table></div>
        """

    chk = d.get("checked") or {}
    chk_rows = "".join(
        f"<tr><td style='width:280px;color:var(--muted)'>{_esc(k)}</td><td><b>{_esc(v)}</b></td></tr>"
        for k, v in (chk.get("counts") or {}).items())
    chk_srcs = "".join(f"<li>{_esc(s)}</li>" for s in (chk.get("sources") or []))
    checked_block = f"""
    <h3>Что было проверено</h3>
    <table><tbody>{chk_rows}</tbody></table>
    <details><summary>Источники опроса ({len(chk.get('sources') or [])})</summary>
    <ul style='padding:14px 20px 14px 34px'>{chk_srcs}</ul></details>
    """

    body = f"""
    <div class="stats">
      <div class="stat ok"><b>{br.get('count', 0)}</b><span>записей в утечках</span></div>
      <div class="stat warn"><b>{len(br.get('sources') or [])}</b><span>источников утечек</span></div>
      <div class="stat ok"><b>{len(sm.get('identified_fields') or [])}</b><span>полей установлено</span></div>
      <div class="stat"><b>{len(d.get('web_evidence') or [])}</b><span>упоминаний</span></div>
    </div>

    {checked_block}
    <h3>Установленные сведения</h3>
    <table><tbody>
      {field('ФИО / имя', idn['full_name'])}
      {field('Имя', idn['first_name'])}
      {field('Фамилия', idn['last_name'])}
      {field('Отчество', idn['middle_name'])}
      {field('Дата рождения', idn['birth_date'])}
      {field('Пол', idn['gender'])}
      {field('Адрес', loc['address'])}
      {field('Город', loc['city'])}
      {field('Регион', loc['region'])}
      {field('Район', loc['district'])}
      {field('Страна', loc['country'])}
      {field('Индекс', loc['zip'])}
      {field('Телефоны', con['phones'])}
      {field('Email', con['emails'])}
      {field('Логины', con['usernames'])}
      {field('IP-адреса', con['ips'])}
    </tbody></table>

    <h3>Источники данных</h3>
    <p>{srcs or '<span class="hint">нет</span>'}</p>
    {personal_block}
    {ident_block}
    {accounts}

    <h3>Источники утечек <span class="count">{len(br.get('sources') or [])}</span></h3>
    <div class="tablewrap"><table><thead><tr><th>Сервис</th><th>Дата</th></tr></thead>
    <tbody>{br_rows or '<tr><td colspan="2" class="empty">Утечек не найдено</td></tr>'}</tbody></table></div>

    {('<h3>Извлечённые данные из открытых страниц</h3>'
      f'<div class="tablewrap"><table><thead><tr><th>Страница</th><th>Извлечено</th></tr></thead>'
      f'<tbody>{ev_rows}</tbody></table></div>') if ev_rows else ''}

    <details><summary>Полный отчёт (JSON)</summary>{_jblock(d)}</details>
    """
    return _page("tab-dossier").replace('<div id="dossier-result"></div>',
                                         f'<div id="dossier-result">{body}</div>')


@app.post("/web", response_class=HTMLResponse)
def web_route(query: str = Form(...)):
    sp = serper_search(query.strip())
    if sp.get("active") and sp.get("results"):
        rows = "".join(
            f"<tr><td><a href='{_esc(r['url'])}' target='_blank'>{_esc(r['title'])}</a></td>"
            f"<td>{_esc(r['url'].split('/')[2] if r.get('url') else '')}</td>"
            f"<td>{_esc(r.get('snippet') or '')}</td></tr>" for r in sp["results"])
        body = f"""
        <div class="stats"><div class="stat ok"><b>{sp.get('total', 0)}</b><span>результатов Google</span></div>
        <div class="stat"><b>Serper.dev</b><span>источник</span></div></div>
        {_toolbar(sp)}
        <h3>Результаты <span class="count">{sp.get('total', 0)}</span></h3>
        <div class="tablewrap"><table><thead><tr><th>Заголовок</th><th>Домен</th><th>Фрагмент</th></tr></thead>
        <tbody>{rows}</tbody></table></div>
        """
        return _page("tab-web").replace('<div id="web-result"></div>', f'<div id="web-result">{body}</div>')

    res = web_search(query.strip())
    rows = "".join(
        f"<tr><td><a href='{_esc(r['url'])}' target='_blank'>{_esc(r['title'])}</a></td>"
        f"<td>{_esc(r['domain'])}</td><td>{_esc(r['snippet'])}</td></tr>" for r in res.get("results", []))
    err = f"<p class='hint' style='color:var(--bad)'>{_esc(res.get('error'))}</p>" if res.get("error") else ""
    extra = ("<p class='hint'>Совет: добавьте ключ Serper.dev во вкладке «Ключи» &mdash; "
             "поиск пойдёт через настоящий Google.</p>")
    body = f"""{err}{extra}
    <div class="stats"><div class="stat"><b>{res.get('count', 0)}</b><span>упоминаний (DuckDuckGo)</span></div></div>
    <h3>Результаты</h3>
    <div class="tablewrap"><table><thead><tr><th>Заголовок</th><th>Домен</th><th>Фрагмент</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="3" class="empty">Ничего не найдено</td></tr>'}</tbody></table></div>
    """
    return _page("tab-web").replace('<div id="web-result"></div>', f'<div id="web-result">{body}</div>')


@app.post("/keys", response_class=HTMLResponse)
async def keys_route(request: Request):
    form = await request.form()
    current = {s["env"]: s for s in key_status()}
    keys = {}
    for name in KEY_MAP:
        v = (form.get(name) or "").strip()
        if not v:
            continue
        # Если поле предзаполнено маской активного ключа — не трогаем реальное значение
        st = current.get(name, {})
        if st.get("active") and v == st.get("masked"):
            continue
        keys[name] = v
    ok = save_keys(keys) if keys else False
    if keys:
        msg = ("<p class='hint' style='color:var(--ok)'>Ключи сохранены в osint_keys.json "
               "и подхвачены автоматически.</p>")
    else:
        msg = "<p class='hint'>Новые ключи не заданы — текущие остались без изменений.</p>"
    return _page("tab-keys").replace('<div id="keys-result"></div>', f'<div id="keys-result">{msg}</div>')


@app.post("/other", response_class=HTMLResponse)
def other_route(ip: str = Form(""), domain: str = Form(""),
                phone: str = Form(""), name: str = Form("")):
    out = {}
    if ip.strip():
        out["ip"] = search_ip(ip.strip())
    if domain.strip():
        out["domain"] = search_domain(domain.strip())
    if phone.strip():
        out["phone"] = search_phone(phone.strip())
    if name.strip():
        out["name"] = search_name(name.strip())
    body = f"<h3>Собранные данные</h3>{_jblock(out)}"
    return _page("tab-other").replace('<div id="other-result"></div>', f'<div id="other-result">{body}</div>')


@app.get("/api/scan", response_class=JSONResponse)
async def api_scan(value: str, cats: str = ""):
    """JSON-API для автоматизации."""
    sel = [c.strip() for c in cats.split(",") if c.strip()] or None
    return JSONResponse(await scan(value, sel))


if __name__ == "__main__":
    import os as _os
    port = int(_os.environ.get("PORT", "8765"))
    host = _os.environ.get("HOST", "127.0.0.1")
    print(f"[Gotham OSINT] http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
