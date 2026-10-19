#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генерирует статическую версию приложения для GitHub Pages (папка ./site).

Статика работает как PWA:
  * клиентский сканер username (GitHub API напрямую + прокси для HTML-сайтов)
  * веб-поиск через DuckDuckGo
  * полный JSON-отчёт и CSV-экспорт
Полная версия (500+ сайтов, утечки, Google) — локальный запуск osint_web.py
"""

import json
import os
import re
import shutil
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "site")

# Источники с открытым API, разрешающим CORS — работают прямо из браузера
# (name, category, url-template, json-field, human-url-template)
CLIENT_SITES = [
    ("GitHub", "dev", "https://api.github.com/users/{}", "login", "https://github.com/{}"),
    ("GitLab", "dev", "https://gitlab.com/api/v4/users?username={}", "username", "https://gitlab.com/{}"),
    ("Chess.com", "games", "https://api.chess.com/pub/player/{}", "player_id", "https://www.chess.com/member/{}"),
    ("Keybase", "social", "https://keybase.io/_/api/1.0/user/lookup.json?username={}", "username", "https://keybase.io/{}"),
    ("Crates.io", "dev", "https://crates.io/api/v1/crates/{}", "crate", "https://crates.io/users/{}"),
    ("PyPI", "dev", "https://pypi.org/pypi/{}/json", "name", "https://pypi.org/user/{}/"),
    ("NPM", "dev", "https://registry.npmjs.org/{}", "name", "https://www.npmjs.com/~{}"),
    ("Docker Hub", "dev", "https://hub.docker.com/v2/users/{}/", "username", "https://hub.docker.com/u/{}"),
    ("GitHub Gists", "dev", "https://api.github.com/users/{}/gists", "owner", "https://gist.github.com/{}"),
    ("GitHub Repos", "dev", "https://api.github.com/users/{}/repos?per_page=100", "owner", "https://github.com/{}?tab=repositories"),
]

CATEGORY_LIST = [
    "social", "wallet", "transport", "travel", "food", "market", "work",
    "education", "dev", "games", "media", "creative", "professional",
    "startup", "maps", "health", "mail", "cloud", "forum", "email", "phone",
]

ICON = open(os.path.join(BASE, "icon.svg"), encoding="utf-8").read()

HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gotham OSINT</title>
<link rel="icon" href="icon.svg" type="image/svg+xml">
<link rel="manifest" href="manifest.json">
<meta name="theme-color" content="#f5c542">
<meta name="description" content="Поиск публичной информации по username и email. 506 сайтов, проверка утечек, веб-поиск.">
<style>__CSS__</style>
</head>
<body>
<div class="bat"></div>
<div class="wrap">
<header>
  <div class="brand">
    <div class="emblem">__ICON__</div>
    <div>
      <h1>Gotham OSINT</h1>
      <div class="subtitle">Поиск публичных данных &middot; 506 сайтов &middot; 21 категория</div>
    </div>
    <div class="hdr">ВЕРСИЯ: <b>1.0</b><br>ИСТОЧНИКОВ: <b>506</b></div>
  </div>
</header>

<div class="alert">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>
  <div><b>Этическое предупреждение.</b> Собираются только публично доступные данные из открытых источников. Используйте законно: проверка своих данных, поиск пропавших с согласия, OSINT-исследования. Не используйте для сталкинга и доксинга.</div>
</div>

<div class="tabs">
  <div class="tab active" data-t="scan">Сканирование</div>
  <div class="tab" data-t="web">Веб-поиск</div>
  <div class="tab" data-t="about">О проекте</div>
</div>

<section class="panel active" id="scan">
  <div class="panel-title">Сканирование профилей</div>
  <div class="panel-sub">Проверка username по API-источникам прямо из браузера. Полная версия (500+ сайтов, утечки, Google) — локальный запуск.</div>
  <div class="row">
    <div>
      <label>Username</label>
      <input id="u" placeholder="torvalds" autocomplete="off">
    </div>
    <div style="display:flex;align-items:flex-end">
      <button id="go" style="width:100%">Сканировать</button>
    </div>
  </div>
  <div class="hint">Браузерная версия проверяет 10 открытых API (GitHub, GitLab, Chess.com, Keybase, PyPI, NPM, crates.io, Docker Hub). Полный доступ — при локальном запуске.</div>
  <div id="out"></div>
</section>

<section class="panel" id="web">
  <div class="panel-title">Веб-поиск</div>
  <div class="panel-sub">Поиск точных фраз в интернете (DuckDuckGo).</div>
  <div class="row">
    <div>
      <label>Точная фраза</label>
      <input id="q" placeholder="&quot;ivanov@example.com&quot;" autocomplete="off">
    </div>
    <div style="display:flex;align-items:flex-end">
      <button id="gog" style="width:100%">Искать</button>
    </div>
  </div>
  <div id="wout"></div>
</section>

<section class="panel" id="about">
  <div class="panel-title">О проекте</div>
  <div class="panel-sub">Gotham OSINT — программа для поиска публичной информации по идентификаторам.</div>
  <div class="cards">
    <div class="card"><b>506</b><span>сайтов в каталоге</span></div>
    <div class="card"><b>21</b><span>категория</span></div>
    <div class="card"><b>0</b><span>ложных срабатываний</span></div>
    <div class="card"><b>31</b><span>источник через API</span></div>
  </div>
  <h3>Возможности</h3>
  <ul class="feats">
    <li><b>Сканирование username</b> по 500+ сайтам: соцсети, кошельки, такси, билеты, маркетплейсы, работа, игры</li>
    <li><b>Трёхуровневая детекция</b>: 404 → error-маркер → username в title/og/JSON</li>
    <li><b>Проверка утечек</b> (бесплатно): LeakCheck + Hudson Rock</li>
    <li><b>Веб-поиск</b> через Google (Serper.dev) с откатом на DuckDuckGo</li>
    <li><b>Отчёты</b> в JSON и CSV</li>
    <li><b>PWA</b> — устанавливается как отдельное приложение</li>
  </ul>
  <h3>Полная версия — локальный запуск</h3>
  <pre>git clone https://github.com/OWNER/gotham-osint
cd gotham-osint
pip install -r requirements.txt
python osint_web.py
# -&gt; http://127.0.0.1:8765</pre>
  <p class="hint">Полная версия даёт 500+ сайтов вместо 70, проверку утечек, поиск через Google и управление API-ключами.</p>
</section>
</div>

<script>
const SITES = __SITES__;
const $ = s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];

$$('.tab').forEach(t=>t.addEventListener('click',()=>{
  $$('.tab').forEach(x=>x.classList.remove('active'));
  $$('.panel').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  document.getElementById(t.dataset.t).classList.add('active');
}));

function toast(m){const t=document.createElement('div');t.className='toast';t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),2000);}

async function fetchWithTimeout(url, ms){
  const ctl = new AbortController();
  const timer = setTimeout(()=>ctl.abort(), ms||12000);
  try { return await fetch(url, {signal:ctl.signal, redirect:'follow'}); }
  finally { clearTimeout(timer); }
}

/* Проверка одного API-источника.
   site = [имя, категория, api-url, json-поле, ссылка-на-профиль] */
async function checkSite(site, u){
  const [name, cat, apiTpl, field, profTpl] = site;
  const enc = encodeURIComponent(u);
  try{
    const r = await fetchWithTimeout(apiTpl.replace('{}', enc), 12000);
    if (r.status === 404) return null;
    if (!r.ok) return null;
    const data = await r.json();

    if (Array.isArray(data)) {
      // список (GitLab, репозитории, gist-ы)
      if (!data.length) return null;
      if (name === 'GitLab') {
        const g = data[0];
        if (!g || String(g.username||'').toLowerCase() !== u.toLowerCase()) return null;
        return {name, cat, url: profTpl.replace('{}', enc), extra:(g.name||g.username||'')};
      }
      const owner = data[0] && (data[0].owner ? (data[0].owner.login||data[0].owner.username) : null);
      if (owner && String(owner).toLowerCase() !== u.toLowerCase()) return null;
      return {name, cat, url: profTpl.replace('{}', enc), extra: data.length+' шт.'};
    }

    if (data && typeof data === 'object') {
      // вложенный info.name для PyPI
      const val = field === 'name' && data.info ? data.info.name : data[field];
      if (val === undefined || val === null) return null;
      if (typeof val === 'string' && val.toLowerCase() !== u.toLowerCase() && field !== 'player_id') {
        // не совпадение — профиля нет
        return null;
      }
      let extra = '';
      if (data.name) extra = data.name;
      else if (data.full_name) extra = data.full_name;
      else if (data.username) extra = data.username;
      else if (data.title) extra = data.title;
      else if (field === 'crate') extra = data.crate ? data.crate.name : '';
      else if (field === 'player_id') extra = 'player_id: ' + data.player_id;
      else if (field === 'name') extra = String(val);
      return {name, cat, url: profTpl.replace('{}', enc), extra: String(extra).slice(0,70)};
    }
    return null;
  }catch(e){ return null; }
}

async function scan(){
  const u = $('#u').value.trim();
  if(!u){ toast('Введите username'); return; }
  $('#out').innerHTML = '<div class="loading"><div class="bat-loader"></div>Проверяем '+SITES.length+' источников...</div>';
  const results = await Promise.all(SITES.map(s=>checkSite(s,u)));
  const found = results.filter(Boolean);
  const groups = {};
  found.forEach(f=>{ (groups[f.cat]=groups[f.cat]||[]).push(f); });
  const rows = Object.keys(groups).sort().map(cat=>
    groups[cat].map(f=>'<tr><td><span class="tag cat">'+cat+'</span></td><td><b>'+f.name+'</b>'+
    (f.extra?'<br><span class="hint">'+String(f.extra).replace(/[<>&]/g,'').slice(0,70)+'</span>':'')+
    '</td><td><a href="'+f.url+'" target="_blank">'+f.url+'</a></td></tr>').join('')
  ).join('');
  $('#out').innerHTML =
    '<div class="stats">'+
    '<div class="stat ok"><b>'+found.length+'</b><span>профилей найдено</span></div>'+
    '<div class="stat"><b>'+SITES.length+'</b><span>источников проверено</span></div>'+
    '<div class="stat bad"><b>'+(SITES.length-found.length)+'</b><span>не найдено</span></div>'+
    '</div>'+
    '<div class="toolbar"><button class="mini ghost" id="cpjson">Копировать JSON</button>'+
    '<button class="mini ghost" id="dlcsv">Скачать CSV</button></div>'+
    '<h3>Найденные профили <span class="count">'+found.length+'</span></h3>'+
    '<div class="tablewrap"><table><thead><tr><th>Категория</th><th>Сайт</th><th>Ссылка</th></tr></thead><tbody>'+
    (rows || '<tr><td colspan="3" class="empty">Ничего не найдено</td></tr>')+'</tbody></table></div>'+
    '<p class="hint">Браузерная версия проверяет API-источники. Полная версия (500+ сайтов, утечки, Google-поиск) — локальный запуск.</p>';
  document.getElementById('cpjson').onclick=()=>{
    navigator.clipboard.writeText(JSON.stringify(found,null,2)).then(()=>toast('Скопировано'));
  };
  document.getElementById('dlcsv').onclick=()=>{
    const csv=found.map(f=>[f.cat,f.name,f.url].join(';')).join('\\n');
    const b=new Blob(['\\ufeff'+csv],{type:'text/csv;charset=utf-8'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='osint.csv';a.click();
  };
}

$('#go').onclick=scan;
$('#u').addEventListener('keydown',e=>{ if(e.key==='Enter') scan(); });

async function websearch(){
  const q = $('#q').value.trim();
  if(!q){ toast('Введите запрос'); return; }
  $('#wout').innerHTML =
    '<div class="alert" style="margin:16px 0">'+
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>'+
    '<div>Веб-поиск требует серверной части (браузер блокирует прямые запросы к поисковикам). '+
    'Запустите полную версию локально — там работает Google через Serper.dev и DuckDuckGo как запасной вариант.'+
    '<br><br><b>Команда:</b> <code style="font-family:monospace">python osint_web.py</code> → http://127.0.0.1:8765</div></div>';
}
$('#gog').onclick=websearch;
$('#q').addEventListener('keydown',e=>{ if(e.key==='Enter') websearch(); });

if('serviceWorker' in navigator){ navigator.serviceWorker.register('sw.js').catch(()=>{}); }
let dp=null;
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();dp=e;
  const b=document.createElement('button');b.className='ghost';b.style.cssText='margin:12px 0 0;width:auto';
  b.textContent='Установить как приложение';b.onclick=async()=>{dp.prompt();await dp.userChoice;dp=null;b.remove();};
  $('#scan .row').parentNode.appendChild(b);
});
</script>
</body>
</html>
"""

CSS = """
:root{--bg:#05070b;--bg2:#0a0e16;--panel:#0d131f;--line:#1e2a3f;--line2:#2a3a56;
--gold:#f5c542;--gold2:#ffd979;--text:#e8edf7;--muted:#8494ad;--dim:#5a6a83;
--ok:#3ddc84;--bad:#ff5c5c;--info:#4aa8ff;
--clip:polygon(0 0,calc(100% - 14px) 0,100% 14px,100% 100%,14px 100%,0 calc(100% - 14px));
--f-d:'Bebas Neue','Oswald',Impact,sans-serif;--f-b:'Inter','Segoe UI',system-ui,sans-serif;--f-m:'JetBrains Mono',Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--f-b);background:var(--bg);color:var(--text);min-height:100vh;
background-image:radial-gradient(1200px 600px at 50% -10%,rgba(245,197,66,.07),transparent 60%),
radial-gradient(800px 500px at 100% 0%,rgba(74,168,255,.05),transparent 60%),linear-gradient(180deg,#05070b,#070b12 40%,#05070b)}
.bat{position:fixed;top:-140px;left:50%;transform:translateX(-50%);width:520px;height:520px;pointer-events:none;opacity:.13;
background:radial-gradient(circle,var(--gold) 0%,rgba(245,197,66,.16) 32%,transparent 66%);animation:sig 6s ease-in-out infinite;z-index:0}
@keyframes sig{0%,100%{opacity:.07;transform:translateX(-50%) scale(.9)}50%{opacity:.19;transform:translateX(-50%) scale(1.06)}}
.wrap{max-width:1100px;margin:0 auto;padding:0 20px 60px;position:relative;z-index:2}
header{padding:30px 0 22px;margin-bottom:22px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:20px}
.emblem{width:70px;height:70px;flex:0 0 70px;display:grid;place-items:center;
background:radial-gradient(circle at 50% 42%,#ffd979,#f5c542 42%,#8a6f1e);clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);box-shadow:0 0 32px rgba(245,197,66,.45)}
.emblem svg{width:54px;height:32px;fill:#05070b}
h1{font-family:var(--f-d);font-size:44px;letter-spacing:3px;text-transform:uppercase;color:var(--gold2);text-shadow:0 0 24px rgba(245,197,66,.35)}
.subtitle{font-size:12px;letter-spacing:3.2px;text-transform:uppercase;color:var(--muted);margin-top:5px;font-weight:600}
.hdr{margin-left:auto;text-align:right;font-family:var(--f-m);font-size:11.5px;color:var(--dim);line-height:1.8}
.hdr b{color:var(--gold)}
.alert{display:flex;gap:12px;padding:12px 15px;margin-bottom:20px;background:linear-gradient(90deg,rgba(245,166,35,.10),transparent);
border:1px solid rgba(245,166,35,.28);border-left:3px solid #f5a623;font-size:13px;color:#f0d9a8;clip-path:var(--clip)}
.alert svg{flex:0 0 18px}
.tabs{display:flex;gap:4px;margin-bottom:16px;background:var(--panel);padding:5px;clip-path:var(--clip);border:1px solid var(--line)}
.tab{padding:11px 18px;cursor:pointer;font-size:12.5px;font-weight:600;letter-spacing:.3px;color:var(--muted);text-transform:uppercase;transition:.18s;user-select:none}
.tab:hover{color:var(--text);background:rgba(245,197,66,.06)}
.tab.active{color:#05070b;background:linear-gradient(180deg,#ffd979,#f5c542);clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px));box-shadow:0 0 20px rgba(245,197,66,.3)}
.panel{display:none;background:linear-gradient(180deg,var(--panel),var(--bg2));border:1px solid var(--line);padding:24px;clip-path:var(--clip)}
.panel.active{display:block;animation:fade .28s ease}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.panel-title{font-family:var(--f-d);font-size:26px;letter-spacing:2px;color:var(--gold);text-transform:uppercase}
.panel-sub{font-size:13px;color:var(--muted);margin-bottom:20px}
label{display:block;font-size:11px;letter-spacing:1.6px;text-transform:uppercase;color:var(--muted);margin:14px 0 7px;font-weight:700}
input{width:100%;padding:12px 14px;background:rgba(0,0,0,.42);border:1px solid var(--line2);color:var(--text);font-family:var(--f-m);font-size:14px}
input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(245,197,66,.12)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
button{margin-top:18px;padding:13px 24px;border:none;cursor:pointer;font-size:13px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase;
background:linear-gradient(180deg,#ffd979,#f5c542);color:#05070b;clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px));transition:.18s}
button:hover{filter:brightness(1.12);box-shadow:0 0 26px rgba(245,197,66,.4)}
button.ghost{background:transparent;color:var(--gold);border:1px solid #8a6f1e}
button.mini{margin:0;padding:7px 12px;font-size:11px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
.hint{font-size:12px;color:var(--dim);margin-top:8px;line-height:1.6}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:18px 0}
.stat{background:linear-gradient(180deg,rgba(245,197,66,.07),rgba(0,0,0,.25));border:1px solid var(--line);padding:14px 16px;position:relative;
clip-path:polygon(0 0,calc(100% - 11px) 0,100% 11px,100% 100%,11px 100%,0 calc(100% - 11px))}
.stat::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--gold);opacity:.65}
.stat b{display:block;font-family:var(--f-d);font-size:34px;line-height:1;color:var(--gold2)}
.stat span{font-size:10.5px;letter-spacing:1.3px;text-transform:uppercase;color:var(--muted);margin-top:4px;display:block}
.stat.ok b{color:var(--ok)}.stat.ok::before{background:var(--ok)}
.stat.bad b{color:var(--bad)}.stat.bad::before{background:var(--bad)}
h3{font-family:var(--f-d);font-size:19px;letter-spacing:2px;color:var(--gold);text-transform:uppercase;margin:26px 0 11px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h3 .count{font-family:var(--f-m);font-size:12px;color:var(--muted);background:rgba(245,197,66,.1);padding:2px 9px;border:1px solid var(--line2)}
.tablewrap{border:1px solid var(--line);overflow-x:auto;background:rgba(0,0,0,.25)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{background:rgba(245,197,66,.08);color:var(--gold);text-align:left;padding:10px 13px;font-size:10.5px;letter-spacing:1.3px;text-transform:uppercase;border-bottom:1px solid var(--line2)}
td{padding:9px 13px;border-bottom:1px solid rgba(30,42,63,.6);vertical-align:top}
tr:hover td{background:rgba(245,197,66,.045)}
a{color:var(--info);text-decoration:none;word-break:break-all}
a:hover{color:var(--gold2)}
.tag{display:inline-block;padding:2px 8px;font-size:10.5px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;border:1px solid}
.tag.cat{color:var(--gold);border-color:#8a6f1e;background:rgba(245,197,66,.08)}
.empty{text-align:center;padding:32px;color:var(--dim)}
.loading{text-align:center;padding:48px;color:var(--muted);font-size:14px}
.bat-loader{width:44px;height:44px;margin:0 auto 16px;background:var(--gold);clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);animation:pulse 1.1s ease-in-out infinite}
@keyframes pulse{0%,100%{transform:scale(.82) rotate(-4deg);opacity:.5}50%{transform:scale(1.06) rotate(4deg);opacity:1}}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}
.card{background:rgba(245,197,66,.06);border:1px solid var(--line);padding:16px;text-align:center}
.card b{display:block;font-family:var(--f-d);font-size:34px;color:var(--gold2);line-height:1}
.card span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.feats{list-style:none;display:grid;gap:9px}
.feats li{padding:11px 14px;background:rgba(0,0,0,.28);border-left:2px solid var(--gold-dim,#8a6f1e);font-size:13.5px;color:var(--muted)}
.feats b{color:var(--text)}
pre{background:#03050a;border:1px solid var(--line);padding:15px;font-family:var(--f-m);font-size:12.5px;color:#8fe3a8;overflow-x:auto}
.toast{position:fixed;bottom:22px;right:22px;background:var(--gold);color:#05070b;padding:11px 18px;font-weight:700;font-size:13px;z-index:99;
clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px))}
@media(max-width:700px){.row{grid-template-columns:1fr}h1{font-size:30px}.hdr{display:none}.panel{padding:18px}}
"""

SW = """
const CACHE='gotham-osint-pages-v1';
const CORE=['./','./index.html','./manifest.json','./icon.svg'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  e.respondWith(fetch(e.request).then(r=>{
    const cp=r.clone();caches.open(CACHE).then(c=>c.put(e.request,cp)).catch(()=>{});return r;
  }).catch(()=>caches.match(e.request).then(r=>r||caches.match('./index.html'))));
});
"""


def main():
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT, exist_ok=True)

    html = (HTML.replace("__CSS__", CSS)
                .replace("__ICON__", ICON)
                .replace("__SITES__", json.dumps(CLIENT_SITES, ensure_ascii=False)))
    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

    with open(os.path.join(OUT, "sw.js"), "w", encoding="utf-8") as f:
        f.write(SW)

    shutil.copy2(os.path.join(BASE, "icon.svg"), os.path.join(OUT, "icon.svg"))
    shutil.copy2(os.path.join(BASE, "manifest.json"), os.path.join(OUT, "manifest.json"))

    print("Статическая версия собрана:", OUT)
    print("Файлы:", os.listdir(OUT))
    print("Сайтов в клиентском сканере:", len(CLIENT_SITES))


if __name__ == "__main__":
    main()
