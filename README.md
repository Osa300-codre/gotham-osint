# 🦇 Gotham OSINT

Программа для поиска **публичной** информации по идентификаторам: username, email, телефон, IP, домен, имя.

Сканирует **950+ источников** в 41 категории (13 ветвей каталога OSINT), проверяет утечки данных, ищет упоминания в интернете, сводит несколько идентификаторов в одно досье и складывает всё в накопительную **базу знаний**.

🌐 **Демо (PWA, работает в браузере):** <https://osa300-codre.github.io/gotham-osint/>

> ⚠️ **Этическое предупреждение.** Инструмент собирает только публично доступную информацию из открытых источников. Используйте его исключительно в законных целях: проверка собственных данных, поиск пропавших с согласия, OSINT-исследования. **Не используйте** для сталкинга, доксинга или нарушения приватности. Закон о защите персональных данных действует во всех странах.

---

## 🧩 Мультикоррелятор и база знаний

### Что добавлено

| Модуль | Назначение |
|--------|-----------|
| `correlator.py` | Несколько идентификаторов (телефон, e-mail, Telegram, VK, username, ФИО) → одно досье: профили, ФИО, адреса, ссылки на соцсети, граф связей, оценка экспозиции 0–100 |
| `linker.py` | Правила связывания площадок: общий e-mail/телефон, перцептивный хеш аватара (dHash), общие домены в био, нормализованное ФИО с транслитерацией |
| `knowledge.py` | Накопительная база знаний (SQLite): узлы, связи, атрибуты, свидетельства, кластеры. Каждый запуск дополняет базу, повторные подтверждения повышают уверенность |
| `person_resolve.py` | Извлечение ФИО, адресов, городов и ссылок на соцсети из публичных страниц (с фильтрацией служебных строк) |
| `catalog.py` | OSINT Catalog: дерево источников по таксономии (13 ветвей), поиск, экспорт в JSON/Markdown |
| `site_checks_ext.py` | +399 площадок и +107 справочных ресурсов по 30+ новым категориям |
| `test_linker_kb.py` | 13 офлайн-тестов связывания и базы знаний |

### Новые вкладки веб-интерфейса

| Вкладка | Что делает |
|---------|-----------|
| **Коррелятор личности** | Несколько идентификаторов сразу → единое досье + граф связей + оценка экспозиции |
| **Каталог OSINT** | Mind-map дерево источников: 13 ветвей, 41 категория, 951 источник, с фильтром |
| **База знаний** | Накопленный граф по всем запускам: узлы, связи, кластеры, поиск, полный граф |

### Как это связано

```
идентификаторы ──► identify.py / dossier.py / scanner.py   (сбор по 950+ источникам)
                          │
                          ▼
                    linker.py  (правила связывания площадок)
                          │
                          ▼
                    correlator.py (граф, кластеры, ФИО, риск)
                          │
                          ▼
                    knowledge.py (накопительная база osint_kb.sqlite)
                          │
                          ▼
                    catalog.py  (карта источников для следующих запусков)
```

### Использование

```bash
# CLI: несколько идентификаторов -> одно досье
python correlator.py --phone "+79991234567" --email ivan@example.com \
                     --telegram @ivan_petrov --vk https://vk.com/id123456 \
                     --name "Иван Петров" --deep --yes

# выгрузки: correlation_report.json / .md / correlation_graph.html

# каталог источников
python catalog.py            # печатает статистику + экспортирует osint_catalog.json и OSINT_CATALOG.md

# база знаний
python -c "import knowledge,json; print(json.dumps(knowledge.KnowledgeBase().stats(),ensure_ascii=False,indent=2))"

# тесты
python test_linker_kb.py
```

### Как «связаны» площадки

Каждая пара профилей проверяется по набору правил, результаты складываются:

| Правило | Вес |
|----------|-----|
| общий e-mail в профилях | 0.95 |
| общий телефон | 0.92 |
| перцептивный хеш аватара (расстояние ≤ 6) | 0.80 |
| идентичный файл аватара | 0.90 |
| совпадение ФИО (с транслитерацией, без отчества) | до 0.85 |
| общий домен в био/ссылках | 0.75 |
| одинаковый ник на разных площадках | 0.60 |

Несколько независимых правил усиливают связь (+0.05 каждое, максимум +0.15).
Связи складываются в SQLite-базу, где повторное подтверждение поднимает
уверенность — со временем граф становится плотнее и точнее.


---

## 🚀 Быстрый старт

### Веб-интерфейс (рекомендуется)

```bash
pip install -r requirements.txt
python osint_web.py
```

Откройте <http://127.0.0.1:8765>

### Командная строка

```bash
# сканирование username по всем сайтам
python osint_finder.py --username torvalds --yes

# только соцсети
python osint_finder.py --username torvalds --categories social --yes

# проверка утечек (бесплатно, без ключей)
python osint_finder.py --leaks ivanov@example.com --yes

# поиск упоминаний в Google
python osint_finder.py --search "ivanov@example.com" --yes

# IP / домен / телефон
python osint_finder.py --ip 8.8.8.8 --domain github.com --phone +79991234567 --yes

# JSON-вывод для автоматизации
python osint_finder.py --username torvalds --json --yes
```

---

## 🗂 Категории сайтов (506)

| Категория | Примеры |
|---|---|
| `social` | VK, OK, Telegram, Instagram, Twitter/X, TikTok, YouTube, Reddit, Pinterest, Threads, Bluesky, Mastodon |
| `wallet` | PayPal, YooMoney, Qiwi, WebMoney, AdvCash, Binance, Coinbase, Kraken, Ledger, Trezor, Trust Wallet, MetaMask |
| `transport` | Uber, Яндекс Go, Bolt, Didi, BlaBlaCar, FlixBus, РЖД, Aviasales, Ryanair, Wizz Air, Pulkovo |
| `travel` | Booking, Airbnb, TripAdvisor, Озон Травел, Яндекс Путешествия, Level.Travel, Tiqets |
| `food` | Delivery Club, Яндекс Еда, Glovo, Wolt, Grab, DoorDash, Zomato, iFood |
| `market` | Ozon, Wildberries, Avito, DNS, Citilink, M.Video, Lamoda, AliExpress, eBay |
| `work` | hh.ru, Фрилансхаб, Kwork, Fiverr, Upwork, Profi.ru, YouDo, Glassdoor |
| `education` | Coursera, Udemy, Stepik, Skillbox, Нетология, GeekBrains, Skyeng |
| `dev` | GitHub, GitLab, npm, PyPI, Docker Hub, Kaggle, Codewars, HackerRank, Replit |
| `games` | Steam, Chess.com, Lichess, Roblox, Epic Games, Battle.net, osu!, itch.io |
| `media` | YouTube-альт, SoundCloud, Bandcamp, IMDb, Letterboxd, Habr, vc.ru, Pikabu, Dzen |
| `creative` | Behance, Dribbble, Figma, DeviantArt, Ko-fi, Patreon, Gumroad, Canva |
| `professional` | LinkedIn, Xing, Read.cv, Polywork, Peerlist, Apollo.io, Lusha |
| `startup` | Product Hunt, Indie Hackers, AngelList, Wellfound, Crunchbase, Kickstarter |
| `maps` | Google Maps, OpenStreetMap, Яндекс Карты, 2GIS, Mapillary, Komoot |
| `health` | Strava, Garmin, MyFitnessPal, Life360, Nike, Fitbit, Headspace |
| `mail` | Gmail, Outlook, ProtonMail, Mail.ru, Рамблер, Inbox.lv, Tutanota |
| `cloud` | AWS-подобные: Vercel, Netlify, DigitalOcean, Cloudflare, Timeweb, Selectel, REG.RU |
| `forum` | AskUbuntu, 3DToday, Overclockers, Tom's Hardware, Disqus, GameFAQs |
| `email` | Gravatar, EmailRep, HIBP, IntelX, Epieos, Hunter.io, Pipl |
| `phone` | Truecaller, Sync.me, PhoneBooker, WhitePages, SpamCalls, ShouldIAnswer |

---

## 🔍 Как работает определение профиля

Обычные скрипты дают **ложные срабатывания**, потому что URL почти всегда содержит подставленный username. Здесь используется трёхуровневая проверка:

1. **HTTP 404/410** → профиля точно нет
2. **error-маркер** в тексте страницы → профиля нет
3. **подтверждение в сигналах** → username найден в `<title>`, `<h1>`, `og:title`, `og:description` или в JSON-полях (`"username":"..."`)

> `og:url` намеренно **не** используется — он всегда содержит username и давал ложные срабатывания.

31 сайт проверяется через **открытые API** (GitHub, Steam XML, Chess.com, NPM, PyPI, HackerNews, Reddit, Docker Hub…) — это самая точная детекция.

**Проверка точности:** на заведомо несуществующем username — **0 ложных срабатываний** из 465 проверок.

---

## 🎯 Точный поиск (новое)

Отдельный режим для конкретных идентификаторов — собирает полное досье:

### Telegram
```bash
python osint_finder.py --telegram durov --yes
```
Имя, описание (bio), аватар, число подписчиков, проверка существования, утечки, упоминания в интернете.

### Ссылка ВКонтакте
```bash
python osint_finder.py --vk https://vk.com/durov --yes
```
Принимает любую форму: `vk.com/durov`, `vk.ru/durov`, `m.vk.com/durov`, `vk.com/id123`, `vk.com/club123`.
Достаёт имя, ник, город, место работы, статус, аватар, утечки, упоминания.
*(Обычный HTML ВК содержит только оболочку страницы, поэтому профиль читается через текстовый рендер.)*

### Email
```bash
python osint_finder.py --identify ivanov@example.com --yes
```
Профиль Gravatar (имя, фото, ссылки на соцсети), утечки, заражения инфостилерами, HIBP, упоминания в Google.

### Номер телефона
```bash
python osint_finder.py --identify +79991234567 --yes
```
Нормализация в E.164, страна по коду, оператор и тип линии (Numverify), утечки по номеру, упоминания.

### Универсальный режим
```bash
python osint_finder.py --identify "значение" --yes
```
Тип определяется автоматически: email / ВК-ссылка / Telegram / телефон.

В веб-интерфейсе это вкладка **«Точный поиск»** — можно заполнить несколько полей сразу.

---

## 🕵️ Досье (максимум данных по email / телефону)

Отдельный режим, собирающий всё доступное по идентификатору в одном отчёте:

| Что | Откуда |
|---|---|
| **ФИО, дата рождения, пол** | публичные базы утечек (DeHashed) |
| **Адрес, город, регион, район, индекс** | публичные базы утечек + объявления (веб-поиск) |
| **Телефоны, email, логины, IP** | утечки, профили, связанные аккаунты |
| **Утечки** | LeakCheck (метаданные) + DeHashed (полные записи) + HIBP |
| **Заражение инфостилером** | Hudson Rock |
| **Оператор и тип линии** | Numverify |
| **Связанные аккаунты** | сканер 506 сайтов по найденным логинам |
| **Упоминания в интернете** | Google (Serper.dev) / DuckDuckGo |

```bash
python osint_finder.py --dossier ivanov@example.com --yes
python osint_finder.py --dossier +79991234567 --yes
```

В веб-интерфейсе — вкладка **«Досье»**.

### Что нужно для ФИО / даты рождения / адреса

LeakCheck (бесплатный) отдаёт только **метаданные** — какие поля утекали, без значений.
**Значения** (ФИО, ДР, адрес, город, телефон) отдаёт **DeHashed** — $3 за 100 кредитов
(1 кредит = 1 запрос). Ключ вставляется во вкладку «Ключи».

### 💳 Как оплатить из России

У DeHashed оплата только криптой, у Patreon/HIBP и зарубежных Stripe-сервисов
российские карты не проходят. Рабочие варианты:

| Способ | Детали |
|---|---|
| **Не платить вообще** | XposedOrNot (11.6 млрд записей) + **Safe Surf / НКЦКИ** + LeakCheck + Hudson Rock уже дают полную картину |
| **USDT через P2P** | Bybit / Binance P2P → купить USDT за рубли с карты РФ → оплатить DeHashed. P2P — официальная площадка биржи, комиссия ~0,3–1 % |
| **IntelX** | от €2 500/год, принимает карты и банковские переводы |

---

## 🕵️ Личные данные (без единого платного ключа)

В разделе **«Досье»** появился блок **«Личные данные»** — собирает ФИО, адрес,
владельца номера и **все соцсети** человека. Работает полностью на бесплатных
источниках:

| Что | Бесплатный источник |
|---|---|
| **ФИО** | коммиты GitHub по email (`author.name` — настоящее имя), веб-поиск по объявлениям |
| **Все аккаунты с этим email** | GitHub Search API без ключа — до 20 логинов сразу |
| **Владелец номера** | Kaspersky Who Calls (РФ) — имя, город, оператор |
| **Адрес, город, этаж/квартира** | веб-поиск (dorks по «Имя:», «Адрес:», объявлениям) |
| **Все соцсети** | сканер 506 сайтов по каждому найденному логину |
| **Профили в Steam** | Steam Community Search по email |
| **Утечки** | LeakCheck, XposedOrNot, Safe Surf (НКЦКИ) |

Целевые веб-запросы (dorks) строятся автоматически, например:
`"79991234567" "Имя:"`, `"79991234567" "Адрес:"`, `"79991234567" site:avito.ru`,
`"79991234567" владелец номера`, `"ivanov@example.com" ФИО`.

Каждое найденное значение сопровождается **ссылкой на источник** — можно
сразу проверить, откуда взялось имя или адрес.

---

## 🕸️ Глубокое исследование (граф связей)

Новый режим: по **любому** идентификатору строится граф связей с рекурсивным обходом.

```
Точка входа → профиль → извлечение новых идентификаторов → новая ветка → …
```

Из каждого найденного профиля извлекаются: **ники, email, телефон, ФИО, фото, домены, ссылки**.
Каждый новый идентификатор становится новой ветвью поиска.

```bash
python osint_finder.py --deep durov --depth 2 --yes
```

| Вход | Что раскрывается |
|---|---|
| **Telegram username** | имя, bio, аватар → утечки → 800+ соцсетей → email/телефон из профилей → веб-поиск по найденным данным |
| **Email** | Gravatar, утечки, GitHub-коммиты (настоящее ФИО!), аккаунты с этим email |
| **Телефон** | утечки, владелец номера, объявления, профили по производным логинам |
| **ФИО / ник** | 800+ сайтов + веб-поиск + утечки |
| **Ссылка ВК** | имя, город, работа, статус, фото → ветви |

Результат: **граф (узлы + рёбра)**, слои исследования, сводка по типам данных.
Глубина 1 — 30–60 сек, глубина 2 — 1–3 мин, глубина 3 — 5–10 мин.

В веб-интерфейсе — вкладка **«Глубокое исследование»** с ползунком глубины.

---

## 📚 Каталог OSINT-ресурсов

Вкладка **«Каталог»** — 14 категорий, 123 инструмента (структура OSINT Catalog):

| Категория | Инструменты |
|---|---|
| Поиск и мониторинг | Google/Bing/Yandex, DuckDuckGo, Brave, Mojeek, Searx, urlscan.io, Wayback |
| Люди и контакты | Hunter.io, Apollo, RocketReach, SignalHire, ContactOut, Pipl, Numverify, Epieos |
| Соцсети и мессенджеры | Telegram, VK, OK, Instagram, X, TikTok, YouTube, Reddit, Pikabu, Habr |
| Домены, сеть и угрозы | crt.sh, hackertarget, VirusTotal, URLhaus, OTX, Shodan, Censys, GreyNoise |
| Гео и объекты | Google/Яндекс.Карты, 2ГИС, OSM, Mapillary, ip-api, ipinfo.io |
| Медиа и файлы | **Bing Visual Search**, Яндекс.Картинки, TinEye, SauceNAO, ExifTool |
| Реестры и бизнес | Руспрофиль, СБИС, Чеко, List-Org, ЕГРЮЛ, Контур.Фокус, SEC EDGAR |
| Рабочая среда | GitHub, GitLab, Sourcegraph, grep.app, Stack Overflow, npm/PyPI |
| OPSEC и обучение | HIBP, Firefox Monitor, Safe Surf/НКЦКИ, EFF Cover Your Tracks |
| Код и репозитории | GitHub/GitLab/Codeberg, Gitea, Replit, SourceForge, Docker Hub |
| Промпты и скиллы | Gists, Pastebin, GitLab Snippets, Hugging Face |
| Дорки | готовые шаблоны запросов под контакты, утечки, профили, PDF/таблицы |
| Порты | Shodan, Censys, Netlas, FOFA, ZoomEye |

---

## 💧 Проверка утечек (бесплатно, без ключей)

| Источник | Что даёт |
|---|---|
| **LeakCheck** | количество утечек, **названия источников** (Trello, Wattpad…), даты, **какие данные утекли** (пароли, телефоны, адреса, IP) |
| **XposedOrNot** | 792 утечки / 11.6 млрд записей, **без ключа** — список утечек, типы данных, **риск-скор**, стойкость паролей, отрасль |
| **Safe Surf / НКЦКИ** 🇷🇺 | **российский госсервис** (ФСТЭК) — агрегатор утечек, полностью на русском, **бесплатно, без VPN и без карт** |
| **Hudson Rock** | был ли компьютер заражён инфостилером (кража ОС-данных) |
| **Have I Been Pwned** | 1046+ баз утечек — *нужен платный ключ* |

```bash
python osint_finder.py --leaks ivanov@example.com --yes
```

---

## 🔑 Платные сервисы (необязательно)

Базовый функционал полностью бесплатен. Ключи подключаются в веб-интерфейсе (вкладка **«Ключи»**) и сохраняются в `osint_keys.json`.

| Ключ | Сервис | Цена | Возможности |
|---|---|---|---|
| `SERPER_API_KEY` | Serper.dev | 2500 запросов бесплатно, далее $0.30–1 / 1000 | Настоящий поиск Google вместо DuckDuckGo |
| `HUNTER_API_KEY` | Hunter.io | 50 кредитов/мес бесплатно, $34/мес | Все email сотрудников компании + проверка валидности |
| `HIBP_API_KEY` | Have I Been Pwned | ~$3.50/мес | 1046+ баз утечек |
| `DEHASHED_API_KEY` | DeHashed | $3 / 100 кредитов | Поиск по утечкам по любому термину |
| `XON_API_KEY` | xonAPI+ (XposedOrNot) | $9/мес, **оплата картой** | 792 утечки / 11.6 млрд записей, домены, пасты |
| `REVEALER_API_KEY` | Revealer.us | $12.99–29.99/мес, **оплата картой** | 800+ платформ, breach lookup, people reveal, API |
| `NUMVERIFY_API_KEY` | Numverify | 100/мес бесплатно | Страна, оператор, тип линии телефона |
| `EPIEOS_API_KEY` | Epieos | €29.99/мес | Обратный поиск email/телефона по 14+ соцсетям |
| `INTELX_API_KEY` | Intelligence X | от €2 500/год | Поиск по Tor/I2P/пастам |

Из CLI:

```bash
python osint_finder.py --keys                    # статус ключей
python osint_finder.py --set-key HIBP_API_KEY=xxx # сохранить ключ
python osint_finder.py --premium ivanov@example.com --yes
```

---

## 🖥 Установка как приложение (PWA)

`osint_web.py` поддерживает Progressive Web App — в Chrome/Edge:

1. Откройте <http://127.0.0.1:8765>
2. Нажмите иконку установки в адресной строке (или «Установить приложение» в меню)
3. Появится отдельное окно приложения с иконкой — работает как обычная программа

Также встроенная кнопка **«Установить как приложение»** на главной вкладке.

---

## ☁️ Развёртывание

### GitHub Pages (статическая PWA-версия)

```bash
python export_static.py      # собирает папку site/
```

Веб-версия на Pages работает в браузере без сервера: сканирование по открытым API
(GitHub, GitLab, Chess.com, Keybase, PyPI, NPM, crates.io, Docker Hub) + PWA-установка.
Деплой настроен через `.github/workflows/deploy.yml` — push в `main` публикует сайт автоматически.

### Облако (полная версия с 500+ сайтами)

`Dockerfile` и `render.yaml` в комплекте:

```bash
docker build -t gotham-osint .
docker run -p 8765:8765 gotham-osint
```

Или подключите репозиторий в Render.com / Railway / Fly.io — деплой в один клик.
Ключи задаются через переменные окружения: `HIBP_API_KEY`, `SERPER_API_KEY`,
`HUNTER_API_KEY`, `DEHASHED_API_KEY`, `NUMVERIFY_API_KEY`, `EPIEOS_API_KEY`.

### Свой сервер

```bash
python osint_web.py
# или: HOST=0.0.0.0 PORT=8765 python osint_web.py
```

---

## 📁 Структура проекта

```
gotham-osint/
├── osint_finder.py    # CLI-точка входа
├── osint_web.py       # веб-интерфейс (FastAPI) + PWA
├── scanner.py         # асинхронный движок проверки (aiohttp, 30 потоков)
├── site_checks.py     # каталог 506 сайтов и 21 категория
├── websearch.py       # веб-поиск (DuckDuckGo)
├── leaks.py           # проверка утечек (LeakCheck, Hudson Rock, HIBP)
├── premium.py         # платные сервисы и управление ключами
├── identify.py        # точный поиск: Telegram, email, ВК, телефон
├── personal.py        # личные данные: ФИО, адрес, владелец номера, все соцсети
├── safesurf_ru.py     # Safe Surf / НКЦКИ — российский сервис утечек
├── dossier.py         # полное досье: ФИО, ДР, адрес, контакты, утечки
├── export_static.py   # сборка статической PWA-версии для GitHub Pages
├── manifest.json      # PWA-манифест
├── icon.svg           # иконка приложения
├── Dockerfile         # деплой в облако
├── render.yaml        # конфиг Render.com
├── .github/workflows/deploy.yml
├── requirements.txt
├── LICENSE
└── README.md
```

---

## ⚙️ Требования

- Python 3.10+
- `requests`, `aiohttp`, `fastapi`, `uvicorn`, `beautifulsoup4`

---

## 📜 Лицензия

MIT. См. [LICENSE](LICENSE).
