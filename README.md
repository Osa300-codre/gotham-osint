# 🦇 Gotham OSINT

Программа для поиска **публичной** информации по идентификаторам: username, email, телефон, IP, домен, имя.

Сканирует **506 сайтов** в 21 категории, проверяет утечки данных и ищет упоминания в интернете.

🌐 **Демо (PWA, работает в браузере):** <https://osa300-codre.github.io/gotham-osint/>

> ⚠️ **Этическое предупреждение.** Инструмент собирает только публично доступную информацию из открытых источников. Используйте его исключительно в законных целях: проверка собственных данных, поиск пропавших с согласия, OSINT-исследования. **Не используйте** для сталкинга, доксинга или нарушения приватности. Закон о защите персональных данных действует во всех странах.

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

## 💧 Проверка утечек (бесплатно, без ключей)

| Источник | Что даёт |
|---|---|
| **LeakCheck** | количество утечек, **названия источников** (Trello, Wattpad…), даты, **какие данные утекли** (пароли, телефоны, адреса, IP) |
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
| `NUMVERIFY_API_KEY` | Numverify | 100/мес бесплатно | Страна, оператор, тип линии телефона |
| `EPIEOS_API_KEY` | Epieos | €29.99/мес | Обратный поиск email/телефона по 14+ соцсетям |

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
