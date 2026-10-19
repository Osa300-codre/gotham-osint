#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Каталог OSINT-ресурсов по категориям (структура «OSINT Catalog»).
Используется в веб-интерфейсе как справочник и как источник шаблонов
поиска для глубокого исследования.
"""

from typing import Any, Dict, List

CATEGORIES: List[Dict[str, Any]] = [
    {
        "name": "Поиск и мониторинг",
        "icon": "🔎",
        "tools": [
            ("Google / Bing / Yandex", "https://www.google.com", "Дорки по любому идентификатору"),
            ("DuckDuckGo", "https://duckduckgo.com", "Поиск без трекинга"),
            ("Brave Search", "https://search.brave.com", "Независимый поисковик"),
            ("Mojeek", "https://www.mojeek.com", "Индекс без Google"),
            ("Searx / 4get", "https://searx.be", "Метапоисковики"),
            ("Serper.dev", "https://serper.dev", "Google Search API (2500 бесплатно)"),
            ("urlscan.io", "https://urlscan.io", "История сканирований и скриншоты"),
            ("Wayback Machine", "https://web.archive.org", "Архив прошлых версий сайтов"),
            ("ChangeDetection.io", "https://changedetection.io", "Отслеживание изменений сайтов"),
        ],
    },
    {
        "name": "Люди и контакты",
        "icon": "👤",
        "tools": [
            ("Hunter.io", "https://hunter.io", "Email по домену, проверка email"),
            ("Apollo.io", "https://www.apollo.io", "Контакты компаний"),
            ("RocketReach", "https://rocketreach.co", "Email и телефоны"),
            ("SignalHire", "https://www.signalhire.com", "Резюме и контакты"),
            ("ContactOut", "https://contactout.com", "Email и телефоны по имени"),
            ("Clearbit", "https://clearbit.com", "Данные о компаниях"),
            ("Pipl", "https://pipl.com", "Поиск людей"),
            ("Lusha", "https://www.lusha.com", "B2B-контакты"),
            ("Numverify", "https://numverify.com", "Оператор и тип линии"),
            ("Epieos", "https://epieos.com", "Обратный поиск по email/телефону"),
        ],
    },
    {
        "name": "Соцсети и мессенджеры",
        "icon": "💬",
        "tools": [
            ("Telegram", "https://t.me", "Профили и каналы"),
            ("VK", "https://vk.com", "Профили, сообщества, фото"),
            ("OK", "https://ok.ru", "Профили"),
            ("Instagram", "https://instagram.com", "Профили и фото"),
            ("Facebook", "https://facebook.com", "Профили"),
            ("X / Twitter", "https://x.com", "Профили и твиты"),
            ("TikTok", "https://tiktok.com", "Профили и видео"),
            ("YouTube", "https://youtube.com", "Каналы и видео"),
            ("Reddit", "https://reddit.com", "Профили и комментарии"),
            ("Pinterest", "https://pinterest.com", "Доски и профили"),
            ("Pikabu", "https://pikabu.ru", "Профили"),
            ("Habr", "https://habr.com", "Пользователи и блоги"),
            ("vc.ru", "https://vc.ru", "Авторы и редакции"),
            ("Telegram-мосты", "https://telemetr.io", "Поиск по сообщениям Telegram"),
        ],
    },
    {
        "name": "Домены, сеть и угрозы",
        "icon": "🛡️",
        "tools": [
            ("crt.sh", "https://crt.sh", "Поддомены через сертификаты"),
            ("hackertarget", "https://hackertarget.com", "Поддомены и DNS"),
            ("SecurityTrails", "https://securitytrails.com", "История DNS"),
            ("VirusTotal", "https://virustotal.com", "Репутция домена и IP"),
            ("URLhaus", "https://urlhaus.abuse.ch", "Вредоносные URL"),
            ("AlienVault OTX", "https://otx.alienvault.com", "Индикаторы компрометации"),
            ("Shodan", "https://shodan.io", "Поиск по IP и портам"),
            ("Censys", "https://censys.io", "Инвентаризация хостов"),
            ("GreyNoise", "https://greynoise.io", "IP сканеров"),
            ("CVE", "https://cve.mitre.org", "Уязвимости"),
    ],
    },
    {
        "name": "Гео и объекты",
        "icon": "🛰️",
        "tools": [
            ("Google Maps", "https://maps.google.com", "Профили и объекты"),
            ("Яндекс.Карты", "https://yandex.ru/maps", "Объекты и организации"),
            ("2ГИС", "https://2gis.ru", "Организации и адреса"),
            ("OpenStreetMap", "https://openstreetmap.org", "POI и пользователи"),
            ("Mapillary", "https://mapillary.com", "Уличные фото"),
            ("Geonames", "https://geonames.org", "Геосправочник"),
            ("IP-API", "https://ip-api.com", "Геолокация по IP"),
            ("ipinfo.io", "https://ipinfo.io", "Оператор и ASN"),
        ],
    },
    {
        "name": "Медиа и файлы",
        "icon": "🖼️",
        "tools": [
            ("Bing Visual Search", "https://www.bing.com/images", "Обратный поиск по фото"),
            ("Яндекс.Картинки", "https://yandex.com/images", "Обратный поиск по фото"),
            ("TinEye", "https://tineye.com", "Обратный поиск по фото"),
            ("SauceNAO", "https://saucenao.com", "Поиск по аниме-арту"),
            ("ExifTool", "https://exiftool.org", "Метаданные фото и видео"),
            ("Archive.org", "https://archive.org", "Файлы и веб-архивы"),
            ("VirusTotal (файлы)", "https://virustotal.com", "Хеши и проверка файлов"),
        ],
    },
    {
        "name": "Реестры и бизнес",
        "icon": "🏢",
        "tools": [
            ("Руспрофиль", "https://www.rusprofile.ru", "Реестр компаний РФ"),
            ("СБИС", "https://sbis.ru", "Реквизиты и сотрудники"),
            ("Чеко", "https://checko.ru", "Проверка контрагентов"),
            ("List-Org", "https://list-org.com", "Организации по всей миру"),
            ("ЕГРЮЛ", "https://egrul.nalog.ru", "Официальный реестр РФ"),
            ("Контур.Фокус", "https://focus.kontur.ru", "Финансовая отчётность"),
            ("SEC EDGAR", "https://sec.gov/edgar", "Отчётность США"),
            ("OpenCorporates", "https://opencorporates.com", "Компании мира"),
        ],
    },
    {
        "name": "Рабочая среда",
        "icon": "🖥️",
        "tools": [
            ("GitHub", "https://github.com", "Репозитории, коммиты, профили"),
            ("GitLab", "https://gitlab.com", "Репозитории и профили"),
            ("Sourcegraph", "https://sourcegraph.com", "Поиск по коду"),
            ("grep.app", "https://grep.app", "Поиск по коду"),
            ("Gitter", "https://gitter.im", "Чаты разработчиков"),
            ("Stack Overflow", "https://stackoverflow.com", "Профили и вопросы"),
            ("npm / PyPI / Docker Hub", "https://npmjs.com", "Пакеты и аккаунты"),
        ],
    },
    {
        "name": "OPSEC и обучение",
        "icon": "🛡",
        "tools": [
            ("Have I Been Pwned", "https://haveibeenpwned.com", "Проверка своих утечек"),
            ("Firefox Monitor", "https://monitor.mozilla.org", "Бесплатная проверка"),
            ("Safe Surf / НКЦКИ", "https://chk.safe-surf.ru", "Проверка утечек, РФ"),
            ("SecurityTrails", "https://securitytrails.com", "История изменений домена"),
            ("Privacy Checker", "https://privacy-checker.org", "Проверка трекеров"),
            ("EFF Cover Your Tracks", "https://coveryourtracks.eff.org", "Защита от слежки"),
        ],
    },
    {
        "name": "Код и репозитории",
        "icon": "💻",
        "tools": [
            ("GitHub", "https://github.com", "Код, коммиты, email авторов"),
            ("GitLab", "https://gitlab.com", "Код и пайплайны"),
            ("Codeberg", "https://codeberg.org", "Открытый хостинг Git"),
            ("Gitea / Forgejo", "https://codeberg.org", "Свой Git-сервер"),
            ("Replit", "https://replit.com", "Проекты и аккаунты"),
            ("SourceForge", "https://sourceforge.net", "Проекты и пользователи"),
            ("Docker Hub", "https://hub.docker.com", "Образы и пользователи"),
        ],
    },
    {
        "name": "Промпты и скиллы",
        "icon": "🧠",
        "tools": [
            ("GitHub Gists", "https://gist.github.com", "Сниппеты и аккаунты"),
            ("Pastebin", "https://pastebin.com", "Публичные пасты"),
            ("GitLab Snippets", "https://gitlab.com/snippets", "Сниппеты"),
            ("r/prompt", "https://reddit.com", "Сообщества по промптам"),
            ("Hugging Face", "https://huggingface.co", "Модели и авторы"),
        ],
    },
    {
        "name": "Дорки",
        "icon": "🎯",
        "tools": [
            ("Базовый синтаксис", "https://www.google.com", '"точная фраза" site:домен filetype:pdf'),
            ("Контакты", "https://www.google.com", '"email" OR "телефон" -site:example.com'),
            ("Данные из утечек", "https://www.google.com", '"номер" "Дата рождения"'),
            ("Профили", "https://www.google.com", '"никнейм" site:t.me OR site:github.com'),
            ("PDF/таблицы", "https://www.google.com", '"email" filetype:xlsx OR filetype:csv'),
            ("Кэш Google", "https://www.google.com", 'cache:site:домен'),
            ("Сайт-оператор", "https://www.google.com", 'site:site.com -site:www.site.com'),
            ("Личный кабинет", "https://www.google.com", 'inurl:login OR inurl:profile'),
        ],
    },
    {
        "name": "Порты",
        "icon": "🔌",
        "tools": [
            ("Shodan", "https://shodan.io", "Открытые порты и сервисы"),
            ("Censys", "https://censys.io", "Сертификаты и хосты"),
            ("Crt.sh", "https://crt.sh", "Поддомены и TLS"),
            ("Netlas", "https://app.netlas.io", "Хосты и сервисы"),
            ("FOFA", "https://fofa.info", "Поиск по хостам"),
            ("ZoomEye", "https://www.zoomeye.org", "Китайский Shodan"),
        ],
    },
]


def all_tools() -> List[Dict[str, str]]:
    """Плоский список всех инструментов."""
    out = []
    for cat in CATEGORIES:
        for name, url, desc in cat["tools"]:
            out.append({"category": cat["name"], "name": name, "url": url, "desc": desc})
    return out


def total() -> int:
    return sum(len(c["tools"]) for c in CATEGORIES)
