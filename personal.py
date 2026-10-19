#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сбор личных данных по email / телефону из БЕСПЛАТНЫХ открытых источников.

Источники (все без API-ключей и без оплаты):
  * GitHub API (без ключа)      — ФИО из коммитов + все аккаунты с этим email
  * Kaspersky Who Calls (RU)    — владелец номера, город, оператор
  * Steam Search                — профили по email
  * Google/Serper веб-поиск     — объявления и страницы с ФИО, адресом, городом
  * 506-сайтовый сканер          — все профили по найденным логинам
  * XposedOrNot / LeakCheck      — метаданные утечек

Данные берутся только из публично доступных страниц и открытых API.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

TIMEOUT = 20
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8",
}


def _get(url: str, **params) -> Optional[requests.Response]:
    try:
        return requests.get(url, params=params, headers=HEADERS, timeout=TIMEOUT)
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  GitHub: ФИО и аккаунты по email (без ключа)
# ---------------------------------------------------------------------------
def github_commits_identity(email: str) -> Dict[str, Any]:
    """Имена автора и репозитории из коммитов по email."""
    out: Dict[str, Any] = {"names": [], "repos": [], "profile_hints": [], "error": None}
    r = _get("https://api.github.com/search/commits",
             q=f"author-email:{email}", per_page=30)
    if r is None:
        out["error"] = "GitHub недоступен"
        return out
    if r.status_code != 200:
        out["error"] = f"GitHub commits: HTTP {r.status_code}"
        return out
    try:
        data = r.json()
    except Exception:
        out["error"] = "не удалось разобрать ответ GitHub"
        return out

    seen_names, seen_repos = set(), set()
    for item in (data.get("items") or [])[:30]:
        author = (item.get("commit") or {}).get("author") or {}
        name = (author.get("name") or "").strip()
        if name and name.lower() not in seen_names and "@" not in name:
            seen_names.add(name.lower())
            out["names"].append(name)
        repo = (item.get("repository") or {}).get("full_name")
        owner = (item.get("repository") or {}).get("owner", {}).get("login")
        if repo and repo not in seen_repos:
            seen_repos.add(repo)
            out["repos"].append(repo)
        if owner and owner not in out["profile_hints"]:
            out["profile_hints"].append(owner)
    out["total_commits"] = data.get("total_count")
    return out


def github_users_by_email(email: str) -> Dict[str, Any]:
    """Аккаунты GitHub, где email указан в профиле."""
    out: Dict[str, Any] = {"logins": [], "error": None}
    r = _get("https://api.github.com/search/users", q=f"{email} in:email", per_page=20)
    if r is None:
        out["error"] = "GitHub недоступен"
        return out
    if r.status_code != 200:
        out["error"] = f"GitHub users: HTTP {r.status_code}"
        return out
    try:
        data = r.json()
    except Exception:
        return out
    for u in (data.get("items") or [])[:20]:
        login = u.get("login")
        if login and login not in out["logins"]:
            out["logins"].append(login)
    out["total"] = data.get("total_count")
    return out


# ---------------------------------------------------------------------------
#  Kaspersky Who Calls (РФ) — владелец номера
# ---------------------------------------------------------------------------
def whocalls_lookup(phone: str) -> Dict[str, Any]:
    """Российский сервис определения владельца номера (бесплатно)."""
    out: Dict[str, Any] = {"phone": phone, "owner": None, "city": None,
                           "operator": None, "comment": None, "url": None, "error": None}
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 10:
        out["error"] = "некорректный номер"
        return out
    if digits.startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]
    if len(digits) == 10:
        digits = "7" + digits

    try:
        resp = requests.post("https://whocalls.ru/search", data={"phone": digits},
                             headers={**HEADERS, "Accept": "text/html"}, timeout=TIMEOUT)
    except Exception as e:
        out["error"] = f"{type(e).__name__}"
        return out

    out["url"] = str(resp.url)
    html = resp.text
    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))

    # JSON-LD QAPage: ответы экспертов содержат имя владельца
    for m in re.finditer(r'"acceptedAnswer"\s*:\s*\[(.*?)\]', html, re.S):
        blob = m.group(1)
        nm = re.search(r'"name"\s*:\s*"([^"]{2,60})"', blob)
        tx = re.search(r'"text"\s*:\s*"([^"]{5,400})"', blob)
        if nm and not out["owner"]:
            out["owner"] = nm.group(1)
        if tx and not out["comment"]:
            out["comment"] = tx.group(1)[:300]

    def grab(label):
        i = plain.find(label)
        if i < 0:
            return None
        tail = plain[i + len(label):]
        tail = re.sub(r"^[^A-Za-zА-Яа-я0-9+]+", "", tail)
        m = re.match(r"([A-Za-zА-Яа-яЁё0-9\.\- ]{2,45})", tail)
        return m.group(1).strip() if m else None

    if not out["owner"]:
        for lab in ("Владелец номера", "владелец номера", "Владелец", "владелец"):
            v = grab(lab)
            if v and v.lower() not in ("номера", "номер"):
                out["owner"] = v
                break
    for key, labs in (("operator", ("Оператор", "оператор", "Компания", "Провайдер")),
                      ("city", ("Регион", "регион", "Город", "город", "Республика"))):
        for lab in labs:
            v = grab(lab)
            if v and len(v) > 1:
                out[key] = v
                break

    if out["owner"] and "не определен" in str(out["owner"]).lower():
        out["owner"] = None
    return out


# ---------------------------------------------------------------------------
#  Steam: профили по email
# ---------------------------------------------------------------------------
def steam_search_by_email(email: str) -> Dict[str, Any]:
    """Steam Community: поиск аккаунтов по email."""
    out: Dict[str, Any] = {"profiles": [], "error": None}
    try:
        r = requests.get("https://steamcommunity.com/actions/Search",
                         params={"T": "Account", "K": email}, headers=HEADERS, timeout=TIMEOUT)
    except Exception:
        out["error"] = "Steam недоступен"
        return out
    if r.status_code != 200:
        out["error"] = f"Steam: HTTP {r.status_code}"
        return out
    for m in re.finditer(r'href="(https://steamcommunity\.com/(?:id|profiles)/[^"]+)"', r.text):
        link = m.group(1)
        if link not in out["profiles"]:
            out["profiles"].append(link)
    return out


# ---------------------------------------------------------------------------
#  Веб-поиск: dorks для ФИО / адреса / соцсетей
# ---------------------------------------------------------------------------
DORKS_PHONE = [
    '"{v}" "Имя:"',
    '"{v}" "Фамилия:"',
    '"{v}" "Отчество:"',
    '"{v}" "Дата рождения"',
    '"{v}" "Адрес регистрации"',
    '"{v}" "Место рождения"',
    '"{v}" "Отчество"',
    '"{v}" отзыв объявление',
    '"{v}" site:avito.ru',
    '"{v}" владелец номера',
    '"{v}" контакты',
]
DORKS_EMAIL = [
    '"{v}" "Имя:"',
    '"{v}" "Фамилия:"',
    '"{v}" "Отчество:"',
    '"{v}" "Дата рождения"',
    '"{v}" "Адрес регистрации"',
    '"{v}" "Место рождения"',
    '"{v}" ФИО',
    '"{v}" контакты',
]


def phone_variants(phone: str) -> List[str]:
    """Все варианты записи номера, которые встречаются в объявлениях и утечках.

    Поиск только по одной форме записи почти ничего не находит: в вакансиях
    пишут «8 999 123-45-67», в утечках «79991234567», в WhatsApp «+7 999 123 45 67».
    """
    raw = (phone or "").strip()
    digits = re.sub(r"\D", "", raw)
    variants: List[str] = []

    def add(v):
        if v and v not in variants:
            variants.append(v)

    if digits:
        if len(digits) == 11 and digits.startswith("8"):
            digits = "7" + digits[1:]
        if len(digits) == 10:
            digits = "7" + digits
        add(digits)
        add("+" + digits)
        if len(digits) == 11 and digits.startswith("7"):
            add(digits[1:])                 # без кода страны
            add(digits[2:])                 # последние 9
            add(digits[3:])                 # последние 8
        add(digits[-10:])                   # последние 10
        add(digits[-7:])                    # последние 7
        # форматированные варианты
        if len(digits) == 11 and digits.startswith("7"):
            rest = digits[1:]
            add(f"8 {rest[0:3]} {rest[3:6]}-{rest[6:8]}-{rest[8:10]}")
            add(f"8 ({rest[0:3]}) {rest[3:6]}-{rest[6:8]}-{rest[8:10]}")
            add(f"+7 {rest[0:3]} {rest[3:6]} {rest[6:8]} {rest[8:10]}")
            add(f"8-{rest[0:3]}-{rest[3:6]}-{rest[6:8]}-{rest[8:10]}")
    if raw:
        add(raw)
    return variants[:10]


def personal_dorks(value: str, kind: str = "phone") -> Dict[str, Any]:
    """Целевые веб-поиски для извлечения ФИО и адреса.

    Для телефона ищется сразу по нескольким формам записи номера —
    иначе объявления не находятся (в вакансиях «8 999 123-45-67»,
    в утечках «79991234567», в мессенджерах «+7 999 123 45 67»).

    Два прохода: сначала быстрый общий поиск по всем вариантам записи
    (параллельно), затем точечные уточнения «Имя:» / «Адрес:» — только
    если общего поиска не хватило.
    """
    from concurrent.futures import ThreadPoolExecutor

    out: Dict[str, Any] = {"results": [], "queries": [], "variants": [], "error": None}
    try:
        from premium import serper_search
    except Exception:
        out["error"] = "нет доступа к веб-поиску"
        return out

    if kind == "phone":
        variants = phone_variants(value)
    else:
        variants = [value]
    out["variants"] = variants

    seen = set()

    def run(q):
        try:
            return q, serper_search(q, limit=10) or {}
        except Exception:
            return q, {}

    def collect(pairs):
        for _q, res in pairs:
            for r in (res.get("results") or []):
                url = r.get("url")
                if not url or url in seen:
                    continue
                seen.add(url)
                out["results"].append({
                    "title": r.get("title"),
                    "url": url,
                    "snippet": (r.get("snippet") or "")[:400],
                    "domain": r.get("domain"),
                    "query": _q,
                })

    # --- проход 1: общий поиск по всем вариантам записи (параллельно) ---
    queries1 = [f'"{v}"' for v in variants]
    out["queries"].extend(queries1)
    with ThreadPoolExecutor(max_workers=3) as ex:
        collect(list(ex.map(run, queries1)))

    # --- проход 2: точечные уточнения по конкретным полям ---
    if len(out["results"]) < 20:
        templates = DORKS_PHONE if kind == "phone" else DORKS_EMAIL
        queries2 = []
        for v in variants[:4]:
            for tpl in templates:
                queries2.append(tpl.format(v=v))
        out["queries"].extend(queries2)
        with ThreadPoolExecutor(max_workers=3) as ex:
            collect(list(ex.map(run, queries2)))

    return out


# ---------------------------------------------------------------------------
#  Извлечение ФИО / адреса из текста объявлений
# ---------------------------------------------------------------------------
_FIO = re.compile(
    r"(?:Имя|ФИО|Ф\.И\.О\.?|Имя Фамилия|Отчество|Name|Владелец|Продавец|Контакт(?:ное лицо)?|"
    r"Подпись|Пользователь|Заказчик|Сотрудник|Менеджер|Доставщик)\s*[:\-–]\s*"
    r"([А-ЯЁ][а-яё]{1,20}(?:[\s,]+[А-ЯЁ][а-яё]{1,20}){0,2})"
)
_ADDR = re.compile(
    r"(?:Адрес|Address|Индекс|дом\.|кв\.|ул\.|проспект|пр-т|улица|пер\.|квартира|"
    r"доставка по|доставка в|город|г\.|с\.|поселок)\s*[:\-–]?\s*"
    r"([А-ЯЁа-яё0-9][А-ЯЁа-яё0-9 ,.\-]{4,70})"
)
_CITY = re.compile(
    r"\b(?:г\.|город|Город|Location|с\.|пос[её]лок|область|Область|край)\s*[:\-–]?\s*"
    r"([А-ЯЁ][а-яё\-]{2,25}(?:\s+[А-ЯЁ][а-яё\-]{2,25}){0,2})"
)
_FIO_FREE = re.compile(
    r"\b([А-ЯЁ][а-яё]{1,15}\s+[А-ЯЁ][а-яё]{1,15}(?:\s+[А-ЯЁ][а-яё]{1,15})?)\b"
)
# ФИО с инициалами: «Зима С. Н.», «Хомяков А. А.», «Политко М. М.»
_FIO_INITIALS = re.compile(
    r"\b([А-ЯЁ][а-яё]{2,15})\s+([А-ЯЁ])\.\s*([А-ЯЁ])\."
)
_DOB_RE = re.compile(
    r"(?:\b(?:Д\.?Р\.?|Дата рождения|Дата Рождения|родил(?:ся|ась)|born|birth ?date|DOB|"
    r"Дата и время рождения)\s*[:\-–]?\s*)"
    r"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4}|\d{4}-\d{2}-\d{2})"
)
_NAME_STOP = {
    "Доставка", "Доставка из", "Объявление", "Купить", "Продать", "Услуги", "Работа",
    "Результаты", "Найдено", "Поиск", "Вход", "Регистрация", "Мой", "Ваш", "Скидка",
    "Страница", "Сайт", "Новости", "Статьи", "Авито", "ВКонтакте", "WhatsApp",
    "Телеграм", "Отзывы", "Объявления", "Информация", "Каталог", "Размещено",
    # служебные слова — в паре «Город Служебное» это не ФИО
    "Оператор", "Связь", "Мобильный", "Мобильная", "Телефон", "Телефоны", "Интернет",
    "Продавец", "Покупатель", "Заказчик", "Исполнитель", "Подрядчик", "Клиент",
    "Администратор", "Менеджер", "Менеджеры", "Курьер", "Водитель", "Мастер",
    "Специалист", "Магазин", "Компания", "Организация", "Фирма", "Служба",
    "Сервис", "Центр", "Группа", "Отдел", "Филиал", "Офис", "Салон", "Студия",
    "Работа", "Вакансия", "Резюме", "Профиль", "Аккаунт", "Кабинет", "Личный",
    "Вопрос", "Ответ", "Помощь", "Поддержка", "Обратная", "Связь", "Заказать",
}


def extract_personal(text: str) -> Dict[str, List[str]]:
    """Достаёт ФИО, даты рождения, пол, адреса, районы и индексы из текста.

    Утечки и выгрузки часто содержат JSON-подобные записи вида:
    «Фамилия: Иванов, Имя: Алексей, Отчество: Петрович, Дата рождения:
    1990-05-15, Адрес регистрации: г. Москва, ул. 1-я Эдуардовская, д. 10,
    кв. 5, Россия, 105316» — такой разбирается покомпонентно.
    """
    out = {"names": [], "birth_dates": [], "genders": [], "addresses": [],
           "districts": [], "zips": [], "cities": []}
    if not text:
        return out

    def add(bucket, val):
        val = (val or "").strip(" .,:;\"'«»\n\t")
        if val and val not in out[bucket]:
            out[bucket].append(val)

    # --- ФИО по отдельным полям ---
    first = _grab_field(text, ("Имя", "First name", "Firstname", "Name", "Имя Фамилия"))
    last = _grab_field(text, ("Фамилия", "Last name", "Lastname", "Surname", "Фамилия Имя"))
    mid = _grab_field(text, ("Отчество", "Middle name", "Middlename", "Patronymic"))
    fio = " ".join(x for x in (last, first, mid) if x)
    if last and first:
        add("names", fio)
    else:
        for m in _FIO.finditer(text):
            v = m.group(1).strip(" .,:;")
            if v.lower() not in ("имя", "name", "имя фамилия", "отчество", "адрес") and len(v) > 3:
                add("names", v)

    if not out["names"]:
        # «Зима С. Н.», «Хомяков А. А.» — ФИО с инициалами
        for m in _FIO_INITIALS.finditer(text):
            v = f"{m.group(1)} {m.group(2)}. {m.group(3)}."
            if m.group(1) not in _NAME_STOP:
                add("names", v)
                break
    if not out["names"]:
        for m in _FIO_FREE.finditer(text):
            v = m.group(1).strip()
            parts = v.split()
            if len(parts) < 2:
                continue
            if parts[0] in _NAME_STOP or parts[1] in _NAME_STOP:
                continue
            if v in _NAME_STOP or any(v.startswith(s) for s in _NAME_STOP):
                continue
            add("names", v)
            break

    # --- Дата рождения ---
    for m in _DOB_RE.finditer(text):
        add("birth_dates", m.group(1))
        break
    for m in re.finditer(r"birthDate\D{0,12}(\d{4}-\d{2}-\d{2})", text, re.I):
        add("birth_dates", m.group(1))
        break
    for m in re.finditer(r"(?:Дата рождения|Дата и время рождения|birthDate|родился)\D{0,25}(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})", text, re.I):
        add("birth_dates", m.group(1))
        break

    # --- Пол ---
    for m in re.finditer(r"(?:пол|gender|sex|пол\s*рождения)\s*[:=]\s*[\"']?([mfмжfMFЖ])",
                         text, re.I):
        raw = m.group(1).lower()
        add("genders", "мужской" if raw in ("m", "м", "male") else "женский")
        break
    for m in re.finditer(r"\b(Мужской|Женский|Male|Female)\b", text):
        add("genders", "мужской" if m.group(1).lower() in ("мужской", "male") else "женский")
        break

    # --- Адрес, район, индекс, город ---
    for lab in ("Адрес регистрации", "Адрес", "Address", "Место жительства",
                "место рождения", "Место рождения", "Проживание", "Адрес прописки"):
        val = _grab_field(text, (lab,), max_len=120)
        if val:
            add("addresses", _clean_address(val))
            break
    for m in _ADDR.finditer(text):
        v = m.group(1).strip(" .,:;")
        if len(v) > 6:
            add("addresses", _clean_address(v))
            break

    for lab in ("Район", "район", "District", "Микрорайон"):
        val = _grab_field(text, (lab,), max_len=60)
        if val:
            add("districts", val)
            break
    for m in re.finditer(r"\b(\d{6})\b", text):
        add("zips", m.group(1))
        break

    for m in _CITY.finditer(text):
        v = m.group(1).strip(" .,:;")
        if v.lower() not in ("город", "г", "с") and len(v) > 2:
            add("cities", v)
            break
    for m in re.finditer(r"\b(?:г\.|город)\s*([А-ЯЁ][а-яё\-]{2,20})", text):
        add("cities", m.group(1))
        break

    return out


def _clean_address(value: str) -> str:
    """Чистит адрес от мусора: эмодзи, телефоны, служебные вставки."""
    v = (value or "").strip()
    v = re.sub(r"[❗️⚠️✔️❗]", " ", v)
    # обрываем на телефоне / служебных словах
    v = re.split(r"\s[-–—]\s*\+?\d|\s-\s|\+?\d{10,}|Пожалуйста|Пример|"
                 r"ОБЩИЙ|Зима|❗|Проживание|Чтобы", v)[0]
    v = re.sub(r"\s{2,}", " ", v).strip(" .,;:-\u2022")
    return v[:90]


def _grab_field(text: str, labels, max_len: int = 60) -> Optional[str]:
    """Достаёт значение поля по одной из меток: «Метка: значение»."""
    for lab in labels:
        # «Метка: значение» или «Метка, значение» (JSON-подобный формат)
        m = re.search(re.escape(lab) + r"\s*[:=]?\s*[\"']?"
                      r"([^,;\"'\n]{1,%d})" % max_len, text, re.I)
        if m:
            v = m.group(1).strip(" .,:;\"'")
            if v and len(v) > 1:
                return v
    return None


# ---------------------------------------------------------------------------
#  Сбор логинов и скан профилей
# ---------------------------------------------------------------------------
def collect_usernames(value: str, kind: str = "phone", extra: Optional[List[str]] = None) -> List[str]:
    """Собирает возможные логины из всех найденных источников."""
    found: List[str] = []

    def add(u):
        if u and 3 <= len(u) <= 40 and re.fullmatch(r"[A-Za-z0-9_.\-]+", u):
            if u.lower() not in [x.lower() for x in found]:
                found.append(u)

    for u in (extra or []):
        add(u)

    if kind == "email":
        local = value.split("@")[0]
        if local and not local.startswith("+"):
            add(local)
        g = github_users_by_email(value)
        for l in g.get("logins", []):
            add(l)
    else:
        digits = re.sub(r"\D", "", value)
        if len(digits) == 11 and digits.startswith("8"):
            digits = "7" + digits[1:]
        if len(digits) == 10:
            digits = "7" + digits
        if len(digits) == 11 and digits.startswith("7"):
            add(digits[1:])
        add(digits[-10:])
    return found


def scan_usernames(usernames: List[str], limit: int = 2) -> Dict[str, List[Dict[str, Any]]]:
    """Прогоняет 506-сайтовый сканер по списку логинов."""
    from concurrent.futures import ThreadPoolExecutor

    out: Dict[str, List[Dict[str, Any]]] = {}
    try:
        from scanner import scan_sync
    except Exception:
        return out

    def run(u):
        try:
            return u, scan_sync(u, ["social", "dev", "professional", "media"]) or {}
        except Exception:
            return u, {}

    with ThreadPoolExecutor(max_workers=3) as ex:
        for u, res in ex.map(run, usernames[:limit]):
            if res.get("found_count"):
                out[u] = res["found"]
    return out
