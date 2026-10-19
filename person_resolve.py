#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Слой «Личность»: сводка ФИО / локаций / адресов / ссылок на соцсети.

Источники (только публичные, опубликованные самим человеком или уже
предупреждающие о нём сервисы утечек):
  * профили, найденные сканером (GitHub, Telegram, VK, Gravatar, и т.д.);
  * страницы этих профилей (парсинг текста рядом с идентификатором);
  * Gravatar (displayName / currentLocation / aboutMe / accounts);
  * выдача веб-поиска по точному совпадению идентификатора;
  * отчёты об утечках (LeakCheck / HIBP / Hudson Rock).

Каждое найденное значение помечается источником и уверенностью, чтобы
результат можно было проверить вручную, а не принимать на веру.
"""

import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d[\s\-().]*){9,17}\d")

CYR_NAME = re.compile(
    r"(?<![А-Яа-яЁё])([А-ЯЁ][а-яё]{1,20})"
    r"(?:\s+([А-ЯЁ][а-яё]{1,20}))?"
    r"(?:\s+([А-ЯЁ][а-яё]{1,20}))?(?![а-яё])"
)
LAT_NAME = re.compile(
    r"(?<![A-Za-z])([A-Z][a-z]{2,20})"
    r"(?:\s+([A-Z][a-z]{2,20}))?"
    r"(?:\s+([A-Z][a-z]{2,20}))?(?![a-z])"
)

# Слова-шум, которые похожи на имена
NAME_STOP = {
    "Россия", "Российская", "Москва", "Московская", "Санкт", "Петербург", "Российской",
    "Федерация", "РФ", "США", "Европа", "Украина", "Казахстан", "Беларусь",
    "Яндекс", "Google", "Github", "GitHub", "Telegram", "ВКонтакте", "Вконтакте",
    "Instagram", "Twitter", "Reddit", "YouTube", "WhatsApp", "Outlook", "Windows",
    "Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье",
    "January", "February", "March", "April", "August", "September", "October",
    "November", "December", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
    "Saturday", "Sunday", "Copyright", "Вход", "Регистрация", "Профиль", "Загрузка",
    "Настройки", "Сообщения", "Подписки", "Поиск", "Меню", "Главная", "Помощь",
    # служебные слова, которые не являются частью ФИО
    "Shop", "Profile", "Login", "Signup", "Sign", "Gists", "Dashboard", "Home",
    "Gifts", "Sell", "Retro", "Shop", "Official", "Store", "News", "Blog", "Help",
    "Support", "Settings", "Account", "User", "Users", "Products", "Buy", "Cart",
    "Reviews", "Photos", "Videos", "Wall", "Feed", "About", "Contact", "Privacy",
    "Terms", "Cookie", "Copyright", "All", "Gifts", "Account", "Group", "Pages",
    "Redbubble", "Docker", "Hub", "Shops", "Sale", "Discount", "Free", "Print",
    "Clothing", "Stickers", "Totes", "Posters", "Cards", "Cases", "Accessories",
}

# Слова, при которых имя-кандидат отбрасывается целиком
NAME_REJECT = re.compile(
    r"\b(Shop|Profile|Login|Signup|Gists|Store|Official|Forum|Blog|News|Group|"
    r"Pages|Account|Dashboard|Products|Gifts|Reviews|Photos|Videos|Faq|FAQ|"
    r"Каталог|Магазин|Профиль|Вход|Регистрация|Новости|Главная|Форум|Корзина)\b")

ADDRESS_PATTERNS = [
    # «ул. Ленина, д. 5, кв. 12»
    re.compile(r"(?:ул(?:ица)?|проспект|пр-т|переулок|пер\.|бульвар|б-р|набережная|наб\.|"
               r"ш(?:оссе|ссе)|пл(?:ощадь)?|проезд|аллея|тупик|микрорайон|мкр\.?|квартал)"
               r"[^;\n<>]{0,90}", re.I),
    # «д. 5 кв. 12» + город
    re.compile(r"(?:г|город|пос\.|пгт|с\.|д\.)\.\s*[А-ЯЁ][^;\n<>]{0,60}?"
               r"(?:,\s*д\.\s*\d+[^;\n<>]{0,25})?(?:,?\s*кв\.\s*\d+)?", re.I),
    # просто «кв. 12» рядом с городом
    re.compile(r"(?:кв\.|квартира)\s*\d+[а-яА-Я]?", re.I),
]
CITY_RE = re.compile(
    r"(?:г\.|город|г\. ?город)\s*([А-ЯЁ][а-яё\-]{2,25})|"
    r"([А-ЯЁ][а-яё\-]{2,25})\s*,?\s*(?:Россия|РФ|Украина|Казахстан|Беларусь)",
    re.I)

SOCIAL_DOMAINS = {
    "vk.com": "VK", "vk.ru": "VK", "ok.ru": "OK", "t.me": "Telegram",
    "telegram.me": "Telegram", "instagram.com": "Instagram", "twitter.com": "Twitter",
    "x.com": "X", "facebook.com": "Facebook", "youtube.com": "YouTube",
    "tiktok.com": "TikTok", "github.com": "GitHub", "gitlab.com": "GitLab",
    "habr.com": "Habr", "pinterest.com": "Pinterest", "twitch.tv": "Twitch",
    "linkedin.com": "LinkedIn", "rutube.ru": "Rutube", "dzen.ru": "Dzen",
    "livejournal.com": "LiveJournal", "medium.com": "Medium", "steamcommunity.com": "Steam",
    "reddit.com": "Reddit", "avito.ru": "Avito", "flamp.ru": "Flamp", "2gis.ru": "2GIS",
    "drive2.ru": "Drive2", "pixabay.com": "Pixabay", "about.me": "About.me",
    "behance.net": "Behance", "kaggle.com": "Kaggle", "steamcommunity.com": "Steam",
}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def dedup_keep(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for v in values:
        v = norm(v)
        k = v.lower()
        if v and k not in seen:
            seen.add(k)
            out.append(v)
    return out


# --------------------------------------------------------------- имена

def extract_names(text: str) -> List[Tuple[str, int]]:
    """Возвращает (ФИО-кандидат, позиция в тексте)."""
    out: List[Tuple[str, int]] = []
    for rx in (CYR_NAME, LAT_NAME):
        for m in rx.finditer(text):
            parts = [p for p in m.groups() if p]
            if not parts:
                continue
            head = parts[0]
            if head.lower() in NAME_STOP or head in NAME_STOP:
                continue
            if all(p.lower() in NAME_STOP for p in parts):
                continue
            if len(parts) == 1:
                # одно слово с заглавной — слишком слабый сигнал
                continue
            candidate = " ".join(parts)
            if NAME_REJECT.search(candidate):
                continue
            out.append((candidate, m.start()))
    return out


# Маркеры, рядом с которыми слово почти наверняка является ФИО
NAME_MARKERS = re.compile(
    r"(им[яе]|фамили[яи]|отчеств[оа]|ф\.?\s*и\.?\s*о\.?|"
    r"author|username|ник\s*им[яе]|пользовател[ьи]|"
    r"пишите|звоните|звон|тел\.?|телефон|контакт|объявлени[ея]|"
    r"продавец|покупател[ьи]|заказчик|исполнител[ьи]|автор|"
    r"подписан|подпись|меня зовут|зовут|владелец|"
    r"напишите|пишу|связь|whatsapp|viber|telegram)",
    re.I)


def names_near(text: str, needles: List[str], window: int = 260,
               require_marker: bool = False, marker_window: int = 90) -> List[str]:
    """Имена, встречающиеся рядом с идентификатором (телефон/e-mail/username).

    require_marker=True — имя должно быть рядом с маркером ФИО/контакта,
    иначе подойдут обычные слова вёрстки («Gift Cards Torvalds»).
    """
    if not text or not needles:
        return []
    low = text.lower()
    positions: List[int] = []
    for n in needles:
        if not n:
            continue
        start = 0
        nl = n.lower()
        while True:
            i = low.find(nl, start)
            if i < 0:
                break
            positions.append(i)
            start = i + 1
            if len(positions) > 60:
                break
    if not positions:
        return []
    marker_positions = [m.start() for m in NAME_MARKERS.finditer(text)]

    found: List[str] = []
    for name, pos in extract_names(text):
        if not any(abs(pos - p) <= window for p in positions):
            continue
        if require_marker:
            # сильный сигнал: «Имя Фамилия, +7...» — имя прямо перед идентификатором
            adjacent = False
            for p in positions:
                gap = text[pos + len(name):p]
                if 0 <= p - (pos + len(name)) <= 25 and re.fullmatch(r"[\s,;:\-–—/]*", gap):
                    adjacent = True
                    break
            if not adjacent:
                if not marker_positions:
                    continue
                if not any(abs(pos - mp) <= marker_window for mp in marker_positions):
                    continue
        found.append(name)
    return found


# --------------------------------------------------------------- адреса

HOUSE_RE = re.compile(r"(?:д\.|дом|стр\.|корп\.|к\.|кв\.)\s*\d+", re.I)
STREET_RE = re.compile(
    r"(?:ул(?:ица)?|проспект|пр-т|переулок|пер\.|бульвар|б-р|набережная|наб\.|"
    r"ш(?:оссе|ссе)|пл(?:ощадь)?|проезд|аллея|микрорайон|мкр\.?|квартал)", re.I)
CITY_WORD_RE = re.compile(r"(?:г\.|город|пос\.|пгт|с\.|с\.п\.|деревня|д\.)", re.I)
HTML_ENT_RE = re.compile(r"&[a-z]+;|&#\d+;", re.I)


def extract_addresses(text: str) -> List[str]:
    """Отбирает только осмысленные адреса: улица/дом + номер, город + номер."""
    out: List[str] = []
    seen: Set[str] = set()
    for rx in ADDRESS_PATTERNS:
        for m in rx.finditer(text):
            v = norm(m.group(0))
            v = HTML_ENT_RE.sub("", v)
            v = re.sub(r"\s+", " ", v).strip(" ,;|")
            if len(v) < 10:
                continue
            if len(v) > 140:
                v = v[:140]
            has_house = bool(HOUSE_RE.search(v))
            has_street = bool(STREET_RE.search(v))
            has_city = bool(CITY_WORD_RE.search(v))
            # нужен номер дома И (улица или город)
            if not (has_house and (has_street or has_city)):
                continue
            # отсекаем мусор: «2D», «18 ...»
            if not re.search(r"\d", v):
                continue
            if v.lower() in seen:
                continue
            seen.add(v.lower())
            out.append(v)
    return out


def extract_cities(text: str) -> List[str]:
    out: List[str] = []
    for m in CITY_RE.finditer(text or ""):
        v = m.group(1) or m.group(2)
        if v and v.lower() not in NAME_STOP:
            out.append(norm(v))
    return out


# --------------------------------------------------------------- соцсети

ASSET_RE = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|mp4|webm)(\?|$)", re.I)
NOISE_RE = re.compile(r"(telesco\.pe|/js/|/css/|/img/|/dl\?|/favicon|/apple-touch)", re.I)


def clean_links(urls: Iterable[str], keep_assets: bool = False) -> List[str]:
    """Нормализует и чистит список ссылок: убирает ассеты, CDN и мусор."""
    out: List[str] = []
    seen: Set[str] = set()
    for u in urls:
        u = (u or "").strip()
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith("http"):
            continue
        if not keep_assets:
            if ASSET_RE.search(u) or NOISE_RE.search(u):
                continue
        u = u.rstrip(".,);\"'")
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


# Платформы, в заголовке которых профиль человека называется настоящим именем
PROFILE_TITLE_SITES = {
    "github.com": "GitHub", "gitlab.com": "GitLab", "habr.com": "Habr",
    "steamcommunity.com": "Steam", "drive2.ru": "Drive2", "pikabu.ru": "Pikabu",
    "ok.ru": "OK", "livejournal.com": "LiveJournal", "keybase.io": "Keybase",
    "leetcode.com": "LeetCode", "codeforces.com": "Codeforces", "kaggle.com": "Kaggle",
    "medium.com": "Medium", "behance.net": "Behance", "dev.to": "DEV",
    "chess.com": "Chess.com", "lichess.org": "Lichess", "twitch.tv": "Twitch",
    "tiktok.com": "TikTok", "instagram.com": "Instagram", "x.com": "X",
    "twitter.com": "Twitter", "facebook.com": "Facebook", "youtube.com": "YouTube",
    "vk.com": "VK", "vk.ru": "VK", "pinterest.com": "Pinterest", "tumblr.com": "Tumblr",
    "mastodon.social": "Mastodon", "linkedin.com": "LinkedIn", "hub.docker.com": "Docker Hub",
    "pypi.org": "PyPI", "npmjs.com": "npm", "flickr.com": "Flickr",
    "myspace.com": "MySpace", "rutube.ru": "Rutube", "dzen.ru": "Dzen",
    "about.me": "About.me", "patreon.com": "Patreon",
}

_TITLE_NOISE_RE = re.compile(
    r"\s*[·|\-–—]\s*.*$|"
    r"\s*[·|\-–—]\s*(GitHub|GitLab|Habr|Steam|Kaggle|YouTube|Twitch|LiveJournal|"
    r"Medium|Dev\.to|Chess\.com|Lichess|Pinterest|Tumblr|LinkedIn|Patreon|About\.me)$",
    re.I)

# «Linus Torvalds (torvalds)» / «GitHub - torvalds (Linus Torvalds)»
_PAREN_RE = re.compile(r"\(([^)]{3,60})\)")
# «Компьютер Steam :: NaraKa», «Профиль X :: Ник»
_AFTER_COLON_RE = re.compile(r"::\s*([^·|\-–—]{2,40})")
_PREFIX_RE = re.compile(r"^(?:GitHub|GitLab|Habr|Steam|Kaggle|YouTube|Chess\.com|"
                        r"Lichess|Disqus Profile|Профиль)\s*[-–—:]\s*", re.I)


# Технические/брендовые строки, которые не являются ФИО
NOT_A_NAME_RE = re.compile(
    r"(telegram|вконтакте|вконтакте|контакты|sign in|sign up|log ?in|log ?out|"
    r"register|registration|sign up|page not found|not found|error|запросы|"
    r"большие запросы|ограничен|captcha|подтвердите|требуется авторизация|"
    r"a new era of messaging|messenger|privacy policy|new message|"
    r"privacy|terms of (service|use)|cookie|contact|support|about us|"
    r"welcome|home|search|explore|notifications|settings|profile|image|photo|"
    r"video|audio|sticker|game|bot|channel|group|story|reel|post|live)",
    re.I)


def is_name_like(value: str) -> bool:
    """Проверяет, что строка похожа на ФИО, а не на служебный текст."""
    v = (value or "").strip()
    if not v or len(v) > 60:
        return False
    if NOT_A_NAME_RE.search(v):
        return False
    if "@" in v or "http" in v.lower():
        return False
    if any(c.isdigit() for c in v):
        return False
    parts = v.split()
    if not (2 <= len(parts) <= 3):
        return False
    if not all(p[0].isupper() for p in parts):
        return False
    return True


def _clean_name_candidate(t: str) -> Optional[str]:
    t = re.sub(r"\s+", " ", (t or "").strip()).strip(" ·|-–—,.")
    if not t or len(t) > 60:
        return None
    parts = t.split()
    if not (2 <= len(parts) <= 3):
        return None
    if NAME_REJECT.search(t):
        return None
    if all(p.lower() in NAME_STOP for p in parts):
        return None
    if not is_name_like(t):
        return None
    return t


def name_from_title(title: str, url: str) -> Optional[str]:
    """Достаёт имя из заголовка страницы профиля (если заголовок — профиль человека)."""
    from urllib.parse import urlparse

    title = (title or "").strip()
    if not title:
        return None
    try:
        host = urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return None
    if not any(host == d or host.endswith("." + d) for d in PROFILE_TITLE_SITES):
        return None

    cands: List[str] = []
    # 1) имя в скобках: «torvalds (Linus Torvalds)»
    for m in _PAREN_RE.finditer(title):
        cands.append(m.group(1))
    # 2) после «::»
    for m in _AFTER_COLON_RE.finditer(title):
        cands.append(m.group(1))
    # 3) без префикса площадки
    cands.append(_PREFIX_RE.sub("", title))
    # 4) без хвоста после разделителя
    cands.append(_TITLE_NOISE_RE.sub("", title).strip(" ·|-–—"))

    for c in cands:
        res = _clean_name_candidate(c)
        if res:
            return res
    return None


# Внутренние служебные пути площадок — это не профили человека
INTERNAL_PATH_RE = re.compile(
    r"^/(wall|video|photo|audio|clip|market|news|feed|search|groups|communities|"
    r"messages|im|apps|games|blog|faq|help|about|settings|notifications|login|"
    r"join|reg|auth|public|privacy|terms|playlists|collections|stickers|emoji|"
    r"promo|events|nft|contest|designers|transferintelligencecups|"
    r"wall\d|video\d|photo\d|clips\d|docs?\d)($|/|_)", re.I)


def social_links(urls: Iterable[str], subject: Optional[str] = None) -> List[Dict[str, Any]]:
    """Отбирает ссылки на соцсети и сводит «профиль + посты» к одному URL.

    Если задан subject (username/e-mail), оставляются только те ссылки,
    чей путь содержит этот идентификатор — так отсекаются соцсети сайта,
    а не человека (например, Twitter Redbubble на странице Redbubble).
    """
    from urllib.parse import urlparse

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    subj = (subject or "").lower().lstrip("@")
    for u in clean_links(urls):
        try:
            p = urlparse(u)
        except Exception:
            continue
        host = p.netloc.lower().replace("www.", "")
        for dom, name in SOCIAL_DOMAINS.items():
            if not (host == dom or host.endswith("." + dom)):
                continue
            path = p.path.rstrip("/")
            # t.me/user/418 -> t.me/user ; t.me/s/user -> t.me/user
            if name == "Telegram" and path.startswith("/s/"):
                path = path[2:]
            path = re.sub(r"/\d+$", "", path)
            if name == "Telegram" and path in ("", "/"):
                break
            # внутренние служебные страницы площадки — не профиль человека
            if INTERNAL_PATH_RE.match(path):
                break
            if not path.strip("/"):
                break
            base = f"https://{dom}{path}"
            key = f"{name}:{base}"
            if key in seen:
                break
            seen.add(key)
            match = "прямая" if (subj and subj in path.lower()) else "встречается на странице"
            out.append({"platform": name, "url": base, "match": match})
            break
    out.sort(key=lambda x: 0 if x.get("match") == "прямая" else 1)
    return out


# --------------------------------------------------------------- сводка

def _conf(base: float, *bumpers: Tuple[float, str]) -> Tuple[float, List[str]]:
    score = base
    why: List[str] = []
    for b, reason in bumpers:
        if b > 0:
            score += b
            why.append(reason)
    return min(1.0, round(score, 2)), why


def build_identity_summary(
    identifiers: List[str],
    profiles: List[Dict[str, Any]],
    pages: List[Dict[str, Any]],
    email_analysis: Dict[str, Any],
    phone_analysis: Dict[str, Any],
    leaks: Dict[str, Any],
) -> Dict[str, Any]:
    """Собирает сводку «личность» из уже собранных данных."""
    needles = [i for i in identifiers if i and len(i) > 3]
    needles_digits = [re.sub(r"\D", "", n) for n in needles]
    needles_digits = [d for d in needles_digits if len(d) >= 5]

    names: List[Dict[str, Any]] = []
    name_index: Dict[str, Dict[str, Any]] = {}

    def add_name(value: str, source: str, url: str, base: float, bump: Tuple[float, str] = (0, "")):
        value = norm(value)
        if not value or value.lower() in NAME_STOP:
            return
        if not is_name_like(value):
            return
        key = value.lower()
        conf, why = _conf(base, bump)
        if key in name_index:
            e = name_index[key]
            e["confidence"] = max(e["confidence"], conf)
            if source not in e["sources"]:
                e["sources"].append(source)
            if url and url not in e["urls"]:
                e["urls"].append(url)
            for w in why:
                if w not in e["reasons"]:
                    e["reasons"].append(w)
            return
        e = {"value": value, "confidence": conf, "sources": [source],
             "urls": [url] if url else [], "reasons": why}
        name_index[key] = e
        names.append(e)

    addresses: List[Dict[str, Any]] = []
    addr_index: Dict[str, Dict[str, Any]] = {}

    def add_address(value: str, source: str, url: str, kind: str, base: float,
                    bump: Tuple[float, str] = (0, "")):
        value = norm(value)
        if not value:
            return
        key = value.lower()
        conf, why = _conf(base, bump)
        if key in addr_index:
            e = addr_index[key]
            e["confidence"] = max(e["confidence"], conf)
            if source not in e["sources"]:
                e["sources"].append(source)
            for w in why:
                if w not in e["reasons"]:
                    e["reasons"].append(w)
            return
        e = {"value": value, "confidence": conf, "kind": kind, "sources": [source],
             "urls": [url] if url else [], "reasons": why}
        addr_index[key] = e
        addresses.append(e)

    cities: Dict[str, Dict[str, Any]] = {}

    def add_city(value: str, source: str, base: float = 0.5):
        value = norm(value)
        if not value:
            return
        key = value.lower()
        if key in cities:
            e = cities[key]
            e["confidence"] = max(e["confidence"], base)
            if source not in e["sources"]:
                e["sources"].append(source)
            return
        cities[key] = {"value": value, "confidence": base, "sources": [source]}

    # --- профили из сканера
    for p in profiles:
        plat = p.get("platform", "")
        url = p.get("url", "")
        nm = p.get("name") or ""
        extra = p.get("extra") or {}
        # заголовок обычной веб-страницы — не ФИО
        is_page = plat in ("Web", "", "Веб")
        if nm and not is_page and not NAME_REJECT.search(nm) and is_name_like(nm):
            add_name(nm, plat, url, 0.55, (0.2, "имя в профиле"))
        loc = extra.get("location") or ""
        if loc:
            add_city(loc, plat, 0.6)
        if extra.get("status"):
            for n in names_near(extra["status"], needles + needles_digits, require_marker=False):
                add_name(n, f"{plat} (статус)", url, 0.45, (0.1, "имя в статусе"))
        for em in p.get("emails") or []:
            for n in names_near(p.get("bio", "") or "", [em]):
                add_name(n, f"{plat} (био)", url, 0.5, (0.15, "e-mail в био"))

    # --- страницы профилей: имена/адреса рядом с идентификатором
    for pg in pages:
        text = pg.get("text") or ""
        if not text:
            continue
        url = pg.get("url", "")
        src = pg.get("source") or url
        # имя из заголовка профиля известной платформы
        tname = name_from_title(pg.get("page_title") or pg.get("title") or "", url)
        if tname:
            add_name(tname, "заголовок профиля", url, 0.55, (0.1, "имя в заголовке профиля"))
        # страница релевантна только если идентификатор реально присутствует в тексте
        low = text.lower()
        has_id = any(n.lower() in low for n in needles if n) or \
                 any(d in re.sub(r"\D", "", low) for d in needles_digits if len(d) >= 5)
        near = names_near(text, needles + needles_digits, require_marker=True)
        for n in near[:6]:
            if not has_id:
                continue
            add_name(n, src, url, 0.45, (0.15, "найдено рядом с идентификатором"))
        for a in extract_addresses(text)[:5]:
            if not has_id:
                continue
            bump = (0.15, "адрес в тексте страницы") if re.search(r"\d", a) else (0.0, "")
            add_address(a, src, url, "публичная страница", 0.35, bump)
        if has_id:
            for c in extract_cities(text)[:3]:
                add_city(c, src, 0.4)

    # --- Gravatar
    if email_analysis.get("gravatar_found"):
        dn = email_analysis.get("display_name")
        if dn:
            add_name(dn, "Gravatar", email_analysis.get("avatar_url") or "", 0.6,
                     (0.15, "публичный профиль Gravatar"))
        loc = email_analysis.get("location")
        if loc:
            add_city(loc, "Gravatar", 0.65)
        about = email_analysis.get("about") or ""
        for n in names_near(about, needles):
            add_name(n, "Gravatar (about)", "", 0.4)
        for a in extract_addresses(about)[:3]:
            add_address(a, "Gravatar", "", "публичная страница", 0.35)
        for acc in email_analysis.get("accounts") or []:
            if acc.get("url"):
                for link in social_links([acc["url"]]):
                    pass

    # --- веб-поиск: сниппеты по точному идентификатору
    for block in (email_analysis.get("mentions") or {}, phone_analysis.get("mentions") or {}):
        for r in (block.get("results") or [])[:25]:
            snippet = r.get("snippet") or ""
            title = r.get("title") or ""
            blob = f"{title}. {snippet}"
            for n in names_near(blob, needles + needles_digits, require_marker=True):
                add_name(n, r.get("domain") or "веб-поиск", r.get("url", ""), 0.4,
                         (0.1, "в выдаче по точному идентификатору"))
            for a in extract_addresses(blob)[:2]:
                add_address(a, r.get("domain") or "веб-поиск", r.get("url", ""),
                            "публичная страница", 0.3)
            for c in extract_cities(blob)[:2]:
                add_city(c, r.get("domain") or "веб-поиск", 0.3)

    # --- телефоны: регион/оператор как источник локации
    pmeta = phone_analysis.get("meta") or {}
    if pmeta.get("region"):
        add_city(pmeta["region"], "префикс телефона", 0.5)

    # --- утечки: какие типы данных засветились
    leak_fields: List[str] = []
    leak_sources: List[str] = []
    lc = (leaks.get("leakcheck") or {})
    leak_fields += list(lc.get("fields") or [])
    for s in lc.get("sources") or []:
        if s.get("name"):
            leak_sources.append(f"{s.get('name')} ({s.get('date')})")
    inf = leaks.get("infostealer") or {}
    if inf.get("infected"):
        leak_sources.append(f"infostealer: {inf.get('data', {}).get('date_compromised')}")

    # --- соцсети из всех ссылок
    all_links: List[str] = []
    for p in profiles:
        all_links += list(p.get("links") or [])
    for pg in pages:
        all_links += list(pg.get("links") or [])
    subjects = [n for n in identifiers if n and len(n) > 2]
    socials: List[Dict[str, Any]] = []
    seen_sl: Set[str] = set()
    for subj in subjects:
        for s in social_links(all_links, subject=subj):
            key = f"{s['platform']}:{s['url']}"
            if key in seen_sl:
                continue
            seen_sl.add(key)
            socials.append(s)
    for s in social_links(all_links):
        key = f"{s['platform']}:{s['url']}"
        if key in seen_sl:
            continue
        seen_sl.add(key)
        socials.append(s)

    names.sort(key=lambda x: -x["confidence"])
    addresses.sort(key=lambda x: -x["confidence"])

    return {
        "full_names": names,
        "addresses": addresses,
        "cities": sorted(cities.values(), key=lambda x: -x["confidence"]),
        "social_links": socials,
        "leak_exposure": {
            "fields": sorted(set(leak_fields)),
            "sources": leak_sources,
            "records": lc.get("found"),
        },
        "notes": [
            "Значения приведены с указанием источника; проверяйте их вручную перед использованием.",
            "Данные из утечек опубликованы публично — их же можно запросить на удаление.",
        ],
    }
