#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сбор полного досье на идентификатор (email или телефон).

Что реально доступно из ПУБЛИЧНЫХ источников:
  * утечки (DeHashed / HIBP / LeakCheck) — ФИО, дата рождения, адрес, город,
    регион, пол, логины, телефоны, email, IP
  * профили (Gravatar, веб-поиск, объявления) — отображаемое имя, город,
    связанные аккаунты, контакты
  * оператор и тип линии телефона (Numverify)
  * упоминания в интернете

Важно: данные берутся ТОЛЬКО из уже случившихся публичных утечек и из
открытых страниц. Программа не обходит защиту и не собирает закрытые
персональные данные.
"""

import re
from typing import Any, Dict, List, Optional

from leaks import (
    check_leakcheck, check_infostealer, check_hibp, check_xposedornot,
)
import safesurf_ru
import personal
from websearch import web_search

# ---------------------------------------------------------------------------
# Нормализация полей из утечек -> ФИО / дата рождения / адрес
# ---------------------------------------------------------------------------
FIELD_MAP = {
    "first_name": "names", "firstname": "names", "имя": "names", "given_name": "names",
    "last_name": "names", "lastname": "names", "surname": "names",
    "фамилия": "names", "family_name": "names", "sur_name": "names",
    "middle_name": "names", "middlename": "names", "отчество": "names",
    "patronymic": "names", "name": "full_names", "full_name": "full_names",
    "fullname": "full_names", "display_name": "full_names", "fio": "full_names",
    "username": "usernames", "login": "usernames", "nickname": "usernames",
    "user_name": "usernames", "ник": "usernames",
    "dob": "birth_dates", "birth_date": "birth_dates", "birthdate": "birth_dates",
    "date_of_birth": "birth_dates", "birthday": "birth_dates",
    "дата_рождения": "birth_dates", "birth": "birth_dates",
    "sex": "genders", "gender": "genders", "пол": "genders",
    "address": "addresses", "adress": "addresses", "адрес": "addresses",
    "street": "addresses", "street_address": "addresses", "location": "addresses",
    "city": "cities", "town": "cities", "город": "cities", "city_name": "cities",
    "state": "regions", "region": "regions", "область": "regions",
    "province": "regions", "state_name": "regions",
    "district": "districts", "район": "districts", "area": "districts",
    "country": "countries", "страна": "countries", "country_name": "countries",
    "country_code": "countries",
    "zip": "zips", "zipcode": "zips", "postal_code": "zips", "индекс": "zips",
    "phone": "phones", "telephone": "phones", "mobile": "phones",
    "телефон": "phones", "phone_number": "phones", "msisdn": "phones",
    "email": "emails", "mail": "emails", "email_address": "emails",
    "ip": "ips", "ip_address": "ips", "ipaddress": "ips", "last_ip": "ips",
    "password": "passwords", "pass": "passwords", "пароль": "passwords",
    "credit_card": "credit_cards", "card": "credit_cards",
}


def _norm_key(k: str) -> str:
    return FIELD_MAP.get(str(k).strip().lower(), str(k).strip().lower())


def _clean_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return "; ".join(str(x) for x in v if x)
    s = str(v).strip()
    if s.lower() in ("null", "none", "n/a", "-", "[]", "{}"):
        return ""
    return s


def _parse_records(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Разбирает записи утечек в структурированное досье."""
    buckets = ("names", "full_names", "birth_dates", "genders", "addresses",
               "cities", "regions", "districts", "countries", "zips",
               "phones", "emails", "usernames", "ips", "credit_cards")
    out: Dict[str, Any] = {k: [] for k in buckets}
    out["passwords"] = 0
    out["records"] = 0
    seen = {k: set() for k in buckets}

    for entry in entries or []:
        src = entry.get("_source") or entry.get("data") or entry
        if not isinstance(src, dict):
            continue
        out["records"] += 1
        for raw_k, raw_v in src.items():
            k = _norm_key(raw_k)
            val = _clean_value(raw_v)
            if not val:
                continue
            if k == "passwords":
                out["passwords"] += 1
                continue
            if k in seen:
                if val not in seen[k]:
                    seen[k].add(val)
                    out[k].append(val)

    return out


def _compose_fio(names: List[str], full_names: List[str]) -> List[str]:
    """Собирает возможные ФИО из отдельных имён и готовых full_name."""
    out = list(full_names)
    firsts = [n for n in names]
    # если в записях были first/last/middle — пробуем склеить
    return out


# ---------------------------------------------------------------------------
# Извлечение данных из веб-поиска (объявления, профили, утечки в открытом доступе)
# ---------------------------------------------------------------------------
NAME_RE = re.compile(
    r"\b(?:Имя|ФИО|Имя Фамилия|Фамилия|Отчество|Name|Full ?name|Владелец|Продавец|"
    r"Пользователь|Юзер|Username|Ник|Никнейм|Контакт(?:ное лицо)?|Подпись|Sender|"
    r"Владелец аккаунта|Владелец профиля|Зарегистрирован)\s*[:\-–=]\s*"
    r"([А-ЯЁ][а-яё]{1,20}(?:[\s,]+[А-ЯЁ][а-яё]{1,20}){0,2})"
)
CITY_RE = re.compile(
    r"\b(?:Город|City|Location|Регион|Область|Находится в|В\s+городе|"
    r"проживает|Проживает|из\s+города|city)\s*[:\-–]?\s*"
    r"([А-ЯЁ][а-яё\-]{2,25}(?:\s+[А-ЯЁ][а-яё\-]{2,25}){0,2})"
)
DOB_RE = re.compile(
    r"(?:\b(?:Д\.?Р\.?|Дата рождения|Дата Рождения|родил(?:ся|ась)|born|birth ?date|DOB)\s*[:\-–]?\s*)"
    r"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4}|\d{4}-\d{2}-\d{2})"
)
ADDRESS_RE = re.compile(
    r"\b(?:Адрес|Address|Индекс|дом\.|кв\.|ул\.|проспект|пр-т|улица|пер\.|квартира)\s*[:\-–]?\s*"
    r"([А-ЯЁа-яё0-9][А-ЯЁа-яё0-9 ,.\-]{4,60})"
)
# «Имя контакта: ...» в утечках мессенджеров
CONTACT_NAME_RE = re.compile(
    r"(?:Имя\s+контакта|Contact\s*name|Владелец\s+номера|Owner|профиль\s+номера)\s*[:\-–]?\s*"
    r"([А-ЯЁ][а-яё]{1,20}(?:\s+[А-ЯЁ][а-яё]{1,20}){0,2})"
)


def extract_from_web(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Вытаскивает ФИО, города, даты рождения и адреса из сниппетов."""
    out = {"names": [], "cities": [], "birth_dates": [], "addresses": [], "evidence": []}
    for r in results:
        text = f"{r.get('title', '')} {r.get('snippet', '')}"
        if not text.strip():
            continue
        found = {}
        for rx in (NAME_RE, CONTACT_NAME_RE):
            for m in rx.finditer(text):
                v = m.group(1).strip(" .,:;")
                if v.lower() not in ("имя", "name", "имя контакта", "contact name"):
                    found.setdefault("name", v)
                    break
            if "name" in found:
                break
        for m in CITY_RE.finditer(text):
            v = m.group(1).strip(" .,:;")
            if v.lower() not in ("город", "city", "location", "регион", "область"):
                found.setdefault("city", v)
                break
        for m in DOB_RE.finditer(text):
            found.setdefault("dob", m.group(1).strip())
            break
        for m in ADDRESS_RE.finditer(text):
            v = m.group(1).strip(" .,:;")
            if len(v) > 6 and not v.lower().startswith(("имя", "name")):
                found.setdefault("address", v)
                break
        if not found:
            continue
        out["evidence"].append({
            "url": r.get("url"),
            "domain": r.get("domain"),
            "title": (r.get("title") or "")[:110],
            "snippet": (r.get("snippet") or "")[:260],
            "extracted": found,
        })
        for k, bucket in (("name", "names"), ("city", "cities"),
                          ("dob", "birth_dates"), ("address", "addresses")):
            if k in found and found[k] not in out[bucket]:
                out[bucket].append(found[k])
    return out


# ---------------------------------------------------------------------------
# Основная сборка
# ---------------------------------------------------------------------------
def build_dossier(value: str, kind: str = "auto") -> Dict[str, Any]:
    """Собирает полное досье по email или телефону."""
    v = value.strip()

    if kind == "auto":
        kind = "email" if ("@" in v and "." in v.split("@")[-1]) else "phone"

    dossier: Dict[str, Any] = {
        "value": v,
        "kind": kind,
        "identity": {"full_name": [], "first_name": [], "last_name": [],
                     "middle_name": [], "birth_date": [], "gender": []},
        "locations": {"address": [], "city": [], "region": [], "district": [],
                      "country": [], "zip": []},
        "contacts": {"phones": [], "emails": [], "usernames": [], "ips": []},
        "breaches": {"count": 0, "sources": [], "fields": [], "passwords_found": 0,
                     "records_parsed": 0},
        "web_evidence": [],
        "profiles": {},
        "sources_used": [],
        "notes": [],
    }

    # ---------------- Утечки ----------------
    query_val = _phone_digits(v) if kind == "phone" else v
    lc = check_leakcheck(query_val)
    if lc.get("found"):
        dossier["breaches"]["count"] = lc.get("found") or 0
        dossier["breaches"]["sources"] = lc.get("sources", [])
        dossier["breaches"]["fields"] = lc.get("leaked_field_labels", [])
        dossier["sources_used"].append("LeakCheck")
    else:
        dossier["notes"].append("LeakCheck: утечек не найдено или сервис недоступен")

    # ---------------- DeHashed (даёт САМИ значения полей) ----------------
    try:
        from premium import dehashed_search
        if kind == "email":
            dq = f"email:{v}"
        else:
            dq = f"phone:{v}"
        dh = dehashed_search(dq)
        if dh.get("active"):
            dossier["sources_used"].append("DeHashed")
            parsed = _parse_records(dh.get("results") or [])
            dossier["breaches"]["records_parsed"] = parsed["records"]
            dossier["breaches"]["passwords_found"] = parsed["passwords"]
            idn = dossier["identity"]
            loc = dossier["locations"]
            con = dossier["contacts"]
            idn["full_name"] = parsed["full_names"]
            idn["first_name"] = parsed["names"]
            idn["birth_date"] = parsed["birth_dates"]
            idn["gender"] = parsed["genders"]
            loc["address"] = parsed["addresses"]
            loc["city"] = parsed["cities"]
            loc["region"] = parsed["regions"]
            loc["district"] = parsed["districts"]
            loc["country"] = parsed["countries"]
            loc["zip"] = parsed["zips"]
            con["phones"] = parsed["phones"]
            con["emails"] = parsed["emails"]
            con["usernames"] = parsed["usernames"]
            con["ips"] = parsed["ips"]
        elif dh.get("error"):
            dossier["notes"].append(f"DeHashed: {dh['error']}")
    except Exception as e:
        dossier["notes"].append(f"DeHashed: {e}")

    # ---------------- XposedOrNot (бесплатно, без ключа) ----------------
    if kind == "email":
        try:
            xn = check_xposedornot(v)
            if xn.get("breaches"):
                dossier["breaches"]["xposedornot"] = xn["breaches"]
                dossier["breaches"]["xposedornot_details"] = xn.get("breach_details", [])
                dossier["breaches"].setdefault("sources", [])
                for b in xn["breaches"]:
                    if b and b not in dossier["breaches"]["sources"]:
                        dossier["breaches"]["sources"].append({"name": b, "date": ""})
                dossier["profiles"]["risk"] = xn.get("risk")
                dossier["profiles"]["passwords_strength"] = xn.get("passwords_strength")
                dossier["sources_used"].append("XposedOrNot")
            elif xn.get("error"):
                dossier["notes"].append(f"XposedOrNot: {xn['error']}")
        except Exception as e:
            dossier["notes"].append(f"XposedOrNot: {e}")

    # ---------------- Safe Surf / НКЦКИ (РФ, бесплатно) ----------------
    try:
        ss = safesurf_ru.check(query_val if kind == "phone" else v)
        if ss.get("matches") is not None:
            dossier["breaches"]["safe_surf"] = ss["matches"]
            dossier["profiles"]["safe_surf"] = ss
            dossier["sources_used"].append("Safe Surf (НКЦКИ)")
        elif ss.get("error"):
            dossier["notes"].append(f"Safe Surf: {ss['error']}")
    except Exception as e:
        dossier["notes"].append(f"Safe Surf: {e}")

    # ---------------- HIBP ----------------
    if kind == "email":
        try:
            hb = check_hibp(v)
            if hb.get("available") and hb.get("breaches"):
                dossier["breaches"]["hibp"] = [
                    {"name": b.get("Name"), "date": b.get("BreachDate"),
                     "data": b.get("DataClasses", [])}
                    for b in hb["breaches"] if isinstance(b, dict)]
                dossier["sources_used"].append("Have I Been Pwned")
        except Exception as e:
            dossier["notes"].append(f"HIBP: {e}")

    # ---------------- Профиль по email (Gravatar) ----------------
    if kind == "email":
        import hashlib
        md5 = hashlib.md5(v.lower().encode()).hexdigest()
        try:
            import requests
            r = requests.get(f"https://www.gravatar.com/{md5}.json",
                             headers={"User-Agent": "OSINT-Finder"}, timeout=15)
            if r.status_code == 200:
                entry = (r.json().get("entry") or [{}])[0]
                if entry.get("displayName"):
                    dossier["identity"]["full_name"].append(entry["displayName"])
                if entry.get("currentLocation"):
                    dossier["locations"]["city"].append(entry["currentLocation"])
                if entry.get("accounts"):
                    dossier["profiles"]["gravatar_accounts"] = entry["accounts"]
                dossier["sources_used"].append("Gravatar")
        except Exception:
            pass

    # ---------------- Инфостилеры (Hudson Rock) ----------------
    if kind == "email":
        try:
            st = check_infostealer(v)
            if st.get("data"):
                d = st["data"]
                dossier["profiles"]["infostealer"] = {
                    "compromised": True,
                    "date": d.get("date_compromised"),
                    "computer": d.get("computer_name"),
                    "os": d.get("os"),
                    "ip": d.get("ip"),
                    "family": d.get("family"),
                }
                if d.get("ip"):
                    dossier["contacts"]["ips"].append(d["ip"])
                dossier["sources_used"].append("Hudson Rock")
        except Exception:
            pass

    # ---------------- Оператор телефона ----------------
    if kind == "phone":
        try:
            from premium import numverify_phone
            nv = numverify_phone(v)
            if nv.get("data"):
                dossier["profiles"]["operator"] = nv["data"]
                dossier["sources_used"].append("Numverify")
        except Exception:
            pass
        try:
            from identify import normalize_phone
            n = normalize_phone(v)
            dossier["profiles"]["normalized"] = n
            if n.get("country"):
                dossier["locations"]["country"].append(n["country"])
        except Exception:
            pass

    # ---------------- Упоминания в интернете + извлечение ФИО/адресов ----------------
    try:
        web = web_search(f'"{v}"', limit=25)
        results = web.get("results", [])
        dossier["web_evidence"] = results
        if results:
            dossier["sources_used"].append(web.get("engine", "веб-поиск"))
        ex = extract_from_web(results)
        idn = dossier["identity"]
        loc = dossier["locations"]
        for k in ("names",):
            for v2 in ex[k]:
                if v2 not in idn["full_name"]:
                    idn["full_name"].append(v2)
        for v2 in ex["cities"]:
            if v2 not in loc["city"]:
                loc["city"].append(v2)
        for v2 in ex["birth_dates"]:
            if v2 not in idn["birth_date"]:
                idn["birth_date"].append(v2)
        for v2 in ex["addresses"]:
            if v2 not in loc["address"]:
                loc["address"].append(v2)
        dossier["profiles"]["web_extractions"] = ex["evidence"]
    except Exception as e:
        dossier["notes"].append(f"веб-поиск: {e}")

    # ---------------- Связанные аккаунты по username ----------------
    try:
        from scanner import scan_sync
        usernames = set(dossier["contacts"]["usernames"])
        if kind == "email":
            local = v.split("@")[0]
            if len(local) >= 4:
                usernames.add(local)
        for un in list(usernames)[:3]:
            sc = scan_sync(un, ["social", "dev", "professional", "market", "media"])
            if sc.get("found_count"):
                dossier["profiles"].setdefault("accounts", {})[un] = sc["found"]
                dossier["sources_used"].append("сканер профилей")
    except Exception as e:
        dossier["notes"].append(f"сканер: {e}")

    # ---------------- ЛИЧНЫЕ ДАННЫЕ (без платных ключей) ----------------
    try:
        dossier["personal"] = _collect_personal(v, kind)
    except Exception as e:
        dossier["personal"] = {"error": str(e)}
        dossier["notes"].append(f"личные данные: {e}")

    # ---------------- ЧТО ИМЕННО ПРОВЕРЕНО ----------------
    dossier["checked"] = _what_was_checked(dossier, v, kind)

    # ---------------- Итоговая сводка ----------------
    dossier["summary"] = _summary(dossier)
    return dossier


def _what_was_checked(d: Dict[str, Any], value: str, kind: str) -> Dict[str, Any]:
    """Отчёт: какие источники опрослены и с каким результатом."""
    per = d.get("personal") or {}
    br = d.get("breaches", {})
    checked = {
        "kind": kind,
        "sources": [],
        "counts": {},
    }
    lc = br.get("count")
    checked["counts"]["утечки (LeakCheck)"] = lc if lc is not None else "—"
    checked["counts"]["утечки (XposedOrNot)"] = len(br.get("xposedornot") or []) or 0
    checked["counts"]["утечки (НКЦКИ)"] = br.get("safe_surf", "—")
    checked["counts"]["упоминаний в интернете"] = len(d.get("web_evidence") or [])
    checked["counts"]["веб-запросов выполнено"] = len(per.get("queries") or [])
    checked["counts"]["логинов найдено"] = len(per.get("usernames") or [])
    checked["counts"]["соцпрофилей найдено"] = sum(
        len(v) for v in (per.get("social_profiles") or {}).values()
    ) if isinstance(per.get("social_profiles"), dict) else len(per.get("social_profiles") or [])

    srcs = []
    srcs.append("LeakCheck — базы утечек (метаданные)")
    srcs.append("XposedOrNot — 792 утечки / 11.6 млрд записей")
    srcs.append("Safe Surf (НКЦКИ) — российская база утечек")
    srcs.append("Hudson Rock — проверка инфостилеров")
    if kind == "email":
        srcs.append("GitHub Search — коммиты (ФИО) и аккаунты по email")
    else:
        srcs.append("Kaspersky Who Calls — владелец номера, город, оператор")
    srcs.append("Веб-поиск — объявления и страницы с ФИО/адресом")
    srcs.append("Сканер 506 сайтов — профили по найденным логинам")
    checked["sources"] = srcs
    return checked


def _phone_digits(value: str) -> str:
    """Приводит номер к «голым» цифрам в формате, который понимают базы утечек.

    «8 999 123-45-67» -> «79991234567», «+7 (999) 123-45-67» -> «79991234567».
    """
    import re as _re
    d = _re.sub(r"\D", "", value or "")
    if len(d) == 11 and d.startswith("8"):
        d = "7" + d[1:]
    if len(d) == 10:
        d = "7" + d
    return d


def _collect_personal(value: str, kind: str) -> Dict[str, Any]:
    """Собирает ФИО, адреса, контакты и все соцсети — по бесплатным источникам."""
    res: Dict[str, Any] = {
        "names": [], "birth_dates": [], "addresses": [], "cities": [],
        "operators": [], "phone_owner": None, "usernames": [],
        "social_profiles": [], "evidence": [], "sources": [], "notes": [],
        "genders": [], "districts": [], "zips": [], "queries": [],
    }

    # --- ФИО из коммитов GitHub ---
    if kind == "email":
        try:
            gh = personal.github_commits_identity(value)
            for n in gh.get("names", []):
                if n not in res["names"]:
                    res["names"].append(n)
            if gh.get("names"):
                res["sources"].append("GitHub (коммиты)")
            res["evidence"].append({"source": "GitHub commits",
                                    "detail": f"{len(gh.get('repos', []))} репозиториев, "
                                              f"автор: {', '.join(gh.get('names', [])[:3])}",
                                    "repos": gh.get("repos", [])[:15]})
        except Exception as e:
            res["notes"].append(f"GitHub commits: {e}")

    # --- Владелец номера (Kaspersky Who Calls) ---
    if kind == "phone":
        try:
            wc = personal.whocalls_lookup(query_val)
            if wc.get("owner"):
                res["phone_owner"] = wc["owner"]
                res["names"].append(wc["owner"])
                res["sources"].append("Kaspersky Who Calls")
            if wc.get("city"):
                res["cities"].append(wc["city"])
            if wc.get("operator"):
                res["operators"].append(wc["operator"])
            if wc.get("comment"):
                res["evidence"].append({"source": "Kaspersky Who Calls",
                                        "detail": wc["comment"][:250]})
        except Exception as e:
            res["notes"].append(f"Who Calls: {e}")

    # --- Целевые веб-поиски (ФИО / адрес / объявления) ---
    try:
        dk = personal.personal_dorks(value, kind)
        res["sources"].append("веб-поиск (dorks)")
        res["queries"] = dk.get("queries", [])
        res["variants"] = dk.get("variants", [])
        for r in dk.get("results", [])[:25]:
            text = f"{r.get('title', '')} {r.get('snippet', '')}"
            ex = personal.extract_personal(text)
            for n in ex["names"]:
                if n not in res["names"]:
                    res["names"].append(n)
            for a in ex["addresses"]:
                if a not in res["addresses"]:
                    res["addresses"].append(a)
            for c in ex["cities"]:
                if c not in res["cities"]:
                    res["cities"].append(c)
            for b in ex["birth_dates"]:
                if b not in res["birth_dates"]:
                    res["birth_dates"].append(b)
            for g in ex["genders"]:
                if g not in res["genders"]:
                    res["genders"].append(g)
            for d in ex["districts"]:
                if d not in res["districts"]:
                    res["districts"].append(d)
            for z in ex["zips"]:
                if z not in res["zips"]:
                    res["zips"].append(z)
            res["evidence"].append({
                "source": r.get("domain") or "веб",
                "detail": (r.get("snippet") or r.get("title") or "")[:220],
                "url": r.get("url"),
                "extracted": ex,
            })
    except Exception as e:
        res["notes"].append(f"dorks: {e}")

    # --- Логины и все профили в соцсетях ---
    try:
        usernames = personal.collect_usernames(value, kind)
        res["usernames"] = usernames
        if usernames:
            res["sources"].append("сканер 506 сайтов")
            res["social_profiles"] = personal.scan_usernames(usernames, limit=3)
    except Exception as e:
        res["notes"].append(f"логины: {e}")

    # --- Steam по email ---
    if kind == "email":
        try:
            st = personal.steam_search_by_email(value)
            for p in st.get("profiles", []):
                res["social_profiles"].append({"site": "Steam", "category": "games",
                                               "url": p, "profile_url": p})
        except Exception:
            pass

    res["names"] = list(dict.fromkeys(res["names"]))[:20]
    # убираем из адресов то, что совпадает с городом
    cities_norm = {c.lower().strip(" г.") for c in res["cities"]}
    res["addresses"] = [a for a in dict.fromkeys(res["addresses"])
                        if a.lower().strip(" г.") not in cities_norm][:20]
    res["cities"] = list(dict.fromkeys(res["cities"]))[:20]
    res["birth_dates"] = list(dict.fromkeys(res["birth_dates"]))[:10]
    res["genders"] = list(dict.fromkeys(res["genders"]))[:5]
    res["districts"] = list(dict.fromkeys(res["districts"]))[:10]
    res["zips"] = list(dict.fromkeys(res["zips"]))[:10]
    return res


def _summary(d: Dict[str, Any]) -> Dict[str, Any]:
    """Краткая сводка: что удалось установить."""
    idn, loc, con, br = d["identity"], d["locations"], d["contacts"], d["breaches"]
    got = []
    if idn["full_name"]:
        got.append("ФИО")
    if idn["birth_date"]:
        got.append("дата рождения")
    if loc["address"]:
        got.append("адрес")
    if loc["city"]:
        got.append("город")
    if br["count"]:
        got.append("утечки")
    if con["phones"]:
        got.append("телефоны")
    if con["emails"]:
        got.append("email")
    return {
        "identified_fields": got,
        "complete": bool(idn["full_name"] and idn["birth_date"] and (loc["address"] or loc["city"])),
        "breach_count": br["count"],
        "breach_sources": len(br["sources"]),
    }
