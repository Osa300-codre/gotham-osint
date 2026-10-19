#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Офлайн-тесты: linker.py (связывание площадок) и knowledge.py (база знаний)."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import linker as L
import knowledge as K


def test_translit():
    assert L.translit("Пётр") == "petr"
    assert L.translit("Иванов") == "ivanov"


def test_name_key():
    assert L.name_key("Пётр Иванов") == L.name_key("Иванов Пётр")
    assert L.name_key("Ivan Petrov") != L.name_key("Pavel Durov")
    assert L.name_key("Иван Петрович Иванов") == L.name_key("Иванов Иван")


def test_name_similarity():
    assert L.name_similarity("Иван Иванов", "Иванов Иван") >= 0.9
    assert L.name_similarity("Иван Иванов", "Пётр Иванов") < 1.0
    assert L.name_similarity("", "") == 0.0


def test_hamming():
    assert L.hamming("0000000000000000", "0000000000000000") == 0
    assert L.hamming("0000000000000000", "000000000000000f") == 4
    assert L.hamming(None, "00") is None


def test_domains():
    d = L.domains_of("Мой сайт https://ivan-petroff.ru/ и https://vk.com/durov")
    assert "ivan-petroff.ru" in d
    assert "vk.com" not in d


def test_contact_overlap():
    a = {"emails": ["x@y.ru"], "phones": ["79991234567"], "usernames": ["ivan"]}
    b = {"emails": ["X@Y.RU"], "phones": [], "usernames": ["ivan", "petr"]}
    found = L.contact_overlap(a, b)
    kinds = {k for k, _ in found}
    assert "emails" in kinds and "usernames" in kinds


def test_link_profiles_shared_email():
    a = {"platform": "GitHub", "name": "Ivan", "emails": ["i@y.ru"],
         "phones": [], "links": [], "avatar": "", "ident_value": "ivan"}
    b = {"platform": "Habr", "name": "Ivan", "emails": ["i@y.ru"],
         "phones": [], "links": [], "avatar": "", "ident_value": "ivan"}
    rules = L.link_profiles(a, b)
    conf, reasons = L.merge_rules(rules)
    assert conf >= 0.9, rules
    assert any("общий email" in r for r in reasons)


def test_link_profiles_same_domain():
    a = {"platform": "A", "name": "", "emails": [], "phones": [],
         "links": ["https://mysite.ru/x"], "avatar": "", "ident_value": "a"}
    b = {"platform": "B", "name": "", "emails": [], "phones": [],
         "links": ["https://mysite.ru/y"], "avatar": "", "ident_value": "b"}
    rules = L.link_profiles(a, b)
    assert any("общий домен" in r for _, r in rules), rules


def test_merge_rules_bonus():
    r = [(0.6, "a"), (0.6, "b")]
    conf, reasons = L.merge_rules(r)
    assert conf > 0.6
    assert len(reasons) == 2


# --------------------------------------------------------------- база знаний

def _kb():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    os.remove(path)
    return K.KnowledgeBase(path)


def test_kb_node_and_edge():
    kb = _kb()
    a = kb.node("email", "x@y.ru")
    b = kb.node("username", "ivan")
    assert a and b and a != b
    kb.edge(a, b, "связь", 0.8, "тест")
    kb.edge(a, b, "связь", 0.8, "тест")
    rows = kb.conn.execute("SELECT confidence, sightings FROM edges").fetchall()
    assert len(rows) == 1
    assert rows[0]["sightings"] == 2
    assert rows[0]["confidence"] > 0.8  # повторное подтверждение повышает
    kb.close()


def test_kb_attributes_and_search():
    kb = _kb()
    n = kb.node("email", "x@y.ru")
    kb.attr(n, "full_name", "Иван Иванов", "тест", 0.7)
    res = kb.search("Иванов")
    assert res and any(r["value"] == "иван иванов" for r in res)
    kb.close()


def test_kb_ingest_and_clusters():
    kb = _kb()
    rep = {
        "identifiers": [{"type": "email", "value": "x@y.ru", "key": "email:x@y.ru",
                         "source": "input"}],
        "profiles": [{"platform": "GitHub", "url": "https://github.com/ivan",
                      "ident_value": "ivan", "name": "Ivan", "links": [],
                      "emails": [], "phones": [], "extra": {}}],
        "identity": {"full_names": [{"value": "Ivan Petrov", "sources": ["GitHub"],
                                     "confidence": 0.7}],
                     "addresses": [], "cities": [], "jobs": [],
                     "social_links": []},
        "correlation": {"edges": [{"a": "email:x@y.ru", "b": "GitHub:ivan",
                                   "confidence": 0.85, "reasons": ["тест"]}],
                        "clusters": []},
    }
    stats = kb.ingest(rep)
    assert stats["nodes"] >= 2 and stats["edges"] >= 1
    st = kb.stats()
    assert st["nodes"] >= 2 and st["edges"] >= 1
    g = kb.graph()
    assert g["nodes"] and g["edges"]
    assert g["clusters"], "ожидался кластер"
    known = kb.known_links()
    assert known
    kb.close()


def test_kb_neighbors():
    kb = _kb()
    a = kb.node("email", "x@y.ru")
    b = kb.node("username", "ivan")
    kb.edge(a, b, "связь", 0.9, "тест")
    kb.attr(a, "full_name", "Иван", "тест", 0.8)
    n = kb.neighbors("email", "x@y.ru")
    assert n["found"]
    assert len(n["nodes"]) == 2
    assert any(x["key"] == "full_name" for x in n["attributes"])
    kb.close()


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"[OK]   {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
