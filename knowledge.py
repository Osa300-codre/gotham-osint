#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
База знаний OSINT: накопительный граф «клубок ниток».

Идея: каждый запуск коррелятора не выбрасывает результат, а добавляет его в
общую SQLite-базу. Со временем в ней накапливается граф:

    узлы   — идентификаторы (телефон, e-mail, username, Telegram, VK, ФИО)
              и профили (площадка + URL);
    связи  — «один и тот же человек» с типом, доказательством и уверенностью;
    атрибуты— ФИО, адреса, города, места работы, ники (с источником);
    свидетельства — где конкретно что нашли (URL, заголовок, сниппет).

Связи накапливаются: если один и тот же факт подтвердился дважды, уверенность
растёт. Кластеры считаются как компоненты связности по связям с confidence
не ниже порога. База позволяет отвечать на вопрос «что мы уже знаем про этот
человек», даже если площадка сейчас недоступна.

Файл базы: osint_kb.sqlite (можно переопределить переменной OSINT_KB).
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_PATH = os.environ.get("OSINT_KB", "osint_kb.sqlite")
CLUSTER_MIN_CONFIDENCE = 0.6

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    meta       TEXT DEFAULT '',
    sightings  INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen  TEXT,
    UNIQUE(kind, value)
);
CREATE TABLE IF NOT EXISTS edges (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    a          INTEGER NOT NULL,
    b          INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    evidence   TEXT DEFAULT '',
    sightings  INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen  TEXT,
    UNIQUE(a, b, kind)
);
CREATE TABLE IF NOT EXISTS attributes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    INTEGER NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    source     TEXT DEFAULT '',
    confidence REAL DEFAULT 0.5,
    sightings  INTEGER DEFAULT 0,
    last_seen  TEXT,
    UNIQUE(node_id, key, value)
);
CREATE TABLE IF NOT EXISTS sightings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    INTEGER NOT NULL,
    platform   TEXT DEFAULT '',
    url        TEXT DEFAULT '',
    title      TEXT DEFAULT '',
    snippet    TEXT DEFAULT '',
    last_seen  TEXT
);
CREATE INDEX IF NOT EXISTS idx_edges_a ON edges(a);
CREATE INDEX IF NOT EXISTS idx_edges_b ON edges(b);
CREATE INDEX IF NOT EXISTS idx_attr_node ON attributes(node_id);
CREATE INDEX IF NOT EXISTS idx_attr_value ON attributes(value);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class KnowledgeBase:
    """Графовая база знаний с накоплением связей и атрибутов."""

    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path
        self.conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.ensure()

    # -------------------------------------------------- инфраструктура
    def ensure(self) -> None:
        with _LOCK:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -------------------------------------------------- узлы
    def node(self, kind: str, value: str, meta: Optional[Dict[str, Any]] = None) -> int:
        value = (value or "").strip()
        if not value:
            return 0
        ts = now_iso()
        meta_s = json.dumps(meta or {}, ensure_ascii=False)
        with _LOCK:
            cur = self.conn.execute(
                "SELECT id, sightings FROM nodes WHERE kind=? AND value=?",
                (kind, value.lower()))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE nodes SET sightings=sightings+1, last_seen=?, "
                    "meta=CASE WHEN ?<>'' THEN ? ELSE meta END WHERE id=?",
                    (ts, meta_s, meta_s, row["id"]))
                self.conn.commit()
                return int(row["id"])
            cur = self.conn.execute(
                "INSERT INTO nodes(kind, value, meta, sightings, first_seen, last_seen) "
                "VALUES(?,?,?,1,?,?)",
                (kind, value.lower(), meta_s, ts, ts))
            self.conn.commit()
            return int(cur.lastrowid)

    def get_node(self, kind: str, value: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM nodes WHERE kind=? AND value=?", (kind, value.lower()))
        return cur.fetchone()

    # -------------------------------------------------- связи
    def edge(self, a: int, b: int, kind: str, confidence: float,
             evidence: str = "") -> None:
        if not a or not b or a == b:
            return
        lo, hi = (a, b) if a < b else (b, a)
        ts = now_iso()
        with _LOCK:
            cur = self.conn.execute(
                "SELECT id, confidence, sightings FROM edges "
                "WHERE a=? AND b=? AND kind=?", (lo, hi, kind))
            row = cur.fetchone()
            if row:
                # повторное подтверждение повышает уверенность
                new_conf = min(1.0, max(row["confidence"], confidence) + 0.03)
                self.conn.execute(
                    "UPDATE edges SET confidence=?, sightings=sightings+1, "
                    "evidence=?, last_seen=? WHERE id=?",
                    (new_conf, evidence or "", ts, row["id"]))
            else:
                self.conn.execute(
                    "INSERT INTO edges(a, b, kind, confidence, evidence, sightings, "
                    "first_seen, last_seen) VALUES(?,?,?,?,?,1,?,?)",
                    (lo, hi, kind, confidence, evidence or "", ts, ts))
            self.conn.commit()

    # -------------------------------------------------- атрибуты
    def attr(self, node_id: int, key: str, value: str, source: str = "",
             confidence: float = 0.5) -> None:
        value = (value or "").strip()
        if not node_id or not value:
            return
        ts = now_iso()
        with _LOCK:
            cur = self.conn.execute(
                "SELECT id, confidence FROM attributes "
                "WHERE node_id=? AND key=? AND value=?",
                (node_id, key, value.lower()))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE attributes SET confidence=?, source=?, sightings=sightings+1, "
                    "last_seen=? WHERE id=?",
                    (min(1.0, max(row["confidence"], confidence)), source or "", ts, row["id"]))
            else:
                self.conn.execute(
                    "INSERT INTO attributes(node_id, key, value, source, confidence, "
                    "sightings, last_seen) VALUES(?,?,?,?,?,1,?)",
                    (node_id, key, value.lower(), source or "", confidence, ts))
            self.conn.commit()

    # -------------------------------------------------- свидетельства
    def sighting(self, node_id: int, platform: str, url: str,
                 title: str = "", snippet: str = "") -> None:
        if not node_id:
            return
        ts = now_iso()
        with _LOCK:
            self.conn.execute(
                "INSERT INTO sightings(node_id, platform, url, title, snippet, last_seen) "
                "VALUES(?,?,?,?,?,?)", (node_id, platform or "", url or "",
                                        title or "", snippet or "", ts))
            self.conn.commit()

    # -------------------------------------------------- загрузка отчёта
    def ingest(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Загружает отчёт коррелятора в базу. Возвращает статистику."""
        stats = {"nodes": 0, "edges": 0, "attributes": 0, "sightings": 0}
        if not isinstance(report, dict) or report.get("error"):
            return stats

        idents = report.get("identifiers") or []
        ident_ids: Dict[str, int] = {}
        for i in idents:
            nid = self.node(i.get("type", "unknown"), i.get("value", ""),
                            {"source": i.get("source", "")})
            if nid:
                ident_ids[i.get("key", "")] = nid
                stats["nodes"] += 1

        prof_ids: Dict[str, int] = {}
        for p in report.get("profiles") or []:
            key = f"{p.get('platform')}:{p.get('ident_value') or p.get('url')}"
            nid = self.node("profile", key,
                            {"platform": p.get("platform"), "url": p.get("url")})
            if not nid:
                continue
            prof_ids[key] = nid
            stats["nodes"] += 1
            if p.get("url"):
                self.sighting(nid, p.get("platform", ""), p.get("url", ""),
                              p.get("name", ""))
                stats["sightings"] += 1
            if p.get("name"):
                self.attr(nid, "name", p["name"], p.get("platform", ""), 0.7)
                stats["attributes"] += 1
            extra = p.get("extra") or {}
            if extra.get("city") or extra.get("location"):
                self.attr(nid, "city", extra.get("city") or extra.get("location"),
                          p.get("platform", ""), 0.6)
                stats["attributes"] += 1
            if extra.get("work"):
                self.attr(nid, "work", extra["work"], p.get("platform", ""), 0.5)
                stats["attributes"] += 1
            if p.get("bio"):
                self.attr(nid, "bio", p["bio"][:200], p.get("platform", ""), 0.4)
                stats["attributes"] += 1
            for lk in (p.get("links") or []):
                self.attr(nid, "link", lk, p.get("platform", ""), 0.4)
                stats["attributes"] += 1

        # атрибуты личности — вешаем на узлы-идентификаторы
        ident_block = report.get("identity") or {}
        for n in ident_block.get("full_names") or []:
            for nid in ident_ids.values():
                self.attr(nid, "full_name", n["value"],
                          ", ".join(n.get("sources") or []), n.get("confidence", 0.5))
                stats["attributes"] += 1
        for a in ident_block.get("addresses") or []:
            for nid in ident_ids.values():
                self.attr(nid, "address", a["value"],
                          ", ".join(a.get("sources") or []), a.get("confidence", 0.5))
                stats["attributes"] += 1
        for c in ident_block.get("cities") or []:
            for nid in ident_ids.values():
                self.attr(nid, "city", c["value"],
                          ", ".join(c.get("sources") or []), c.get("confidence", 0.4))
                stats["attributes"] += 1
        for s in ident_block.get("social_links") or []:
            for nid in ident_ids.values():
                self.attr(nid, "social", f"{s.get('platform')}:{s.get('url')}",
                          "соцсети", 0.5)
                stats["attributes"] += 1

        # связи
        for e in (report.get("correlation") or {}).get("edges") or []:
            a = ident_ids.get(e.get("a")) or prof_ids.get(e.get("a"))
            b = ident_ids.get(e.get("b")) or prof_ids.get(e.get("b"))
            if a and b:
                self.edge(a, b, e.get("kind", "связь"),
                          e.get("confidence", 0.5),
                          "; ".join(e.get("reasons") or []))
                stats["edges"] += 1

        return stats

    # -------------------------------------------------- чтение
    def graph(self, min_confidence: float = CLUSTER_MIN_CONFIDENCE,
              limit_nodes: int = 4000) -> Dict[str, Any]:
        """Возвращает узлы, связи и кластеры всей накопленной базы."""
        nodes = self.conn.execute(
            "SELECT id, kind, value, meta, sightings FROM nodes "
            "ORDER BY sightings DESC LIMIT ?", (limit_nodes,)).fetchall()
        edges = self.conn.execute(
            "SELECT id, a, b, kind, confidence, evidence, sightings FROM edges "
            "WHERE confidence >= ? ORDER BY confidence DESC", (min_confidence,)).fetchall()

        node_list = []
        adj: Dict[int, List[int]] = {}
        for r in nodes:
            try:
                meta = json.loads(r["meta"] or "{}")
            except Exception:
                meta = {}
            node_list.append({
                "id": r["id"], "kind": r["kind"], "value": r["value"],
                "meta": meta, "sightings": r["sightings"],
            })
            adj.setdefault(r["id"], [])
        edge_list = []
        for r in edges:
            if r["a"] in adj and r["b"] in adj:
                edge_list.append({
                    "a": r["a"], "b": r["b"], "kind": r["kind"],
                    "confidence": r["confidence"], "evidence": r["evidence"],
                    "sightings": r["sightings"],
                })
                adj[r["a"]].append(r["b"])
                adj[r["b"]].append(r["a"])

        clusters = self._components(adj)
        return {"nodes": node_list, "edges": edge_list, "clusters": clusters}

    def _components(self, adj: Dict[int, List[int]]) -> List[List[int]]:
        seen: Set[int] = set()
        out: List[List[int]] = []
        for start in adj:
            if start in seen:
                continue
            stack = [start]
            comp: List[int] = []
            seen.add(start)
            while stack:
                n = stack.pop()
                comp.append(n)
                for m in adj.get(n, []):
                    if m not in seen:
                        seen.add(m)
                        stack.append(m)
            if len(comp) > 1:
                out.append(sorted(comp))
        out.sort(key=len, reverse=True)
        return out

    def cluster_detail(self, cluster: List[int]) -> Dict[str, Any]:
        ids = cluster
        marks = ",".join("?" * len(ids))
        nodes = self.conn.execute(
            f"SELECT id, kind, value, sightings FROM nodes WHERE id IN ({marks})",
            ids).fetchall()
        edges = self.conn.execute(
            f"SELECT kind, confidence, evidence, a, b FROM edges "
            f"WHERE a IN ({marks}) AND b IN ({marks})", ids + ids).fetchall()
        attrs = self.conn.execute(
            f"SELECT key, value, source, confidence FROM attributes "
            f"WHERE node_id IN ({marks})", ids).fetchall()
        return {
            "nodes": [dict(kind=r["kind"], value=r["value"], sightings=r["sightings"])
                      for r in nodes],
            "edges": [dict(kind=r["kind"], confidence=r["confidence"],
                           evidence=r["evidence"]) for r in edges],
            "attributes": [dict(key=r["key"], value=r["value"], source=r["source"],
                                confidence=r["confidence"]) for r in attrs],
        }

    def known_links(self) -> Dict[str, Dict[str, Any]]:
        """Все накопленные связи в виде «kind:valueA|kind:valueB» -> данные."""
        out: Dict[str, Dict[str, Any]] = {}
        rows = self.conn.execute(
            "SELECT id, a, b, kind, confidence, evidence, sightings FROM edges").fetchall()
        ids = [r["a"] for r in rows] + [r["b"] for r in rows]
        meta: Dict[int, str] = {}
        if ids:
            marks = ",".join("?" * len(ids))
            for n in self.conn.execute(
                    f"SELECT id, kind, value FROM nodes WHERE id IN ({marks})", ids):
                meta[int(n["id"])] = f"{n['kind']}:{n['value']}"
        for r in rows:
            ka, kb = meta.get(int(r["a"])), meta.get(int(r["b"]))
            if not ka or not kb:
                continue
            key = "|".join(sorted([ka, kb]))
            prev = out.get(key)
            if prev is None or r["sightings"] > prev["sightings"]:
                out[key] = {"confidence": r["confidence"], "evidence": r["evidence"],
                            "sightings": r["sightings"], "kind": r["kind"]}
        return out

    def stats(self) -> Dict[str, Any]:
        def one(sql: str) -> int:
            try:
                return int(self.conn.execute(sql).fetchone()[0])
            except Exception:
                return 0

        by_kind = {r["kind"]: r["n"] for r in self.conn.execute(
            "SELECT kind, COUNT(*) n FROM nodes GROUP BY kind ORDER BY n DESC")}
        by_edge = {r["kind"]: r["n"] for r in self.conn.execute(
            "SELECT kind, COUNT(*) n FROM edges GROUP BY kind ORDER BY n DESC")}
        clusters = self._components({
            r["id"]: [] for r in self.conn.execute("SELECT id FROM nodes")})
        return {
            "path": os.path.abspath(self.path),
            "nodes": one("SELECT COUNT(*) FROM nodes"),
            "edges": one("SELECT COUNT(*) FROM edges"),
            "attributes": one("SELECT COUNT(*) FROM attributes"),
            "sightings": one("SELECT COUNT(*) FROM sightings"),
            "nodes_by_kind": by_kind,
            "edges_by_kind": by_edge,
            "clusters": len(clusters),
            "largest_cluster": len(clusters[0]) if clusters else 0,
        }

    def search(self, query: str, limit: int = 60) -> List[Dict[str, Any]]:
        """Поиск по узлам и атрибутам."""
        q = (query or "").strip().lower()
        if not q:
            return []
        like = f"%{q}%"
        out: List[Dict[str, Any]] = []
        for r in self.conn.execute(
                "SELECT id, kind, value, sightings FROM nodes "
                "WHERE value LIKE ? ORDER BY sightings DESC LIMIT ?", (like, limit)):
            out.append({"type": "node", "kind": r["kind"], "value": r["value"],
                        "sightings": r["sightings"], "id": r["id"]})
        for r in self.conn.execute(
                "SELECT a.key, a.value, a.source, a.confidence, n.kind AS node_kind, "
                "n.value AS node_value, n.id AS node_id FROM attributes a "
                "JOIN nodes n ON n.id = a.node_id "
                "WHERE a.value LIKE ? ORDER BY a.confidence DESC LIMIT ?", (like, limit)):
            out.append({"type": "attribute", "kind": r["key"], "value": r["value"],
                        "source": r["source"], "confidence": r["confidence"],
                        "node_kind": r["node_kind"], "node_value": r["node_value"],
                        "id": r["node_id"]})
        return out

    def neighbors(self, kind: str, value: str, depth: int = 2) -> Dict[str, Any]:
        """Всё, что база знает об узле и о его окружении."""
        node = self.get_node(kind, value)
        if node is None:
            return {"found": False, "kind": kind, "value": value}
        nid = int(node["id"])
        seen = {nid}
        frontier = {nid}
        for _ in range(max(0, depth)):
            nxt: Set[int] = set()
            for x in frontier:
                for r in self.conn.execute(
                        "SELECT a, b, kind, confidence, evidence FROM edges "
                        "WHERE a=? OR b=?", (x, x)):
                    other = r["b"] if r["a"] == x else r["a"]
                    if other not in seen:
                        seen.add(other)
                        nxt.add(other)
            frontier = nxt
        marks = ",".join("?" * len(seen))
        nodes = self.conn.execute(
            f"SELECT id, kind, value, sightings FROM nodes WHERE id IN ({marks})",
            list(seen)).fetchall()
        edges = self.conn.execute(
            f"SELECT a, b, kind, confidence, evidence, sightings FROM edges "
            f"WHERE a IN ({marks}) AND b IN ({marks})", list(seen) + list(seen)).fetchall()
        attrs = self.conn.execute(
            f"SELECT key, value, source, confidence FROM attributes "
            f"WHERE node_id IN ({marks})", list(seen)).fetchall()
        return {
            "found": True,
            "kind": kind, "value": value,
            "nodes": [dict(id=r["id"], kind=r["kind"], value=r["value"],
                           sightings=r["sightings"]) for r in nodes],
            "edges": [dict(a=r["a"], b=r["b"], kind=r["kind"],
                           confidence=r["confidence"], evidence=r["evidence"],
                           sightings=r["sightings"]) for r in edges],
            "attributes": [dict(key=r["key"], value=r["value"], source=r["source"],
                                confidence=r["confidence"]) for r in attrs],
        }


if __name__ == "__main__":  # pragma: no cover
    kb = KnowledgeBase()
    print(json.dumps(kb.stats(), ensure_ascii=False, indent=2))
