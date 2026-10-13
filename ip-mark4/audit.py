"""
audit.py - SQLite audit log. Two tables: one row per decision, many evidence rows per decision.
Why two tables: an auditor can pick any decision and see EXACTLY which source said what, when.
A third table, whitelist, holds the trusted IP ranges (same database, same connection pattern).
"""
import os
import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(os.getenv("AUDIT_DB") or Path(__file__).parent / "audit.db")  # AUDIT_DB: used by tests

SCHEMA = """
CREATE TABLE IF NOT EXISTS classifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT,   -- groups all IPs from one batch upload
    ip            TEXT NOT NULL,
    label         TEXT NOT NULL,   -- Known Tor Exit | Known Hosted VPN/Proxy Endpoint | Unknown
    confidence    TEXT NOT NULL,   -- High | Medium | Low
    rule_fired    TEXT,            -- R1 / R2 / R3 / R4 / none
    reason        TEXT,
    asn           TEXT,
    as_name       TEXT,
    classified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    classification_id INTEGER NOT NULL REFERENCES classifications(id),
    source            TEXT,   -- which dataset said it
    question          TEXT,   -- which rule asked
    result            TEXT,   -- MATCH / no match
    detail            TEXT,
    data_status       TEXT,   -- live / mock / mock_fallback / unavailable
    source_timestamp  TEXT    -- when that dataset was fetched
);
CREATE TABLE IF NOT EXISTS whitelist (
    id        TEXT PRIMARY KEY,         -- "wl_" + 8 hex chars
    cidr      TEXT NOT NULL UNIQUE,     -- canonical network, e.g. 192.168.1.0/24
    label     TEXT NOT NULL DEFAULT '',
    added_at  TEXT NOT NULL,            -- ISO 8601 UTC
    enabled   INTEGER NOT NULL DEFAULT 1
);
"""


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)  # safe to run every time (IF NOT EXISTS)
    return conn


def log_classification(res, run_id=""):
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO classifications (run_id, ip, label, confidence, rule_fired, reason, asn, as_name, classified_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, res["ip"], res["label"], res["confidence"], res["rule_fired"],
             res["reason"], res["asn"], res["as_name"], res["classified_at"]))
        cid = cur.lastrowid
        conn.executemany(
            "INSERT INTO evidence (classification_id, source, question, result, detail, data_status, source_timestamp)"
            " VALUES (?,?,?,?,?,?,?)",
            [(cid, e["source"], e["question"], e["result"], e["detail"],
              e["data_status"], e["source_timestamp"]) for e in res["evidence"]])
    return cid


def read_table(sql, params=()):
    import pandas as pd
    with _conn() as conn:
        return pd.read_sql_query(sql, conn, params=params)


# ---- whitelist CRUD ----------------------------------------------------------------
def wl_list():
    """All whitelist entries, newest first, as dicts {id, cidr, label, added_at, enabled(bool)}."""
    with _conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM whitelist ORDER BY added_at DESC, rowid DESC").fetchall()
    return [{**dict(r), "enabled": bool(r["enabled"])} for r in rows]


def wl_add(cidr, label, added_at, enabled=True):
    wid = "wl_" + uuid.uuid4().hex[:8]
    with _conn() as conn:
        conn.execute("INSERT INTO whitelist (id, cidr, label, added_at, enabled) VALUES (?,?,?,?,?)",
                     (wid, cidr, label or "", added_at, int(bool(enabled))))
    return wid


def wl_update(wid, **fields):
    allowed = {"cidr", "label", "enabled"}
    cols = [k for k in fields if k in allowed]
    if not cols:
        return
    vals = [int(bool(fields[k])) if k == "enabled" else fields[k] for k in cols]
    with _conn() as conn:
        conn.execute(f"UPDATE whitelist SET {', '.join(c + ' = ?' for c in cols)} WHERE id = ?", (*vals, wid))


def wl_delete(wid):
    with _conn() as conn:
        conn.execute("DELETE FROM whitelist WHERE id = ?", (wid,))
