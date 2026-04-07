"""
database.py — Historial de conexiones, eventos y bloqueos en SQLite.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "watchdog_history.db")

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS connections (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT    NOT NULL,
            pid       INTEGER,
            process   TEXT,
            exe       TEXT,
            username  TEXT,
            local     TEXT,
            remote_ip TEXT,
            remote_port INTEGER,
            hostname  TEXT,
            status    TEXT,
            country   TEXT,
            city      TEXT,
            org       TEXT,
            geo_flag  TEXT,
            is_external INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT    NOT NULL,
            event_type TEXT   NOT NULL,   -- BLOCK, UNBLOCK, KILL, CAPTURE_START, etc.
            target    TEXT,
            detail    TEXT,
            ok        INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS blocked (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT    NOT NULL,
            ip         TEXT,
            process    TEXT,
            exe        TEXT,
            rule_name  TEXT,
            direction  TEXT,
            active     INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT,
            target_ip   TEXT,
            ts          TEXT,
            direction   TEXT,
            proto       TEXT,
            src         TEXT,
            dst         TEXT,
            size        INTEGER,
            summary     TEXT,
            raw_preview TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
        CREATE INDEX IF NOT EXISTS idx_conn_ip ON connections(remote_ip);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        """)

def log_connection(conn_info: dict):
    """Registra una conexión nueva (externa) en el historial."""
    if not conn_info.get("is_external"):
        return
    geo = conn_info.get("geo", {})
    try:
        with get_conn() as db:
            db.execute("""
                INSERT INTO connections
                (ts, pid, process, exe, username, local, remote_ip, remote_port,
                 hostname, status, country, city, org, geo_flag, is_external)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                conn_info.get("pid"),
                conn_info.get("process"),
                conn_info.get("exe"),
                conn_info.get("username"),
                conn_info.get("local"),
                conn_info.get("remote_ip"),
                conn_info.get("remote_port"),
                conn_info.get("hostname"),
                conn_info.get("status"),
                geo.get("country"),
                geo.get("city"),
                geo.get("org"),
                geo.get("flag"),
                1 if conn_info.get("is_external") else 0,
            ))
    except Exception:
        pass

def log_event(event_type: str, target: str, detail: str = "", ok: bool = True):
    try:
        with get_conn() as db:
            db.execute("""
                INSERT INTO events (ts, event_type, target, detail, ok)
                VALUES (?,?,?,?,?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                event_type,
                target,
                detail,
                1 if ok else 0,
            ))
    except Exception:
        pass

def log_blocked(ip: str = None, process: str = None, exe: str = None,
                rule_name: str = None, direction: str = "both"):
    try:
        with get_conn() as db:
            db.execute("""
                INSERT INTO blocked (ts, ip, process, exe, rule_name, direction)
                VALUES (?,?,?,?,?,?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip or "", process or "", exe or "", rule_name or "", direction
            ))
    except Exception:
        pass

def log_packet(session_id: str, target_ip: str, pkt: dict):
    try:
        with get_conn() as db:
            db.execute("""
                INSERT INTO packets
                (session_id, target_ip, ts, direction, proto, src, dst, size, summary, raw_preview)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                session_id, target_ip,
                pkt.get("ts"), pkt.get("direction"), pkt.get("proto"),
                pkt.get("src"), pkt.get("dst"), pkt.get("size"),
                pkt.get("summary"), pkt.get("raw"),
            ))
    except Exception:
        pass

def get_history_connections(limit: int = 200, remote_ip: str = None) -> list[dict]:
    with get_conn() as db:
        if remote_ip:
            rows = db.execute(
                "SELECT * FROM connections WHERE remote_ip=? ORDER BY id DESC LIMIT ?",
                (remote_ip, limit)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM connections ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]

def get_history_events(limit: int = 100) -> list[dict]:
    with get_conn() as db:
        rows = db.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_blocked_ips() -> list[dict]:
    with get_conn() as db:
        rows = db.execute(
            "SELECT * FROM blocked WHERE active=1 ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]

def mark_unblocked(ip: str):
    with get_conn() as db:
        db.execute("UPDATE blocked SET active=0 WHERE ip=?", (ip,))

def get_packets_for_session(session_id: str, limit: int = 200) -> list[dict]:
    with get_conn() as db:
        rows = db.execute(
            "SELECT * FROM packets WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit)
        ).fetchall()
    return [dict(r) for r in rows]

def get_top_destinations(limit: int = 20) -> list[dict]:
    """Top IPs/hosts más contactados."""
    with get_conn() as db:
        rows = db.execute("""
            SELECT remote_ip, hostname, country, geo_flag,
                   COUNT(*) as total,
                   GROUP_CONCAT(DISTINCT process) as processes
            FROM connections
            WHERE remote_ip != '' AND remote_ip IS NOT NULL
            GROUP BY remote_ip
            ORDER BY total DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]

def get_stats_summary() -> dict:
    with get_conn() as db:
        total_conn = db.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
        unique_ips = db.execute("SELECT COUNT(DISTINCT remote_ip) FROM connections WHERE remote_ip != ''").fetchone()[0]
        total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = db.execute("SELECT COUNT(*) FROM blocked WHERE active=1").fetchone()[0]
    return {
        "total_connections_logged": total_conn,
        "unique_remote_ips": unique_ips,
        "total_events": total_events,
        "currently_blocked": blocked,
    }
