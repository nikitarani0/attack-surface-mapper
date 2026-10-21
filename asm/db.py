import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path("data/asm.db")


def get_connection() -> sqlite3.Connection:
    """Open a connection, ensuring the data/ dir and schema exist."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row            # rows accessible by column name
    conn.execute("PRAGMA foreign_keys = ON")  # enforce FK relationships
    return conn


def init_db() -> None:
    """Create all tables if they don't exist. Safe to call repeatedly."""
    conn = get_connection()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target      TEXT NOT NULL,
        started_at  TEXT NOT NULL,
        finished_at TEXT,
        status      TEXT DEFAULT 'running'
    );

    CREATE TABLE IF NOT EXISTS subdomains (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id   INTEGER NOT NULL,
        hostname  TEXT NOT NULL,
        source    TEXT,
        resolved  INTEGER DEFAULT 0,
        ip        TEXT,
        UNIQUE(scan_id, hostname),
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS hosts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id      INTEGER NOT NULL,
        subdomain_id INTEGER,
        url          TEXT,
        status_code  INTEGER,
        title        TEXT,
        tech         TEXT,
        waf          TEXT,
        server       TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS services (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id  INTEGER NOT NULL,
        ip       TEXT,
        port     INTEGER,
        protocol TEXT,
        service  TEXT,
        version  TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS cloud_assets (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id            INTEGER NOT NULL,
        type               TEXT,
        identifier         TEXT,
        provider           TEXT,
        public             INTEGER DEFAULT 0,
        takeover_candidate INTEGER DEFAULT 0,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS endpoints (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        host_id INTEGER,
        url     TEXT,
        method  TEXT,
        params  TEXT,
        source  TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS secrets (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id        INTEGER NOT NULL,
        type           TEXT,
        value_redacted TEXT,
        location       TEXT,
        severity       TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS findings (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id          INTEGER NOT NULL,
        title            TEXT,
        severity         TEXT,
        category         TEXT,
        evidence         TEXT,
        correlation_type TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );
    """)
    conn.commit()
    conn.close()


def create_scan(target: str) -> int:
    """Insert a new scan row, return its id."""
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO scans (target, started_at) VALUES (?, ?)",
        (target, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def finish_scan(scan_id: int) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET finished_at = ?, status = 'done' WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), scan_id),
    )
    conn.commit()
    conn.close()


def insert_subdomains(scan_id: int, hostnames: set[str], source: str) -> int:
    """
    Bulk-insert subdomains for a scan. Ignores duplicates via the
    UNIQUE(scan_id, hostname) constraint. Returns count newly inserted.
    Defensively filters to clean, non-empty strings only.
    """
    # Guarantee we only bind strings — flaky sources sometimes yield
    # nested/odd types, which SQLite can't bind.
    clean = {
        str(h).strip().lower()
        for h in hostnames
        if isinstance(h, str) and h.strip()
    }

    if not clean:
        return 0

    conn = get_connection()
    before = conn.execute(
        "SELECT COUNT(*) FROM subdomains WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]

    conn.executemany(
        "INSERT OR IGNORE INTO subdomains (scan_id, hostname, source) VALUES (?, ?, ?)",
        [(scan_id, h, source) for h in clean],
    )
    conn.commit()

    after = conn.execute(
        "SELECT COUNT(*) FROM subdomains WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    conn.close()
    return after - before

def get_subdomains(scan_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT hostname, source, resolved, ip FROM subdomains WHERE scan_id = ? ORDER BY hostname",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows
