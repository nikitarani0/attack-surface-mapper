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
def update_subdomain_resolution(scan_id: int, hostname: str, resolved: bool, ip: str | None) -> None:
    """Mark a subdomain as resolved (or not) and store its IP."""
    conn = get_connection()
    conn.execute(
        "UPDATE subdomains SET resolved = ?, ip = ? WHERE scan_id = ? AND hostname = ?",
        (1 if resolved else 0, ip, scan_id, hostname),
    )
    conn.commit()
    conn.close()


def get_resolved_subdomains(scan_id: int) -> list[sqlite3.Row]:
    """Return only subdomains that resolved — the live set for downstream modules."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT hostname, ip FROM subdomains WHERE scan_id = ? AND resolved = 1 ORDER BY hostname",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows
def insert_host(scan_id: int, subdomain_id: int | None, url: str,
                status_code: int | None, title: str | None,
                tech: str | None, waf: str | None, server: str | None) -> None:
    """Insert a probed live web host into the hosts table."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO hosts
           (scan_id, subdomain_id, url, status_code, title, tech, waf, server)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, subdomain_id, url, status_code, title, tech, waf, server),
    )
    conn.commit()
    conn.close()


def get_hosts(scan_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT url, status_code, title, server, tech, waf FROM hosts WHERE scan_id = ? ORDER BY url",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows
def get_unique_resolved_ips(scan_id: int) -> list[str]:
    """Distinct IPs from resolved subdomains — scan each IP once, not per-hostname."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT DISTINCT ip FROM subdomains WHERE scan_id = ? AND resolved = 1 AND ip IS NOT NULL",
        (scan_id,),
    ).fetchall()
    conn.close()
    return [r["ip"] for r in rows]


def insert_service(scan_id: int, ip: str, port: int, protocol: str,
                   service: str | None, version: str | None) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO services (scan_id, ip, port, protocol, service, version)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, ip, port, protocol, service, version),
    )
    conn.commit()
    conn.close()


def get_services(scan_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT ip, port, protocol, service, version FROM services WHERE scan_id = ? ORDER BY ip, port",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows
def insert_cloud_asset(scan_id: int, asset_type: str, identifier: str,
                       provider: str, public: bool, takeover_candidate: bool) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO cloud_assets
           (scan_id, type, identifier, provider, public, takeover_candidate)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, asset_type, identifier, provider,
         1 if public else 0, 1 if takeover_candidate else 0),
    )
    conn.commit()
    conn.close()


def get_cloud_assets(scan_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT type, identifier, provider, public, takeover_candidate
           FROM cloud_assets WHERE scan_id = ? ORDER BY provider, type""",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows
def insert_endpoint(scan_id: int, host_id: int | None, url: str,
                    method: str | None, params: str | None, source: str) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO endpoints (scan_id, host_id, url, method, params, source)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, host_id, url, method, params, source),
    )
    conn.commit()
    conn.close()


def insert_secret(scan_id: int, secret_type: str, value_redacted: str,
                  location: str, severity: str) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO secrets (scan_id, type, value_redacted, location, severity)
           VALUES (?, ?, ?, ?, ?)""",
        (scan_id, secret_type, value_redacted, location, severity),
    )
    conn.commit()
    conn.close()


def get_endpoints(scan_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT url, method, source FROM endpoints WHERE scan_id = ? ORDER BY url",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows


def get_secrets(scan_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT type, value_redacted, location, severity FROM secrets WHERE scan_id = ? ORDER BY severity",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows
def insert_finding(scan_id: int, title: str, severity: str, category: str,
                   evidence: str, correlation_type: str) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO findings
           (scan_id, title, severity, category, evidence, correlation_type)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, title, severity, category, evidence, correlation_type),
    )
    conn.commit()
    conn.close()


def get_findings(scan_id: int) -> list[sqlite3.Row]:
    """Return findings ordered by severity (critical first)."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT title, severity, category, evidence, correlation_type
           FROM findings WHERE scan_id = ?
           ORDER BY CASE severity
               WHEN 'critical' THEN 1 WHEN 'high' THEN 2
               WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END""",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows


def clear_findings(scan_id: int) -> None:
    """Wipe prior findings for a scan so re-running correlation isn't additive."""
    conn = get_connection()
    conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()
def get_scan(scan_id: int) -> sqlite3.Row | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return row


def get_scan_summary(scan_id: int) -> dict:
    """Assemble all data for a scan into one dict for reporting."""
    conn = get_connection()

    def rows_to_dicts(query, params=(scan_id,)):
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    summary = {
        "scan": dict(scan) if scan else {},
        "subdomains": rows_to_dicts(
            "SELECT hostname, source, resolved, ip FROM subdomains WHERE scan_id = ? ORDER BY hostname"),
        "hosts": rows_to_dicts(
            "SELECT url, status_code, title, server, tech, waf FROM hosts WHERE scan_id = ? ORDER BY url"),
        "services": rows_to_dicts(
            "SELECT ip, port, protocol, service, version FROM services WHERE scan_id = ? ORDER BY ip, port"),
        "cloud_assets": rows_to_dicts(
            "SELECT type, identifier, provider, public, takeover_candidate FROM cloud_assets WHERE scan_id = ?"),
        "endpoints": rows_to_dicts(
            "SELECT url, method, source FROM endpoints WHERE scan_id = ? ORDER BY url"),
        "secrets": rows_to_dicts(
            "SELECT type, value_redacted, location, severity FROM secrets WHERE scan_id = ?"),
        "findings": rows_to_dicts(
            """SELECT title, severity, category, evidence, correlation_type
               FROM findings WHERE scan_id = ?
               ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
               WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"""),
    }
    conn.close()
    return summary
