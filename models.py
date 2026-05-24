"""SQLite 数据模型与漏洞入库。"""
import hashlib
import sqlite3
from dataclasses import dataclass, asdict
from typing import Optional

from config import DB_PATH


@dataclass
class VulnerabilityRecord:
    vuln_name: str
    severity: str
    asset_ip: str
    port: int
    url: str
    description: str
    solution: str
    source_tool: str = "unknown"
    external_id: str = ""
    cve: str = ""
    cwe: str = ""
    plugin_id: str = ""
    owasp: str = ""
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        raw = "|".join([
            self.asset_ip.lower(),
            str(self.port),
            (self.url or "").rstrip("/").lower(),
            self.vuln_name.strip().lower(),
            self.plugin_id,
            self.cve,
        ])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_name TEXT NOT NULL,
    severity TEXT,
    asset_ip TEXT,
    port INTEGER,
    url TEXT,
    description TEXT,
    solution TEXT,
    source_tool TEXT DEFAULT 'unknown',
    external_id TEXT DEFAULT '',
    cve TEXT DEFAULT '',
    cwe TEXT DEFAULT '',
    plugin_id TEXT DEFAULT '',
    owasp TEXT DEFAULT '',
    fingerprint TEXT UNIQUE,
    fix_status TEXT DEFAULT 'pending',
    remediation_rule TEXT DEFAULT '',
    auto_fixable INTEGER DEFAULT 0,
    last_fix_msg TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_asset ON vulnerabilities(asset_ip);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(fix_status);
"""

MIGRATION_COLUMNS = [
    ("source_tool", "TEXT DEFAULT 'unknown'"),
    ("external_id", "TEXT DEFAULT ''"),
    ("cve", "TEXT DEFAULT ''"),
    ("cwe", "TEXT DEFAULT ''"),
    ("plugin_id", "TEXT DEFAULT ''"),
    ("owasp", "TEXT DEFAULT ''"),
    ("fingerprint", "TEXT"),
    ("fix_status", "TEXT DEFAULT 'pending'"),
    ("remediation_rule", "TEXT DEFAULT ''"),
    ("auto_fixable", "INTEGER DEFAULT 0"),
    ("last_fix_msg", "TEXT DEFAULT ''"),
    ("created_at", "TEXT DEFAULT ''"),
    ("updated_at", "TEXT DEFAULT ''"),
]


def _table_columns(c) -> set:
    return {row[1] for row in c.execute("PRAGMA table_info(vulnerabilities)")}


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    conn = get_connection()
    c = conn.cursor()
    c.executescript(SCHEMA_SQL)
    existing = {row[1] for row in c.execute("PRAGMA table_info(vulnerabilities)")}
    for col, typedef in MIGRATION_COLUMNS:
        if col not in existing:
            try:
                c.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typedef}")
            except sqlite3.OperationalError:
                pass
    try:
        c.executescript(INDEX_SQL)
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


def upsert_vulnerability(
    record: VulnerabilityRecord,
    remediation_rule: str = "",
    auto_fixable: bool = False,
) -> str:
    """插入或更新漏洞，返回 inserted|updated|skipped。"""
    init_database()
    if not record.fingerprint:
        record.fingerprint = record.compute_fingerprint()

    conn = get_connection()
    c = conn.cursor()
    cols = _table_columns(c)
    c.execute("SELECT id FROM vulnerabilities WHERE fingerprint = ?", (record.fingerprint,))
    row = c.fetchone()

    fields = asdict(record)
    if row:
        set_clause = """
            UPDATE vulnerabilities SET
                vuln_name=?, severity=?, asset_ip=?, port=?, url=?,
                description=?, solution=?, source_tool=?, external_id=?,
                cve=?, cwe=?, plugin_id=?, owasp=?,
                remediation_rule=?, auto_fixable=?
        """
        if "updated_at" in cols:
            set_clause += ", updated_at=datetime('now')"
        set_clause += " WHERE fingerprint=?"
        c.execute(
            set_clause,
            (
                fields["vuln_name"], fields["severity"], fields["asset_ip"], fields["port"],
                fields["url"], fields["description"], fields["solution"],
                fields["source_tool"], fields["external_id"],
                fields["cve"], fields["cwe"], fields["plugin_id"], fields["owasp"],
                remediation_rule, 1 if auto_fixable else 0,
                record.fingerprint,
            ),
        )
        conn.commit()
        conn.close()
        return "updated"

    try:
        c.execute(
            """
            INSERT INTO vulnerabilities (
                vuln_name, severity, asset_ip, port, url, description, solution,
                source_tool, external_id, cve, cwe, plugin_id, owasp, fingerprint,
                fix_status, remediation_rule, auto_fixable
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                fields["vuln_name"], fields["severity"], fields["asset_ip"], fields["port"],
                fields["url"], fields["description"], fields["solution"],
                fields["source_tool"], fields["external_id"],
                fields["cve"], fields["cwe"], fields["plugin_id"], fields["owasp"],
                record.fingerprint,
                "auto_fixable" if auto_fixable else "manual_only",
                remediation_rule,
                1 if auto_fixable else 0,
            ),
        )
        conn.commit()
        conn.close()
        return "inserted"
    except sqlite3.IntegrityError:
        conn.close()
        return "skipped"


def update_fix_status(vuln_id: int, status: str, msg: str = "") -> None:
    init_database()
    conn = get_connection()
    c = conn.cursor()
    cols = _table_columns(c)
    if "updated_at" in cols:
        c.execute(
            "UPDATE vulnerabilities SET fix_status=?, last_fix_msg=?, updated_at=datetime('now') WHERE id=?",
            (status, msg[:500], vuln_id),
        )
    else:
        c.execute(
            "UPDATE vulnerabilities SET fix_status=?, last_fix_msg=? WHERE id=?",
            (status, msg[:500], vuln_id),
        )
    conn.commit()
    conn.close()


def get_vulnerability(vuln_id: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
    conn.close()
    return row
