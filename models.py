"""SQLite 数据模型与漏洞入库。"""
import hashlib
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime
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


# ───────────────────────── 用户表 ─────────────────────────

USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    role TEXT DEFAULT 'user',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

TASKS_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id INTEGER REFERENCES vulnerabilities(id),
    rule_id TEXT,
    target_ip TEXT,
    target_url TEXT,
    status TEXT DEFAULT 'pending',
    started_at TEXT,
    finished_at TEXT,
    result_text TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

IMPORT_HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS import_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    source_tool TEXT,
    total INTEGER DEFAULT 0,
    inserted INTEGER DEFAULT 0,
    updated INTEGER DEFAULT 0,
    auto_fixable INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

SETTINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);
"""

PIPELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    status TEXT DEFAULT 'completed',
    target TEXT DEFAULT '',
    total INTEGER DEFAULT 0,
    inserted INTEGER DEFAULT 0,
    source_file TEXT DEFAULT '',
    details TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
"""

SCAN_JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    tools TEXT DEFAULT '[]',
    auto_fix INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    progress TEXT DEFAULT '{}',
    results TEXT DEFAULT '{}',
    summary TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    started_at TEXT,
    finished_at TEXT
);
"""


def init_all_tables():
    conn = get_connection()
    c = conn.cursor()
    c.executescript(SCHEMA_SQL)
    for s in [USERS_SCHEMA, TASKS_SCHEMA, IMPORT_HISTORY_SCHEMA, SETTINGS_SCHEMA, PIPELINE_SCHEMA, SCAN_JOBS_SCHEMA]:
        c.executescript(s)
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


# ── 用户 CRUD ──

def create_user(username: str, password_hash: str, display_name: str = "", role: str = "user") -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, password_hash, display_name, role) VALUES (?,?,?,?)",
        (username, password_hash, display_name, role),
    )
    conn.commit()
    uid = c.lastrowid
    conn.close()
    return uid


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_id(uid: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    row = conn.execute("SELECT id, username, display_name, role, is_active, created_at FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def list_users() -> list:
    conn = get_connection()
    rows = conn.execute("SELECT id, username, display_name, role, is_active, created_at FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user(uid: int, **kwargs) -> bool:
    allowed = {"display_name", "role", "is_active", "password_hash"}
    sets = {k: v for k, v in kwargs.items() if k in allowed}
    if not sets:
        return False
    conn = get_connection()
    c = conn.cursor()
    query = "UPDATE users SET " + ", ".join(f"{k}=?" for k in sets) + " WHERE id=?"
    c.execute(query, list(sets.values()) + [uid])
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


def delete_user(uid: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


def count_users() -> int:
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    conn.close()
    return row[0]


# ── 任务 CRUD ──

def create_task(vuln_id: int, rule_id: str, target_ip: str, target_url: str, created_by: str = "") -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """INSERT INTO tasks (vuln_id, rule_id, target_ip, target_url, status, created_by)
           VALUES (?,?,?,?,?,?)""",
        (vuln_id, rule_id, target_ip, target_url, "pending", created_by),
    )
    conn.commit()
    tid = c.lastrowid
    conn.close()
    return tid


def update_task_status(task_id: int, status: str, result_text: str = "") -> None:
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if status in ("running",):
        c.execute("UPDATE tasks SET status=?, started_at=? WHERE id=?", (status, now, task_id))
    elif status in ("success", "failed"):
        c.execute("UPDATE tasks SET status=?, finished_at=?, result_text=? WHERE id=?", (status, now, result_text, task_id))
    else:
        c.execute("UPDATE tasks SET status=? WHERE id=?", (status, task_id))
    conn.commit()
    conn.close()


def get_task(task_id: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    conn.close()
    return row


def list_tasks(page: int = 1, per_page: int = 20, status: str = "") -> tuple:
    """返回 (rows, total)"""
    conn = get_connection()
    c = conn.cursor()
    where = "WHERE 1=1"
    params = []
    if status:
        where += " AND status = ?"
        params.append(status)
    total = c.execute(f"SELECT COUNT(*) FROM tasks {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = c.execute(
        f"SELECT * FROM tasks {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def delete_task(task_id: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


# ── 导入历史 CRUD ──

def add_import_history(filename: str, source_tool: str, total: int, inserted: int, updated: int, auto_fixable: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO import_history (filename, source_tool, total, inserted, updated, auto_fixable) VALUES (?,?,?,?,?,?)",
        (filename, source_tool, total, inserted, updated, auto_fixable),
    )
    conn.commit()
    conn.close()


def list_import_history(page: int = 1, per_page: int = 20) -> tuple:
    conn = get_connection()
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM import_history").fetchone()[0]
    offset = (page - 1) * per_page
    rows = c.execute(
        "SELECT * FROM import_history ORDER BY id DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def delete_import_history(hid: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM import_history WHERE id=?", (hid,))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


# ── 系统设置 CRUD ──

def get_setting(key: str, default: str = "") -> str:
    conn = get_connection()
    row = conn.execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def set_setting(key: str, value: str) -> None:
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?,?)", (key, value))
    conn.commit()
    conn.close()


def get_all_settings() -> dict:
    conn = get_connection()
    rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}


# ── 流水线运行记录 CRUD ──

def add_pipeline_run(tool: str, status: str = "completed", target: str = "",
                     total: int = 0, inserted: int = 0,
                     source_file: str = "", details: str = "") -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """INSERT INTO pipeline_runs (tool, status, target, total, inserted, source_file, details)
           VALUES (?,?,?,?,?,?,?)""",
        (tool, status, target, total, inserted, source_file, details[:500]),
    )
    conn.commit()
    rid = c.lastrowid
    conn.close()
    return rid


def list_pipeline_runs(page: int = 1, per_page: int = 20, tool: str = "") -> tuple:
    conn = get_connection()
    c = conn.cursor()
    where = "WHERE 1=1"
    params = []
    if tool:
        where += " AND tool = ?"
        params.append(tool)
    total = c.execute(f"SELECT COUNT(*) FROM pipeline_runs {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = c.execute(
        f"SELECT * FROM pipeline_runs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def get_pipeline_run(run_id: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM pipeline_runs WHERE id=?", (run_id,)).fetchone()
    conn.close()
    return row


def delete_pipeline_run(run_id: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM pipeline_runs WHERE id=?", (run_id,))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


# ── 扫描任务 CRUD ──

import json

def create_scan_job(target: str, tools: list, auto_fix: bool = False, created_by: str = "") -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """INSERT INTO scan_jobs (target, tools, auto_fix, status, progress, results, created_by)
           VALUES (?,?,?,?,?,?,?)""",
        (target, json.dumps(tools, ensure_ascii=False), 1 if auto_fix else 0,
         "pending", "{}", "{}", created_by),
    )
    conn.commit()
    sid = c.lastrowid
    conn.close()
    return sid


def update_scan_job(job_id: int, **kwargs) -> bool:
    allowed = {"status", "progress", "results", "summary", "started_at", "finished_at"}
    sets = {k: v for k, v in kwargs.items() if k in allowed}
    if not sets:
        return False
    conn = get_connection()
    c = conn.cursor()
    # JSON fields need serialization
    params = []
    set_clauses = []
    for k, v in sets.items():
        if k in ("progress", "results"):
            set_clauses.append(f"{k}=?")
            params.append(json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else v)
        else:
            set_clauses.append(f"{k}=?")
            params.append(v)
    query = "UPDATE scan_jobs SET " + ", ".join(set_clauses) + " WHERE id=?"
    params.append(job_id)
    c.execute(query, params)
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


def get_scan_job(job_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["tools"] = json.loads(d.get("tools", "[]"))
        d["progress"] = json.loads(d.get("progress", "{}"))
        d["results"] = json.loads(d.get("results", "{}"))
        return d
    return None


def list_scan_jobs(page: int = 1, per_page: int = 20) -> tuple:
    conn = get_connection()
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]
    offset = (page - 1) * per_page
    rows = c.execute(
        "SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["tools"] = json.loads(d.get("tools", "[]"))
        d["progress"] = json.loads(d.get("progress", "{}"))
        d["results"] = json.loads(d.get("results", "{}"))
        result.append(d)
    return result, total


def delete_scan_job(job_id: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scan_jobs WHERE id=?", (job_id,))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok
