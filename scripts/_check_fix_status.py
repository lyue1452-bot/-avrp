import sqlite3
from config import DB_PATH

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print("=== 漏洞修复状态汇总 ===")
for row in cur.execute(
    "SELECT fix_status, COUNT(*) c FROM vulnerabilities GROUP BY fix_status ORDER BY c DESC"
):
    print(f"  {row['fix_status']}: {row['c']}")

print("\n=== 可自动修复漏洞明细 ===")
for row in cur.execute(
    """
    SELECT id, vuln_name, severity, fix_status, auto_fixable, remediation_rule,
           substr(last_fix_msg, 1, 100) AS msg
    FROM vulnerabilities WHERE auto_fixable = 1 ORDER BY id
    """
):
    print(dict(row))

print("\n=== 最近任务 ===")
for row in cur.execute(
    "SELECT id, vuln_id, status, substr(COALESCE(log, ''), 1, 120) AS log FROM tasks ORDER BY id DESC LIMIT 10"
):
    print(dict(row))

print("\n=== 192.168.101.36 漏洞 ===")
for row in cur.execute(
    """
    SELECT id, vuln_name, fix_status, substr(last_fix_msg, 1, 120) AS msg
    FROM vulnerabilities WHERE asset_ip = '192.168.101.36' ORDER BY id
    """
):
    print(dict(row))

conn.close()
