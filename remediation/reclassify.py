"""重新匹配漏洞修复规则并更新 auto_fixable 标记。"""
from typing import Dict, Optional

from models import VulnerabilityRecord, get_connection


def row_to_record(row) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        vuln_name=row["vuln_name"] or "",
        severity=row["severity"] or "",
        asset_ip=row["asset_ip"] or "",
        port=int(row["port"] or 0),
        url=row["url"] or "",
        description=row["description"] or "",
        solution=row["solution"] or "",
        source_tool=row["source_tool"] or "",
        plugin_id=row["plugin_id"] or "",
        cve=row["cve"] or "",
        cwe=row["cwe"] or "",
        owasp=row["owasp"] or "",
    )


def reclassify_row(row, conn=None) -> bool:
    """对单条漏洞重分类，返回是否有变更。"""
    from remediation.rules import classify_record

    rec = row_to_record(row)
    rule, auto = classify_record(rec)
    rule_id = rule.rule_id if rule else ""
    auto_i = 1 if auto else 0
    old_rule = row["remediation_rule"] or ""
    old_auto = int(row["auto_fixable"] or 0)
    if rule_id == old_rule and auto_i == old_auto:
        return False

    fix_status = row["fix_status"] or "pending"
    if fix_status == "fixed":
        pass  # 已修复不因重分类降级
    elif auto and fix_status in ("manual_only", "pending"):
        fix_status = "auto_fixable"
    elif not auto and fix_status == "auto_fixable":
        fix_status = "manual_only"

    own_conn = conn is None
    if own_conn:
        conn = get_connection()
    conn.execute(
        "UPDATE vulnerabilities SET remediation_rule=?, auto_fixable=?, fix_status=? WHERE id=?",
        (rule_id, auto_i, fix_status, row["id"]),
    )
    if own_conn:
        conn.commit()
        conn.close()
    return True


def reclassify_vulnerabilities(asset_ip: Optional[str] = None) -> Dict:
    """批量重分类，可选限定资产 IP。"""
    conn = get_connection()
    if asset_ip:
        rows = conn.execute(
            "SELECT * FROM vulnerabilities WHERE asset_ip=? ORDER BY id",
            (asset_ip,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY id").fetchall()

    updated = 0
    auto_count = 0
    for row in rows:
        if reclassify_row(row, conn=conn):
            updated += 1
        row2 = conn.execute("SELECT auto_fixable FROM vulnerabilities WHERE id=?", (row["id"],)).fetchone()
        if row2 and row2["auto_fixable"]:
            auto_count += 1
    conn.commit()
    conn.close()
    return {"total": len(rows), "updated": updated, "auto_fixable": auto_count}
