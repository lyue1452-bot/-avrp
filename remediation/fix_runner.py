"""统一漏洞修复执行：创建任务、运行剧本、更新状态。"""
import logging
from typing import Dict, Optional, Tuple

from config import VERIFY_AFTER_FIX
from models import create_task, update_task_status, update_fix_status
from remediation.rules import REMEDIATION_RULES, RemediationRule
from remediation.executor import run_playbook, get_ansible_runtime
from remediation.fix_context import build_extra_vars, extra_vars_to_cli
from remediation.verify import verify_fix

logger = logging.getLogger(__name__)


def run_vuln_fix(
    row,
    rule: RemediationRule,
    created_by: str = "system",
    source: str = "manual",
) -> Tuple[bool, int, str]:
    """
    执行单条漏洞修复。
    返回 (成功与否, task_id, 输出日志)。
    """
    vuln_id = row["id"]
    task_id = create_task(
        vuln_id, rule.rule_id, row["asset_ip"], row["url"] or "", created_by=created_by,
    )
    update_task_status(task_id, "running")
    update_fix_status(vuln_id, "fixing", f"任务 #{task_id} 执行中...")

    extra = extra_vars_to_cli(build_extra_vars(row))
    runtime = get_ansible_runtime()
    ok, output = run_playbook(rule, row["asset_ip"], extra_vars=extra)

    if runtime.get("mode") == "simulate":
        output = f"[{runtime['label']}] {output}"

    if ok and VERIFY_AFTER_FIX and runtime.get("mode") != "simulate":
        v_ok, v_msg = verify_fix(rule, row["url"] or "", row["asset_ip"])
        output += f"\n验证: {v_msg}"
        if not v_ok:
            update_task_status(task_id, "failed", output)
            update_fix_status(vuln_id, "failed", output)
            return False, task_id, output

    task_status = "success" if ok else "failed"
    update_task_status(task_id, task_status, output)
    update_fix_status(vuln_id, "fixed" if ok else "failed", output)
    logger.info("修复 %s vuln#%s task#%s -> %s", source, vuln_id, task_id, task_status)
    return ok, task_id, output


def run_batch_fix_for_host(host: str, created_by: str = "scan") -> Dict:
    """对指定资产上所有可自动修复的漏洞批量执行修复。"""
    from models import get_connection
    from remediation.reclassify import reclassify_vulnerabilities

    runtime = get_ansible_runtime()
    if not runtime.get("available"):
        return {
            "total": 0, "fixed": 0, "failed": 0, "skipped": 0,
            "msg": runtime.get("detail", "Ansible 不可用"),
        }

    reclassify_vulnerabilities(asset_ip=host)
    conn = get_connection()
    conn.execute(
        "UPDATE vulnerabilities SET fix_status='auto_fixable' "
        "WHERE asset_ip=? AND auto_fixable=1 AND fix_status IN ('failed','fixing')",
        (host,),
    )
    conn.commit()
    rows = conn.execute(
        "SELECT * FROM vulnerabilities "
        "WHERE asset_ip=? AND auto_fixable=1 AND fix_status IN ('auto_fixable','pending')",
        (host,),
    ).fetchall()
    conn.close()

    stats = {"total": len(rows), "fixed": 0, "failed": 0, "skipped": 0, "task_ids": []}
    for row in rows:
        rule = next((r for r in REMEDIATION_RULES if r.rule_id == row["remediation_rule"]), None)
        if not rule:
            stats["skipped"] += 1
            continue
        ok, task_id, _ = run_vuln_fix(row, rule, created_by=created_by, source="scan")
        stats["task_ids"].append(task_id)
        if ok:
            stats["fixed"] += 1
        else:
            stats["failed"] += 1
    return stats
