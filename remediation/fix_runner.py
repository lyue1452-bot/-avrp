"""统一漏洞修复执行：创建任务、运行剧本、更新状态。"""
import logging
from typing import Dict, List, Optional, Tuple

from config import VERIFY_AFTER_FIX
from models import create_task, update_task_status, update_fix_status
from remediation.rules import REMEDIATION_RULES, RemediationRule
from remediation.executor import run_playbook, get_ansible_runtime
from remediation.fix_context import build_extra_vars
from remediation.verify import verify_fix

logger = logging.getLogger(__name__)


def _apply_fix_result(vuln_ids: List[int], task_id: int, ok: bool, output: str) -> None:
    status = "success" if ok else "failed"
    fix_status = "fixed" if ok else "failed"
    update_task_status(task_id, status, output)
    for vid in vuln_ids:
        update_fix_status(vid, fix_status, output)


def run_vuln_fix(
    row,
    rule: RemediationRule,
    created_by: str = "system",
    source: str = "manual",
    related_vuln_ids: Optional[List[int]] = None,
) -> Tuple[bool, int, str]:
    """
    执行单条漏洞修复。
    返回 (成功与否, task_id, 输出日志)。
    related_vuln_ids: 同规则批量修复时，一并更新状态的漏洞 ID 列表。
    """
    vuln_id = row["id"]
    vuln_ids = related_vuln_ids or [vuln_id]
    task_id = create_task(
        vuln_id, rule.rule_id, row["asset_ip"], row["url"] or "", created_by=created_by,
    )
    update_task_status(task_id, "running")
    for vid in vuln_ids:
        update_fix_status(vid, "fixing", "")

    extra = build_extra_vars(row)
    runtime = get_ansible_runtime()
    if runtime.get("mode") == "simulate":
        output = (
            "演示模式已禁用。请使用 .\\scripts\\start_real_ansible.ps1 启动后端，"
            "或设置 RAYSCAN_ANSIBLE_MODE=wsl、RAYSCAN_SIMULATE_ON_WINDOWS=0"
        )
        _apply_fix_result(vuln_ids, task_id, False, output)
        return False, task_id, output

    ok, output = run_playbook(rule, row["asset_ip"], extra_vars=extra)

    if runtime.get("mode") == "simulate":
        output = f"[{runtime['label']}] {output}"

    if ok and VERIFY_AFTER_FIX and runtime.get("mode") != "simulate":
        v_ok, v_msg = verify_fix(rule, row["url"] or "", row["asset_ip"])
        output += f"\n验证: {v_msg}"
        if not v_ok:
            _apply_fix_result(vuln_ids, task_id, False, output)
            return False, task_id, output

    _apply_fix_result(vuln_ids, task_id, ok, output)
    logger.info("修复 %s vuln#%s task#%s -> %s", source, vuln_id, task_id, "success" if ok else "failed")
    return ok, task_id, output


def retry_existing_task(task_row, vuln_row, rule: RemediationRule) -> Tuple[bool, str]:
    """重试已有任务（不新建任务记录）。"""
    task_id = task_row["id"]
    vuln_id = vuln_row["id"]
    update_task_status(task_id, "running")
    update_fix_status(vuln_id, "fixing", "")

    extra = build_extra_vars(vuln_row)
    runtime = get_ansible_runtime()
    if runtime.get("mode") == "simulate":
        output = "演示模式已禁用，请使用真实 Ansible 模式启动后端"
        update_task_status(task_id, "failed", output)
        update_fix_status(vuln_id, "failed", output)
        return False, output

    ok, output = run_playbook(rule, vuln_row["asset_ip"], extra_vars=extra)

    if ok and VERIFY_AFTER_FIX and runtime.get("mode") != "simulate":
        v_ok, v_msg = verify_fix(rule, vuln_row["url"] or "", vuln_row["asset_ip"])
        output += f"\n验证: {v_msg}"
        if not v_ok:
            update_task_status(task_id, "failed", output)
            update_fix_status(vuln_id, "failed", output)
            return False, output

    update_task_status(task_id, "success" if ok else "failed", output)
    update_fix_status(vuln_id, "fixed" if ok else "failed", output)
    return ok, output


def run_batch_fix_for_host(host: str, created_by: str = "scan") -> Dict:
    """对指定资产上所有可自动修复的漏洞批量执行修复（同规则合并为一次剧本）。"""
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

    # 同 remediation_rule 只执行一次剧本，避免重复重启 Apache 导致验证失败
    groups: Dict[str, list] = {}
    for row in rows:
        rule_id = row["remediation_rule"] or ""
        groups.setdefault(rule_id, []).append(row)

    stats = {"total": len(rows), "fixed": 0, "failed": 0, "skipped": 0, "task_ids": []}
    for rule_id, group in groups.items():
        rule = next((r for r in REMEDIATION_RULES if r.rule_id == rule_id), None)
        if not rule:
            stats["skipped"] += len(group)
            continue
        rep = group[0]
        related_ids = [r["id"] for r in group]
        ok, task_id, _ = run_vuln_fix(
            rep, rule, created_by=created_by, source="scan", related_vuln_ids=related_ids,
        )
        stats["task_ids"].append(task_id)
        if ok:
            stats["fixed"] += len(group)
        else:
            stats["failed"] += len(group)
    return stats
