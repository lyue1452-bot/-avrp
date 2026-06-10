"""漏洞库 CRUD 与修复接口。"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import (
    get_connection, get_vulnerability, update_fix_status,
    create_task, update_task_status,
)
from remediation.rules import REMEDIATION_RULES, match_remediation, classify_record
from remediation.executor import run_playbook, ansible_runtime_info
from remediation.verify import verify_fix
from remediation.fix_context import build_extra_vars, extra_vars_to_cli
from remediation.reclassify import reclassify_vulnerabilities, reclassify_row, row_to_record
from config import VERIFY_AFTER_FIX

vulns_bp = Blueprint("vulns", __name__, url_prefix="/vulns")


@vulns_bp.route("")
@jwt_required()
def list_vulns():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    search = request.args.get("search", "")
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")
    sort_by = request.args.get("sort_by", "id")
    sort_order = request.args.get("sort_order", "desc")

    allowed_sort = {"id", "severity", "asset_ip", "vuln_name", "created_at"}
    if sort_by not in allowed_sort:
        sort_by = "id"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    conn = get_connection()
    c = conn.cursor()

    where = "WHERE 1=1"
    params = []
    if search:
        where += " AND (vuln_name LIKE ? OR asset_ip LIKE ? OR description LIKE ? OR cve LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if severity:
        where += " AND severity = ?"
        params.append(severity)
    if status:
        where += " AND fix_status = ?"
        params.append(status)

    total = c.execute(f"SELECT COUNT(*) FROM vulnerabilities {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = c.execute(
        f"SELECT * FROM vulnerabilities {where} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()

    # 获取所有级别和状态用于筛选
    levels = [r[0] for r in c.execute(
        "SELECT DISTINCT severity FROM vulnerabilities ORDER BY severity"
    ).fetchall()]
    statuses = [r[0] for r in c.execute(
        "SELECT DISTINCT fix_status FROM vulnerabilities ORDER BY fix_status"
    ).fetchall()]

    conn.close()

    return jsonify({
        "ok": True,
        "data": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "filters": {"severity": levels, "fix_status": statuses},
    })


@vulns_bp.route("/<int:vuln_id>")
@jwt_required()
def vuln_detail(vuln_id):
    row = get_vulnerability(vuln_id)
    if not row:
        return jsonify({"ok": False, "msg": "漏洞不存在"}), 404
    return jsonify({"ok": True, "data": dict(row)})


@vulns_bp.route("/<int:vuln_id>", methods=["PUT"])
@jwt_required()
def vuln_update(vuln_id):
    row = get_vulnerability(vuln_id)
    if not row:
        return jsonify({"ok": False, "msg": "漏洞不存在"}), 404

    data = request.get_json() or {}
    allowed = {"vuln_name", "severity", "asset_ip", "port", "url", "description", "solution", "cve", "cwe", "fix_status"}
    sets = {k: v for k, v in data.items() if k in allowed}
    if not sets:
        return jsonify({"ok": False, "msg": "没有要更新的字段"}), 400

    conn = get_connection()
    c = conn.cursor()
    query = "UPDATE vulnerabilities SET " + ", ".join(f"{k}=?" for k in sets) + " WHERE id=?"
    c.execute(query, list(sets.values()) + [vuln_id])
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "msg": "已更新"})


@vulns_bp.route("/<int:vuln_id>", methods=["DELETE"])
@jwt_required()
def vuln_delete(vuln_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM vulnerabilities WHERE id=?", (vuln_id,))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    if not ok:
        return jsonify({"ok": False, "msg": "漏洞不存在"}), 404
    return jsonify({"ok": True, "msg": "已删除"})


@vulns_bp.route("/reclassify", methods=["POST"])
@jwt_required()
def reclassify():
    """重新匹配所有漏洞的修复规则（历史数据升级用）。"""
    data = request.get_json(silent=True) or {}
    asset_ip = (data.get("asset_ip") or "").strip() or None
    stats = reclassify_vulnerabilities(asset_ip=asset_ip)
    return jsonify({
        "ok": True,
        "msg": f"已重分类 {stats['updated']}/{stats['total']} 条，其中 {stats['auto_fixable']} 条可自动修复",
        "stats": stats,
    })


def _ensure_fixable(row):
    """若历史记录未标记可修复，尝试重新匹配规则并更新。"""
    rec = row_to_record(row)
    rule, auto = classify_record(rec)
    if not rule or not auto:
        return None
    if not row["auto_fixable"] or (row["remediation_rule"] or "") != rule.rule_id:
        conn = get_connection()
        reclassify_row(row, conn=conn)
        conn.commit()
        conn.close()
    return rule


@vulns_bp.route("/<int:vuln_id>/fix", methods=["POST"])
@jwt_required()
def fix_single(vuln_id):
    row = get_vulnerability(vuln_id)
    if not row:
        return jsonify({"ok": False, "msg": "漏洞不存在"}), 404

    rule = _ensure_fixable(row)
    if not rule:
        hint = match_remediation(row_to_record(row))
        hint_name = hint.name if hint else "无匹配规则"
        return jsonify({"ok": False, "msg": f"该漏洞需人工处理（{hint_name}）"})

    row = get_vulnerability(vuln_id)
    rule_id = row["remediation_rule"]
    rule = next((r for r in REMEDIATION_RULES if r.rule_id == rule_id), None) or rule

    uid = int(get_jwt_identity())
    task_id = create_task(vuln_id, rule.rule_id, row["asset_ip"], row["url"], created_by=str(uid))
    update_task_status(task_id, "running")
    update_fix_status(vuln_id, "fixing", "执行中...")

    extra = extra_vars_to_cli(build_extra_vars(row))
    ok, output = run_playbook(rule, row["asset_ip"], extra_vars=extra)

    runtime = ansible_runtime_info()
    if runtime.get("mode") == "simulate":
        output = f"[{runtime['label']}] {output}"

    if ok and VERIFY_AFTER_FIX and runtime.get("mode") != "simulate":
        v_ok, v_msg = verify_fix(rule, row["url"], row["asset_ip"])
        output += f"\n验证: {v_msg}"
        if not v_ok:
            update_task_status(task_id, "failed", output)
            update_fix_status(vuln_id, "failed", output)
            return jsonify({"ok": False, "msg": f"剧本已执行但验证未通过：{v_msg}", "task_id": task_id})

    status = "success" if ok else "failed"
    update_task_status(task_id, status, output)
    fix_st = "fixed" if ok else "failed"
    update_fix_status(vuln_id, fix_st, output)

    return jsonify({
        "ok": ok,
        "msg": f"修复{'成功' if ok else '失败'}: {row['vuln_name']}",
        "task_id": task_id,
    })


@vulns_bp.route("/batch-fix", methods=["POST"])
@jwt_required()
def batch_fix():
    data = request.get_json() or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"ok": False, "msg": "请选择要修复的漏洞"}), 400

    results = []
    for vid in ids:
        row = get_vulnerability(vid)
        if not row:
            results.append({"id": vid, "ok": False, "msg": "不存在"})
            continue

        rule = _ensure_fixable(row)
        if not rule:
            results.append({"id": vid, "ok": False, "msg": "不可自动修复"})
            continue

        row = get_vulnerability(vid)
        rule_id = row["remediation_rule"]
        rule = next((r for r in REMEDIATION_RULES if r.rule_id == rule_id), None) or rule

        uid = int(get_jwt_identity())
        task_id = create_task(vid, rule.rule_id, row["asset_ip"], row["url"], created_by=str(uid))
        update_task_status(task_id, "running")
        update_fix_status(vid, "fixing", "执行中...")

        extra = extra_vars_to_cli(build_extra_vars(row))
        ok, output = run_playbook(rule, row["asset_ip"], extra_vars=extra)
        status = "success" if ok else "failed"
        update_task_status(task_id, status, output)
        update_fix_status(vid, "fixed" if ok else "failed", output)
        results.append({"id": vid, "ok": ok, "task_id": task_id})

    return jsonify({"ok": True, "results": results})
