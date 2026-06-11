"""任务管理接口。"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

from models import list_tasks, get_task, delete_task, get_vulnerability
from remediation.rules import REMEDIATION_RULES
from remediation.fix_runner import run_vuln_fix, retry_existing_task

tasks_bp = Blueprint("tasks", __name__, url_prefix="/tasks")


@tasks_bp.route("")
@jwt_required()
def task_list():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    status = request.args.get("status", "")
    rows, total = list_tasks(page=page, per_page=per_page, status=status)
    return jsonify({"ok": True, "data": rows, "total": total, "page": page, "per_page": per_page})


@tasks_bp.route("/<int:task_id>")
@jwt_required()
def task_detail(task_id):
    row = get_task(task_id)
    if not row:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    data = dict(row)
    vuln = get_vulnerability(row["vuln_id"]) if row["vuln_id"] else None
    if vuln:
        data["vuln_name"] = vuln["vuln_name"]
        data["severity"] = vuln["severity"]
    return jsonify({"ok": True, "data": data})


@tasks_bp.route("/<int:task_id>", methods=["DELETE"])
@jwt_required()
def task_delete(task_id):
    ok = delete_task(task_id)
    if not ok:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    return jsonify({"ok": True, "msg": "已删除"})


@tasks_bp.route("/<int:task_id>/retry", methods=["POST"])
@jwt_required()
def task_retry(task_id):
    row = get_task(task_id)
    if not row:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404

    rule = next((r for r in REMEDIATION_RULES if r.rule_id == row["rule_id"]), None)
    if not rule:
        return jsonify({"ok": False, "msg": "修复规则已不存在"}), 400

    vuln = get_vulnerability(row["vuln_id"])
    if not vuln:
        return jsonify({"ok": False, "msg": "关联漏洞不存在"}), 404

    ok, output = retry_existing_task(row, vuln, rule)
    return jsonify({"ok": ok, "msg": "重试完成" if ok else "重试失败", "task_id": task_id, "output": output[:500]})
