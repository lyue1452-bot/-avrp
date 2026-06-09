"""任务管理接口。"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

from models import list_tasks, get_task, delete_task, update_task_status
from remediation.rules import REMEDIATION_RULES
from remediation.executor import run_playbook
from remediation.verify import verify_fix
from config import VERIFY_AFTER_FIX

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
    return jsonify({"ok": True, "data": dict(row)})


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

    update_task_status(task_id, "running")
    ok, output = run_playbook(rule, row["target_ip"])

    if ok and VERIFY_AFTER_FIX:
        v_ok, v_msg = verify_fix(rule, row["target_url"] or "", row["target_ip"])
        output += f"\n验证: {v_msg}"

    status = "success" if ok else "failed"
    update_task_status(task_id, status, output)
    return jsonify({"ok": ok, "msg": "重试完成", "task_id": task_id})
