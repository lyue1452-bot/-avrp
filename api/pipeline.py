"""Pipeline 集成 — CI 报告接收 + 流水线运行历史 + 统一扫描触发。"""
import json
import tempfile
from pathlib import Path

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from adapters import parse_report
from models import (
    init_all_tables, upsert_vulnerability, add_import_history,
    add_pipeline_run, list_pipeline_runs, get_pipeline_run, delete_pipeline_run,
    list_scan_jobs, delete_scan_job,
)
from remediation.fix_status import enrich_vuln
from remediation.rules import classify_record
from scanner.orchestrator import (
    start_scan, get_scan_status, cancel_scan,
    ALL_TOOLS, TOOL_LABELS, SCANNER_RUNNERS,
)
from scanner.target_utils import tool_status, tool_available, parse_scan_target
from scanner.tool_installer import install_tool, install_missing_tools, tool_detail, INSTALLABLE
from models import get_connection

pipeline_bp = Blueprint("pipeline", __name__, url_prefix="/pipeline")


@pipeline_bp.route("/health")
def health():
    return jsonify({"ok": True, "status": "running", "tool": "rayscan"})


@pipeline_bp.route("/ingest", methods=["POST"])
@jwt_required()
def ingest():
    """接收 CI 工具生成的 JSON 报告内容，解析后写入漏洞数据库。"""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"ok": False, "msg": "请求体不是有效的 JSON"}), 400

    tool = data.get("tool", data.get("source_tool", "pipeline"))
    target = data.get("target", "")
    report_data = data.get("report", data)
    format = data.get("format", "auto")

    # 将报告写入临时文件，通过已有适配器解析
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        if isinstance(report_data, str):
            f.write(report_data)
        else:
            json.dump(report_data, f, ensure_ascii=False)
        tmp = f.name

    try:
        records, detected_tool = parse_report(Path(tmp))
        if not records:
            # 尝试直接用 JSON 兜底
            from adapters.generic_json import GenericJsonAdapter
            records = GenericJsonAdapter().parse(Path(tmp))
            detected_tool = "generic_json"
    except Exception as e:
        import os
        os.unlink(tmp)
        return jsonify({"ok": False, "msg": f"解析报告失败: {e}"}), 400

    import os
    os.unlink(tmp)

    source_tool = tool if tool != "pipeline" else detected_tool
    stats = {"total": len(records), "inserted": 0, "updated": 0, "auto_fixable": 0}

    for rec in records:
        if not rec.source_tool or rec.source_tool in ("unknown", "generic"):
            rec.source_tool = source_tool
        rule, auto = classify_record(rec)
        rule_id = rule.rule_id if rule else ""
        if auto:
            stats["auto_fixable"] += 1
        result = upsert_vulnerability(rec, remediation_rule=rule_id, auto_fixable=auto)
        stats[result] = stats.get(result, 0) + 1

    # 记录导入历史
    add_import_history(
        filename=f"pipeline:{source_tool}",
        source_tool=source_tool,
        total=stats["total"],
        inserted=stats.get("inserted", 0),
        updated=stats.get("updated", 0),
        auto_fixable=stats["auto_fixable"],
    )

    # 记录流水线运行
    run_id = add_pipeline_run(
        tool=source_tool,
        status="completed",
        target=target,
        total=stats["total"],
        inserted=stats.get("inserted", 0),
        source_file=f"pipeline:{source_tool}",
        details=f"解析 {stats['total']} 条，新增 {stats.get('inserted',0)}，自动修复 {stats['auto_fixable']}",
    )

    return jsonify({
        "ok": True,
        "run_id": run_id,
        "msg": f"流水线 {source_tool} 完成：解析 {stats['total']} 条，新增 {stats.get('inserted', 0)}，可自动修复 {stats['auto_fixable']} 条",
        "stats": stats,
    })


@pipeline_bp.route("/runs")
@jwt_required()
def run_list():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    tool = request.args.get("tool", "")
    rows, total = list_pipeline_runs(page=page, per_page=per_page, tool=tool)
    return jsonify({"ok": True, "data": rows, "total": total, "page": page, "per_page": per_page})


@pipeline_bp.route("/runs/<int:run_id>")
@jwt_required()
def run_detail(run_id):
    row = get_pipeline_run(run_id)
    if not row:
        return jsonify({"ok": False, "msg": "记录不存在"}), 404
    return jsonify({"ok": True, "data": dict(row)})


@pipeline_bp.route("/runs/<int:run_id>", methods=["DELETE"])
@jwt_required()
def run_delete(run_id):
    ok = delete_pipeline_run(run_id)
    if not ok:
        return jsonify({"ok": False, "msg": "记录不存在"}), 404
    return jsonify({"ok": True, "msg": "已删除"})


# ────────────── 统一扫描触发 ──────────────


@pipeline_bp.route("/tools")
@jwt_required()
def list_tools():
    """返回可用的扫描器列表及安装状态。"""
    status_map = tool_status()
    available = []
    for key in ALL_TOOLS:
        info = status_map.get(key, {})
        detail = tool_detail(key) if key in INSTALLABLE else {}
        available.append({
            "id": key,
            "name": TOOL_LABELS.get(key, key),
            "installed": info.get("installed", tool_available(key)),
            "note": info.get("note", ""),
            "path": detail.get("path", ""),
            "auto_installable": detail.get("auto_installable", False),
            "manual": detail.get("manual", ""),
        })
    return jsonify({"ok": True, "data": available})


@pipeline_bp.route("/ansible/status")
@jwt_required()
def ansible_status():
    """Ansible 运行时状态（供设置页展示）。"""
    from remediation.executor import get_ansible_runtime
    from config import ANSIBLE_USER, ANSIBLE_MODE, TARGET_OS
    from remediation.target_os import detect_target_os
    info = get_ansible_runtime()
    sample_ip = request.args.get("asset_ip", "192.168.101.36")
    return jsonify({
        "ok": True,
        "data": {
            **info,
            "ansible_user": ANSIBLE_USER,
            "ansible_mode_env": ANSIBLE_MODE,
            "target_os_env": TARGET_OS,
            "detected_os": detect_target_os(sample_ip),
            "setup_hint": "以管理员运行 scripts/setup_ssh_for_ansible.ps1 配置 SSH 免密",
        },
    })


@pipeline_bp.route("/tools/install", methods=["POST"])
@jwt_required()
def install_tools():
    """自动安装缺失的扫描工具（Windows 使用 winget）。"""
    data = request.get_json(silent=True) or {}
    tool_id = (data.get("tool") or "").strip()
    if tool_id:
        result = install_tool(tool_id)
        return jsonify({"ok": result.get("ok", False), **result})
    batch = install_missing_tools(data.get("tools"))
    ok = batch["all_installed"] or any(r.get("ok") for r in batch["results"])
    return jsonify({
        "ok": ok,
        "msg": "工具安装完成" if batch["all_installed"] else "部分工具需手动安装或重启后端",
        **batch,
    })


@pipeline_bp.route("/scan", methods=["POST"])
@jwt_required()
def trigger_scan():
    """发起统一扫描。"""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "msg": "请指定扫描目标（IP/URL/镜像名）"}), 400

    tools = data.get("tools", [])
    auto_fix = data.get("auto_fix", False)

    user = get_jwt_identity()
    username = user.get("username", "") if isinstance(user, dict) else str(user)

    try:
        job_id = start_scan(target, tools=tools, auto_fix=auto_fix, created_by=username)
        return jsonify({"ok": True, "job_id": job_id, "status": "pending"})
    except Exception as e:
        return jsonify({"ok": False, "msg": f"创建扫描任务失败: {str(e)}"}), 500


@pipeline_bp.route("/scan/<int:job_id>")
@jwt_required()
def scan_status(job_id):
    """查询扫描任务状态。"""
    job = get_scan_status(job_id)
    if not job:
        return jsonify({"ok": False, "msg": "扫描任务不存在"}), 404
    return jsonify({"ok": True, "data": job})


@pipeline_bp.route("/scan/<int:job_id>/cancel")
@jwt_required()
def scan_cancel(job_id):
    """取消扫描任务。"""
    ok = cancel_scan(job_id)
    if not ok:
        return jsonify({"ok": False, "msg": "取消失败：任务不存在或状态不允许"}), 400
    return jsonify({"ok": True, "msg": "已取消"})


@pipeline_bp.route("/scan-jobs")
@jwt_required()
def scan_job_list():
    """扫描历史列表。"""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    rows, total = list_scan_jobs(page=page, per_page=per_page)
    return jsonify({"ok": True, "data": rows, "total": total, "page": page, "per_page": per_page})


@pipeline_bp.route("/scan-jobs/<int:job_id>", methods=["DELETE"])
@jwt_required()
def scan_job_delete(job_id):
    ok = delete_scan_job(job_id)
    if not ok:
        return jsonify({"ok": False, "msg": "记录不存在"}), 404
    return jsonify({"ok": True, "msg": "已删除"})


@pipeline_bp.route("/scan-jobs/<int:job_id>/vulns")
@jwt_required()
def scan_job_vulns(job_id):
    """扫描任务关联漏洞（按目标 IP，展示当前库内状态）。"""
    job = get_scan_status(job_id)
    if not job:
        return jsonify({"ok": False, "msg": "扫描任务不存在"}), 404
    host, _, _, _ = parse_scan_target(job["target"])
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, vuln_name, severity, asset_ip, port, fix_status, auto_fixable, remediation_rule, source_tool "
        "FROM vulnerabilities WHERE asset_ip=? ORDER BY id DESC LIMIT 100",
        (host,),
    ).fetchall()
    summary = conn.execute(
        """
        SELECT
          SUM(CASE WHEN fix_status='fixed' THEN 1 ELSE 0 END) AS fixed_cnt,
          SUM(CASE WHEN fix_status IN ('auto_fixable','pending','failed','fixing') AND auto_fixable=1 THEN 1 ELSE 0 END) AS needs_fix_cnt
        FROM vulnerabilities WHERE asset_ip=?
        """,
        (host,),
    ).fetchone()
    conn.close()
    data = [enrich_vuln(dict(r)) for r in rows]
    return jsonify({
        "ok": True,
        "data": data,
        "asset_ip": host,
        "summary": {
            "fixed": int(summary["fixed_cnt"] or 0),
            "needs_fix": int(summary["needs_fix_cnt"] or 0),
        },
    })