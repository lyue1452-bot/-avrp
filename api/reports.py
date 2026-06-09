"""报告管理接口。"""
import csv
import io
import json
from pathlib import Path

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required

from config import PROJECT_ROOT
from models import (
    init_all_tables, get_connection, list_import_history,
    add_import_history, delete_import_history,
)
from import_report import import_file

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/import", methods=["POST"])
@jwt_required()
def import_upload():
    f = request.files.get("report")
    if not f or not f.filename:
        return jsonify({"ok": False, "msg": "请选择报告文件"})

    upload_dir = PROJECT_ROOT / "uploads"
    upload_dir.mkdir(exist_ok=True)
    save_path = upload_dir / f.filename
    f.save(save_path)

    mapping_path = None
    mf = request.files.get("mapping")
    if mf and mf.filename:
        mapping_path = upload_dir / mf.filename
        mf.save(mapping_path)

    from import_report import import_file
    init_all_tables()
    stats = import_file(save_path, mapping_path=mapping_path)

    # 记录导入历史
    tool = stats.get("source_tool", "generic")
    add_import_history(
        filename=f.filename,
        source_tool=tool,
        total=stats["total"],
        inserted=stats.get("inserted", 0),
        updated=stats.get("updated", 0),
        auto_fixable=stats["auto_fixable"],
    )

    extra = f"，映射文件 {mf.filename}" if mf and mf.filename else ""
    return jsonify({
        "ok": True,
        "msg": f"导入完成{extra}：解析 {stats['total']} 条，新增 {stats.get('inserted', 0)}，可自动修复 {stats['auto_fixable']} 条",
        "stats": stats,
    })


@reports_bp.route("/history")
@jwt_required()
def import_history():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    rows, total = list_import_history(page=page, per_page=per_page)
    return jsonify({"ok": True, "data": rows, "total": total, "page": page, "per_page": per_page})


@reports_bp.route("/history/<int:hid>", methods=["DELETE"])
@jwt_required()
def history_delete(hid):
    ok = delete_import_history(hid)
    if not ok:
        return jsonify({"ok": False, "msg": "记录不存在"}), 404
    return jsonify({"ok": True, "msg": "已删除"})


@reports_bp.route("/export")
@jwt_required()
def export_report():
    fmt = request.args.get("format", "json")
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")

    conn = get_connection()
    c = conn.cursor()
    query = "SELECT * FROM vulnerabilities WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND fix_status = ?"
        params.append(status)
    query += " ORDER BY id DESC"
    rows = c.execute(query, params).fetchall()
    conn.close()

    data = [dict(r) for r in rows]

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        if data:
            writer.writerow(data[0].keys())
            for row in data:
                writer.writerow(row.values())
        mem = io.BytesIO(output.getvalue().encode("utf-8-sig"))
        return send_file(
            mem,
            mimetype="text/csv",
            as_attachment=True,
            download_name="rayscan_export.csv",
        )

    # 默认 JSON 格式
    mem = io.BytesIO(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
    return send_file(
        mem,
        mimetype="application/json",
        as_attachment=True,
        download_name="rayscan_export.json",
    )
