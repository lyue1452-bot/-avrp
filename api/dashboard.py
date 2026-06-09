"""Dashboard 统计接口。"""
from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from models import get_connection

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


def _query_json(sql: str, params=None):
    conn = get_connection()
    rows = conn.execute(sql, params or []).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _scalar(sql: str, params=None):
    conn = get_connection()
    row = conn.execute(sql, params or []).fetchone()
    conn.close()
    return row[0] if row else 0


@dashboard_bp.route("/stats")
@jwt_required()
def stats():
    total = _scalar("SELECT COUNT(*) FROM vulnerabilities")
    critical = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('严重','Critical','High','高危')")
    high = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('高','High','高危')")
    medium = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('中','Medium','中危')")
    low = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('低','Low','低危','Info')")
    fixed = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE fix_status='fixed'")
    auto_fixable = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE auto_fixable=1")
    pending = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE fix_status='pending'")
    fixing = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE fix_status='fixing'")
    failed = _scalar("SELECT COUNT(*) FROM vulnerabilities WHERE fix_status='failed'")

    # 严重级别占比
    severity_dist = [
        {"name": "严重/Critical", "value": critical},
        {"name": "高危/High", "value": high},
        {"name": "中危/Medium", "value": medium},
        {"name": "低危/Low", "value": low},
    ]
    severity_dist = [s for s in severity_dist if s["value"] > 0]

    # 修复状态分布
    status_dist = [
        {"name": "待修复", "value": pending + fixing},
        {"name": "已修复", "value": fixed},
        {"name": "修复失败", "value": failed},
        {"name": "可自动修复", "value": auto_fixable},
    ]

    return jsonify({
        "ok": True,
        "data": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "fixed": fixed,
            "auto_fixable": auto_fixable,
            "failed": failed,
            "fix_rate": round(fixed / total * 100, 1) if total > 0 else 0,
            "severity_distribution": severity_dist,
            "status_distribution": status_dist,
        },
    })


@dashboard_bp.route("/top-assets")
@jwt_required()
def top_assets():
    rows = _query_json(
        "SELECT asset_ip, COUNT(*) as cnt FROM vulnerabilities GROUP BY asset_ip ORDER BY cnt DESC LIMIT 10"
    )
    return jsonify({"ok": True, "data": rows})


@dashboard_bp.route("/trend")
@jwt_required()
def trend():
    """近 30 天每日新增漏洞数"""
    data = []
    today = datetime.now()
    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        date_str = day.strftime("%Y-%m-%d")
        cnt = _scalar(
            "SELECT COUNT(*) FROM vulnerabilities WHERE date(created_at) = ?",
            (date_str,),
        )
        data.append({"date": date_str, "count": cnt})
    return jsonify({"ok": True, "data": data})
