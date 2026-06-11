"""自动化漏洞管理与修复平台 — REST API + Vue 3 前端入口。"""
import json
from pathlib import Path

from flask import Flask, render_template_string, request, jsonify, send_from_directory
from werkzeug.exceptions import HTTPException
from flask_jwt_extended import JWTManager
from flask_cors import CORS

from config import PROJECT_ROOT, JWT_SECRET, API_PORT, API_HOST
from models import (
    get_connection, get_vulnerability, update_fix_status, init_all_tables,
)
from remediation.rules import REMEDIATION_RULES, match_remediation
from remediation.executor import run_playbook, ansible_runtime_info
from remediation.fix_status import status_label
from config import VERIFY_AFTER_FIX


def create_app():
    # 确保数据库表已创建
    init_all_tables()

    app = Flask(__name__, static_folder="frontend/dist", static_url_path="/")
    app.config["JWT_SECRET_KEY"] = JWT_SECRET
    app.config["JWT_TOKEN_LOCATION"] = ["headers"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False  # 由 token 自身控制

    CORS(app, resources={r"/api/*": {"origins": "*"}})
    jwt = JWTManager(app)

    @jwt.expired_token_loader
    def _expired(jwt_header, jwt_payload):
        return jsonify({"ok": False, "msg": "登录已过期，请重新登录"}), 401

    @jwt.invalid_token_loader
    def _invalid(error):
        return jsonify({"ok": False, "msg": "无效的登录凭证"}), 401

    @jwt.unauthorized_loader
    def _missing(error):
        return jsonify({"ok": False, "msg": "请先登录"}), 401

    @app.errorhandler(HTTPException)
    def _handle_http(err):
        return jsonify({"ok": False, "msg": err.description}), err.code

    @app.errorhandler(Exception)
    def _handle_error(err):
        if app.debug:
            import traceback
            traceback.print_exc()
        return jsonify({"ok": False, "msg": str(err)}), 500

    @app.route("/api/health")
    def api_health():
        return jsonify({"ok": True, "service": "rayscan-api", "port": API_PORT})

    # 注册 API Blueprint
    from api import api_bp
    app.register_blueprint(api_bp)

    # ────────────── 旧版路由兼容（单页 HTML + 导入/修复 API） ──────────────

    @app.route("/")
    def index():
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

        vulns = c.execute(query, params).fetchall()
        levels = [r[0] for r in c.execute(
            "SELECT DISTINCT severity FROM vulnerabilities ORDER BY severity"
        ).fetchall()]
        statuses = [r[0] for r in c.execute(
            "SELECT DISTINCT fix_status FROM vulnerabilities ORDER BY fix_status"
        ).fetchall()]
        stats = c.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN auto_fixable=1 THEN 1 ELSE 0 END) as auto_cnt,
                SUM(CASE WHEN fix_status='fixed' THEN 1 ELSE 0 END) as fixed_cnt
            FROM vulnerabilities
        """).fetchone()
        conn.close()

        html = _OLD_HTML_TEMPLATE
        vuln_list = [dict(row) for row in vulns]
        return render_template_string(
            html,
            vulns=vulns,
            vuln_json=json.dumps(vuln_list, ensure_ascii=False),
            levels=levels,
            statuses=statuses,
            stats=stats,
            cur_severity=severity,
            cur_status=status,
            ansible_info=ansible_runtime_info(),
            status_label=status_label,
        )

    @app.route("/import", methods=["POST"])
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
        extra = f"，映射文件 {mf.filename}" if mf and mf.filename else ""
        return jsonify({
            "ok": True,
            "msg": f"导入完成{extra}：解析 {stats['total']} 条，新增 {stats.get('inserted',0)}，可自动修复 {stats['auto_fixable']} 条",
        })

    @app.route("/fix", methods=["POST"])
    def fix_vuln():
        data = request.get_json() or {}
        vuln_id = data.get("id")
        row = get_vulnerability(vuln_id)
        if not row:
            return jsonify({"ok": False, "msg": "漏洞不存在"}), 404

        if not row["auto_fixable"]:
            rule = match_remediation(row)
            hint = rule.name if rule else "无匹配规则"
            return jsonify({"ok": False, "msg": f"该漏洞需人工处理（{hint}）"})

        rule_id = row["remediation_rule"]
        rule = next((r for r in REMEDIATION_RULES if r.rule_id == rule_id), None)
        if not rule:
            rule = match_remediation(row)
        if not rule:
            return jsonify({"ok": False, "msg": "未找到修复规则"})

        update_fix_status(vuln_id, "fixing", "执行中...")
        ok, output = run_playbook(rule, row["asset_ip"])

        if ok and VERIFY_AFTER_FIX:
            v_ok, v_msg = verify_fix(rule, row["url"], row["asset_ip"])
            output += f"\n验证: {v_msg}"
            if not v_ok:
                update_fix_status(vuln_id, "failed", output)
                return jsonify({"ok": False, "msg": f"剧本已执行但验证未通过：{v_msg}\n{output[-300:]}"})

        status = "fixed" if ok else "failed"
        update_fix_status(vuln_id, status, output)
        return jsonify({
            "ok": ok,
            "msg": (f"修复成功：{row['vuln_name']}" if ok else f"修复失败：{output[-400:]}"),
        })

    @app.route("/rules")
    def list_rules():
        return jsonify([
            {"id": r.rule_id, "name": r.name, "playbook": r.playbook, "manual": r.manual_only}
            for r in REMEDIATION_RULES
        ])

    return app


# ────────────── 旧版单页 HTML 模板 ──────────────

_OLD_HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>自动化漏洞管理与修复平台</title>
    <style>
        body{font-family:Segoe UI,Arial;margin:24px;background:#f0f2f5}
        .box{background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:16px}
        h1{font-size:20px;margin:0 0 8px}
        .meta{color:#666;font-size:13px;margin-bottom:12px}
        .filter a{display:inline-block;padding:5px 10px;margin:2px;background:#0d6efd;color:#fff;
            border-radius:4px;text-decoration:none;font-size:13px}
        .filter a.dim{background:#6c757d}
        .filter a.on{background:#198754}
        table{width:100%;border-collapse:collapse;font-size:13px}
        th,td{padding:8px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}
        th{background:#f8f9fa}
        .tag{font-size:11px;padding:2px 6px;border-radius:3px;background:#e9ecef}
        .tag.ok{background:#d1e7dd;color:#0f5132}
        .tag.warn{background:#fff3cd;color:#664d03}
        .tag.err{background:#f8d7da;color:#842029}
        button{border:none;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px;margin-right:4px}
        .btn-info{background:#0dcaf0;color:#000}
        .btn-fix{background:#dc3545;color:#fff}
        .btn-fix:disabled{background:#ccc;cursor:not-allowed}
        .high{color:#c00}.medium{color:#c60}.low{color:#080}
        .import-box input[type=file]{margin-right:8px}
        .import-box button{background:#6610f2;color:#fff;padding:6px 14px}
    </style>
</head>
<body>
    <div class="box import-box">
        <h1>漏洞管理与自动化修复平台</h1>
        <div class="meta">
            共 {{ stats.total or 0 }} 条 | 可自动修复 {{ stats.auto_cnt or 0 }} 条 |
            已修复 {{ stats.fixed_cnt or 0 }} 条 |
            Ansible: {{ ansible_info.label }}
        </div>
        <form id="uploadForm">
            <input type="file" name="report" accept=".json,.jsonl,.xml,.csv,.nessus,.md,.markdown,.yaml,.yml" required>
            <input type="file" name="mapping" accept=".yaml,.yml" title="可选：YAML 字段映射">
            <button type="submit">导入报告（自动识别格式）</button>
        </form>
        <div class="meta" style="margin-top:8px">支持 JSON / CSV / XML / Markdown + 通用智能识别；可选 YAML 字段映射</div>
        <span id="uploadMsg"></span>
    </div>

    <div class="box">
        <div class="filter">
            <strong>级别：</strong>
            <a class="dim" href="/">全部</a>
            {% for l in levels %}
            <a class="{{ 'on' if l == cur_severity else '' }}" href="/?severity={{ l }}&status={{ cur_status }}">{{ l }}</a>
            {% endfor %}
        </div>
        <div class="filter" style="margin-top:8px">
            <strong>状态：</strong>
            <a class="dim" href="/?severity={{ cur_severity }}">全部</a>
            {% for s in statuses %}
            <a class="{{ 'on' if s == cur_status else '' }}" href="/?severity={{ cur_severity }}&status={{ s }}">{{ s }}</a>
            {% endfor %}
        </div>
    </div>

    <div class="box">
        <table>
            <tr>
                <th>来源</th><th>资产</th><th>漏洞</th><th>级别</th>
                <th>规则</th><th>状态</th><th>操作</th>
            </tr>
            {% for v in vulns %}
            <tr>
                <td><span class="tag">{{ v.source_tool }}</span></td>
                <td>{{ v.asset_ip }}:{{ v.port }}</td>
                <td>{{ v.vuln_name[:60] }}{% if v.vuln_name|length > 60 %}...{% endif %}</td>
                <td class="{{ 'high' if '高' in (v.severity or '') else 'medium' if '中' in (v.severity or '') else 'low' }}">
                    {{ v.severity }}
                </td>
                <td><span class="tag">{{ v.remediation_rule or '-' }}</span></td>
                <td>
                    <span class="tag {{ 'ok' if v.fix_status=='fixed' else 'warn' if v.fix_status=='auto_fixable' else 'err' if v.fix_status=='failed' else '' }}">
                        {{ status_label(v.fix_status) }}
                    </span>
                </td>
                <td>
                    <button class="btn-info" onclick='showDetail({{ v.id|tojson }})'>详情</button>
                    <button class="btn-fix" {% if not v.auto_fixable %}disabled title="需人工处理"{% endif %}
                        onclick='fixVuln({{ v.id }}, {{ v.asset_ip|tojson }})'>修复</button>
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <script>
        const vulnData = {{ vuln_json|safe }};

        function showDetail(id) {
            const v = vulnData.find(x => x.id === id);
            if (!v) return;
            alert(
                '【来源】' + v.source_tool +
                '\\n【漏洞】' + v.vuln_name +
                '\\n【CVE】' + (v.cve || '-') +
                '\\n\\n【描述】\\n' + (v.description || '').slice(0, 800) +
                '\\n\\n【建议】\\n' + (v.solution || '').slice(0, 800) +
                '\\n\\n【最近修复】\\n' + (v.last_fix_msg || '-')
            );
        }

        function fixVuln(id, ip) {
            if (!confirm('确认对 ' + ip + ' 执行自动修复？')) return;
            fetch('/fix', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id: id})
            }).then(r => r.json()).then(d => {
                alert(d.msg);
                if (d.ok) location.reload();
            });
        }

        document.getElementById('uploadForm').onsubmit = function(e) {
            e.preventDefault();
            const fd = new FormData(this);
            fetch('/import', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(d => {
                    document.getElementById('uploadMsg').textContent = d.msg;
                    if (d.ok) setTimeout(() => location.reload(), 800);
                });
        };
    </script>
</body>
</html>
'''


if __name__ == "__main__":
    import os
    import sys

    if sys.platform.startswith("win"):
        os.environ.setdefault("RAYSCAN_ANSIBLE_MODE", "wsl")
        os.environ.setdefault("RAYSCAN_SIMULATE_ON_WINDOWS", "0")
        os.environ.setdefault("RAYSCAN_TARGET_OS", "windows")

    init_all_tables()
    app = create_app()
    print(f"后端 API: http://127.0.0.1:{API_PORT}/api/health")
    print(f"前端开发请另开终端: cd frontend && npm run dev  (http://127.0.0.1:3002)")
    app.run(host=API_HOST, port=API_PORT, debug=True, use_reloader=False)