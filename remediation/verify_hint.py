"""根据修复规则与漏洞名称生成人工验证说明（入库/扫描后自动适用）。"""
from typing import Any, Dict, List, Optional


def _cmd(url: str, pattern: str) -> str:
    return f'curl -sI "{url}" | findstr /i "{pattern}"'


def _block(
    title: str,
    check_cmd: str,
    success_lines: List[str],
    fail_lines: List[str],
    extra: str = "",
) -> str:
    lines = [
        f"【{title}】",
        "验证命令：",
        check_cmd,
        "",
        "✅ 判定为修复成功（响应中应出现）：",
        *[f"  {x}" for x in success_lines],
        "",
        "❌ 判定为修复失败（出现以下情况）：",
        *[f"  {x}" for x in fail_lines],
    ]
    if extra:
        lines.append("")
        lines.append(extra)
    return "\n".join(lines)


def _security_header_hint(url: str, header_name: str, header_key: str, success_example: str) -> str:
    return _block(
        header_name,
        _cmd(url, header_key),
        [f"{header_name}: {success_example}"],
        ["命令无任何输出（该响应头缺失）", "curl 无法连接目标 URL"],
        "批量检查全部安全头：.\\scripts\\verify_http_fix.ps1",
    )


def build_verify_hint(row: Dict[str, Any]) -> str:
    """任意入库漏洞均可调用；依赖 remediation_rule + vuln_name + url/asset_ip。"""
    url = (row.get("url") or "").strip() or f"http://{row.get('asset_ip', '')}"
    rule = (row.get("remediation_rule") or "").strip()
    name = (row.get("vuln_name") or "").lower()

    if rule == "apache_server_tokens" or "server" in name or "版本" in name:
        return _block(
            "Server 版本隐藏",
            _cmd(url, "Server:"),
            ["Server: Apache", "Server: Apache/2.4（无 Win64、OpenSSL 等详细版本串也可接受）"],
            ["Server: Apache/2.4.39 (Win64) OpenSSL/...（仍带完整版本号）", "命令无 Server 行且站点不可访问"],
        )

    if "x-content-type-options" in name or "content-type-options" in name:
        return _security_header_hint(url, "X-Content-Type-Options", "X-Content-Type-Options", "nosniff")

    if "x-frame-options" in name or "frame-options" in name or "clickjacking" in name:
        return _security_header_hint(url, "X-Frame-Options", "X-Frame-Options", "SAMEORIGIN 或 DENY")

    if "referrer-policy" in name or "referrer" in name:
        return _security_header_hint(
            url, "Referrer-Policy", "Referrer-Policy", "strict-origin-when-cross-origin 等有效策略值"
        )

    if "content-security-policy" in name or "csp" in name:
        return _security_header_hint(
            url, "Content-Security-Policy", "Content-Security-Policy", "default-src 'self' ..."
        )

    if rule == "security_headers_bundle":
        return _block(
            "HTTP 安全响应头",
            _cmd(url, "Referrer-Policy X-Frame X-Content Content-Security"),
            [
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: SAMEORIGIN",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Content-Security-Policy: default-src ...",
                "（至少出现与本漏洞相关的一行；4 行全部存在 = 成功）",
            ],
            ["findstr 无任何输出", "仅有部分头、缺少本漏洞对应的那一项", "curl 连接超时或拒绝连接"],
            "一键验证：.\\scripts\\verify_http_fix.ps1",
        )

    if rule == "cookie_samesite" or "samesite" in name:
        return _block(
            "Cookie SameSite",
            _cmd(url, "Set-Cookie"),
            ["Set-Cookie: ... SameSite=Lax", "Set-Cookie: ... SameSite=Strict"],
            ["Set-Cookie 中无 SameSite 属性", "SameSite=None 且无 Secure（不安全）"],
        )

    if rule == "cookie_secure_httponly" or "httponly" in name or "secure" in name:
        return _block(
            "Cookie Secure / HttpOnly",
            _cmd(url, "Set-Cookie"),
            ["Set-Cookie: ... HttpOnly", "Set-Cookie: ... Secure（HTTPS 站点）"],
            ["Set-Cookie 缺少 HttpOnly 或 Secure"],
        )

    if rule in ("open_port_exposure", "ssh_hardening", "weak_password", "database_misconfig"):
        port = row.get("port") or "?"
        return _block(
            "端口/服务暴露",
            f"netstat -ano | findstr :{port}",
            [f"端口 {port} 不再对公网开放或已防火墙阻断", "重新扫描不再报告该暴露"],
            [f"端口 {port} 仍可从外部连接", "仅平台状态变化但端口仍开放"],
            "建议修复后重新扫描或使用 nmap 验证。",
        )

    if rule == "http_to_https" or "明文传输" in name or "cleartext" in name:
        host = (row.get("asset_ip") or "127.0.0.1").strip()
        https_url = url.replace("http://", "https://", 1) if url.startswith("http://") else f"https://{host}"
        return _block(
            "HTTP → HTTPS",
            f'curl -kI "{https_url}"\ncurl -I "http://{host}/"',
            [
                "HTTPS 访问返回 200/302 且含 Strict-Transport-Security（可选）",
                "HTTP 访问返回 301/302 并 Location 指向 https://",
                "重新扫描后「用户认证信息明文传输」不再报告",
            ],
            [
                "HTTP 仍可正常访问且无跳转",
                "443 端口无法连接或未配置证书",
                "仅平台状态变化，浏览器仍只能 http:// 访问",
            ],
            "自签证书浏览器会提示不受信任，属正常现象；生产环境请换正式证书。",
        )

    if rule == "brute_force_login" or "暴力猜解" in name or "登录表单" in name:
        login_url = url if url else f"http://{row.get('asset_ip', '')}/"
        return _block(
            "登录接口防护（Apache 层）",
            f'curl -sI "{login_url}" | findstr /i "X-RayScan-Login-Protection"',
            [
                "响应头含 X-RayScan-Login-Protection: rate-limit,reqtimeout",
                "连续快速 POST 登录请求明显变慢或被限速",
                "重新扫描后「可暴力猜解的登录表单」风险降低或不再报告",
            ],
            [
                "登录页无任何防护响应头",
                "仍可无限高速尝试登录",
                "验证码/账号锁定未配置（需应用层，见修复建议）",
            ],
            "验证码、账号锁定、MFA 需在应用代码中实现；弱口令请单独处理「弱口令」类漏洞。",
        )

    if not rule:
        return ""

    return _block(
        "通用验证",
        f"# 请根据漏洞描述手动检查 {url}",
        ["目标上已不再出现漏洞描述中的问题特征", "重新扫描后该漏洞不再报告"],
        ["漏洞特征仍然存在", "仅平台状态为已修复但环境未变化"],
        "建议修复后重新扫描确认。",
    )


def should_show_verify_hint(row: Dict[str, Any]) -> bool:
    return bool((row.get("remediation_rule") or "").strip() or row.get("auto_fixable"))
