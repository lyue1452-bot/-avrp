"""内置 Web 安全探测（ZAP 不可用时的替代方案）。"""
import json
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

from models import VulnerabilityRecord
from adapters.utils import normalize_severity


SECURITY_HEADERS = [
    ("Content-Security-Policy", "HTTP Content-Security-Policy 响应头未设置", "中危"),
    ("X-Frame-Options", "X-Frame-Options 响应头未设置", "低危"),
    ("X-Content-Type-Options", "HTTP X-Content-Type-Options 响应头未设置", "低危"),
    ("Referrer-Policy", "HTTP Referrer-Policy 响应头未设置", "低危"),
    ("Strict-Transport-Security", "HTTP Strict-Transport-Security (HSTS) 未设置", "中危"),
]

BUILTIN_WEB_SCANNER = "web_probe"


def _fetch(url: str, timeout: int = 8) -> Tuple[int, dict, str, list]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "RayScan-WebProbe/1.0"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(65536).decode("utf-8", errors="replace")
        cookies = resp.headers.get_all("Set-Cookie") or []
        return resp.status, headers, body, cookies


def scan_web_target(url: str) -> List[VulnerabilityRecord]:
    """对 Web URL 做轻量安全检测，输出与漏扫报告兼容的记录。"""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 默认端口不可达时，尝试常见 Web 端口
    urls_to_try = [url]
    if not parsed.port and parsed.scheme == "http":
        base_path = parsed.path or "/"
        for alt in (8080, 8888):
            urls_to_try.append(f"http://{host}:{alt}{base_path}")

    last_error = ""
    for try_url in urls_to_try:
        records = _scan_single_url(try_url, host)
        if records and records[0].vuln_name != "Web 目标不可达":
            return records
        if records and records[0].vuln_name == "Web 目标不可达":
            last_error = records[0].description

    return [VulnerabilityRecord(
        vuln_name="Web 目标不可达",
        severity="信息",
        asset_ip=host,
        port=port,
        url=url,
        description=last_error or "无法连接目标 Web 服务",
        solution="确认 URL、端口正确且目标可从扫描机访问（如 http://IP:8080/路径）",
        source_tool=BUILTIN_WEB_SCANNER,
    )]


def _scan_single_url(url: str, host: str) -> List[VulnerabilityRecord]:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    records: List[VulnerabilityRecord] = []

    try:
        status, headers, body, cookies = _fetch(url)
    except urllib.error.HTTPError as e:
        status = e.code
        headers = {k.lower(): v for k, v in e.headers.items()}
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        cookies = e.headers.get_all("Set-Cookie") or []
    except Exception as e:
        return [VulnerabilityRecord(
            vuln_name="Web 目标不可达",
            severity="信息",
            asset_ip=host,
            port=port,
            url=url,
            description=str(e)[:500],
            solution="确认目标 URL 可从扫描机访问",
            source_tool=BUILTIN_WEB_SCANNER,
        )]

    # 安全响应头
    for header_name, vuln_title, severity in SECURITY_HEADERS:
        if header_name.lower() not in headers:
            if header_name == "Strict-Transport-Security" and parsed.scheme != "https":
                continue
            records.append(VulnerabilityRecord(
                vuln_name=vuln_title,
                severity=severity,
                asset_ip=host,
                port=port,
                url=url,
                description=f"响应中缺少 {header_name} 头。HTTP {status}",
                solution=f"在 Web 服务器配置 {header_name} 响应头。",
                source_tool=BUILTIN_WEB_SCANNER,
            ))

    # HTTP 明文
    if parsed.scheme == "http":
        records.append(VulnerabilityRecord(
            vuln_name="用户认证信息明文传输",
            severity="中危",
            asset_ip=host,
            port=port,
            url=url,
            description="站点使用 HTTP 明文传输，登录表单或 Cookie 可能被窃听。",
            solution="启用 HTTPS 并强制 HTTP 跳转 HTTPS。",
            source_tool=BUILTIN_WEB_SCANNER,
        ))

    # Cookie 属性
    for raw in cookies:
        low = raw.lower()
        if "samesite" not in low:
            records.append(VulnerabilityRecord(
                vuln_name="Cookie 未配置 SameSite 属性或配置不合理",
                severity="中危",
                asset_ip=host,
                port=port,
                url=url,
                description=f"Set-Cookie: {raw[:200]}",
                solution="为 Cookie 配置 SameSite=Strict 或 Lax。",
                source_tool=BUILTIN_WEB_SCANNER,
            ))
            break
        if parsed.scheme == "https" and ("secure" not in low or "httponly" not in low):
            records.append(VulnerabilityRecord(
                vuln_name="Cookie 缺少 HttpOnly 或 Secure 属性",
                severity="低危",
                asset_ip=host,
                port=port,
                url=url,
                description=f"Set-Cookie: {raw[:200]}",
                solution="为 Cookie 添加 HttpOnly 与 Secure 属性。",
                source_tool=BUILTIN_WEB_SCANNER,
            ))
            break

    # Server 版本泄露
    server = headers.get("server", "")
    if server and re.search(r"/\d|apache|nginx|iis", server, re.I):
        records.append(VulnerabilityRecord(
            vuln_name="HTTP 响应头服务器版本信息泄漏",
            severity="低危",
            asset_ip=host,
            port=port,
            url=url,
            description=f"Server: {server}",
            solution="隐藏或精简 Server 响应头中的版本信息。",
            source_tool=BUILTIN_WEB_SCANNER,
        ))

    # 登录表单 / 暴力破解
    if re.search(r'<form[^>]+login|type=["\']password["\']|name=["\']password["\']', body, re.I):
        records.append(VulnerabilityRecord(
            vuln_name="发现可暴力猜解的登录表单",
            severity="低危",
            asset_ip=host,
            port=port,
            url=url,
            description="页面包含登录表单，未发现明显的登录频率限制。",
            solution="启用账号锁定、验证码或 MFA。",
            source_tool=BUILTIN_WEB_SCANNER,
        ))

    return records


def write_probe_report(url: str, path: Path) -> int:
    records = scan_web_target(url)
    data = {
        "site": [{
            "@name": url,
            "alerts": [
                {
                    "name": r.vuln_name,
                    "riskdesc": r.severity,
                    "description": r.description,
                    "solution": r.solution,
                    "uri": r.url,
                }
                for r in records
            ],
        }]
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(records)
