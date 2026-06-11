"""修复后轻量验证（HTTP 头 / 连通性）。"""
import re
import time
import urllib.error
import urllib.request
from typing import Tuple

from remediation.rules import RemediationRule


def verify_fix(rule: RemediationRule, url: str, asset_ip: str, retries: int = 3, delay: float = 2.0) -> Tuple[bool, str]:
    last_msg = ""
    attempts = max(1, retries) if rule.verify_type == "http_header" else 1
    for i in range(attempts):
        if rule.verify_type == "ping":
            ok, last_msg = _ping(asset_ip)
        elif rule.verify_type == "http_header":
            if rule.rule_id == "apache_server_tokens":
                ok, last_msg = _check_server_header(url or f"http://{asset_ip}")
            else:
                ok, last_msg = _check_security_headers(url or f"http://{asset_ip}")
        else:
            return True, "无需自动验证"
        if ok:
            if i > 0:
                last_msg += f"（第 {i + 1} 次重试验证通过）"
            return True, last_msg
        if i < attempts - 1:
            time.sleep(delay)
    return False, last_msg


def _check_server_header(url: str) -> Tuple[bool, str]:
    if not url.startswith("http"):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "RayScan-Verifier/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            server = resp.headers.get("Server", "")
        if server and not re.search(r"/\d+\.\d+", server):
            return True, f"Server 头已隐藏版本: {server}"
        if server:
            return False, f"Server 仍暴露版本（需重启 Apache）: {server}"
        return True, "未检测到 Server 版本信息"
    except urllib.error.HTTPError as e:
        server = e.headers.get("Server", "")
        if server and not re.search(r"/\d+\.\d+", server):
            return True, f"Server 头已隐藏版本: {server}"
        return False, f"HTTP {e.code}; Server={server or '(无)'}"
    except Exception as e:
        return False, f"无法访问 URL: {e}"


def _ping(host: str) -> Tuple[bool, str]:
    import subprocess
    import sys
    param = "-n" if sys.platform.startswith("win") else "-c"
    try:
        r = subprocess.run(
            ["ping", param, "1", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ok = r.returncode == 0
        return ok, "主机可达" if ok else "主机不可达"
    except Exception as e:
        return False, str(e)


def _check_security_headers(url: str) -> Tuple[bool, str]:
    if not url.startswith("http"):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "RayScan-Verifier/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
        checks = []
        if headers.get("x-content-type-options"):
            checks.append("X-Content-Type-Options")
        if headers.get("x-frame-options"):
            checks.append("X-Frame-Options")
        if headers.get("referrer-policy"):
            checks.append("Referrer-Policy")
        if headers.get("content-security-policy"):
            checks.append("CSP")
        if checks:
            return True, f"已检测到响应头: {', '.join(checks)}"
        return False, "响应中仍未检测到常见安全头（可能需在目标机执行剧本或仅前端静态资源）"
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        if any(h in headers for h in ("x-frame-options", "content-security-policy")):
            return True, "错误响应中已含部分安全头"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"无法访问 URL: {e}"
