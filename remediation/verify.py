"""修复后轻量验证（HTTP 头 / 连通性）。"""
import re
import urllib.error
import urllib.request
from typing import Tuple

from remediation.rules import RemediationRule


def verify_fix(rule: RemediationRule, url: str, asset_ip: str) -> Tuple[bool, str]:
    if rule.verify_type == "ping":
        return _ping(asset_ip)
    if rule.verify_type == "http_header":
        return _check_security_headers(url or f"http://{asset_ip}")
    return True, "无需自动验证"


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
