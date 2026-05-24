"""漏洞 → 修复剧本 规则匹配引擎。"""
import re
from dataclasses import dataclass
from typing import List, Optional

from models import VulnerabilityRecord


@dataclass
class RemediationRule:
    rule_id: str
    name: str
    playbook: str
    patterns: List[str]
    priority: int = 100
    manual_only: bool = False
    verify_type: str = ""  # http_header, ping, none


# 规则按 priority 升序匹配（数字越小越优先）
REMEDIATION_RULES: List[RemediationRule] = [
    RemediationRule(
        "apache_server_tokens",
        "Apache 版本信息泄露",
        "fix_server_tokens.yml",
        ["server 信息泄露", "server banner", "server 版本", "apache 版本", "禁止 apach", "server 头", "版本信息泄漏", "服务器版本"],
        priority=20,
        verify_type="http_header",
    ),
    RemediationRule(
        "security_headers_bundle",
        "HTTP 安全响应头",
        "fix_security_headers.yml",
        [
            "content-security-policy", "csp", "x-frame-options", "clickjacking",
            "x-content-type-options", "referrer-policy", "permissions-policy",
            "x-xss-protection", "cross-origin", "缺少.*响应头", "响应头未设置",
            "strict-transport-security", "hsts",
        ],
        priority=30,
        verify_type="http_header",
    ),
    RemediationRule(
        "cookie_samesite",
        "Cookie SameSite",
        "fix_cookie_headers.yml",
        ["samesite", "same-site", "cookie未配置"],
        priority=40,
        verify_type="http_header",
    ),
    RemediationRule(
        "cookie_secure_httponly",
        "Cookie Secure/HttpOnly",
        "fix_cookie_headers.yml",
        ["httponly", "secure.*cookie", "cookie.*secure", "cookie 未设置 secure"],
        priority=41,
        verify_type="http_header",
    ),
    RemediationRule(
        "tls_ssl_config",
        "TLS/SSL 配置",
        "fix_tls_hardening.yml",
        [
            "ssl", "tls 1.0", "tls 1.1", "弱加密", "cipher", "证书", "自签名",
            "poodle", "beast", "sweet32",
        ],
        priority=50,
        verify_type="none",
    ),
    RemediationRule(
        "http_to_https",
        "HTTP 明文传输",
        "fix_force_https.yml",
        [
            "明文传输", "未使用 https", "http 传输", "cleartext", "without ssl",
            "用户认证信息明文",
        ],
        priority=60,
        manual_only=True,  # 需证书，默认仅提示
        verify_type="none",
    ),
    RemediationRule(
        "ssh_hardening",
        "SSH 弱配置",
        "fix_ssh_hardening.yml",
        ["ssh", "root 登录", "弱算法", "openssh"],
        priority=70,
        verify_type="none",
    ),
    RemediationRule(
        "directory_listing",
        "目录浏览",
        "fix_directory_listing.yml",
        ["目录浏览", "directory listing", "index of", "默认目录"],
        priority=80,
        verify_type="none",
    ),
    RemediationRule(
        "brute_force_login",
        "登录暴力破解",
        "fix_rate_limit.yml",
        ["暴力猜解", "brute force", "bruteforce", "登录表单", "account lockout"],
        priority=200,
        manual_only=True,
        verify_type="none",
    ),
    RemediationRule(
        "generic_connectivity",
        "连通性检查（兜底）",
        "fix_connectivity.yml",
        [".*"],
        priority=9999,
        verify_type="ping",
    ),
]


def _text_blob(rec: VulnerabilityRecord) -> str:
    return " ".join([
        rec.vuln_name, rec.description, rec.solution,
        rec.cve, rec.cwe, rec.owasp, rec.plugin_id,
    ]).lower()


def match_remediation(rec: VulnerabilityRecord) -> Optional[RemediationRule]:
    blob = _text_blob(rec)
    matched: List[RemediationRule] = []

    for rule in REMEDIATION_RULES:
        if rule.rule_id == "generic_connectivity":
            continue
        for pat in rule.patterns:
            if re.search(pat, blob, re.I):
                matched.append(rule)
                break

    if matched:
        matched.sort(key=lambda r: r.priority)
        return matched[0]

    return next((r for r in REMEDIATION_RULES if r.rule_id == "generic_connectivity"), None)


def classify_record(rec: VulnerabilityRecord):
    """返回 (规则, 是否可自动修复)。"""
    rule = match_remediation(rec)
    if not rule:
        return None, False
    if rule.manual_only:
        return rule, False
    if rule.rule_id == "generic_connectivity":
        return rule, False
    return rule, True
