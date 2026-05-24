"""跨格式字段同义词表（CSV 表头 / XML 标签 / JSON 键名）。"""

FIELD_SYNONYMS = {
    "vuln_name": [
        "vuln_name", "vul_name", "name", "title", "plugin name", "plugin_name",
        "vulnerability", "finding", "issue", "alert", "漏洞", "漏洞名称", "威胁",
        "pluginname", "check", "rule", "template-id", "template_id", "nvt",
    ],
    "severity": [
        "severity", "risk", "level", "threat", "priority", "cvss", "危险程度",
        "风险", "级别", "危险等级", "impact",
    ],
    "asset_ip": [
        "host", "ip", "ip address", "asset", "asset_ip", "target", "hostname",
        "主机", "地址", "server", "asset ip", "machine",
    ],
    "port": ["port", "端口", "service port"],
    "url": [
        "url", "vul_url", "uri", "link", "matched-at", "matched_at", "affected url",
        "location", "path", "request url", "站点",
    ],
    "description": [
        "description", "detail", "synopsis", "summary", "issue detail",
        "desc", "描述", "details", "info", "message", "output",
    ],
    "solution": [
        "solution", "remediation", "fix", "recommendation", "advice",
        "修复建议", "建议", "remediation detail", "mitigation",
    ],
    "cve": ["cve", "cve id", "cve-id", "cves"],
    "plugin_id": [
        "plugin id", "plugin_id", "pluginid", "plugin", "id", "oid",
        "template-id", "template_id", "rule id", "check id",
    ],
    "cwe": ["cwe", "cwe-id", "cwe_id"],
    "owasp": ["owasp", "owasp_name", "category", "classification"],
}


def normalize_key(key: str) -> str:
    return key.strip().lower().replace("_", " ").replace("-", " ")


def score_header(header: str, field: str) -> float:
    """表头/标签与某字段同义词的匹配得分（0~1）。"""
    h = normalize_key(header)
    if not h:
        return 0.0
    best = 0.0
    for syn in FIELD_SYNONYMS.get(field, []):
        s = normalize_key(syn)
        if h == s:
            return 1.0
        if h in s or s in h:
            best = max(best, 0.85)
        elif any(part and part in h for part in s.split()):
            best = max(best, 0.7)
    return best


def resolve_column_map(headers: list) -> dict:
    """为 CSV 表头智能映射到标准字段名。"""
    mapping = {}
    used = set()
    for field in FIELD_SYNONYMS:
        best_header = None
        best_score = 0.55
        for h in headers:
            if h in used:
                continue
            sc = score_header(h, field)
            if sc > best_score:
                best_score = sc
                best_header = h
        if best_header:
            mapping[field] = best_header
            used.add(best_header)
    return mapping
