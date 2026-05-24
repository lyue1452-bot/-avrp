"""适配器公共工具。"""
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import json5
except ImportError:
    json5 = None


def load_json_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    if json5:
        try:
            return json5.loads(text)
        except Exception:
            pass
    return json.loads(text)


def load_json_or_jsonl(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        return load_json_file(path)
    items = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            items.append(json.loads(line))
    return items


def parse_host_port(url_or_host: str, default_port: int = 80) -> Tuple[str, int]:
    if not url_or_host:
        return "unknown", default_port
    if "://" not in url_or_host:
        url_or_host = f"http://{url_or_host}"
    parsed = urlparse(url_or_host)
    host = parsed.hostname or parsed.path.split(":")[0] or "unknown"
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = default_port
    return host, port


def normalize_severity(value: str) -> str:
    if not value:
        return "未知"
    v = str(value).lower()
    mapping = {
        "critical": "高危", "high": "高危", "高危": "高危", "高": "高危", "高风险": "高危",
        "medium": "中危", "中危": "中危", "中": "中危", "中风险": "中危",
        "low": "低危", "低危": "低危", "低": "低危", "低风险": "低危",
        "info": "信息", "informational": "信息", "信息": "信息",
    }
    for key, label in mapping.items():
        if key in v:
            return label
    return str(value)


def first_str(data: Dict, keys: List[str], default: str = "") -> str:
    for k in keys:
        if k in data and data[k] is not None:
            return str(data[k])
    return default


def extract_cve(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"CVE-\d{4}-\d+", text, re.I)
    return m.group(0).upper() if m else ""
