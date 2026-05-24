"""通用 JSON：递归发现疑似漏洞条目（未知工具兜底）。"""
from pathlib import Path
from typing import Any, Dict, List

from adapters.base import BaseAdapter
from adapters.utils import (
    load_json_file, load_json_or_jsonl, normalize_severity,
    parse_host_port, first_str, extract_cve,
)
from models import VulnerabilityRecord

NAME_KEYS = ["vuln_name", "VUL_NAME", "name", "title", "plugin_name", "finding", "issue"]
SEV_KEYS = ["severity", "SEVERITY", "risk", "level", "threat"]
HOST_KEYS = ["host", "ip", "asset_ip", "target", "asset", "Host"]
PORT_KEYS = ["port", "Port"]
URL_KEYS = ["url", "VUL_URL", "uri", "matched-at", "link"]
DESC_KEYS = ["description", "DESCRIPTION", "detail", "synopsis", "issueDetail"]
SOL_KEYS = ["solution", "SOLUTION", "remediation", "fix", "remediationDetail"]
CVE_KEYS = ["cve", "CVE"]
PLUGIN_KEYS = ["plugin_id", "pluginID", "Plugin ID", "template-id"]


class GenericJsonAdapter(BaseAdapter):
    tool_name = "generic"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return path.suffix.lower() in (".json", ".jsonl")

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        try:
            data = load_json_or_jsonl(path)
        except Exception:
            data = load_json_file(path)
        found: List[VulnerabilityRecord] = []
        seen = set()
        self._walk(data, found, seen, str(path.name))
        return found

    def _walk(self, node: Any, out: List[VulnerabilityRecord], seen: set, ctx: str) -> None:
        if isinstance(node, dict):
            if self._looks_like_vuln(node):
                rec = self._dict_to_record(node)
                key = rec.compute_fingerprint()
                if key not in seen:
                    seen.add(key)
                    out.append(rec)
            for v in node.values():
                self._walk(v, out, seen, ctx)
        elif isinstance(node, list):
            for item in node:
                self._walk(item, out, seen, ctx)

    def _looks_like_vuln(self, d: Dict) -> bool:
        has_name = any(k in d for k in NAME_KEYS)
        has_risk = any(k in d for k in SEV_KEYS)
        has_host = any(k in d for k in HOST_KEYS + URL_KEYS)
        return has_name and (has_risk or has_host)

    def _dict_to_record(self, d: Dict) -> VulnerabilityRecord:
        url = first_str(d, URL_KEYS, "")
        host = first_str(d, HOST_KEYS, "")
        if url:
            asset_ip, port = parse_host_port(url)
        elif host:
            asset_ip, port = parse_host_port(host)
        else:
            asset_ip, port = "unknown", 80

        port_override = d.get("port") or d.get("Port")
        if port_override:
            try:
                port = int(port_override)
            except (TypeError, ValueError):
                pass

        name = first_str(d, NAME_KEYS, "Unknown Finding")
        desc = first_str(d, DESC_KEYS, "")
        sol = first_str(d, SOL_KEYS, "")
        cve = first_str(d, CVE_KEYS, "") or extract_cve(name + desc)

        return VulnerabilityRecord(
            vuln_name=name,
            severity=normalize_severity(first_str(d, SEV_KEYS, "未知")),
            asset_ip=asset_ip,
            port=port,
            url=url or f"http://{asset_ip}:{port}",
            description=desc[:2000],
            solution=sol[:2000],
            source_tool=self.tool_name,
            plugin_id=first_str(d, PLUGIN_KEYS, ""),
            cve=cve,
        )
