"""ProjectDiscovery Nuclei JSON / JSONL 报告。"""
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import load_json_or_jsonl, normalize_severity, parse_host_port, first_str
from models import VulnerabilityRecord


class NucleiAdapter(BaseAdapter):
    tool_name = "nuclei"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if isinstance(sample, list) and sample:
            item = sample[0]
            return isinstance(item, dict) and (
                "template-id" in item or "templateID" in item or "matcher-name" in item
            )
        if isinstance(sample, dict):
            return "template-id" in sample or "templateID" in sample
        return False

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = load_json_or_jsonl(path)
        if isinstance(data, dict):
            data = [data]
        records: List[VulnerabilityRecord] = []

        for item in data:
            if not isinstance(item, dict):
                continue
            info = item.get("info") or {}
            host = first_str(item, ["host", "ip"], "")
            matched = first_str(item, ["matched-at", "matched", "url"], host)
            asset_ip, port = parse_host_port(matched or host)
            name = first_str(item, ["template-id", "templateID"], "nuclei-finding")
            if info.get("name"):
                name = info["name"]
            desc = first_str(info, ["description"], first_str(item, ["matcher-name"], ""))
            solution = first_str(info, ["remediation", "reference"], "")
            severity = normalize_severity(first_str(info, ["severity"], first_str(item, ["severity"], "info")))
            cve_list = info.get("classification", {}).get("cve-id") or info.get("cve-id") or []
            cve = cve_list[0] if isinstance(cve_list, list) and cve_list else str(cve_list or "")

            records.append(VulnerabilityRecord(
                vuln_name=name,
                severity=severity,
                asset_ip=asset_ip,
                port=port,
                url=matched or f"http://{asset_ip}",
                description=desc,
                solution=solution,
                source_tool=self.tool_name,
                external_id=first_str(item, ["template-id", "templateID"], ""),
                cve=cve if isinstance(cve, str) else str(cve),
                cwe=first_str(info.get("classification", {}), ["cwe-id"], ""),
                plugin_id=first_str(item, ["template-id", "templateID"], ""),
            ))
        return records
