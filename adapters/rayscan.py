"""远江盛邦 RayScan / 一体化漏洞评估系统 JSON。"""
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from adapters.base import BaseAdapter
from models import VulnerabilityRecord
from adapters.utils import load_json_file, parse_host_port


class RayScanAdapter(BaseAdapter):
    tool_name = "rayscan"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return isinstance(sample, dict) and "WEBSITES" in sample and "SCANINFO" in sample

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = load_json_file(path)
        records: List[VulnerabilityRecord] = []

        for site in data.get("WEBSITES", []):
            base_url = site.get("URL", "")
            host, port = parse_host_port(base_url)
            for v in site.get("VULNS", []):
                records.append(VulnerabilityRecord(
                    vuln_name=v.get("VUL_NAME", "未知漏洞"),
                    severity=v.get("SEVERITY", "未知"),
                    asset_ip=host,
                    port=port,
                    url=v.get("VUL_URL", base_url),
                    description=v.get("DESCRIPTION", ""),
                    solution=v.get("SOLUTION", ""),
                    source_tool=self.tool_name,
                    external_id=str(v.get("VUL_ID", "")),
                    cwe="",
                    owasp=v.get("OWASP_NAME", ""),
                    plugin_id="",
                ))
        return records
