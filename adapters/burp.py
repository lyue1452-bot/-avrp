"""Burp Suite XML 导出（issue 列表）。"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity, parse_host_port
from models import VulnerabilityRecord


class BurpXmlAdapter(BaseAdapter):
    tool_name = "burp"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if path.suffix.lower() != ".xml":
            return False
        head = path.read_text(encoding="utf-8", errors="replace")[:800].lower()
        return "issues" in head or "burp" in head or "<issue>" in head

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        records: List[VulnerabilityRecord] = []
        root = ET.parse(path).getroot()

        for issue in root.findall(".//issue"):
            name = _text(issue, "name") or _text(issue, "type") or "Burp Issue"
            severity = normalize_severity(_text(issue, "severity", "info"))
            host = _text(issue, "host", "unknown")
            path_val = _text(issue, "path", "/")
            port_s = _text(issue, "port", "")
            try:
                port = int(port_s) if port_s else 80
            except ValueError:
                port = 80
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}{path_val}"
            asset_ip, parsed_port = parse_host_port(url)
            if parsed_port:
                port = parsed_port

            records.append(VulnerabilityRecord(
                vuln_name=name,
                severity=severity,
                asset_ip=asset_ip,
                port=port,
                url=url,
                description=_text(issue, "issueDetail", "")[:2000],
                solution=_text(issue, "remediationDetail", "")[:2000],
                source_tool=self.tool_name,
                external_id=_text(issue, "type", ""),
            ))
        return records


def _text(parent, tag: str, default: str = "") -> str:
    el = parent.find(tag)
    if el is not None and el.text:
        return el.text.strip()
    return default
