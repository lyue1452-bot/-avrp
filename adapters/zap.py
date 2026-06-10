"""OWASP ZAP JSON 报告适配器。"""
import json
import re
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity, parse_host_port
from models import VulnerabilityRecord


class ZapAdapter(BaseAdapter):
    tool_name = "zap"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if isinstance(sample, dict):
            return "site" in sample or "@version" in sample
        return False

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        records: List[VulnerabilityRecord] = []

        sites = data.get("site", [])
        for site in sites:
            site_name = site.get("@name", "") if isinstance(site, dict) else str(site)
            alerts = site.get("alerts", []) if isinstance(site, dict) else []
            for alert in alerts:
                rec = self._alert_to_record(alert, site_name)
                if rec:
                    records.append(rec)
        return records

    def _alert_to_record(self, alert: dict, default_site: str) -> VulnerabilityRecord:
        name = alert.get("name", "ZAP Finding")
        risk = alert.get("riskdesc", alert.get("risk", "info"))
        severity = normalize_severity(risk)
        desc = alert.get("description", "")
        solution = alert.get("solution", "")
        cwe_id = str(alert.get("cweid", "") or "")
        wasc_id = str(alert.get("wascid", "") or "")

        plugin_id = alert.get("pluginId", alert.get("id", ""))
        confidence = alert.get("confidence", "")

        # 提取 URL 和资产信息
        uri = alert.get("uri", alert.get("url", ""))
        if not uri:
            uri = default_site

        asset_ip, port = parse_host_port(uri)
        param = alert.get("param", "")
        evidence = alert.get("evidence", "")

        detail_parts = [desc]
        if param:
            detail_parts.append(f"参数: {param}")
        if evidence:
            detail_parts.append(f"证据: {evidence}")
        if confidence:
            detail_parts.append(f"可信度: {confidence}")
        description = "\n".join(detail_parts)

        return VulnerabilityRecord(
            vuln_name=name[:500],
            severity=severity,
            asset_ip=asset_ip,
            port=port,
            url=uri,
            description=description[:2000],
            solution=solution[:2000],
            source_tool=self.tool_name,
            external_id=f"plugin-{plugin_id}",
            cwe=cwe_id,
            plugin_id=str(plugin_id),
        )