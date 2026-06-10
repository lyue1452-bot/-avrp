"""数据库安全扫描 JSON 报告适配器。"""
import json
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity, parse_host_port
from models import VulnerabilityRecord


class DbScanAdapter(BaseAdapter):
    tool_name = "db_scan"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if isinstance(sample, list) and sample:
            item = sample[0]
            return isinstance(item, dict) and (
                "db_type" in item or "database" in item
            ) and any(k in item for k in ("issue", "finding", "vulnerability", "检查项"))
        if isinstance(sample, dict):
            return "db_type" in sample or "database" in sample
        return False

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict):
            data = data.get("results", data.get("findings", [data]))
        if isinstance(data, dict):
            data = [data]
        records: List[VulnerabilityRecord] = []

        for item in data:
            if not isinstance(item, dict):
                continue

            db_type = item.get("db_type", item.get("database", "unknown"))
            host = item.get("host", item.get("ip", ""))
            port = int(item.get("port", 0) or 0)
            issue = item.get("issue", item.get("finding", item.get("检查项", "Unknown Issue")))
            severity = normalize_severity(item.get("severity", item.get("risk", "中危")))
            description = item.get("description", item.get("detail", item.get("描述", "")))
            solution = item.get("solution", item.get("建议", item.get("remediation", "")))

            asset_ip, parsed_port = parse_host_port(host)
            if not port:
                port = parsed_port

            vuln_name = f"[{db_type}] {issue}"

            cve = item.get("cve", "")
            cwe = item.get("cwe", "")

            records.append(VulnerabilityRecord(
                vuln_name=vuln_name[:500],
                severity=severity,
                asset_ip=asset_ip,
                port=port or 3306,
                url=f"{db_type}://{asset_ip}:{port or 3306}",
                description=description[:2000],
                solution=solution[:2000],
                source_tool=self.tool_name,
                external_id=item.get("id", ""),
                cve=cve,
                cwe=cwe,
                plugin_id=db_type,
            ))
        return records