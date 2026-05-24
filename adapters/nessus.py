"""Nessus / OpenVAS 类 CSV 及简易 JSON 导出。"""
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import load_json_file, normalize_severity, parse_host_port, first_str
from models import VulnerabilityRecord


class NessusCsvAdapter(BaseAdapter):
    tool_name = "nessus"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return path.suffix.lower() == ".csv"

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        records: List[VulnerabilityRecord] = []
        with path.open(encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return records
            fields_lower = {h.lower(): h for h in reader.fieldnames}

            def col(*names):
                for n in names:
                    if n.lower() in fields_lower:
                        return fields_lower[n.lower()]
                return None

            name_col = col("Plugin Name", "Name", "Vulnerability", "Title", "漏洞名称")
            sev_col = col("Risk", "Severity", "Cvss", "风险")
            host_col = col("Host", "IP Address", "主机")
            port_col = col("Port", "端口")
            plugin_col = col("Plugin ID", "Plugin", "插件")
            desc_col = col("Description", "Synopsis", "描述")
            sol_col = col("Solution", "Remediation", "修复建议")
            cve_col = col("CVE", "Cve")

            if not name_col or not host_col:
                return records

            for row in reader:
                host = row.get(host_col or "", "") or "unknown"
                port_s = row.get(port_col or "", "0") or "0"
                try:
                    port = int(str(port_s).split("/")[0])
                except ValueError:
                    port = 0
                if port == 0:
                    _, port = parse_host_port(host)

                name = row.get(name_col or "", "Nessus Finding") or "Nessus Finding"
                cve = row.get(cve_col or "", "") if cve_col else ""

                records.append(VulnerabilityRecord(
                    vuln_name=name,
                    severity=normalize_severity(row.get(sev_col or "", "未知")),
                    asset_ip=host.split()[0],
                    port=port or 80,
                    url=f"http://{host}" if "://" not in host else host,
                    description=row.get(desc_col or "", "")[:2000],
                    solution=row.get(sol_col or "", "")[:2000],
                    source_tool=self.tool_name,
                    plugin_id=str(row.get(plugin_col or "", "")),
                    cve=cve,
                ))
        return records


class NessusXmlAdapter(BaseAdapter):
    tool_name = "nessus"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return path.suffix.lower() in (".nessus", ".xml") and path.read_text(encoding="utf-8", errors="replace")[:500].find("Report") >= 0

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        records: List[VulnerabilityRecord] = []
        root = ET.parse(path).getroot()

        for report_host in root.iter("ReportHost"):
            host = report_host.get("name", "unknown")
            for item in report_host.findall(".//ReportItem"):
                port = int(item.get("port", "0") or 0)
                plugin_id = item.get("pluginID", "")
                name = item.get("pluginName", "Nessus Finding")
                severity = normalize_severity(item.get("severity", "0"))
                desc = ""
                sol = ""
                cve = ""
                for child in item:
                    tag = child.tag
                    if tag == "description":
                        desc = child.text or ""
                    elif tag in ("solution", "remediation"):
                        sol = child.text or ""
                    elif tag == "cve":
                        cve = child.text or cve

                records.append(VulnerabilityRecord(
                    vuln_name=name,
                    severity=severity,
                    asset_ip=host,
                    port=port or 80,
                    url=f"http://{host}:{port}" if port else f"http://{host}",
                    description=desc[:2000],
                    solution=sol[:2000],
                    source_tool=self.tool_name,
                    plugin_id=plugin_id,
                    cve=cve,
                ))
        return records


class OpenVasJsonAdapter(BaseAdapter):
    tool_name = "openvas"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return isinstance(sample, dict) and (
            "results" in sample or "report" in sample or "vulnerabilities" in sample
        )

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = load_json_file(path)
        items = data.get("results") or data.get("vulnerabilities") or []
        if isinstance(data.get("report"), dict):
            items = data["report"].get("results", items)
        records: List[VulnerabilityRecord] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            host = first_str(item, ["host", "ip", "asset"], "unknown")
            port = int(item.get("port", 0) or 0)
            name = first_str(item, ["name", "nvt", "title", "vulnerability"], "OpenVAS Finding")
            if isinstance(item.get("nvt"), dict):
                nvt = item["nvt"]
                name = nvt.get("name", name)
            records.append(VulnerabilityRecord(
                vuln_name=name,
                severity=normalize_severity(first_str(item, ["severity", "threat"], "未知")),
                asset_ip=host,
                port=port or 80,
                url=first_str(item, ["url"], f"http://{host}"),
                description=first_str(item, ["description", "summary"], "")[:2000],
                solution=first_str(item, ["solution", "insight"], "")[:2000],
                source_tool=self.tool_name,
                plugin_id=first_str(item, ["nvt", "oid", "plugin_id"], ""),
                cve=first_str(item, ["cve"], ""),
            ))
        return records
