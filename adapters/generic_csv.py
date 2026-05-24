"""通用 CSV：表头智能映射 + 可选 YAML 列配置。"""
import csv
from pathlib import Path
from typing import Dict, List, Optional

from adapters.base import BaseAdapter
from adapters.field_synonyms import resolve_column_map, score_header
from adapters.utils import normalize_severity, parse_host_port, extract_cve
from models import VulnerabilityRecord


class GenericCsvAdapter(BaseAdapter):
    tool_name = "generic_csv"

    def __init__(self, column_map: Optional[Dict[str, str]] = None, tool_name: str = ""):
        self.column_map = column_map or {}
        if tool_name:
            self.tool_name = tool_name

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return path.suffix.lower() == ".csv"

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        records: List[VulnerabilityRecord] = []
        with path.open(encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return records

            headers = list(reader.fieldnames)
            col_map = self._build_map(headers)

            for row in reader:
                rec = self._row_to_record(row, col_map)
                if rec:
                    records.append(rec)
        return records

    def _build_map(self, headers: List[str]) -> Dict[str, str]:
        if self.column_map:
            resolved = {}
            lower_headers = {h.lower(): h for h in headers}
            for field, spec in self.column_map.items():
                if isinstance(spec, list):
                    for name in spec:
                        key = name.lower()
                        if key in lower_headers:
                            resolved[field] = lower_headers[key]
                            break
                elif isinstance(spec, str):
                    key = spec.lower()
                    if key in lower_headers:
                        resolved[field] = lower_headers[key]
            return resolved
        return resolve_column_map(headers)

    def _get(self, row: dict, col_map: dict, field: str, default: str = "") -> str:
        header = col_map.get(field)
        if not header:
            return default
        val = row.get(header, "")
        return str(val).strip() if val is not None else default

    def _row_to_record(self, row: dict, col_map: dict) -> Optional[VulnerabilityRecord]:
        name = self._get(row, col_map, "vuln_name")
        if not name:
            return None

        host = self._get(row, col_map, "asset_ip")
        url = self._get(row, col_map, "url")
        port_s = self._get(row, col_map, "port", "0")

        if url:
            asset_ip, port = parse_host_port(url)
        elif host:
            asset_ip, port = parse_host_port(host)
        else:
            return None

        try:
            if port_s and port_s != "0":
                port = int(str(port_s).split("/")[0].split()[0])
        except ValueError:
            pass

        desc = self._get(row, col_map, "description")
        cve = self._get(row, col_map, "cve") or extract_cve(name + desc)

        return VulnerabilityRecord(
            vuln_name=name,
            severity=normalize_severity(self._get(row, col_map, "severity", "未知")),
            asset_ip=asset_ip.split()[0],
            port=port or 80,
            url=url or f"http://{asset_ip}:{port or 80}",
            description=desc[:2000],
            solution=self._get(row, col_map, "solution")[:2000],
            source_tool=self.tool_name,
            plugin_id=self._get(row, col_map, "plugin_id"),
            cve=cve,
            cwe=self._get(row, col_map, "cwe"),
            owasp=self._get(row, col_map, "owasp"),
        )
