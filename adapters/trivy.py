"""Trivy 容器/主机漏洞扫描报告适配器。"""
import json
from pathlib import Path
from typing import Any, Dict, List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity, extract_cve
from models import VulnerabilityRecord


class TrivyAdapter(BaseAdapter):
    tool_name = "trivy"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if isinstance(sample, dict):
            return "Results" in sample or "ArtifactType" in sample
        return False

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        records: List[VulnerabilityRecord] = []

        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "unknown")
            # 从 target 提取资产标识（镜像名 / 路径 / 主机名）
            asset_ip = self._target_to_asset(target)
            vulns = result.get("Vulnerabilities", result.get("Packages", []))
            for vuln in vulns:
                if "VulnerabilityID" not in vuln and "SrcName" not in vuln:
                    continue
                vuln_id = vuln.get("VulnerabilityID", vuln.get("SrcName", ""))
                pkg = vuln.get("PkgName", vuln.get("Name", ""))
                installed = vuln.get("InstalledVersion", vuln.get("Version", ""))
                fixed = vuln.get("FixedVersion", "")
                severity = normalize_severity(
                    vuln.get("Severity", vuln.get("SeveritySource", "未知"))
                )
                title = vuln.get("Title", vuln.get("Description", vuln_id))
                description = (
                    f"Package: {pkg}\n"
                    f"Installed: {installed}\n"
                    f"Fixed: {fixed}\n"
                    f"{vuln.get('Description', '')}"
                )
                solution = f"升级 {pkg} 到 {fixed}" if fixed else "暂无可用修复版本"
                cve = vuln.get("Cve", "") or extract_cve(title)
                url = (
                    vuln.get("PrimaryURL")
                    or vuln.get("Reference", [""])[0]
                    or f"https://avd.aquasec.com/nvd/{vuln_id.lower()}"
                )

                records.append(VulnerabilityRecord(
                    vuln_name=f"{vuln_id} in {pkg}",
                    severity=severity,
                    asset_ip=asset_ip,
                    port=0,
                    url=url,
                    description=description[:2000],
                    solution=solution[:2000],
                    source_tool=self.tool_name,
                    external_id=vuln_id,
                    cve=cve,
                    cwe=vuln.get("Cwe", ""),
                    plugin_id=vuln_id,
                ))
        return records

    @staticmethod
    def _target_to_asset(target: str) -> str:
        """从 Trivy target 字段提取资产标识。"""
        if not target or target == "unknown":
            return "unknown"
        # 镜像名: alpine:3.18, 路径: /app/package-lock.json
        if ":" in target and "/" not in target:
            return target.split(":")[0]
        return target