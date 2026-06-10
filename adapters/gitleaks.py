"""Gitleaks 密钥泄露扫描 JSON 报告适配器。"""
import json
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity
from models import VulnerabilityRecord


class GitleaksAdapter(BaseAdapter):
    tool_name = "gitleaks"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if isinstance(sample, list) and sample:
            item = sample[0]
            return isinstance(item, dict) and (
                "Description" in item or "RuleID" in item or "Fingerprint" in item
            )
        return False

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict):
            data = data.get("findings", data.get("Results", [data]))
        if isinstance(data, dict):
            data = [data]
        records: List[VulnerabilityRecord] = []

        for item in data:
            if not isinstance(item, dict):
                continue
            description = item.get("Description", "Gitleaks Finding")
            rule_id = item.get("RuleID", "")
            file_path = item.get("File", item.get("file", ""))
            match = item.get("Match", item.get("match", ""))
            secret = item.get("Secret", item.get("secret", ""))
            commit = item.get("Commit", item.get("commit", ""))
            author = item.get("Author", item.get("author", ""))
            email = item.get("Email", item.get("email", ""))
            fingerprint = item.get("Fingerprint", item.get("fingerprint", ""))

            # 严重级别：Gitleaks 没有原生 severity，统一标高危
            severity = normalize_severity(item.get("severity", "high"))

            name = f"{description} [{rule_id}]" if rule_id else description
            asset_ip = self._extract_repo_owner(file_path)

            detail_lines = []
            if file_path:
                detail_lines.append(f"文件: {file_path}")
            if match:
                detail_lines.append(f"匹配: {match}")
            if secret:
                detail_lines.append(f"密钥: {secret[:80]}{'...' if len(secret) > 80 else ''}")
            if commit:
                detail_lines.append(f"提交: {commit[:12]}")
            if author:
                detail_lines.append(f"作者: {author} <{email}>")
            detail = "\n".join(detail_lines)

            solution = (
                f"1. 从仓库中删除该密钥文件\n"
                f"2. 在相关服务中轮换该密钥\n"
                f"3. 将新密钥存储在环境变量或密钥管理服务中\n"
                f"4. 添加 .gitignore / .gitleaks.toml 规则防止再次泄露"
            )

            records.append(VulnerabilityRecord(
                vuln_name=name[:500],
                severity=severity,
                asset_ip=asset_ip,
                port=0,
                url=file_path,
                description=detail[:2000],
                solution=solution[:2000],
                source_tool=self.tool_name,
                external_id=rule_id,
                plugin_id=rule_id,
                fingerprint=fingerprint or "",
            ))
        return records

    @staticmethod
    def _extract_repo_owner(file_path: str) -> str:
        """从文件路径提取仓库所有者标识。"""
        if not file_path:
            return "repository"
        parts = file_path.replace("\\", "/").split("/")
        if len(parts) >= 3:
            return f"{parts[0]}/{parts[1]}"
        return parts[0] if parts else "repository"