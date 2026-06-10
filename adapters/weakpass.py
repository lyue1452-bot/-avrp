"""弱口令检测 JSON 报告适配器。"""
import json
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity, parse_host_port
from models import VulnerabilityRecord


class WeakPasswordAdapter(BaseAdapter):
    tool_name = "weakpass"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if isinstance(sample, list) and sample:
            item = sample[0]
            return isinstance(item, dict) and (
                "service" in item or "password" in item
            ) and any(k in item for k in ("username", "user", "account"))
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

            service = item.get("service", item.get("protocol", ""))
            host = item.get("host", item.get("ip", item.get("server", "")))
            port = int(item.get("port", 0) or 0)
            username = item.get("username", item.get("user", ""))
            password = item.get("password", item.get("pass", ""))
            status = item.get("status", item.get("result", "success"))

            if not service or not host:
                continue

            vuln_name = f"弱口令 - {service}"
            if username:
                vuln_name += f" ({username})"

            asset_ip, parsed_port = parse_host_port(host)
            if not port:
                port = parsed_port

            description_parts = [
                f"服务: {service}",
                f"用户名: {username}",
                f"密码: {password}",
            ]
            if status:
                description_parts.append(f"状态: {status}")

            solution = (
                f"1. 修改 {service} 服务的密码为高强度密码（12位以上，含大小写字母、数字、特殊字符）\n"
                f"2. 如果该账号为默认/测试账号，建议禁用或删除\n"
                f"3. 启用登录频率限制和账户锁定策略\n"
                f"4. 定期进行密码审计"
            )

            records.append(VulnerabilityRecord(
                vuln_name=vuln_name[:500],
                severity="高危",
                asset_ip=asset_ip,
                port=port or 0,
                url=f"{service}://{asset_ip}:{port}" if port else f"{service}://{asset_ip}",
                description="\n".join(description_parts)[:2000],
                solution=solution[:2000],
                source_tool=self.tool_name,
                plugin_id=service,
            ))
        return records