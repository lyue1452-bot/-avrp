"""nmap 网络扫描 XML 报告适配器。"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import normalize_severity, extract_cve
from models import VulnerabilityRecord


class NmapAdapter(BaseAdapter):
    tool_name = "nmap"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        if path.suffix.lower() != ".xml":
            return False
        head = path.read_text(encoding="utf-8", errors="replace")[:500].lower()
        return "nmaprun" in head and "scaninfo" in head

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        tree = ET.parse(path)
        root = tree.getroot()
        records: List[VulnerabilityRecord] = []

        for host in root.findall("host"):
            status_el = host.find("status")
            if status_el is None or status_el.get("state", "").lower() != "up":
                continue

            # 提取主机名
            hostname = "unknown"
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    name = hn.get("name", "")
                    if name:
                        hostname = name
                        break

            # IP 地址
            addr_el = host.find("address")
            ip = addr_el.get("addr", hostname) if addr_el is not None else hostname

            # 操作系统检测
            os_info = ""
            os_el = host.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    os_info = osmatch.get("name", "")
                    break

            # 端口
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                port = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state", "").lower() != "open":
                    continue
                svc_el = port_el.find("service")
                svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                svc_product = svc_el.get("product", "") if svc_el is not None else ""
                svc_version = svc_el.get("version", "") if svc_el is not None else ""
                svc_extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""

                # 构建描述
                desc_parts = [f"开放端口: {port}/{protocol} ({svc_name})"]
                if svc_product:
                    desc_parts.append(f"服务: {svc_product} {svc_version}")
                if svc_extrainfo:
                    desc_parts.append(f"额外信息: {svc_extrainfo}")
                if os_info:
                    desc_parts.append(f"操作系统: {os_info}")

                # 脚本扫描结果
                script_outputs = []
                for script_el in port_el.findall("script"):
                    s_id = script_el.get("id", "")
                    s_out = script_el.get("output", "")
                    if s_id and s_out:
                        script_outputs.append(f"[{s_id}] {s_out}")
                if script_outputs:
                    desc_parts.extend(script_outputs)

                vuln_name = f"开放端口 {port}/{protocol} - {svc_name}"
                description = "\n".join(desc_parts)

                # 评分：根据端口服务类型决定严重级别
                severity = self._port_severity(svc_name, port)
                solution = (
                    f"如果 {svc_name} (端口 {port}) 不需要对外暴露，建议在防火墙/安全组中关闭该端口。"
                )

                records.append(VulnerabilityRecord(
                    vuln_name=vuln_name[:500],
                    severity=severity,
                    asset_ip=ip,
                    port=port,
                    url=f"{protocol}://{ip}:{port}",
                    description=description[:2000],
                    solution=solution[:2000],
                    source_tool=self.tool_name,
                    plugin_id=str(port),
                ))
        return records

    @staticmethod
    def _port_severity(svc_name: str, port: int) -> str:
        risky_ports = {21: "中危", 23: "高危", 25: "中危", 53: "中危",
                       135: "中危", 139: "中危", 445: "高危", 1433: "中危",
                       1521: "中危", 3306: "中危", 3389: "中危", 5432: "中危",
                       6379: "中危", 27017: "中危", 11211: "中危"}
        risky_services = ["telnet", "ms-sql-s", "vnc", "rexec", "rlogin"]
        if svc_name.lower() in risky_services:
            return "高危"
        if port in risky_ports:
            return risky_ports[port]
        if port < 1024:
            return "中危"
        return "低危"