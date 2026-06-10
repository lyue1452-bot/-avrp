"""内置弱口令/高危服务暴露探测。"""
import socket
from typing import List

from models import VulnerabilityRecord

# (port, service, default_creds_hint)
WEAK_SERVICES = [
    (21, "ftp", "anonymous/anonymous 或 admin/admin"),
    (22, "ssh", "root/root, admin/admin"),
    (23, "telnet", "无加密远程登录"),
    (445, "smb", "Windows 共享弱口令"),
    (1433, "mssql", "sa/空密码或弱密码"),
    (3306, "mysql", "root/root, root/空密码"),
    (3389, "rdp", "Administrator/弱密码"),
    (5432, "postgresql", "postgres/postgres"),
    (6379, "redis", "未授权访问或空密码"),
    (27017, "mongodb", "未授权访问"),
    (11211, "memcached", "未授权访问"),
]


def probe_weak_services(host: str, timeout: float = 2.0) -> List[VulnerabilityRecord]:
    records: List[VulnerabilityRecord] = []
    for port, service, hint in WEAK_SERVICES:
        if not _port_open(host, port, timeout):
            continue
        severity = "高危" if service in ("telnet", "redis", "mongodb", "memcached") else "中危"
        records.append(VulnerabilityRecord(
            vuln_name=f"暴露的 {service.upper()} 服务（端口 {port}）",
            severity=severity,
            asset_ip=host,
            port=port,
            url=f"{service}://{host}:{port}",
            description=(
                f"检测到 {host}:{port} 上开放 {service} 服务。"
                f"常见弱口令/风险: {hint}。"
                "建议使用专用工具进一步验证弱口令。"
            ),
            solution=(
                f"1. 如非必要，关闭或限制 {service} 对外访问\n"
                "2. 使用强密码并启用登录限制\n"
                "3. 配置防火墙仅允许可信 IP 访问"
            ),
            source_tool="weakpass",
            plugin_id=service,
        ))
    return records


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
