"""内置数据库暴露与安全基线探测。"""
from scanner.weakpass_probe import _port_open
from models import VulnerabilityRecord
from typing import List

DB_SERVICES = [
    (3306, "mysql", "MySQL 数据库"),
    (5432, "postgresql", "PostgreSQL 数据库"),
    (1433, "mssql", "Microsoft SQL Server"),
    (1521, "oracle", "Oracle 数据库"),
    (6379, "redis", "Redis 缓存"),
    (27017, "mongodb", "MongoDB 数据库"),
    (9200, "elasticsearch", "Elasticsearch"),
]


def probe_database_exposure(host: str, timeout: float = 2.0) -> List[VulnerabilityRecord]:
    records: List[VulnerabilityRecord] = []
    for port, db_type, label in DB_SERVICES:
        if not _port_open(host, port, timeout):
            continue
        severity = "高危" if db_type in ("redis", "mongodb", "elasticsearch") else "中危"
        records.append(VulnerabilityRecord(
            vuln_name=f"数据库/数据服务暴露 - {label}",
            severity=severity,
            asset_ip=host,
            port=port,
            url=f"{db_type}://{host}:{port}",
            description=(
                f"检测到 {host}:{port} 开放 {label}。"
                "对外暴露的数据库服务可能导致未授权访问、数据泄露或勒索攻击。"
            ),
            solution=(
                "1. 禁止数据库端口直接暴露于公网\n"
                "2. 启用认证、加密连接与 IP 白名单\n"
                "3. 定期审计账号权限与弱口令"
            ),
            source_tool="db_scan",
            plugin_id=db_type,
        ))
    return records
