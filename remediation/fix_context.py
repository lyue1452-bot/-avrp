"""根据漏洞记录生成 Ansible extra_vars。"""
import json
from typing import Dict


def build_extra_vars(row) -> Dict:
    """从 sqlite Row / dict 构建 playbook 变量。"""
    rule_id = row["remediation_rule"] if row["remediation_rule"] else ""
    name = (row["vuln_name"] or "").lower()
    desc = (row["description"] or "").lower()
    plugin = (row["plugin_id"] or "").lower()
    port = int(row["port"] or 0)
    blob = f"{name} {desc} {plugin}"
    extra: Dict = {}

    if rule_id == "database_misconfig" or any(k in blob for k in ("mysql", "mariadb", "mssql", "1433")):
        extra["db_type"] = "mysql" if "mysql" in blob or port == 3306 else "mssql" if port == 1433 else "mysql"
        extra["allow_remote"] = False
    elif "mongodb" in blob or port == 27017:
        extra["db_type"] = "mongodb"
        extra["allow_remote"] = False
    elif "redis" in blob or port == 6379:
        extra["db_type"] = "redis"
        extra["allow_remote"] = False
    elif "postgres" in blob or port == 5432:
        extra["db_type"] = "postgresql"
        extra["allow_remote"] = False

    if rule_id in ("open_port_exposure", "weak_password", "database_misconfig", "ssh_hardening"):
        disallowed = []
        if port and port not in (80, 443):
            disallowed.append(port)
        if disallowed:
            extra["disallowed_ports"] = disallowed
        if rule_id == "open_port_exposure":
            extra["close_unlisted"] = False
            extra["allowed_ports"] = [22, 80, 443]

    if rule_id == "ssh_hardening" or ("ssh" in blob and port == 22):
        extra.setdefault("allowed_ports", [22, 80, 443])

    return extra


def extra_vars_to_cli(extra: Dict) -> Dict:
    """转为 ansible-playbook -e 可接受的字符串值。"""
    out = {}
    for k, v in extra.items():
        if isinstance(v, (list, dict, bool)):
            out[k] = json.dumps(v)
        else:
            out[k] = str(v)
    return out
