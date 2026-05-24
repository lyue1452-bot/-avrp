#!/usr/bin/env python3
"""导入任意支持的漏洞报告到数据库。"""
import argparse
import sys
from pathlib import Path

from config import DEFAULT_REPORT
from models import init_database, upsert_vulnerability
from adapters import parse_report
from remediation.rules import classify_record


def import_file(path: Path, tool_hint: str = "", mapping_path: Path = None) -> dict:
    records, tool = parse_report(path, mapping_path=mapping_path)
    if tool_hint:
        tool = tool_hint

    stats = {"total": len(records), "inserted": 0, "updated": 0, "skipped": 0, "auto_fixable": 0}
    for rec in records:
        if not rec.source_tool or rec.source_tool == "generic":
            rec.source_tool = tool
        rule, auto = classify_record(rec)
        rule_id = rule.rule_id if rule else ""
        if auto:
            stats["auto_fixable"] += 1
        result = upsert_vulnerability(rec, remediation_rule=rule_id, auto_fixable=auto)
        stats[result] = stats.get(result, 0) + 1

    return stats


def main():
    parser = argparse.ArgumentParser(description="多工具漏洞报告导入")
    parser.add_argument("report", nargs="?", default=str(DEFAULT_REPORT), help="报告文件路径")
    parser.add_argument("--tool", default="", help="强制标记来源工具名")
    parser.add_argument("--mapping", "-m", default="", help="YAML 字段映射文件路径")
    parser.add_argument("--init-only", action="store_true", help="仅初始化数据库")
    args = parser.parse_args()

    init_database()
    if args.init_only:
        print("数据库已初始化")
        return

    path = Path(args.report)
    if not path.exists():
        print(f"文件不存在: {path}")
        sys.exit(1)

    mapping = Path(args.mapping) if args.mapping else None
    print(f"正在导入: {path}" + (f" (映射: {mapping})" if mapping else ""))
    stats = import_file(path, args.tool, mapping_path=mapping)
    print(
        f"完成 | 解析 {stats['total']} 条 | "
        f"新增 {stats.get('inserted', 0)} | 更新 {stats.get('updated', 0)} | "
        f"跳过 {stats.get('skipped', 0)} | 可自动修复 {stats['auto_fixable']} 条"
    )


if __name__ == "__main__":
    main()
