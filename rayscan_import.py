#!/usr/bin/env python3
"""兼容旧入口：导入 RayScan 报告（委托 import_report）。"""
from config import DEFAULT_REPORT
from import_report import import_file, main as _main
from models import init_all_tables

if __name__ == "__main__":
    init_all_tables()
    print("==============================================")
    print(" 自动化漏洞管理与修复平台 - 多工具漏洞导入")
    print("==============================================")
    stats = import_file(DEFAULT_REPORT)
    print(
        f"完成 | 解析 {stats['total']} 条 | 新增 {stats.get('inserted', 0)} | "
        f"可自动修复 {stats['auto_fixable']} 条"
    )
