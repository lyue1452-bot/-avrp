#!/usr/bin/env python3
"""本地扫描 CLI — 调用外部工具并将结果导入漏洞数据库。"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from config import PROJECT_ROOT
from models import init_all_tables, upsert_vulnerability
from adapters import parse_report
from remediation.rules import classify_record


def run_trivy(target: str, args: List[str]) -> dict:
    """执行 Trivy 扫描。"""
    cmd = ["trivy", "image", "--format", "json", target] + args
    print(f"运行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"Trivy 错误: {result.stderr[:500]}")
    return _import_json_result(result.stdout, "trivy", target)


def run_nmap(target: str, args: List[str]) -> dict:
    """执行 nmap 扫描。"""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as f:
        xml_path = f.name
    cmd = ["nmap", "-oX", xml_path, target] + args
    print(f"运行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"nmap 错误: {result.stderr[:500]}")
    stats = _import_file(Path(xml_path), "nmap", target)
    Path(xml_path).unlink(missing_ok=True)
    return stats


def run_gitleaks(target: str, args: List[str]) -> dict:
    """执行 Gitleaks 扫描。"""
    path = target or "."
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        report_path = f.name
    cmd = ["gitleaks", "detect", "--source", path, "--report-format", "json",
           "--report-path", report_path] + [a for a in args if a != "--format"]
    print(f"运行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if Path(report_path).exists():
        stats = _import_file(Path(report_path), "gitleaks", path)
        Path(report_path).unlink(missing_ok=True)
        return stats
    print(f"Gitleaks 输出: {result.stdout[:300]}")
    return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}


def run_zap(target: str, args: List[str]) -> dict:
    """执行 OWASP ZAP 扫描。"""
    cmd = ["zap-full-scan.py", "-t", target, "-r", "zap_report.json"] + args
    print(f"运行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    report_path = Path("zap_report.json")
    if report_path.exists():
        stats = _import_file(report_path, "zap", target)
        report_path.unlink(missing_ok=True)
        return stats
    print(f"ZAP 输出: {(result.stdout or '')[:300]}")
    return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}


def run_weakpass(target: str, args: List[str]) -> dict:
    """执行弱口令检测（自定义脚本或 hydra 结果解析）。

    预期接收一个 JSON 文件路径作为 target，或直接传入扫描结果。
    """
    path = Path(target)
    if path.exists():
        return _import_file(path, "weakpass", target)
    print(f"弱口令扫描文件不存在: {target}")
    return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}


def run_db_scan(target: str, args: List[str]) -> dict:
    """执行数据库扫描。

    预期接收一个 JSON 文件路径作为 target，或直接传入扫描结果。
    """
    path = Path(target)
    if path.exists():
        return _import_file(path, "db_scan", target)
    # 尝试连接数据库进行基础检查
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "db_check.py"), target] + args
    if Path(cmd[2]).exists():
        print(f"运行: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and result.stdout.strip():
            return _import_json_result(result.stdout, "db_scan", target)
    print(f"数据库扫描文件不存在: {target}")
    return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}


def _import_json_result(json_str: str, tool: str, target: str) -> dict:
    """将 JSON 字符串写入临时文件，通过适配器解析导入。"""
    data = json.loads(json_str)
    records, detected = parse_report_from_data(data, tool)
    return _save_records(records, tool, target)


def _import_file(path: Path, tool: str, target: str) -> dict:
    """通过适配器解析文件并导入。"""
    records, detected = parse_report(path)
    return _save_records(records, tool or detected, target)


def parse_report_from_data(data, tool: str):
    """直接从 Python 对象解析。"""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump(data, f, ensure_ascii=False)
        tmp = f.name
    try:
        records, detected = parse_report(Path(tmp))
        return records, detected
    finally:
        Path(tmp).unlink(missing_ok=True)


def _save_records(records, tool: str, target: str) -> dict:
    """将解析结果写入数据库。"""
    stats = {"total": len(records), "inserted": 0, "updated": 0, "auto_fixable": 0}
    for rec in records:
        if not rec.source_tool or rec.source_tool in ("unknown", "generic"):
            rec.source_tool = tool
        rule, auto = classify_record(rec)
        rule_id = rule.rule_id if rule else ""
        if auto:
            stats["auto_fixable"] += 1
        result = upsert_vulnerability(rec, remediation_rule=rule_id, auto_fixable=auto)
        stats[result] = stats.get(result, 0) + 1
    return stats


SCANNERS = {
    "trivy": run_trivy,
    "nmap": run_nmap,
    "gitleaks": run_gitleaks,
    "zap": run_zap,
    "weakpass": run_weakpass,
    "db": run_db_scan,
}


def main():
    parser = argparse.ArgumentParser(description="RayScan 本地扫描 CLI")
    parser.add_argument("scanner", choices=list(SCANNERS.keys()) + ["list"],
                        help="扫描器名称，或 list 查看可用扫描器")
    parser.add_argument("--target", "-t", default="", help="扫描目标")
    parser.add_argument("args", nargs=argparse.REMAINDER,
                        help="传递给扫描器的额外参数")

    args = parser.parse_args()

    if args.scanner == "list":
        print("可用扫描器:")
        for name in SCANNERS:
            print(f"  {name}")
        return

    init_all_tables()
    target = args.target or input(f"请输入 {args.scanner} 扫描目标: ").strip()
    extra_args = args.args or []

    runner = SCANNERS[args.scanner]
    stats = runner(target, extra_args)

    print(f"\n扫描完成: {args.scanner}")
    print(f"  解析 {stats['total']} 条")
    print(f"  新增 {stats.get('inserted', 0)} 条")
    print(f"  更新 {stats.get('updated', 0)} 条")
    print(f"  可自动修复 {stats['auto_fixable']} 条")


if __name__ == "__main__":
    main()