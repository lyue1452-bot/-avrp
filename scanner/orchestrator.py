"""扫描编排核心 — 运行多工具扫描，结果入库，触发自动修复。"""
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

from config import PROJECT_ROOT, GITLEAKS_TIMEOUT, TRIVY_TIMEOUT
from models import (
    create_scan_job, update_scan_job, get_scan_job,
    upsert_vulnerability,
)
from adapters import parse_report
from remediation.rules import classify_record, REMEDIATION_RULES
from remediation.fix_runner import run_batch_fix_for_host
from scanner.target_utils import parse_scan_target, is_windows, tool_available, resolve_tool_cmd
from scanner.web_probe import scan_web_target, write_probe_report, BUILTIN_WEB_SCANNER
from scanner.weakpass_probe import probe_weak_services
from scanner.db_probe import probe_database_exposure
from scanner.tool_installer import install_missing_tools, missing_installable_tools
from scanner.scan_scope import resolve_gitleaks_source, resolve_trivy_scan

logger = logging.getLogger(__name__)

AUTO_INSTALL_TOOLS = os.environ.get("RAYSCAN_AUTO_INSTALL_TOOLS", "1") != "0"


@dataclass
class ScanConfig:
    target: str
    tools: List[str] = field(default_factory=list)
    auto_fix: bool = False
    extra_args: Dict = field(default_factory=dict)


TOOL_LABELS = {
    "nmap": "Nmap 端口扫描",
    "zap": "ZAP Web 扫描",
    "gitleaks": "Gitleaks 密钥扫描",
    "trivy": "Trivy 容器/系统扫描",
    "weakpass": "弱口令检测",
    "db_scan": "数据库安全扫描",
}


def _records_to_stats(records, tool: str, target: str) -> dict:
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


def _import_file(path: Path, tool: str, target: str) -> dict:
    records, detected = parse_report(path)
    return _records_to_stats(records, tool or detected, target)


# ──────────────── 扫描器 Runner ────────────────

def _run_nmap(target: str) -> dict:
    host, _, _, kind = parse_scan_target(target)
    if kind == "path":
        return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0, "error": "Nmap 需要 IP/域名目标"}

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    nmap_bin = resolve_tool_cmd("nmap") or "nmap"
    if is_windows():
        cmd = [nmap_bin, "-Pn", "-sT", "-sV", "--top-ports", "100", "-oX", xml_path, host]
    else:
        cmd = [nmap_bin, "-Pn", "-sS", "-sV", "--top-ports", "100", "-oX", xml_path, host]

    logger.info("运行: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        logger.warning("nmap stderr: %s", (result.stderr or "")[:400])

    stats = {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}
    if Path(xml_path).exists() and Path(xml_path).stat().st_size > 100:
        stats = _import_file(Path(xml_path), "nmap", host)
    Path(xml_path).unlink(missing_ok=True)
    return stats


def _run_zap(target: str) -> dict:
    host, port, scan_url, kind = parse_scan_target(target)
    web_url = scan_url if kind == "url" else f"http://{host}"

    # Docker ZAP 全量扫描（耗时长；Windows 默认跳过，避免权限/挂起问题）
    use_docker_zap = __import__("os").environ.get("RAYSCAN_USE_DOCKER_ZAP", "0") == "1"
    if use_docker_zap and not is_windows() and shutil.which("docker"):
        tmp_dir = Path(tempfile.mkdtemp(prefix="rayscan_zap_"))
        report = tmp_dir / "zap_report.json"
        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmp_dir}:/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-full-scan.py", "-t", web_url, "-J", "zap_report.json",
            ]
            logger.info("运行 Docker ZAP: %s", web_url)
            subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            if report.exists() and report.stat().st_size > 10:
                try:
                    return _import_file(report, "zap", web_url)
                except (PermissionError, OSError, ValueError) as e:
                    logger.warning("读取 ZAP 报告失败: %s", e)
        except subprocess.TimeoutExpired:
            logger.warning("ZAP Docker 扫描超时，回退内置探测")
        finally:
            import shutil as _sh
            _sh.rmtree(tmp_dir, ignore_errors=True)

    # 本地 zap-full-scan.py（Windows 跳过，避免 Permission denied）
    if not is_windows():
        zap_script = shutil.which("zap-full-scan.py")
        if zap_script:
            report_path = Path(tempfile.mkdtemp(prefix="rayscan_zap_")) / "zap_report.json"
            try:
                cmd = [zap_script, "-t", web_url, "-J", str(report_path)]
                subprocess.run(cmd, capture_output=True, text=True, timeout=900)
                if report_path.exists() and report_path.stat().st_size > 10:
                    return _import_file(report_path, "zap", web_url)
            except (PermissionError, OSError, ValueError):
                pass

    # 内置 Web 探测（Windows 默认路径，无需 ZAP）
    logger.info("使用内置 Web 安全探测: %s", web_url)
    records = scan_web_target(web_url)
    return _records_to_stats(records, BUILTIN_WEB_SCANNER, web_url)


def _run_gitleaks(target: str) -> dict:
    source, reason = resolve_gitleaks_source(target)
    logger.info("Gitleaks: %s", reason)

    if not resolve_tool_cmd("gitleaks"):
        raise FileNotFoundError("gitleaks")

    gitleaks_bin = resolve_tool_cmd("gitleaks")
    src_path = Path(source)
    if src_path.is_dir() and not any(src_path.iterdir()):
        return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0, "note": reason}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name
    cmd = [
        gitleaks_bin, "detect", "--source", source,
        "--report-format", "json", "--report-path", report_path,
        "--no-git", "--exit-code", "0",
    ]
    logger.info("运行: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT)
    except subprocess.TimeoutExpired:
        if Path(report_path).exists() and Path(report_path).stat().st_size > 2:
            stats = _import_file(Path(report_path), "gitleaks", source)
            stats["warning"] = f"扫描超时（>{GITLEAKS_TIMEOUT}s），已导入部分结果"
            Path(report_path).unlink(missing_ok=True)
            return stats
        raise

    stats = {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}
    if Path(report_path).exists() and Path(report_path).stat().st_size > 2:
        stats = _import_file(Path(report_path), "gitleaks", source)
    Path(report_path).unlink(missing_ok=True)
    return stats


def _run_trivy(target: str) -> dict:
    if not resolve_tool_cmd("trivy"):
        raise FileNotFoundError("trivy")

    trivy_bin = resolve_tool_cmd("trivy")
    host, _, _, kind = parse_scan_target(target)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    if kind == "image":
        cmd = [trivy_bin, "image", "--format", "json", "-o", report_path, target]
        reason = f"扫描容器镜像 {target}"
    else:
        scan_paths, skip_dirs, reason = resolve_trivy_scan(target)
        logger.info("Trivy: %s", reason)
        if not scan_paths:
            Path(report_path).unlink(missing_ok=True)
            return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}

        cmd = [trivy_bin, "fs", "--format", "json", "-o", report_path, "--scanners", "vuln"]
        for d in skip_dirs:
            cmd.extend(["--skip-dirs", d])
        cmd.extend(scan_paths)

    logger.info("运行: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=TRIVY_TIMEOUT)
    except subprocess.TimeoutExpired:
        if Path(report_path).exists() and Path(report_path).stat().st_size > 2:
            stats = _import_file(Path(report_path), "trivy", target)
            stats["warning"] = f"扫描超时（>{TRIVY_TIMEOUT}s），已导入部分结果"
            Path(report_path).unlink(missing_ok=True)
            return stats
        raise

    stats = {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}
    if Path(report_path).exists() and Path(report_path).stat().st_size > 2:
        stats = _import_file(Path(report_path), "trivy", target)
    Path(report_path).unlink(missing_ok=True)
    return stats


def _run_weakpass(target: str) -> dict:
    host, _, _, kind = parse_scan_target(target)
    if kind == "path":
        path = Path(target)
        if path.exists() and path.suffix.lower() == ".json":
            return _import_file(path, "weakpass", target)
        return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}

    records = probe_weak_services(host)
    return _records_to_stats(records, "weakpass", host)


def _run_db_scan(target: str) -> dict:
    host, _, _, kind = parse_scan_target(target)
    if kind == "path":
        path = Path(target)
        if path.exists() and path.suffix.lower() == ".json":
            return _import_file(path, "db_scan", target)
        return {"total": 0, "inserted": 0, "updated": 0, "auto_fixable": 0}

    records = probe_database_exposure(host)
    return _records_to_stats(records, "db_scan", host)


SCANNER_RUNNERS: Dict[str, Callable] = {
    "nmap": _run_nmap,
    "zap": _run_zap,
    "gitleaks": _run_gitleaks,
    "trivy": _run_trivy,
    "weakpass": _run_weakpass,
    "db_scan": _run_db_scan,
}

ALL_TOOLS = list(SCANNER_RUNNERS.keys())


def _run_auto_fix(target: str, stats: dict) -> dict:
    fix_stats = {"total": stats.get("auto_fixable", 0), "fixed": 0, "failed": 0, "skipped": 0}
    if not ansible_available():
        fix_stats["skipped"] = fix_stats["total"]
        fix_stats["msg"] = "Ansible 不可用，跳过自动修复"
        return fix_stats

    host, _, _, _ = parse_scan_target(target)
    reclassify_vulnerabilities(asset_ip=host)

    from models import get_connection, update_fix_status
    conn = get_connection()
    conn.execute(
        "UPDATE vulnerabilities SET fix_status='auto_fixable' "
        "WHERE asset_ip=? AND auto_fixable=1 AND fix_status='failed'",
        (host,),
    )
    conn.commit()
    rows = conn.execute(
        "SELECT * FROM vulnerabilities "
        "WHERE asset_ip=? AND auto_fixable=1 AND fix_status IN ('auto_fixable','pending','failed')",
        (host,),
    ).fetchall()
    conn.close()

    fix_stats["total"] = len(rows)
    runtime = ansible_runtime_info()

    for row in rows:
        rule_id = row["remediation_rule"]
        rule = next((r for r in REMEDIATION_RULES if r.rule_id == rule_id), None)
        if not rule:
            fix_stats["skipped"] += 1
            continue
        extra = extra_vars_to_cli(build_extra_vars(row))
        ok, output = run_playbook(rule, row["asset_ip"], extra_vars=extra)
        if runtime.get("mode") == "simulate":
            output = f"[{runtime['label']}] {output}"
        status = "fixed" if ok else "failed"
        update_fix_status(row["id"], status, output)
        if ok:
            fix_stats["fixed"] += 1
        else:
            fix_stats["failed"] += 1
    return fix_stats


def _determine_tools(target: str, preferred: List[str]) -> List[str]:
    if preferred:
        return [t for t in preferred if t in SCANNER_RUNNERS]
    return list(SCANNER_RUNNERS.keys())


def _ensure_tools_installed(tools: List[str]) -> None:
    """扫描前尝试自动安装缺失工具。"""
    need = [t for t in tools if t in ("nmap", "gitleaks", "trivy")]
    missing = missing_installable_tools(need)
    if not missing:
        return
    if not AUTO_INSTALL_TOOLS:
        logger.info("缺失工具 %s，自动安装已关闭（RAYSCAN_AUTO_INSTALL_TOOLS=0）", missing)
        return
    logger.info("尝试自动安装缺失工具: %s", missing)
    install_missing_tools(missing)


def start_scan(target: str, tools: Optional[List[str]] = None,
               auto_fix: bool = False, created_by: str = "") -> int:
    tool_list = _determine_tools(target, tools or [])
    _ensure_tools_installed(tool_list)
    job_id = create_scan_job(target, tool_list, auto_fix, created_by)
    thread = threading.Thread(
        target=_run_scan_worker,
        args=(job_id, target, tool_list, auto_fix),
        daemon=True,
    )
    thread.start()
    return job_id


def _run_scan_worker(job_id: int, target: str, tools: List[str], auto_fix: bool):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        update_scan_job(job_id, status="running", started_at=now)
        progress = {t: "pending" for t in tools}
        update_scan_job(job_id, progress=progress)

        job_results = {}
        summary_parts = []

        for tool in tools:
            job = get_scan_job(job_id)
            if job and job["status"] == "cancelled":
                summary_parts.append("扫描已取消")
                break

            progress[tool] = "running"
            update_scan_job(job_id, progress=progress)

            runner = SCANNER_RUNNERS.get(tool)
            if not runner:
                progress[tool] = "failed"
                job_results[tool] = {"total": 0, "error": "未知扫描器"}
                update_scan_job(job_id, progress=progress, results=dict(**job_results))
                continue

            try:
                stats = runner(target)
                if stats.get("error"):
                    progress[tool] = "failed"
                    job_results[tool] = stats
                    summary_parts.append(f"{TOOL_LABELS.get(tool, tool)}: {stats['error']}")
                else:
                    progress[tool] = "completed"
                    job_results[tool] = stats
                    if auto_fix and stats.get("auto_fixable", 0) > 0:
                        fix = _run_auto_fix(target, stats)
                        part = (
                            f"{TOOL_LABELS.get(tool, tool)}: 发现 {stats['total']} 条, "
                            f"自动修复 {fix.get('fixed', 0)}/{fix.get('total', 0)} 条"
                        )
                    else:
                        part = (
                            f"{TOOL_LABELS.get(tool, tool)}: 发现 {stats['total']} 条, "
                            f"可自动修复 {stats.get('auto_fixable', 0)} 条"
                        )
                    summary_parts.append(part)

            except subprocess.TimeoutExpired:
                progress[tool] = "failed"
                hint = "执行超时（非未安装）"
                if tool == "gitleaks":
                    hint = f"执行超时（>{GITLEAKS_TIMEOUT}s）；URL 目标仅扫 uploads/，可增大 RAYSCAN_GITLEAKS_TIMEOUT"
                elif tool == "trivy":
                    hint = f"执行超时（>{TRIVY_TIMEOUT}s）；已跳过 node_modules，可增大 RAYSCAN_TRIVY_TIMEOUT"
                job_results[tool] = {"total": 0, "error": hint}
                summary_parts.append(f"{TOOL_LABELS.get(tool, tool)}: 超时")

            except FileNotFoundError:
                progress[tool] = "failed"
                job_results[tool] = {"total": 0, "error": "工具未安装"}
                summary_parts.append(f"{TOOL_LABELS.get(tool, tool)}: 工具未安装")

            except Exception as e:
                progress[tool] = "failed"
                job_results[tool] = {"total": 0, "error": str(e)[:200]}
                summary_parts.append(f"{TOOL_LABELS.get(tool, tool)}: {str(e)[:80]}")
                logger.exception("扫描器 %s 执行失败", tool)

            update_scan_job(job_id, progress=progress, results=dict(**job_results))

        finish_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        host, _, _, _ = parse_scan_target(target)
        reclassify_vulnerabilities(asset_ip=host)
        update_scan_job(job_id, status="completed", summary=" | ".join(summary_parts), finished_at=finish_time)

    except Exception as e:
        logger.exception("扫描任务 %s 异常", job_id)
        finish_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_scan_job(job_id, status="failed", summary=f"扫描异常: {str(e)[:200]}", finished_at=finish_time)


def cancel_scan(job_id: int) -> bool:
    job = get_scan_job(job_id)
    if not job or job["status"] not in ("pending", "running"):
        return False
    update_scan_job(job_id, status="cancelled")
    return True


def get_scan_status(job_id: int):
    return get_scan_job(job_id)
