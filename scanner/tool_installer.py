"""扫描工具检测与自动安装（Windows 优先 winget）。"""
import logging
import shutil
import subprocess
from typing import Dict, List, Optional

from scanner.target_utils import is_windows, resolve_tool_cmd, tool_available

logger = logging.getLogger(__name__)

# 可自动安装的工具（ZAP/weakpass/db_scan 使用内置能力，无需安装）
INSTALLABLE: Dict[str, Dict] = {
    "gitleaks": {
        "winget_id": "Gitleaks.Gitleaks",
        "label": "Gitleaks 密钥扫描",
        "manual": "winget install Gitleaks.Gitleaks",
        "url": "https://github.com/gitleaks/gitleaks",
    },
    "trivy": {
        "winget_id": "AquaSecurity.Trivy",
        "label": "Trivy 容器/系统扫描",
        "manual": "winget install AquaSecurity.Trivy",
        "url": "https://github.com/aquasecurity/trivy",
    },
    "nmap": {
        "winget_id": "Insecure.Nmap",
        "label": "Nmap 端口扫描",
        "manual": "从 https://nmap.org/download.html 安装，或 winget install Insecure.Nmap",
        "url": "https://nmap.org/download.html",
    },
}


def tool_detail(tool_id: str) -> Dict:
    """返回单个工具的安装状态与路径。"""
    path = resolve_tool_cmd(tool_id)
    info = INSTALLABLE.get(tool_id, {})
    return {
        "id": tool_id,
        "installed": tool_available(tool_id),
        "path": path or "",
        "auto_installable": tool_id in INSTALLABLE,
        "manual": info.get("manual", ""),
        "url": info.get("url", ""),
    }


def missing_installable_tools(tool_ids: Optional[List[str]] = None) -> List[str]:
    ids = tool_ids or list(INSTALLABLE.keys())
    return [t for t in ids if t in INSTALLABLE and not tool_available(t)]


def _run_winget_install(package_id: str, timeout: int = 600) -> tuple:
    winget = shutil.which("winget")
    if not winget:
        return False, "未找到 winget，请手动安装 Microsoft App Installer"
    cmd = [
        winget, "install", "--id", package_id,
        "-e", "--accept-source-agreements", "--accept-package-agreements",
    ]
    logger.info("执行: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        output = ((result.stdout or "") + (result.stderr or "")).strip()[:500]
        if result.returncode == 0 or "已成功安装" in output or "already installed" in output.lower():
            return True, output or "安装完成"
        return False, output or f"winget 退出码 {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"安装超时（>{timeout}s）"
    except Exception as e:
        return False, str(e)


def install_tool(tool_id: str) -> Dict:
    """安装单个工具，返回结果字典。"""
    if tool_id not in INSTALLABLE:
        return {
            "ok": False,
            "tool": tool_id,
            "msg": "该工具不支持自动安装",
            "manual": "",
        }

    if tool_available(tool_id):
        return {
            "ok": True,
            "tool": tool_id,
            "msg": "已安装",
            "path": resolve_tool_cmd(tool_id),
        }

    if not is_windows():
        info = INSTALLABLE[tool_id]
        return {
            "ok": False,
            "tool": tool_id,
            "msg": "非 Windows 环境请手动安装",
            "manual": info["manual"],
            "url": info["url"],
        }

    ok, output = _run_winget_install(INSTALLABLE[tool_id]["winget_id"])
    path = resolve_tool_cmd(tool_id)
    if ok and path:
        return {"ok": True, "tool": tool_id, "msg": "安装成功", "path": path, "detail": output}
    if ok and not path:
        return {
            "ok": True,
            "tool": tool_id,
            "msg": "winget 报告安装成功，但需重启终端/后端后才能识别路径",
            "detail": output,
            "manual": INSTALLABLE[tool_id]["manual"],
        }
    return {
        "ok": False,
        "tool": tool_id,
        "msg": output,
        "manual": INSTALLABLE[tool_id]["manual"],
        "url": INSTALLABLE[tool_id]["url"],
    }


def install_missing_tools(tool_ids: Optional[List[str]] = None) -> Dict:
    """批量安装缺失工具。"""
    missing = missing_installable_tools(tool_ids)
    results = []
    for tool_id in missing:
        results.append(install_tool(tool_id))
    return {
        "missing_before": missing,
        "results": results,
        "all_installed": len(missing_installable_tools(tool_ids)) == 0,
    }
