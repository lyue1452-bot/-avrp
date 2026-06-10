"""扫描目标解析与工具可用性检测。"""
import os
import shutil
import sys
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse


def parse_scan_target(target: str) -> Tuple[str, Optional[int], str, str]:
    """
    解析扫描目标。
    返回: (host_or_ip, port, scan_url, target_kind)
    target_kind: url | ip | path | image
    """
    target = (target or "").strip()
    if not target:
        return "unknown", None, "", "ip"

    if target.startswith(("http://", "https://")):
        p = urlparse(target)
        host = p.hostname or "unknown"
        port = p.port or (443 if p.scheme == "https" else 80)
        return host, port, target, "url"

    if "/" in target and not target.startswith("/"):
        # 可能是 192.168.1.1/path 形式
        host_part = target.split("/")[0]
        if ":" in host_part and not host_part.count(":") > 1:
            host, _, port_s = host_part.partition(":")
            try:
                return host, int(port_s), f"http://{host_part}", "url"
            except ValueError:
                pass
        return host_part, None, f"http://{target}", "url"

    from pathlib import Path
    if Path(target).exists():
        return target, None, target, "path"

    # Docker 镜像名 image:tag
    if ":" in target and target.count("/") <= 1 and not target.replace(".", "").replace(":", "").isdigit():
        return target, None, target, "image"

    # 纯 IP 或 hostname
    host = target.split(":")[0]
    port = None
    if ":" in target:
        try:
            port = int(target.split(":")[1])
        except ValueError:
            pass
    return host, port, f"http://{host}" if port is None else f"http://{host}:{port}", "ip"


def is_windows() -> bool:
    return sys.platform.startswith("win")


def _find_winget_exe(name: str) -> Optional[str]:
    """在 WinGet Packages 目录查找已安装 CLI。"""
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return None
    packages = Path(local) / "Microsoft" / "WinGet" / "Packages"
    if not packages.is_dir():
        return None
    exe_name = f"{name}.exe"
    for pkg_dir in packages.iterdir():
        if name.lower() not in pkg_dir.name.lower():
            continue
        for exe in pkg_dir.rglob(exe_name):
            if exe.is_file():
                return str(exe)
    return None


def resolve_tool_cmd(name: str) -> Optional[str]:
    """解析工具可执行路径（含 Windows 常见安装目录）。"""
    path = shutil.which(name)
    if path:
        return path
    if is_windows():
        winget = _find_winget_exe(name)
        if winget:
            return winget
        candidates = {
            "nmap": [
                r"D:\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ],
            "gitleaks": [
                r"C:\Program Files\Gitleaks\gitleaks.exe",
            ],
            "trivy": [
                r"C:\Program Files\Trivy\trivy.exe",
            ],
        }
        for p in candidates.get(name, []):
            if Path(p).exists():
                return p
    return None


def tool_available(name: str) -> bool:
    """检测 CLI 工具是否可用。"""
    if name == "zap":
        if resolve_tool_cmd("zap-full-scan.py"):
            return True
        return shutil.which("docker") is not None
    if name in ("weakpass", "db_scan"):
        return True
    return resolve_tool_cmd(name) is not None


def tool_status() -> dict:
    return {
        "nmap": {"installed": tool_available("nmap"), "label": "Nmap 端口扫描"},
        "zap": {"installed": True, "label": "ZAP Web 扫描", "note": "无 ZAP/Docker 时使用内置 Web 探测"},
        "gitleaks": {"installed": tool_available("gitleaks"), "label": "Gitleaks 密钥扫描"},
        "trivy": {"installed": tool_available("trivy"), "label": "Trivy 容器/系统扫描"},
        "weakpass": {"installed": True, "label": "弱口令检测", "note": "内置端口与服务探测"},
        "db_scan": {"installed": True, "label": "数据库安全扫描", "note": "内置数据库暴露检测"},
        "web_probe": {"installed": True, "label": "内置 Web 安全探测"},
    }
