"""Ansible 修复执行器（兼容 Windows / WSL）。"""
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import PLAYBOOKS_DIR, ANSIBLE_TIMEOUT, PROJECT_ROOT
from remediation.rules import RemediationRule

# auto | wsl | native | simulate
ANSIBLE_MODE = os.environ.get("RAYSCAN_ANSIBLE_MODE", "auto").lower()


def is_windows() -> bool:
    return sys.platform.startswith("win")


def wsl_available() -> bool:
    return shutil.which("wsl") is not None


def to_wsl_path(path: Path) -> str:
    p = str(path.resolve())
    if len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        return f"/mnt/{drive}{p[2:].replace(chr(92), '/')}"
    return p.replace("\\", "/")


def _test_ansible_native() -> Tuple[bool, str]:
    exe = shutil.which("ansible-playbook")
    if not exe:
        return False, "未找到 ansible-playbook"
    try:
        result = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0:
            return True, (result.stdout or "").splitlines()[0]
        err = (result.stderr or result.stdout or "").strip()
        return False, err[:300]
    except Exception as e:
        return False, str(e)


def _test_ansible_wsl() -> Tuple[bool, str]:
    if not wsl_available():
        return False, "未安装 WSL"
    try:
        result = subprocess.run(
            ["wsl", "bash", "-lc", "command -v ansible-playbook && ansible-playbook --version | head -1"],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode == 0 and "ansible-playbook" in (result.stdout or ""):
            return True, (result.stdout or "").strip().splitlines()[-1]
        return False, (result.stderr or result.stdout or "WSL 内未安装 ansible-playbook")[:300]
    except Exception as e:
        return False, str(e)


def ansible_runtime_info() -> dict:
    """供前端展示：当前平台下 Ansible 是否真正可用。"""
    native_ok, native_msg = _test_ansible_native()
    wsl_ok, wsl_msg = _test_ansible_wsl() if is_windows() else (False, "")

    if ANSIBLE_MODE == "simulate":
        return {
            "available": True,
            "mode": "simulate",
            "label": "演示模式（不连接目标）",
            "detail": native_msg,
        }
    if ANSIBLE_MODE == "wsl" and wsl_ok:
        return {"available": True, "mode": "wsl", "label": "WSL Ansible", "detail": wsl_msg}
    if ANSIBLE_MODE == "native" and native_ok:
        return {"available": True, "mode": "native", "label": "Native Ansible", "detail": native_msg}

    if is_windows():
        if wsl_ok:
            return {"available": True, "mode": "wsl", "label": "WSL Ansible（推荐）", "detail": wsl_msg}
        if native_ok:
            return {"available": True, "mode": "native", "label": "Native Ansible", "detail": native_msg}
        return {
            "available": False,
            "mode": "none",
            "label": "不可用",
            "detail": (
                "Windows 原生 Ansible 存在兼容性问题（os.get_blocking）。"
                "请在 WSL 中运行本项目，或在 WSL 内安装 ansible，"
                "或设置环境变量 RAYSCAN_ANSIBLE_MODE=simulate 启用演示模式。"
                f" 原生检测: {native_msg[:120]}"
            ),
        }

    if native_ok:
        return {"available": True, "mode": "native", "label": "Ansible", "detail": native_msg}
    return {"available": False, "mode": "none", "label": "未安装", "detail": native_msg}


def ansible_available() -> bool:
    return ansible_runtime_info()["available"]


def _resolve_mode() -> str:
    info = ansible_runtime_info()
    if ANSIBLE_MODE == "simulate":
        return "simulate"
    if ANSIBLE_MODE in ("wsl", "native"):
        return ANSIBLE_MODE if info["available"] or ANSIBLE_MODE == "simulate" else info["mode"]
    return info["mode"] if info["available"] else "none"


def _build_playbook_cmd(
    playbook: Path,
    asset_ip: str,
    extra_vars: Optional[Dict],
    use_wsl: bool,
) -> List[str]:
    pb = to_wsl_path(playbook) if use_wsl else str(playbook)
    inner = [
        "ansible-playbook",
        pb,
        "-i", f"{asset_ip},",
        "--ssh-common-args", "-o StrictHostKeyChecking=no",
    ]
    if extra_vars:
        for k, v in extra_vars.items():
            inner.extend(["-e", f"{k}={v}"])

    if not use_wsl:
        return inner

    wsl_cwd = to_wsl_path(PLAYBOOKS_DIR)
    script = f"cd {shlex.quote(wsl_cwd)} && " + " ".join(shlex.quote(x) for x in inner)
    return ["wsl", "bash", "-lc", script]


def run_playbook(
    rule: RemediationRule,
    asset_ip: str,
    extra_vars: Optional[Dict] = None,
) -> Tuple[bool, str]:
    playbook = PLAYBOOKS_DIR / rule.playbook
    if not playbook.exists():
        return False, f"剧本不存在: {playbook}"

    mode = _resolve_mode()
    if mode == "none":
        info = ansible_runtime_info()
        return False, info["detail"]

    if mode == "simulate":
        return True, (
            f"[演示模式] 已模拟修复 {asset_ip} | 规则: {rule.rule_id} | "
            f"剧本: {rule.playbook}（未实际 SSH 连接目标，Windows 本地演示用）"
        )

    use_wsl = mode == "wsl"
    cmd = _build_playbook_cmd(playbook, asset_ip, extra_vars, use_wsl=use_wsl)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ANSIBLE_TIMEOUT,
            cwd=str(PLAYBOOKS_DIR) if not use_wsl else str(PROJECT_ROOT),
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            prefix = "[WSL] " if use_wsl else ""
            return True, prefix + (output[-800:] or "执行成功")
        return False, output[-800:] or f"退出码 {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"执行超时（>{ANSIBLE_TIMEOUT}s）"
    except Exception as e:
        return False, str(e)
