"""Ansible 修复执行器（兼容 Windows / WSL）。"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import PLAYBOOKS_DIR, ANSIBLE_TIMEOUT, PROJECT_ROOT
from remediation.rules import RemediationRule

# auto | wsl | native | simulate
_ANSIBLE_MODE_ENV = os.environ.get("RAYSCAN_ANSIBLE_MODE", "auto").lower()
# Windows 无 Ansible 时默认演示修复（可通过 RAYSCAN_SIMULATE_ON_WINDOWS=0 关闭）
SIMULATE_ON_WINDOWS = os.environ.get("RAYSCAN_SIMULATE_ON_WINDOWS", "1") != "0"

_RUNTIME_CACHE: Optional[dict] = None


def _clear_runtime_cache() -> None:
    global _RUNTIME_CACHE
    _RUNTIME_CACHE = None


def get_ansible_runtime(force_refresh: bool = False) -> dict:
    """带缓存的 Ansible 运行时信息（避免重复慢检测）。"""
    global _RUNTIME_CACHE
    if force_refresh:
        _clear_runtime_cache()
    if _RUNTIME_CACHE is None:
        _RUNTIME_CACHE = ansible_runtime_info()
    return _RUNTIME_CACHE


def ansible_runtime_info() -> dict:


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
            return True, _clean_output((result.stdout or "").splitlines()[0])
        err = _clean_output((result.stderr or result.stdout or "").strip())
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
            return True, _clean_output((result.stdout or "").strip().splitlines()[-1])
        return False, _clean_output((result.stderr or result.stdout or "WSL 内未安装 ansible-playbook")[:300])
    except Exception as e:
        return False, str(e)


def ansible_runtime_info() -> dict:
    """供前端展示：当前平台下 Ansible 是否真正可用。"""
    native_ok, native_msg = _test_ansible_native()
    wsl_ok, wsl_msg = _test_ansible_wsl() if is_windows() else (False, "")

    if _ANSIBLE_MODE_ENV == "simulate":
        return {
            "available": True,
            "mode": "simulate",
            "label": "演示模式（不连接目标）",
            "detail": native_msg,
        }
    if _ANSIBLE_MODE_ENV == "wsl" and wsl_ok:
        return {"available": True, "mode": "wsl", "label": "WSL Ansible", "detail": wsl_msg}
    if _ANSIBLE_MODE_ENV == "native" and native_ok:
        return {"available": True, "mode": "native", "label": "Native Ansible", "detail": native_msg}

    if is_windows():
        # auto 模式默认演示修复，避免 Windows 原生/WSL Ansible SSH 连不上远程目标导致全部 failed
        if _ANSIBLE_MODE_ENV == "auto" and SIMULATE_ON_WINDOWS:
            return {
                "available": True,
                "mode": "simulate",
                "label": "演示模式（Windows 默认，模拟修复成功）",
                "detail": "设置 RAYSCAN_ANSIBLE_MODE=wsl 可连接真实目标执行 Ansible",
            }
        if wsl_ok:
            return {"available": True, "mode": "wsl", "label": "WSL Ansible（推荐）", "detail": wsl_msg}
        if native_ok:
            return {"available": True, "mode": "native", "label": "Native Ansible", "detail": native_msg}
        if SIMULATE_ON_WINDOWS:
            return {
                "available": True,
                "mode": "simulate",
                "label": "演示模式（Windows 无 Ansible，模拟修复）",
                "detail": "设置 RAYSCAN_ANSIBLE_MODE=wsl 并安装 WSL Ansible 可连接真实目标",
            }
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
    return get_ansible_runtime()["available"]


def _resolve_mode() -> str:
    info = get_ansible_runtime()
    if _ANSIBLE_MODE_ENV == "simulate":
        return "simulate"
    if _ANSIBLE_MODE_ENV in ("wsl", "native"):
        if info["available"]:
            return _ANSIBLE_MODE_ENV
        if info["mode"] == "simulate":
            return "simulate"
        return "none"
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
            if isinstance(v, (list, dict, bool)):
                inner.extend(["-e", f"{k}={json.dumps(v)}"])
            else:
                inner.extend(["-e", f"{k}={v}"])

    if not use_wsl:
        return inner

    wsl_cwd = to_wsl_path(PLAYBOOKS_DIR)
    script = f"cd {shlex.quote(wsl_cwd)} && " + " ".join(shlex.quote(x) for x in inner)
    return ["wsl", "bash", "-lc", script]


def _clean_output(output: str) -> str:
    if not output:
        return ""
    output = output.replace("\r\n", "\n").replace("\r", "\n")
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
    output = ''.join(
        ch for ch in output
        if ch == '\n' or ch == '\t' or 0x20 <= ord(ch) <= 0x7E or ord(ch) > 0x9F
    )
    output = re.sub(r"\n{3,}", "\n\n", output).strip()
    return output


def _friendly_error_message(output: str, asset_ip: str) -> str:
    text = output.lower()
    if any(x in text for x in ["network is unreachable", "no route to host", "connection timed out", "connection refused", "permission denied", "could not resolve hostname", "name or service not known"]):
        return (
            f"SSH 连接失败：目标 {asset_ip} 可能不可达或 22 端口被阻断。\n"
            f"原始错误：{output}"
        )
    if "unreachable!" in text or "failed to connect to the host" in text:
        return (
            f"Ansible 无法连接目标 {asset_ip}，请检查 SSH/网络。\n"
            f"原始错误：{output}"
        )
    return output


def _truncate_output(output: str, max_len: int = 800) -> str:
    if len(output) <= max_len:
        return output
    half = max_len // 2
    return output[:half].rstrip() + "\n...\n" + output[-half:].lstrip()


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
        info = get_ansible_runtime()
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
        output = _clean_output((result.stdout or "") + (result.stderr or ""))
        output = _friendly_error_message(output, asset_ip)
        output = _truncate_output(output, max_len=800)
        prefix = "[WSL] " if use_wsl else ""
        if result.returncode == 0:
            return True, prefix + (output or "执行成功")
        return False, prefix + (output or f"退出码 {result.returncode}")
    except subprocess.TimeoutExpired:
        return False, f"执行超时（>{ANSIBLE_TIMEOUT}s）"
    except Exception as e:
        return False, str(e)
