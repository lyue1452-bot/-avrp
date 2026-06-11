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

from config import PLAYBOOKS_DIR, ANSIBLE_TIMEOUT, PROJECT_ROOT, ANSIBLE_USER, SIMULATE_ON_WINDOWS
from remediation.rules import RemediationRule, get_playbook_for_target
from remediation.target_os import detect_target_os

# Windows 无 Ansible 时默认演示修复（可通过 RAYSCAN_SIMULATE_ON_WINDOWS=0 关闭）

_RUNTIME_CACHE: Optional[dict] = None


def _ansible_mode_env() -> str:
    return os.environ.get("RAYSCAN_ANSIBLE_MODE", "auto").lower()


def _simulate_on_windows() -> bool:
    return SIMULATE_ON_WINDOWS or os.environ.get("RAYSCAN_SIMULATE_ON_WINDOWS", "0") == "1"


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

    mode_env = _ansible_mode_env()
    sim_win = _simulate_on_windows()

    if mode_env == "simulate":
        return {
            "available": True,
            "mode": "simulate",
            "label": "演示模式（不连接目标）",
            "detail": native_msg,
        }
    if mode_env == "wsl" and wsl_ok:
        return {"available": True, "mode": "wsl", "label": "WSL Ansible（真实修复）", "detail": wsl_msg}
    if mode_env == "native" and native_ok:
        return {"available": True, "mode": "native", "label": "Native Ansible", "detail": native_msg}

    if is_windows():
        if wsl_ok:
            return {"available": True, "mode": "wsl", "label": "WSL Ansible（真实修复）", "detail": wsl_msg}
        if native_ok:
            return {"available": True, "mode": "native", "label": "Native Ansible", "detail": native_msg}
        if sim_win:
            return {
                "available": True,
                "mode": "simulate",
                "label": "演示模式（需显式开启）",
                "detail": "设置 RAYSCAN_SIMULATE_ON_WINDOWS=1 或 RAYSCAN_ANSIBLE_MODE=simulate 才启用",
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
    mode_env = _ansible_mode_env()
    info = get_ansible_runtime(force_refresh=True)
    if mode_env == "simulate":
        return "simulate"
    # 显式要求 wsl/native 时绝不回退演示模式
    if mode_env == "wsl":
        return "wsl" if info.get("mode") == "wsl" or wsl_available() else "none"
    if mode_env == "native":
        return "native" if info.get("mode") == "native" else "none"
    if mode_env == "auto":
        if is_windows() and wsl_available():
            wsl_ok, _ = _test_ansible_wsl()
            if wsl_ok:
                return "wsl"
        if info.get("mode") in ("wsl", "native"):
            return info["mode"]
        return "none"
    mode = info.get("mode")
    if mode == "simulate" and not _simulate_on_windows() and mode_env != "simulate":
        return "none"
    return mode if info.get("available") and mode != "simulate" else "none"


def _connection_extra_vars(asset_ip: str) -> Dict:
    """注入 ansible_user 等连接参数。"""
    extra: Dict = {}
    user = ANSIBLE_USER or os.environ.get("USERNAME", "")
    if user:
        extra["ansible_user"] = user
    if detect_target_os(asset_ip) == "windows":
        extra["ansible_shell_type"] = "cmd"
        extra["ansible_become"] = "false"
    return extra


def _build_playbook_cmd(
    playbook: Path,
    asset_ip: str,
    extra_vars: Optional[Dict],
    use_wsl: bool,
) -> List[str]:
    pb = to_wsl_path(playbook) if use_wsl else str(playbook)
    merged = dict(_connection_extra_vars(asset_ip))
    if extra_vars:
        merged.update(extra_vars)
    inner = [
        "ansible-playbook",
        pb,
        "-i", f"{asset_ip},",
        "--ssh-common-args", "-o StrictHostKeyChecking=no",
    ]
    for k, v in merged.items():
        if isinstance(v, (list, dict, bool)):
            inner.extend(["-e", f"{k}={json.dumps(v)}"])
        elif isinstance(v, str) and (" " in v or "=" in v):
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
    pb_rel = get_playbook_for_target(rule, asset_ip)
    playbook = PLAYBOOKS_DIR / pb_rel
    if not playbook.exists():
        return False, f"剧本不存在: {playbook}"

    mode = _resolve_mode()
    if mode == "none":
        info = get_ansible_runtime()
        return False, info["detail"]

    if mode == "simulate":
        os_label = detect_target_os(asset_ip)
        return True, (
            f"[演示模式] 已模拟修复 {asset_ip} ({os_label}) | 规则: {rule.rule_id} | "
            f"剧本: {pb_rel}（未实际连接目标；请用 .\\scripts\\start_real_ansible.ps1 启动后端）"
        )

    use_wsl = mode == "wsl"
    runtime = get_ansible_runtime()
    cmd = _build_playbook_cmd(playbook, asset_ip, extra_vars, use_wsl=use_wsl)
    ansible_cfg = PROJECT_ROOT / "ansible.cfg"
    env = os.environ.copy()
    if ansible_cfg.exists():
        env["ANSIBLE_CONFIG"] = str(ansible_cfg)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ANSIBLE_TIMEOUT,
            cwd=str(PLAYBOOKS_DIR) if not use_wsl else str(PROJECT_ROOT),
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        output = _clean_output((result.stdout or "") + (result.stderr or ""))
        output = _friendly_error_message(output, asset_ip)
        output = _truncate_output(output, max_len=800)
        prefix = f"[真实修复 | {runtime.get('label', mode)}] "
        if use_wsl:
            prefix = f"[真实修复 | WSL Ansible] "
        if result.returncode == 0:
            return True, prefix + (output or "执行成功")
        return False, prefix + (output or f"退出码 {result.returncode}")
    except subprocess.TimeoutExpired:
        return False, f"执行超时（>{ANSIBLE_TIMEOUT}s）"
    except Exception as e:
        return False, str(e)
