"""检测修复目标操作系统（Linux / Windows）。"""
import os
import socket
import subprocess
import sys
from typing import Set

from config import TARGET_OS, TARGET_IP


def is_windows() -> bool:
    return sys.platform.startswith("win")


def _powershell_primary_ip() -> str:
    """Windows：排除 VMware/虚拟网卡，优选真实局域网 IP。"""
    if TARGET_IP:
        return TARGET_IP.strip()
    try:
        ps = (
            "$skip='VMware|VirtualBox|vEthernet|Hyper-V|Loopback|Teredo|Bluetooth|WSL'; "
            "$list=@(); "
            "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
            "  $ip=$_.IPAddress; "
            "  if ($ip -like '127.*' -or $ip -like '169.254*') { return }; "
            "  $a=Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -EA SilentlyContinue; "
            "  if ($a.InterfaceAlias -match $skip) { return }; "
            "  $s=0; if ($ip -like '192.168.101.*') { $s+=100 }; "
            "  if ($ip -notmatch '\\.1$') { $s+=20 }; "
            "  if ($a.InterfaceAlias -match 'Ethernet|Wi-?Fi|WLAN') { $s+=30 }; "
            "  $list += [PSCustomObject]@{IP=$ip;S=$s} "
            "}; "
            "($list | Sort-Object S -Descending | Select-Object -First 1).IP"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode == 0:
            ip = (result.stdout or "").strip()
            if ip:
                return ip
    except Exception:
        pass
    return ""


def _local_ipv4_addrs() -> Set[str]:
    addrs = {"127.0.0.1", "localhost"}
    primary = _powershell_primary_ip()
    if primary:
        addrs.add(primary)
    try:
        hostname = socket.gethostname()
        addrs.add(hostname.lower())
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    if is_windows():
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {"
                 "$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*'}).IPAddress -join ','"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                for ip in (result.stdout or "").split(","):
                    ip = ip.strip()
                    if ip and (ip.startswith("192.168.101.") or not ip.endswith(".1")):
                        addrs.add(ip)
        except Exception:
            pass
    return addrs


def detect_target_os(asset_ip: str) -> str:
    """
    返回 'windows' 或 'linux'。
    RAYSCAN_TARGET_OS=windows|linux 强制指定；auto 时本机 Windows 且 IP 为本机则判定为 windows。
    """
    forced = (TARGET_OS or "auto").lower()
    if forced in ("windows", "linux"):
        return forced
    ip = (asset_ip or "").strip().lower()
    if is_windows() and ip in _local_ipv4_addrs():
        return "windows"
    return "linux"


def resolve_playbook(rule, asset_ip: str) -> str:
    """按目标 OS 选择 playbook 路径（相对 playbooks/）。"""
    os_type = detect_target_os(asset_ip)
    win_pb = getattr(rule, "playbook_windows", "") or ""
    if os_type == "windows" and win_pb:
        return win_pb
    return rule.playbook
