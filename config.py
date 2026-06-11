"""项目路径与运行配置（支持环境变量覆盖）。"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("RAYSCAN_DB", PROJECT_ROOT / "rayscan_vulns.db"))
PLAYBOOKS_DIR = Path(os.environ.get("RAYSCAN_PLAYBOOKS", PROJECT_ROOT / "playbooks"))
MAPPINGS_DIR = Path(os.environ.get("RAYSCAN_MAPPINGS", PROJECT_ROOT / "mappings"))
DEFAULT_REPORT = PROJECT_ROOT / "rayscan_report.json"
ANSIBLE_TIMEOUT = int(os.environ.get("RAYSCAN_ANSIBLE_TIMEOUT", "120"))
# Ansible SSH 连接（真实修复时配置）
ANSIBLE_USER = os.environ.get("RAYSCAN_ANSIBLE_USER", os.environ.get("USERNAME", ""))
# auto | wsl | native | simulate（默认 Windows 用 wsl 真实修复，禁用演示模式）
_default_ansible_mode = "wsl" if os.name == "nt" else "auto"
ANSIBLE_MODE = os.environ.get("RAYSCAN_ANSIBLE_MODE", _default_ansible_mode).lower()
SIMULATE_ON_WINDOWS = os.environ.get("RAYSCAN_SIMULATE_ON_WINDOWS", "0") == "1"
# 修复目标 OS：auto | windows | linux
TARGET_OS = os.environ.get("RAYSCAN_TARGET_OS", "auto")
# 本机主 IP（排除 VMware 虚拟网卡时用，如 192.168.101.36）
TARGET_IP = os.environ.get("RAYSCAN_TARGET_IP", "")
VERIFY_AFTER_FIX = os.environ.get("RAYSCAN_VERIFY", "1") != "0"

# API 服务端口（须与 frontend/vite.config.js 中 proxy.target 一致）
API_PORT = int(os.environ.get("RAYSCAN_API_PORT", "6666"))
API_HOST = os.environ.get("RAYSCAN_API_HOST", "127.0.0.1")

# JWT 认证
JWT_SECRET = os.environ.get("RAYSCAN_JWT_SECRET", "rayscan-dev-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.environ.get("RAYSCAN_JWT_EXPIRY", "24"))

# 上传目录
UPLOAD_DIR = PROJECT_ROOT / "uploads"

# 扫描工具超时（秒）
NMAP_TIMEOUT = int(os.environ.get("RAYSCAN_NMAP_TIMEOUT", "600"))
GITLEAKS_TIMEOUT = int(os.environ.get("RAYSCAN_GITLEAKS_TIMEOUT", "600"))
TRIVY_TIMEOUT = int(os.environ.get("RAYSCAN_TRIVY_TIMEOUT", "900"))
ZAP_TIMEOUT = int(os.environ.get("RAYSCAN_ZAP_TIMEOUT", "900"))
