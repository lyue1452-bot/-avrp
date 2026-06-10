"""项目路径与运行配置（支持环境变量覆盖）。"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("RAYSCAN_DB", PROJECT_ROOT / "rayscan_vulns.db"))
PLAYBOOKS_DIR = Path(os.environ.get("RAYSCAN_PLAYBOOKS", PROJECT_ROOT / "playbooks"))
MAPPINGS_DIR = Path(os.environ.get("RAYSCAN_MAPPINGS", PROJECT_ROOT / "mappings"))
DEFAULT_REPORT = PROJECT_ROOT / "rayscan_report.json"
ANSIBLE_TIMEOUT = int(os.environ.get("RAYSCAN_ANSIBLE_TIMEOUT", "120"))
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
