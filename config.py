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
