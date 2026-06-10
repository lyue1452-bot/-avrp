"""限定 URL/IP 目标时的本地扫描范围，避免扫含 node_modules 的整个项目。"""
from pathlib import Path
from typing import List, Tuple

from config import PROJECT_ROOT, UPLOAD_DIR
from scanner.target_utils import parse_scan_target

# Trivy/Gitleaks 跳过的目录（相对路径片段匹配）
SKIP_DIR_NAMES = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".cache", "DVWA的web_20230101060508_(1)",
}

SKIP_PATH_GLOBS = [
    "frontend/node_modules",
    "frontend/dist",
    ".git",
]


def resolve_gitleaks_source(target: str) -> Tuple[str, str]:
    """
    返回 (source_path, reason)。
    URL/IP 目标仅扫描 uploads，避免全项目超时。
    """
    host, _, _, kind = parse_scan_target(target)
    if kind == "path" and Path(target).exists():
        return str(Path(target).resolve()), f"扫描指定路径 {target}"

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    if any(UPLOAD_DIR.iterdir()):
        return str(UPLOAD_DIR.resolve()), (
            f"远程目标 {host} 无法在本地做密钥扫描，改为扫描 uploads/ 目录"
        )
    return str(UPLOAD_DIR.resolve()), (
        f"远程目标 {host}：uploads/ 为空，跳过深度扫描（0 条预期）"
    )


def resolve_trivy_scan(target: str) -> Tuple[List[str], List[str], str]:
    """
    返回 (scan_paths, skip_dirs, reason)。
    """
    host, _, _, kind = parse_scan_target(target)
    if kind == "image":
        return [], [], f"扫描容器镜像 {target}"

    if kind == "path" and Path(target).exists():
        return [str(Path(target).resolve())], list(SKIP_DIR_NAMES), f"扫描指定路径 {target}"

    paths: List[str] = []
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    paths.append(str(UPLOAD_DIR.resolve()))
    req = PROJECT_ROOT / "requirements.txt"
    if req.exists():
        paths.append(str(req))

    skip = list(SKIP_DIR_NAMES)
    return paths, skip, (
        f"远程目标 {host}：扫描 uploads/ 与依赖清单，跳过 node_modules 等大目录"
    )
