"""漏洞修复状态：内部英文码 + 中文展示标签。"""
from typing import Any, Dict, List, Optional

STATUS_LABELS: Dict[str, str] = {
    "pending": "待处理",
    "auto_fixable": "待修复",
    "fixing": "修复中",
    "fixed": "已修复",
    "failed": "修复失败",
    "manual_only": "需人工处理",
}

STATUS_OPTIONS: List[Dict[str, str]] = [
    {"value": k, "label": v} for k, v in STATUS_LABELS.items()
]

_DEMO_MSG_MARKERS = (
    "演示模式",
    "模拟修复",
    "未实际连接目标",
    "未实际 SSH",
    "已撤销演示模式",
    "修复任务已中断",
    "演示模式已禁用",
)


def is_demo_fix_msg(msg: Optional[str]) -> bool:
    if not msg or not str(msg).strip():
        return False
    text = str(msg)
    return any(m in text for m in _DEMO_MSG_MARKERS)


def is_real_fix_msg(msg: Optional[str]) -> bool:
    """是否为真实 Ansible 修复日志（非演示/占位）。"""
    if not msg or not str(msg).strip():
        return False
    if is_demo_fix_msg(msg):
        return False
    text = str(msg)
    if "真实修复" in text:
        return True
    if "[真实修复|SUCCESS]" in text:
        return True
    if "PLAY [" in text and "PLAY RECAP" in text:
        return True
    return False


def status_label(status: Optional[str]) -> str:
    if not status:
        return "未知"
    return STATUS_LABELS.get(status, status)


def normalize_fix_status(status: Optional[str], msg: Optional[str], auto_fixable: bool) -> str:
    """演示模式标记的 fixed 降级；数据库 fixed 状态优先信任。"""
    if status == "fixed":
        if is_demo_fix_msg(msg):
            return "auto_fixable" if auto_fixable else "manual_only"
        return "fixed"
    if status == "fixing" and is_demo_fix_msg(msg):
        return "auto_fixable" if auto_fixable else "manual_only"
    return status or "pending"


from remediation.verify_hint import build_verify_hint, should_show_verify_hint


def enrich_vuln(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    msg = out.get("last_fix_msg") or ""
    auto = bool(out.get("auto_fixable"))
    normalized = normalize_fix_status(out.get("fix_status"), msg, auto)
    out["fix_status"] = normalized
    out["fix_status_label"] = status_label(normalized)
    out["has_fix_log"] = is_real_fix_msg(msg)
    out["last_fix_msg"] = msg if out["has_fix_log"] else ""
    if should_show_verify_hint(out):
        out["verify_hint"] = build_verify_hint(out)
    else:
        out["verify_hint"] = ""
    return out
