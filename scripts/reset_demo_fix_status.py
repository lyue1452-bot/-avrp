"""将演示模式/卡住的修复状态重置为待修复，并清除无效修复日志。"""
import sqlite3
from config import DB_PATH

from remediation.fix_status import is_demo_fix_msg, is_real_fix_msg


def reset_demo_and_stuck_statuses(asset_ip: str | None = None) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    where = "1=1"
    params: list = []
    if asset_ip:
        where += " AND asset_ip=?"
        params.append(asset_ip)

    rows = cur.execute(
        f"SELECT id, fix_status, last_fix_msg, auto_fixable FROM vulnerabilities WHERE {where}",
        params,
    ).fetchall()

    demo_reset = 0
    fixing_reset = 0
    log_cleared = 0

    for row in rows:
        msg = row["last_fix_msg"] or ""
        status = row["fix_status"] or "pending"
        auto = bool(row["auto_fixable"])
        new_status = status
        new_msg = msg

        if status == "fixing":
            new_status = "auto_fixable" if auto else "manual_only"
            new_msg = ""
            fixing_reset += 1
        elif is_demo_fix_msg(msg) or (status == "fixed" and not is_real_fix_msg(msg)):
            new_status = "auto_fixable" if auto else "manual_only"
            new_msg = ""
            demo_reset += 1
        elif not is_real_fix_msg(msg) and msg.strip():
            new_msg = ""
            log_cleared += 1

        if new_status != status or new_msg != msg:
            cur.execute(
                "UPDATE vulnerabilities SET fix_status=?, last_fix_msg=? WHERE id=?",
                (new_status, new_msg, row["id"]),
            )

    task_where = "status='running'"
    task_params: list = []
    if asset_ip:
        task_where += " AND target_ip=?"
        task_params.append(asset_ip)
    cur.execute(
        f"""
        UPDATE tasks
        SET status='failed',
            finished_at=datetime('now'),
            result_text=COALESCE(result_text, '任务超时或中断，已标记失败')
        WHERE {task_where}
        """,
        task_params,
    )
    task_reset = cur.rowcount

    conn.commit()
    conn.close()
    return {
        "demo_reset": demo_reset,
        "fixing_reset": fixing_reset,
        "log_cleared": log_cleared,
        "running_tasks_reset": task_reset,
    }


if __name__ == "__main__":
    stats = reset_demo_and_stuck_statuses()
    print("状态重置完成:", stats)
