"""Generate EncodedCommand Windows Ansible playbooks from PowerShell sources."""
from __future__ import annotations

import base64
from pathlib import Path

GEN = Path(__file__).resolve().parent / "_gen_enc"
PLAYBOOKS = Path(__file__).resolve().parent.parent / "playbooks" / "windows"

COMMON = GEN / "apache_paths.ps1"


def encode_ps(*parts: Path) -> str:
    chunks = []
    if COMMON.exists():
        chunks.append(COMMON.read_text(encoding="utf-8"))
    for part in parts:
        text = part.read_text(encoding="utf-8")
        text = text.replace('. "$PSScriptRoot\\apache_paths.ps1"', "").strip()
        text = text.replace(". \"$PSScriptRoot/apache_paths.ps1\"", "").strip()
        chunks.append(text)
    body = "\n\n".join(c.strip() for c in chunks if c.strip())
    return base64.b64encode(body.encode("utf-16-le")).decode("ascii")


def write_playbook(name: str, title: str, tasks: list[tuple[str, str, bool, bool]]) -> None:
    lines = [
        "---",
        f"- name: {title}",
        "  hosts: all",
        "  gather_facts: no",
        "  tasks:",
    ]
    for task_name, enc, changed, allow_fail in tasks:
        lines.append(f"    - name: {task_name}")
        lines.append(
            "      raw: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
            f"-EncodedCommand {enc}"
        )
        lines.append(f"      changed_when: {'true' if changed else 'false'}")
        if allow_fail:
            lines.append("      failed_when: false")
        lines.append("")
    out = PLAYBOOKS / name
    out.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print("Wrote", out)


def main() -> None:
    server_enc = encode_ps(GEN / "server_tokens.ps1")
    restart_enc = encode_ps(GEN / "restart_apache.ps1")
    write_playbook(
        "fix_server_tokens.yml",
        "Windows Apache Server 版本信息隐藏",
        [
            ("设置 ServerTokens Prod", server_enc, True, False),
            ("重启 Apache", restart_enc, False, True),
        ],
    )


if __name__ == "__main__":
    main()
