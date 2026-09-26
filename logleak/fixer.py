"""fixer.py — workspace preparation and Bob Shell invocation."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# Repo root resolved at import time
_REPO_ROOT = Path(__file__).resolve().parents[1]
_RUNS_DIR = _REPO_ROOT / "runs"

# Directories to skip when copying the target
_SKIP_DIRS = {"__pycache__", ".pytest_cache", ".git", ".tox", "node_modules", ".mypy_cache"}


def _copy_target(src: Path, dest: Path) -> None:
    """Copy src tree to dest, skipping cache and VCS directories."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    for item in src.rglob("*"):
        # Skip if any ancestor component matches the skip list
        rel = item.relative_to(src)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        target = dest / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def prepare_workspace(target: Path) -> Path:
    """Copy target into runs/workspace/<name> and write runs/leak-report.md.

    Returns the workspace path. Never modifies the original target.
    """
    target = target.resolve()
    workspace_dir = _RUNS_DIR / "workspace" / target.name
    _copy_target(target, workspace_dir)

    # Write the masked leak report if a before-report exists
    before_json = _RUNS_DIR / "report_before.json"
    if before_json.exists():
        from logleak.report import Report
        report = Report.from_json(before_json.read_text(encoding="utf-8"))
        # to_markdown needs the source code root (the workspace copy for rendering)
        md = report.to_markdown(workspace_dir)
        (_RUNS_DIR / "leak-report.md").write_text(md, encoding="utf-8")
    else:
        (_RUNS_DIR / "leak-report.md").write_text(
            "# LogLeak Report\n\nNo scan report found. Run `logleak scan` first.\n",
            encoding="utf-8",
        )

    return workspace_dir


def _build_fix_prompt(workspace: Path) -> str:
    """Build the masked Bob Shell prompt for the logleak-fixer mode."""
    leak_report = _RUNS_DIR / "leak-report.md"
    workspace_posix = workspace.as_posix()
    report_posix = leak_report.as_posix()
    return (
        f"Fix every leak in @{report_posix} inside {workspace_posix}. "
        "Follow the fix protocol in .bob/rules-logleak-fixer/01-fix-protocol.md. "
        "When done, call the logleak verify_fix tool and iterate until "
        "the gate passes (max 3 rounds)."
    )


def run_bob(workspace: Path) -> int:
    """Launch Bob Shell in non-interactive mode to fix leaks.

    Returns Bob's exit code.  If bob is not on PATH, prints instructions and
    returns 1 without raising.
    """
    bob_exe = shutil.which("bob")
    if bob_exe is None:
        print(
            "\n[fixer] 'bob' executable not found on PATH.\n"
            "\nFallback — use the Bob IDE instead:\n"
            "  1. Open the Bob IDE and switch to the 'logleak-fixer' mode.\n"
            f"  2. Attach {_RUNS_DIR / 'leak-report.md'} to the conversation.\n"
            f"  3. Prompt: Fix every leak listed in the report inside {workspace}.\n"
            "     Follow the fix protocol. When done, call verify_fix and iterate.\n",
            file=sys.stderr,
        )
        return 1

    prompt = _build_fix_prompt(workspace)
    cmd = [
        bob_exe,
        "--chat-mode=logleak-fixer",
        "--yolo",
        "-p", prompt,
    ]

    print(f"\n[fixer] Running Bob Shell ...\n  cmd: {' '.join(cmd[:3])} -p <prompt>\n")

    # Stream stdout/stderr so the user sees progress
    proc = subprocess.run(cmd, cwd=str(_REPO_ROOT))
    return proc.returncode
