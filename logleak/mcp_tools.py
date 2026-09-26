"""mcp_tools.py — plain functions Bob calls through MCP.

Privacy invariant: no tool ever returns a raw PII value.
Every return value goes through sanitize() before leaving this module.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from logleak.report import Report

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_current_report: Report | None = None

# Repo root — resolved once at import time so relative targets work correctly
# regardless of the subprocess working directory.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_RUNS_DIR = _REPO_ROOT / "runs"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def set_current_report(report: Report) -> None:
    """Load a report into the module-level cache without scanning."""
    global _current_report
    _current_report = report


def sanitize(obj: Any) -> Any:
    """Recursively redact all strings in nested dicts, lists, and tuples."""
    from logleak.redact import redact_text
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(sanitize(v) for v in obj)
    return obj


def _count_by(leaks, attr: str) -> dict[str, int]:
    """Count leaks grouped by a given attribute."""
    counts: dict[str, int] = {}
    for lk in leaks:
        val = getattr(lk, attr)
        counts[val] = counts.get(val, 0) + 1
    return counts


def _resolve_target(target_str: str) -> Path:
    """Resolve a target path relative to the repo root if not absolute."""
    p = Path(target_str)
    if not p.is_absolute():
        p = _REPO_ROOT / p
    return p.resolve()


# ---------------------------------------------------------------------------
# MCP tools (plain functions — thin FastMCP wrappers live in mcp_server.py)
# ---------------------------------------------------------------------------


def scan_logs(target: str) -> dict:
    """Run the target's test flows with canary PII and return a masked leak summary.

    Saves the report to runs/report.json and runs/report_before.json, then loads
    it as the current report for list_leaks / get_leak_context / verify_fix.
    """
    from logleak.scanner import scan_target

    target_path = _resolve_target(target)
    _RUNS_DIR.mkdir(exist_ok=True)
    out_dir = _RUNS_DIR / "scan_tmp"
    out_dir.mkdir(exist_ok=True)

    report = scan_target(target_path, out_dir)
    set_current_report(report)

    # Persist so verify_fix can reload the baseline later
    (_RUNS_DIR / "report.json").write_text(report.to_json(), encoding="utf-8")
    (_RUNS_DIR / "report_before.json").write_text(report.to_json(), encoding="utf-8")

    return sanitize({
        "target": str(target_path),
        "total_leaks": len(report.leaks),
        "by_kind": _count_by(report.leaks, "kind"),
        "by_severity": _count_by(report.leaks, "severity"),
        "executed_sites": len(report.executed_sites),
        "total_sites": report.total_sites,
        "report_path": str(_RUNS_DIR / "report.json"),
        "tests_exit_code": report.tests_exit_code,
    })


def list_leaks(severity: str | None = None) -> list[dict]:
    """List leaks from the latest loaded report, optionally filtered by severity."""
    import dataclasses
    if _current_report is None:
        return []
    leaks = _current_report.leaks
    if severity is not None:
        leaks = [lk for lk in leaks if lk.severity == severity]
    return [sanitize(dataclasses.asdict(lk)) for lk in leaks]


def get_leak_context(fingerprint: str) -> dict:
    """Return source context and fix strategy for one leak. Raises KeyError if not found."""
    if _current_report is None:
        raise KeyError(fingerprint)
    leak_map = {lk.fingerprint: lk for lk in _current_report.leaks}
    if fingerprint not in leak_map:
        raise KeyError(fingerprint)
    leak = leak_map[fingerprint]

    # Determine owner: third-party if path contains site-packages/dist-packages
    # or if the path is absolute and outside the target root
    file_posix = leak.file.replace("\\", "/")
    is_third_party = (
        "site-packages" in file_posix
        or "dist-packages" in file_posix
    )
    if not is_third_party and Path(leak.file).is_absolute():
        target_path = Path(_current_report.target)
        try:
            Path(leak.file).relative_to(target_path)
        except ValueError:
            is_third_party = True

    owner = "third_party" if is_third_party else "app"

    # Read ±5 lines of source context (only for app-owned leaks)
    code_lines: list[str] = []
    if not is_third_party and _current_report.target:
        src_file = Path(_current_report.target) / leak.file
        if src_file.exists():
            all_lines = src_file.read_text(errors="replace").splitlines()
            start = max(0, leak.line - 6)
            end = min(len(all_lines), leak.line + 5)
            code_lines = all_lines[start:end]

    # Fix strategy
    if owner == "third_party":
        strategy = (
            "This leak originates in a third-party library. "
            "Install a RedactionFilter on the root logger or on the specific "
            "library logger, or raise that logger's level to WARNING."
        )
    else:
        strategy = (
            f"Fix the {leak.sink} call at {leak.file}:{leak.line}. "
            f"Remove or mask the {leak.kind} value before logging."
        )

    result = {
        "fingerprint": leak.fingerprint,
        "kind": leak.kind,
        "severity": leak.severity,
        "confidence": leak.confidence,
        "file": leak.file,
        "line": leak.line,
        "sink": leak.sink,
        "owner": owner,
        "code": "\n".join(code_lines),
        "strategy": strategy,
        "sample": leak.sample,
    }
    return sanitize(result)


def verify_fix(target: str) -> dict:
    """Re-scan the target and evaluate the 6-check gate against the before-report.

    Loads the baseline from runs/report_before.json.
    Saves the gate result to runs/gate.json.
    """
    from logleak.scanner import scan_target
    from logleak.verify import run_gate

    target_path = _resolve_target(target)
    _RUNS_DIR.mkdir(exist_ok=True)

    # Load the before-report baseline
    before_json = _RUNS_DIR / "report_before.json"
    if before_json.exists():
        before = Report.from_json(before_json.read_text(encoding="utf-8"))
    elif _current_report is not None:
        before = _current_report
    else:
        return sanitize({"error": "No before-report found. Run scan_logs first."})

    # Scan the (possibly fixed) target
    after_dir = _RUNS_DIR / "after"
    after_dir.mkdir(exist_ok=True)
    after = scan_target(target_path, after_dir)

    result = run_gate(
        before,
        after,
        allowlist_tokens=["PT-", "APT-", "ORD-"],
        probe_masked=probe_safety_net(target_path),
    )

    # Persist gate result
    gate_data = result.to_dict()
    (_RUNS_DIR / "gate.json").write_text(
        json.dumps(gate_data, indent=2), encoding="utf-8"
    )

    return sanitize(gate_data)


def probe_safety_net(app_path) -> bool:
    """Check whether the app's logging config masks PII via RedactionFilter."""
    import subprocess
    import sys

    app_path = Path(app_path).resolve()
    script = (
        "import sys, logging, io\n"
        f"sys.path.insert(0, {str(app_path)!r})\n"
        "try:\n"
        "    from logging_config import configure_logging\n"
        "    configure_logging()\n"
        "except Exception:\n"
        "    pass\n"
        "buf = io.StringIO()\n"
        "h = logging.StreamHandler(buf)\n"
        "logging.getLogger().addHandler(h)\n"
        "logging.getLogger().setLevel(logging.DEBUG)\n"
        "logging.getLogger('probe').info('card 4242424242424242 test')\n"
        "out = buf.getvalue()\n"
        "sys.exit(0 if '4242424242424242' not in out else 1)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        timeout=15,
    )
    return proc.returncode == 0
