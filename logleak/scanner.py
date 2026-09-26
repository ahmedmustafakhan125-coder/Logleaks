"""scanner.py — scan_target(): run pytest+plugin in a subprocess and return a Report."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from logleak.canaries import all_canaries
from logleak.capture import CapturedRecord
from logleak.report import Report
from logleak.sitemap import find_log_sites, unwitnessed
from logleak.tracer import trace


def scan_target(target: Path, out_dir: Path) -> Report:
    """Run the target's test suite with LeakCaptureHandler and return a Report.

    Steps:
    1. Run pytest -p logleak.pytest_plugin inside target, with LOGLEAK_OUT set.
    2. Load the JSONL capture file into CapturedRecord objects.
    3. Call trace() to detect PII and group into Leak objects.
    4. Call find_log_sites() and compute executed/total site counts.
    5. Build and return a masked Report.
    """
    target = Path(target).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    capture_jsonl = out_dir / "capture.jsonl"

    # --- Step 1: Run pytest subprocess ---
    env = {**os.environ}
    env["LOGLEAK_OUT"] = str(capture_jsonl)
    # Ensure the target package itself is importable (supplements pythonpath in pyproject.toml)
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(target) + (os.pathsep + existing_pp if existing_pp else "")

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--tb=short", "-q", "--no-header"],
        cwd=str(target),
        env=env,
        capture_output=True,
        text=True,
    )
    tests_exit_code = result.returncode
    # pytest exit 0 = all passed, 1 = some failed, 2+ = error
    # Treat 0 and 1 as "tests ran"; 0 means all passed
    if tests_exit_code not in (0, 1):
        # pytest itself errored (import failure etc.) — still try to parse whatever was captured
        pass

    # --- Step 2: Load JSONL ---
    records: list[CapturedRecord] = []
    if capture_jsonl.exists():
        for line in capture_jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(CapturedRecord.from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError):
                    continue

    # --- Step 3: Detect and trace ---
    canaries = all_canaries()
    leaks = trace(records, canaries=canaries, root=target)

    # --- Step 4: Build masked log text (all messages joined) ---
    from logleak.redact import redact_text

    log_lines: list[str] = []
    for rec in records:
        # Use exc_text if it's an exception record, else message
        text = rec.exc_text if rec.exc_text else rec.message
        if text:
            log_lines.append(redact_text(text))

    log_text_masked = "\n".join(log_lines)

    # --- Step 5: Sitemap ---
    sites = find_log_sites(target)
    total_sites = len(sites)

    # Build executed sites set from records: (relative posix path, lineno)
    executed_sites: set[tuple[str, int]] = set()
    for rec in records:
        raw_path = rec.pathname
        try:
            rel = Path(raw_path).relative_to(target).as_posix()
        except ValueError:
            rel = raw_path  # third-party — keep as-is
        executed_sites.add((rel, rec.lineno))

    return Report(
        target=str(target),
        leaks=leaks,
        executed_sites=executed_sites,
        total_sites=total_sites,
        log_text_masked=log_text_masked,
        tests_exit_code=0 if tests_exit_code == 0 else 1,
    )
