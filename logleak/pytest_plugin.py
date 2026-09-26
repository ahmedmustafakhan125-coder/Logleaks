"""pytest_plugin.py — LogLeak capture plugin for pytest.

Auto-loaded when logleak is installed (registered as a pytest11 entry point).
Does nothing unless the LOGLEAK_OUT environment variable is set, so the
logleak unit tests are completely unaffected.

When active:
  - Provides a `canary` fixture (dict from logleak.canaries.CANARIES).
  - Attaches LeakCaptureHandler to the root logger at DEBUG.
  - Tees stdout per-test to capture print() calls with correct file:line.
  - Writes all CapturedRecord objects to LOGLEAK_OUT as JSONL at session end.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Globals set at session start
# ---------------------------------------------------------------------------

_handler: "LeakCaptureHandler | None" = None  # type: ignore[name-defined]
_out_path: Path | None = None
_stdout_records: list = []   # accumulated across all tests


# ---------------------------------------------------------------------------
# Session-level hooks
# ---------------------------------------------------------------------------


def pytest_configure(config) -> None:
    """Register the e2e marker (no-op if already registered)."""
    config.addinivalue_line("markers", "e2e: end-to-end tests that run the demo app")


def pytest_sessionstart(session) -> None:
    """Attach LeakCaptureHandler to root logger if LOGLEAK_OUT is set."""
    global _handler, _out_path

    out_env = os.environ.get("LOGLEAK_OUT")
    if not out_env:
        return  # plugin is passive — no LOGLEAK_OUT set

    from logleak.capture import LeakCaptureHandler

    _out_path = Path(out_env)
    _out_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    _handler = LeakCaptureHandler()
    _handler.setLevel(logging.DEBUG)
    root.addHandler(_handler)


def pytest_sessionfinish(session, exitstatus) -> None:
    """Write captured records to LOGLEAK_OUT as JSONL and remove the handler."""
    global _handler, _out_path

    if _handler is None or _out_path is None:
        return

    # Remove handler
    logging.getLogger().removeHandler(_handler)

    # Combine log records + stdout records, then write JSONL
    all_records = list(_handler.records) + list(_stdout_records)
    with _out_path.open("w", encoding="utf-8") as fh:
        for rec in all_records:
            fh.write(json.dumps(rec.to_dict()) + "\n")

    # Store exit status on the handler for scanner to read
    _handler._exit_status = exitstatus


# ---------------------------------------------------------------------------
# Per-test stdout tee (hookwrapper around runtest_call)
# ---------------------------------------------------------------------------


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item) -> None:  # type: ignore[return]
    """Wrap each test call to tee stdout and capture print() file:line."""
    if _handler is None:
        # Plugin inactive
        yield
        return

    from logleak.capture import _StdoutTee

    # pytest captures stdout itself; sys.stdout at this point is pytest's capture object.
    # We wrap it so our tee sits between the test code and pytest's capture.
    original_stdout = sys.stdout
    tee = _StdoutTee(original_stdout, _stdout_records)
    sys.stdout = tee
    try:
        yield
    finally:
        sys.stdout = original_stdout


# ---------------------------------------------------------------------------
# canary fixture — provided unconditionally
# ---------------------------------------------------------------------------


@pytest.fixture
def canary() -> dict[str, str]:
    """Fake-but-valid PII canary values from logleak.canaries."""
    from logleak.canaries import CANARIES
    return dict(CANARIES)
