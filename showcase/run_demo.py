# -*- coding: utf-8 -*-
"""run_demo.py — Drive both app versions through LogLeak's detector and show findings.

Usage:
    python run_demo.py

No server needed — this script exercises the business-logic functions
directly, captures every log line, and feeds them to LogLeak's detector.
"""
from __future__ import annotations

import importlib
import io
import logging
import sys
from contextlib import redirect_stdout
from types import ModuleType

# ---------------------------------------------------------------------------
# Make sure the parent package (logleak) is on the path.
# Works whether you run from `showcase/` or from the repo root.
# ---------------------------------------------------------------------------

import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from logleak.detectors import detect
from logleak.redact import redact_text

# ---------------------------------------------------------------------------
# ANSI colours (disabled on Windows without ANSI support)
# ---------------------------------------------------------------------------

_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

# Force UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]


def _c(colour: str, text: str) -> str:
    """Wrap text in ANSI colour codes."""
    return f"{colour}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Log capture helper
# ---------------------------------------------------------------------------

class _StringHandler(logging.Handler):
    """Captures log records into an in-memory list."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


def _capture_calls(module: ModuleType) -> tuple[list[str], list[str]]:
    """
    Call each business-logic function once with PII-containing test data,
    capture all log output AND stdout, return (log_lines, stdout_lines).
    """
    handler = _StringHandler()
    handler.setFormatter(logging.Formatter("%(levelname)-8s %(name)s  %(message)s"))

    root = logging.getLogger()
    root.addHandler(handler)

    stdout_buf = io.StringIO()

    try:
        with redirect_stdout(stdout_buf):
            # L1 trigger — email + phone in registration log
            module.register_patient(
                name="Jane Doe",
                email="canary.patient@logleak.test",
                phone="+923001234567",
            )

            # L2 trigger — card in debug log
            module.charge_card(
                patient_id="P-0001",
                card_number="4242424242424242",
                cvv="123",
                amount=50000,
            )

            # L3 trigger — card in exception message (CVV=000 forces decline)
            try:
                module.charge_card(
                    patient_id="P-0001",
                    card_number="4242424242424242",
                    cvv="000",
                    amount=50000,
                )
            except ValueError:
                pass

            # L4 trigger — JWT printed to stdout
            module.issue_token("dr.smith")

    finally:
        root.removeHandler(handler)

    return handler.lines, stdout_buf.getvalue().splitlines()


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def _scan_module(label: str, module: ModuleType) -> int:
    """Run a scan on one module variant; print findings; return leak count."""
    log_lines, stdout_lines = _capture_calls(module)

    all_lines = log_lines + stdout_lines

    print(_c(_BOLD, f"\n{'='*60}"))
    print(_c(_BOLD, f"  {label}"))
    print(_c(_BOLD, f"{'='*60}"))
    print(f"  Captured {len(log_lines)} log lines + {len(stdout_lines)} stdout lines\n")

    total_findings = 0

    for line in all_lines:
        findings = detect(line)
        if findings:
            total_findings += len(findings)
            masked = redact_text(line)
            print(_c(_RED,   "  [!] RAW  : ") + line)
            print(_c(_GREEN, "  [v] MASKED: ") + masked)
            for f in findings:
                print(
                    _c(_YELLOW, f"       +-- {f.kind:8s} [{f.confidence}]")
                    + f"  pos {f.start}-{f.end}"
                )
            print()
        else:
            print(_c(_GREEN, "  ✓ clean : ") + line)

    if stdout_lines:
        print()

    print()
    if total_findings:
        print(_c(_RED, f"  [FAIL] {total_findings} PII finding(s) detected!"))
    else:
        print(_c(_GREEN, "  [PASS] No PII found -- all clear."))

    return total_findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run both app variants and print side-by-side findings."""
    # Import both app versions FIRST (their basicConfig calls may add handlers)
    sys.path.insert(0, _HERE)
    leaky = importlib.import_module("app_leaky")
    clean = importlib.import_module("app_clean")

    # NOW strip every StreamHandler from root so our _StringHandler is the
    # only sink during each _scan_module call.
    root = logging.getLogger()
    stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
    for h in stream_handlers:
        root.removeHandler(h)

    leaky_count = _scan_module("app_leaky.py  -- BEFORE (4 leaks planted)", leaky)
    clean_count = _scan_module("app_clean.py  -- AFTER  (all leaks fixed)",  clean)

    # Restore the stripped handlers so any post-demo logging works normally
    for h in stream_handlers:
        root.addHandler(h)

    print("\n" + _c(_BOLD, "Summary"))
    print(f"  app_leaky  : {_c(_RED,   str(leaky_count))} finding(s)")
    print(f"  app_clean  : {_c(_GREEN, str(clean_count))} finding(s)")

    if leaky_count > 0 and clean_count == 0:
        print(_c(_GREEN, "\n  LogLeak demo complete -- fixes verified!\n"))
    else:
        print(_c(_YELLOW, "\n  Unexpected result -- check output above.\n"))


if __name__ == "__main__":
    main()
