"""cli.py — logleak command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Repo root used by scan to write into runs/
_REPO_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1}


def _col(text: str, width: int) -> str:
    """Truncate and left-justify text to width."""
    s = str(text)
    if len(s) > width:
        s = s[: width - 1] + "~"
    return s.ljust(width)


def _print_table(leaks) -> None:
    """Print a formatted leak table to stdout."""
    if not leaks:
        print("  No leaks found.")
        return

    header = (
        f"{'SEV':<9} {'KIND':<8} {'FILE:LINE':<42} {'SINK':<10} "
        f"{'HITS':<5} SAMPLE"
    )
    print(header)
    print("-" * 100)

    sorted_leaks = sorted(
        leaks,
        key=lambda lk: (_SEVERITY_ORDER.get(lk.severity, 9), lk.file, lk.line),
    )
    for leak in sorted_leaks:
        loc = f"{leak.file}:{leak.line}"
        sample = leak.sample[:58] + ("~" if len(leak.sample) > 58 else "")
        print(
            f"{_col(leak.severity, 9)} {_col(leak.kind, 8)} {_col(loc, 42)} "
            f"{_col(leak.sink, 10)} {str(leak.hits):<5} {sample}"
        )


def _ensure_runs_dir() -> Path:
    """Return the runs/ directory (relative to cwd), creating it if necessary."""
    runs = Path("runs")
    runs.mkdir(exist_ok=True)
    return runs


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


def cmd_scan(target_str: str) -> None:
    """Run a scan and print results."""
    import tempfile
    from logleak.scanner import scan_target
    from logleak.sitemap import find_log_sites, unwitnessed

    target = Path(target_str).resolve()
    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    runs = _ensure_runs_dir()

    print(f"\n[scan] LogLeak scanning {target.name} ...\n")

    with tempfile.TemporaryDirectory() as tmp:
        report = scan_target(target, Path(tmp))

    # --- Leak table ---
    print(f"{'='*60}")
    print(f"  {len(report.leaks)} leak(s) found in {target.name}")
    print(f"{'='*60}\n")
    _print_table(report.leaks)

    # --- Coverage line ---
    exec_count = len(report.executed_sites)
    total = report.total_sites
    print(f"\n  {exec_count} of {total} log/print sites exercised in tests")

    # --- Unwitnessed lines ---
    sites = find_log_sites(target)
    unw = unwitnessed(sites, report.executed_sites)
    if unw:
        print(f"\n  [!] {len(unw)} unwitnessed log site(s) -- not proven clean:")
        for s in sorted(unw, key=lambda x: (x.file, x.line)):
            print(f"     {s.file}:{s.line}  ({s.call})")
    else:
        print("\n  [ok] All log sites exercised.")

    # --- Tests status ---
    status = "[PASS]" if report.tests_exit_code == 0 else "[FAIL]"
    print(f"\n  App tests: {status}")

    # --- Write outputs ---
    report_json = runs / "report.json"
    report_before_json = runs / "report_before.json"
    leak_report_md = runs / "leak-report.md"

    report_json.write_text(report.to_json(), encoding="utf-8")
    report_before_json.write_text(report.to_json(), encoding="utf-8")
    leak_report_md.write_text(report.to_markdown(target), encoding="utf-8")

    print(f"\n  Wrote {report_json}")
    print(f"  Wrote {report_before_json}")
    print(f"  Wrote {leak_report_md}\n")


# ---------------------------------------------------------------------------
# fix command
# ---------------------------------------------------------------------------


def cmd_fix(target_str: str, prepare_only: bool) -> None:
    """Prepare workspace and optionally invoke Bob Shell."""
    from logleak.fixer import prepare_workspace, run_bob

    target = Path(target_str).resolve()
    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[fix] Preparing workspace for {target.name} ...")
    workspace = prepare_workspace(target)
    print(f"  Workspace: {workspace}")
    print(f"  Leak report: {Path('runs') / 'leak-report.md'}")

    # Sanity check: original must be unchanged
    if not target.exists():
        print("ERROR: original target was deleted!", file=sys.stderr)
        sys.exit(1)

    if prepare_only:
        print("\n  [ok] --prepare-only: workspace ready. Open the Bob IDE to fix.\n")
        return

    exit_code = run_bob(workspace)
    sys.exit(exit_code)


# ---------------------------------------------------------------------------
# verify command
# ---------------------------------------------------------------------------


def cmd_verify(target_str: str) -> None:
    """Run the verification gate on a workspace and print results."""
    from logleak import mcp_tools

    target = Path(target_str).resolve()
    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[verify] Running gate on {target.name} ...\n")

    gate = mcp_tools.verify_fix(str(target))

    if "error" in gate:
        print(f"  Error: {gate['error']}", file=sys.stderr)
        sys.exit(1)

    passed = gate.get("passed", False)
    checks = gate.get("checks", {})
    reasons = gate.get("reasons", [])

    CHECK_LABELS = {
        "no_confirmed_leaks":   "G1  No confirmed leaks remaining",
        "no_critical_suspected":"G2  No critical suspected leaks",
        "tests_pass":           "G3  App tests pass",
        "no_over_redaction":    "G4  No over-redaction (useful IDs present)",
        "logs_retained":        "G5  Log site retention >= 90%",
        "safety_net":           "G6  Safety-net RedactionFilter active",
    }

    for key, label in CHECK_LABELS.items():
        status = "[PASS]" if checks.get(key) else "[FAIL]"
        print(f"  {status}  {label}")

    if reasons:
        print("\n  Reasons:")
        for r in reasons:
            print(f"    - {r}")

    overall = "[GATE PASSED]" if passed else "[GATE FAILED]"
    print(f"\n  {overall}\n")

    # Write gate.json (mcp_tools.verify_fix already does this, but
    # normalise the path in case the user ran from a different cwd)
    runs = _ensure_runs_dir()
    gate_path = runs / "gate.json"
    if not gate_path.exists():
        gate_path.write_text(json.dumps(gate, indent=2), encoding="utf-8")

    sys.exit(0 if passed else 1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """LogLeak CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="logleak",
        description="LogLeak -- find personal data leaking into application logs.",
    )
    subparsers = parser.add_subparsers(dest="command")

    p_scan = subparsers.add_parser("scan", help="Scan a target app for PII leaks.")
    p_scan.add_argument("target", help="Path to the target app directory.")

    p_fix = subparsers.add_parser("fix", help="Prepare workspace and run Bob fixer.")
    p_fix.add_argument("target", help="Path to the target app directory.")
    p_fix.add_argument(
        "--prepare-only",
        action="store_true",
        help="Copy workspace and write leak-report.md only; do not run Bob Shell.",
    )

    p_verify = subparsers.add_parser("verify", help="Run the 6-check verification gate.")
    p_verify.add_argument("target", help="Path to the workspace to verify.")

    subparsers.add_parser("serve", help="Start the dashboard API server.")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args.target)
    elif args.command == "fix":
        cmd_fix(args.target, prepare_only=args.prepare_only)
    elif args.command == "verify":
        cmd_verify(args.target)
    else:
        parser.print_help()
