"""cli.py — logleak command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
import time
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
# watch command
# ---------------------------------------------------------------------------

# ANSI colour codes (no external deps)
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_GREEN  = "\033[32m"

_SEV_COLOUR = {"critical": _RED, "high": _YELLOW}


def _alert(line: str, findings) -> None:
    """Print a breach alert to stderr with ANSI colours."""
    from logleak.detectors import SEVERITY
    from logleak.redact import mask

    for f in findings:
        sev   = SEVERITY.get(f.kind, "high")
        conf  = f.confidence          # confirmed | suspected
        col   = _SEV_COLOUR.get(sev, _YELLOW)
        masked = mask(f.kind, f.value)
        print(
            f"{col}{_BOLD}[BREACH]{_RESET} "
            f"{col}{sev.upper()}{_RESET} "
            f"{_CYAN}{f.kind}{_RESET} "
            f"({conf}) — "
            f"{masked}",
            file=sys.stderr,
        )
    # Print the (already-safe) masked log line so the user can see context
    from logleak.redact import redact_text
    print(f"  {_BOLD}line:{_RESET} {redact_text(line.rstrip())}", file=sys.stderr)
    print(file=sys.stderr)


def _build_smtp_config(args) -> "object | None":
    """Build a SmtpConfig from parsed CLI args, or return None if unconfigured."""
    if not getattr(args, "smtp_host", None):
        return None
    if not args.smtp_to:
        print(
            "Error: --smtp-host requires --smtp-to (recipient address).",
            file=sys.stderr,
        )
        sys.exit(1)
    from logleak.notifier import SmtpConfig
    return SmtpConfig(
        host=args.smtp_host,
        port=args.smtp_port,
        use_tls=not args.smtp_no_tls,
        username=args.smtp_user or "",
        password=args.smtp_password or "",
        from_addr=args.smtp_from or args.smtp_user or "",
        to_addrs=args.smtp_to,
    )


def _make_email_breach_callback(smtp_cfg, app_name: str, cooldown: float):
    """Return an EmailNotifier configured from smtp_cfg."""
    from logleak.notifier import EmailNotifier
    return EmailNotifier(smtp_cfg, app_name=app_name, cooldown=cooldown)


def cmd_watch(
    log_path: str,
    canaries_only: bool,
    poll: float,
    smtp_cfg=None,
    app_name: str = "LogLeak",
    email_cooldown: float = 300.0,
) -> None:
    """Tail a log file (or stdin) and alert immediately on any PII breach."""
    from logleak.detectors import detect
    from logleak.canaries import all_canaries

    canaries = all_canaries()

    # Build optional email notifier
    email_notifier = None
    if smtp_cfg is not None:
        email_notifier = _make_email_breach_callback(smtp_cfg, app_name, email_cooldown)

    # ------------------------------------------------------------------
    # Open the source: '-' → stdin, otherwise tail the given file.
    # ------------------------------------------------------------------
    reading_stdin = log_path == "-"

    if not reading_stdin:
        p = Path(log_path)
        if not p.exists():
            print(f"Error: log file does not exist: {p}", file=sys.stderr)
            sys.exit(1)

    print(
        f"\n{_BOLD}[watch]{_RESET} LogLeak watching "
        f"{_CYAN}{'stdin' if reading_stdin else log_path}{_RESET} ...",
        file=sys.stderr,
    )
    if canaries_only:
        print(
            f"  Mode: {_YELLOW}canaries-only{_RESET} "
            "(only confirmed canary matches are reported)",
            file=sys.stderr,
        )
    if email_notifier is not None:
        print(
            f"  Email alerts → {_CYAN}{', '.join(smtp_cfg.to_addrs)}{_RESET}",
            file=sys.stderr,
        )
    print(f"  Press Ctrl-C to stop.\n", file=sys.stderr)

    breach_count = 0

    def _handle_findings(raw_line: str, findings) -> None:
        nonlocal breach_count
        breach_count += 1
        _alert(raw_line, findings)
        if email_notifier is not None:
            # Build a lightweight BreachEvent-like object for each finding
            from logleak.watch_handler import BreachEvent
            from logleak.detectors import SEVERITY
            from logleak.redact import redact_text, mask
            masked_line = redact_text(raw_line.rstrip())
            for f in findings:
                event = BreachEvent(
                    kind=f.kind,
                    severity=SEVERITY.get(f.kind, "high"),
                    confidence=f.confidence,
                    masked_value=mask(f.kind, f.value),
                    logger_name="",
                    level="",
                    masked_line=masked_line,
                    pathname=log_path,
                    lineno=0,
                )
                email_notifier(event)

    try:
        if reading_stdin:
            for raw_line in sys.stdin:
                findings = detect(raw_line, canaries=canaries)
                if canaries_only:
                    findings = [f for f in findings if f.confidence == "confirmed"]
                if findings:
                    _handle_findings(raw_line, findings)
        else:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                # Seek to end so we only watch new lines
                fh.seek(0, 2)
                while True:
                    raw_line = fh.readline()
                    if raw_line:
                        findings = detect(raw_line, canaries=canaries)
                        if canaries_only:
                            findings = [f for f in findings if f.confidence == "confirmed"]
                        if findings:
                            _handle_findings(raw_line, findings)
                    else:
                        time.sleep(poll)

    except KeyboardInterrupt:
        pass

    colour = _RED if breach_count else _GREEN
    print(
        f"\n{colour}{_BOLD}[watch] stopped — "
        f"{breach_count} breach(es) detected.{_RESET}\n",
        file=sys.stderr,
    )
    sys.exit(1 if breach_count else 0)


# ---------------------------------------------------------------------------
# serve command
# ---------------------------------------------------------------------------


def cmd_serve(host: str, port: int) -> None:
    """Start the FastAPI dashboard server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is not installed. Run: pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    from logleak.server import app  # noqa: F401 — imported for side-effects

    print(f"\n[serve] Dashboard at http://{host}:{port}/ui/\n")
    uvicorn.run(
        "logleak.server:app",
        host=host,
        port=port,
        reload=False,
    )


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

    p_serve = subparsers.add_parser("serve", help="Start the dashboard API server.")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")

    p_watch = subparsers.add_parser(
        "watch",
        help="Tail a log file (or stdin) and alert immediately on any PII breach.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Watch a log file (or stdin) for PII in real time.\n"
            "Prints a coloured alert on every breach, and optionally\n"
            "sends an HTML email alert (like a deployment failure email).\n\n"
            "Example — file tail with email:\n"
            "  logleak watch /var/log/app.log \\\n"
            "    --smtp-host smtp.gmail.com --smtp-user alerts@example.com \\\n"
            "    --smtp-password secret --smtp-to oncall@example.com\n\n"
            "Example — pipe stdin with email:\n"
            "  uvicorn myapp:app 2>&1 | logleak watch - \\\n"
            "    --smtp-host smtp.gmail.com --smtp-to security@example.com"
        ),
    )
    p_watch.add_argument(
        "log",
        help="Path to the log file to watch, or '-' to read from stdin.",
    )
    p_watch.add_argument(
        "--canaries-only",
        action="store_true",
        help="Only report confirmed canary matches (suppress suspected findings).",
    )
    p_watch.add_argument(
        "--poll",
        type=float,
        default=0.2,
        metavar="SECONDS",
        help="Polling interval when tailing a file (default: 0.2 s).",
    )

    # --- SMTP / email alert options ---
    smtp_grp = p_watch.add_argument_group(
        "email alerts",
        "Send an HTML breach-alert email (like a deployment failure notification).\n"
        "--smtp-host is required to enable email; --smtp-to is also required.",
    )
    smtp_grp.add_argument(
        "--smtp-host",
        metavar="HOST",
        default=None,
        help="SMTP server hostname (e.g. smtp.gmail.com).",
    )
    smtp_grp.add_argument(
        "--smtp-port",
        type=int,
        default=587,
        metavar="PORT",
        help="SMTP port (default: 587).",
    )
    smtp_grp.add_argument(
        "--smtp-no-tls",
        action="store_true",
        help="Disable STARTTLS (not recommended).",
    )
    smtp_grp.add_argument(
        "--smtp-user",
        metavar="USER",
        default=None,
        help="SMTP login username / sending address.",
    )
    smtp_grp.add_argument(
        "--smtp-password",
        metavar="PASS",
        default=None,
        help="SMTP login password or app password.",
    )
    smtp_grp.add_argument(
        "--smtp-from",
        metavar="ADDR",
        default=None,
        help="From address (defaults to --smtp-user when omitted).",
    )
    smtp_grp.add_argument(
        "--smtp-to",
        metavar="ADDR",
        action="append",
        default=[],
        help="Recipient address. Repeat for multiple recipients.",
    )
    smtp_grp.add_argument(
        "--smtp-app-name",
        metavar="NAME",
        default="LogLeak",
        help="App name shown in the email subject (default: LogLeak).",
    )
    smtp_grp.add_argument(
        "--smtp-cooldown",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help=(
            "Minimum seconds between emails for the same source location "
            "(default: 300). Prevents inbox floods."
        ),
    )

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args.target)
    elif args.command == "fix":
        cmd_fix(args.target, prepare_only=args.prepare_only)
    elif args.command == "verify":
        cmd_verify(args.target)
    elif args.command == "serve":
        cmd_serve(args.host, args.port)
    elif args.command == "watch":
        smtp_cfg = _build_smtp_config(args)
        cmd_watch(
            args.log,
            canaries_only=args.canaries_only,
            poll=args.poll,
            smtp_cfg=smtp_cfg,
            app_name=args.smtp_app_name,
            email_cooldown=args.smtp_cooldown,
        )
    else:
        parser.print_help()
