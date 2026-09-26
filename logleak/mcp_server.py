"""mcp_server.py — FastMCP wrapper exposing LogLeak tools and resources.

FastMCP version: 3.x  (docs confirmed via Context7 /prefecthq/fastmcp)
Decorator style: @mcp.tool  (no parentheses for zero-arg decorator)
Transport: stdio (default), started with mcp.run()

Start with:
    python -m logleak.mcp_server
"""
from __future__ import annotations

from fastmcp import FastMCP

from logleak import mcp_tools

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="logleak",
    instructions=(
        "LogLeak MCP server. All values returned by tools are masked — "
        "no raw PII is ever present in any tool output. "
        "Use scan_logs to get the current leak state, list_leaks and "
        "get_leak_context to understand individual leaks, and verify_fix "
        "to check your fixes against the 6-check gate."
    ),
)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool
def scan_logs(target: str) -> dict:
    """Run the target app's test suite with canary PII and return a masked summary.

    Returns leak counts by kind and severity, executed/total log sites,
    the report file path, and the tests exit code.
    Target may be absolute or relative to the repo root.
    """
    return mcp_tools.scan_logs(target)


@mcp.tool
def list_leaks(severity: str | None = None) -> list[dict]:
    """List leaks from the latest scan, optionally filtered by severity.

    Each entry contains: fingerprint, kind, severity, confidence, file, line,
    sink, hits, and a masked sample. Call scan_logs first.
    """
    return mcp_tools.list_leaks(severity)


@mcp.tool
def get_leak_context(fingerprint: str) -> dict:
    """Return source code context and recommended fix strategy for one leak.

    Returns: file, line, sink, owner (app|third_party), ±5 lines of code,
    a masked sample, and a strategy description.
    Raises an error for unknown fingerprints.
    """
    try:
        return mcp_tools.get_leak_context(fingerprint)
    except KeyError:
        return {"error": f"Unknown fingerprint: {fingerprint}"}


@mcp.tool
def verify_fix(target: str) -> dict:
    """Re-scan target and evaluate the 6-check verification gate.

    Compares against runs/report_before.json (the baseline from scan_logs).
    Saves the result to runs/gate.json.
    Returns: passed (bool), checks (dict[str, bool]), reasons (list[str]).
    """
    return mcp_tools.verify_fix(target)


# ---------------------------------------------------------------------------
# Resource: masking policy
# ---------------------------------------------------------------------------


@mcp.resource("logleak://policy")
def policy() -> str:
    """The LogLeak masking policy table — Bob uses this to apply consistent masks."""
    return """# LogLeak Masking Policy

| Kind    | Masked form                | Rule                                      |
|---------|----------------------------|-------------------------------------------|
| email   | c***@logleak.test          | First char + *** + full domain            |
| card    | ************4242           | Stars for all but last 4 digits (PCI)     |
| phone   | +92*******567              | Keep +92 prefix and last 3 digits         |
| cnic    | [REDACTED:cnic]            | Full redaction (last digit encodes gender)|
| iban    | GB82******************     | Country+check digits only, same length    |
| jwt     | [REDACTED:jwt]             | Never partial                             |
| secret  | [REDACTED:secret]          | Never partial                             |

## Severity
- critical: card, cnic, iban, jwt, secret
- high:     email, phone

## Fix strategies
- app-owned log call: fix the call site (log ID not the data)
- third-party logger: install RedactionFilter or raise logger level to WARNING
- exception message: never put PII in exception text; use an ID instead
- print() debug: remove or replace with a safe logger call
- request body logging: log method, path, status, duration, and request ID only
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    mcp.run()  # stdio transport by default
