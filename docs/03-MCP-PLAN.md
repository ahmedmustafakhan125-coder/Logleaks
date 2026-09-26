# 03 · MCP Plan — LogLeak

LogLeak uses MCP in two different roles:

| Role | Purpose | Servers |
|---|---|---|
| **A. Build-time** | Give Bob up-to-date information while it writes the code (library docs, compliance guidance, GitHub, browser checks) | Context7, Fetch, GitHub, Playwright |
| **B. In-product** | Let Bob use LogLeak itself: read masked leak context, re-scan, and verify its own fixes | `logleak` (our own server) |

Role B is part of the pitch: *Bob closes the loop on its own work through our MCP server.*

---

## A. Build-time MCP servers

### A1. Context7 — current library docs ⭐ most important

- **Why:** FastMCP, FastAPI, and pytest APIs change often. Context7 serves current, version-specific docs, so Bob doesn't write code against outdated APIs.
- **Used for:** `mcp_server.py` (FastMCP decorators and transport), `pytest_plugin.py` (hook names), `server.py` (FastAPI SSE).
- **Prompt pattern:** "Use context7 to get the current FastMCP docs for defining tools, then implement `mcp_server.py`."

### A2. Fetch — compliance and security guidance

- **Why:** the detection and masking rules should match real guidance, not guesses.
- **Pages to fetch:** OWASP Logging Cheat Sheet, OWASP Logging Vocabulary, PCI DSS guidance on displaying and storing card numbers (PAN), and GDPR Article 32 (security of processing).
- **Prompt pattern:** "Fetch the OWASP Logging Cheat Sheet and check that `.bob/rules/01-logleak-core.md` doesn't contradict it."

### A3. GitHub — repo and PR workflow (optional)

- **Why:** Bob can open the "LogLeak fixes" PR in the repo, which gives visible evidence for judges.
- **Security:** the token goes in your **global** config (`~/.bob/mcp_settings.json`), never in the repo.

### A4. Playwright — dashboard checks (optional)

- **Why:** Bob can open the dashboard, take screenshots, and verify that the redaction animation and panels render at 1080p before recording.

---

## B. The `logleak` MCP server (built by us)

### Tools

| Tool | Input | Output (all masked) | Used by Bob to… |
|---|---|---|---|
| `scan_logs` | `target: str` | Summary: leak count by kind and severity, executed/total sites, report path | Get the current state |
| `list_leaks` | `severity?: str` | A list of `Leak` objects: fingerprint, kind, file, line, sink, masked sample | Plan the fixes |
| `get_leak_context` | `fingerprint: str` | ±5 lines of code, the masked sample, sink, owner (`app` or `third_party`), and the recommended fix strategy | Fix one leak precisely |
| `verify_fix` | `target: str` | `GateResult`: passed, the 6 checks, and reasons | Self-check and iterate |

Resource: `logleak://policy` returns the masking table from the architecture doc, so Bob always uses the same masks as the engine.

### Implementation pattern

Keep the logic in `mcp_tools.py` as plain functions, which are easy to unit test. `mcp_server.py` is only a thin wrapper:

```python
# logleak/mcp_server.py
from fastmcp import FastMCP
from logleak import mcp_tools

mcp = FastMCP("logleak")

@mcp.tool
def scan_logs(target: str) -> dict:
    """Run the target's test flows with canary PII and return a masked leak summary."""
    return mcp_tools.scan_logs(target)

@mcp.tool
def list_leaks(severity: str | None = None) -> list[dict]:
    """List leaks from the latest scan. Values are always masked."""
    return mcp_tools.list_leaks(severity)

@mcp.tool
def get_leak_context(fingerprint: str) -> dict:
    """Source context and recommended fix strategy for one leak."""
    return mcp_tools.get_leak_context(fingerprint)

@mcp.tool
def verify_fix(target: str) -> dict:
    """Re-run flows on the target and evaluate the 6-check verification gate."""
    return mcp_tools.verify_fix(target)

if __name__ == "__main__":
    mcp.run()  # stdio transport
```

Check the current FastMCP syntax through Context7 before building. The decorator style has changed between versions.

### The masking invariant

Every return value from every tool goes through `redact_text()` one final time before it is returned. `tests/test_mcp_tools.py` fails if any canary value appears anywhere in any tool output.

---

## C. Configuration

### Project config: `.bob/mcp.json` (committed, no secrets)

```json
{
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"]
    },
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    },
    "playwright": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest"],
      "disabled": true
    },
    "logleak": {
      "command": "python",
      "args": ["-m", "logleak.mcp_server"],
      "alwaysAllow": ["scan_logs", "list_leaks", "get_leak_context", "verify_fix"]
    }
  }
}
```

### Global config: `~/.bob/mcp_settings.json` (not committed; secrets go here)

```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "<your fine-grained PAT, repo-scoped>" }
    }
  }
}
```

Use a fine-grained token scoped to this one repository.

### Prerequisites

- Node 18+ (for `npx`), `uv` (for `uvx`), and Docker (only for GitHub MCP)
- `pip install -e ".[dev]"` so `python -m logleak.mcp_server` resolves

### Smoke test (Phase 0)

In the Bob IDE, ask: *"List the tools available from each MCP server."* Confirm that `context7`, `fetch`, and `logleak` respond. Before `mcp_server.py` exists, `logleak` will fail, which is expected until Phase 3.

---

## D. Where each MCP appears in the Bob evidence

| Phase | MCP | Screenshot moment |
|---|---|---|
| 1 | Fetch | Bob checking the masking rules against the OWASP cheat sheet |
| 2 | Context7 | Bob pulling the pytest hook docs for the plugin |
| 3 | Context7 | Bob building `mcp_server.py` with the current FastMCP API |
| 3 | **logleak** | **Bob calling `verify_fix`, seeing G4 fail, fixing it, and re-verifying.** This is the best screenshot in the whole submission. |
| 4 | Playwright | Bob screenshotting the dashboard (optional) |
