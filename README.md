# LogLeak 🔒

**Your logs are shipping your customers' data. LogLeak proves it, has IBM Bob fix it, then proves the fix.**

LogLeak runs your app's own test flows, watches every log line, `print()`, and exception traceback that gets written, and flags personal data: emails, phone numbers, card numbers, CNICs, IBANs, tokens. Each leak is traced to the exact `file:line` that produced it. IBM Bob, running in a dedicated `logleak-fixer` mode, repairs the leaks. A verification gate then re-runs the same flows and only passes when the logs are clean **and** still useful.

## Quickstart

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate          # macOS / Linux

# 2. Install the package and dev dependencies
pip install -e ".[dev]"

# 3. Run the spec tests (must all pass before doing anything else)
pytest tests -q -m "not e2e"        # 75 tests, ~0.6 s

# 4. Scan the demo app for PII leaks
logleak scan demo/caredesk

# 5. Prepare workspace + fix with Bob (or --prepare-only to use the IDE)
logleak fix demo/caredesk --prepare-only

# 6. Verify the fix passes all 6 gate checks
logleak verify runs/workspace/caredesk

# 7. Start the dashboard
logleak serve                        # opens at http://127.0.0.1:8765/ui/
```

## How it works

```
logleak scan  →  runs your app's own pytest suite with a special plugin that
                  captures every log record, print(), and exception traceback.
                  Canary PII values are injected as fixtures so matches are exact.
                  Detected leaks are grouped by (file, line, kind) and written
                  to runs/report.json and runs/leak-report.md (all values masked).

logleak fix   →  copies demo/caredesk → runs/workspace/caredesk (pristine original
                  is never touched), writes the masked leak report, then launches
                  IBM Bob in logleak-fixer mode to edit the workspace.

logleak verify → re-runs the same pytest flows on the workspace and checks 6 gates:
                  G1 no confirmed leaks · G2 no critical suspected · G3 tests pass
                  G4 no over-redaction · G5 ≥90% log sites retained · G6 safety net

logleak serve  → FastAPI + vanilla JS dashboard at http://127.0.0.1:8765/ui/
                  showing before/after log streams, the leak table, gate panel,
                  and per-leak source context.
```

## Planning pack (read in this order)

| File | What it covers |
|---|---|
| [`docs/00-MASTER-PLAN.md`](docs/00-MASTER-PLAN.md) | Scope, judging strategy, deliverables, video script |
| [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Components, data flow, detection rules, verification gate |
| [`docs/02-BUILD-PLAN.md`](docs/02-BUILD-PLAN.md) | Hour-by-hour build schedule |
| [`docs/03-MCP-PLAN.md`](docs/03-MCP-PLAN.md) | MCP servers Bob uses + the LogLeak MCP server |
| [`docs/04-UI-FRONTEND.md`](docs/04-UI-FRONTEND.md) | Dashboard spec, API endpoints, design tokens |
| [`.bob/rules/01-logleak-core.md`](.bob/rules/01-logleak-core.md) | Rules Bob follows in every conversation |
| [`.bob/rules-logleak-fixer/01-fix-protocol.md`](.bob/rules-logleak-fixer/01-fix-protocol.md) | Extra rules for the fixer mode |
| [`.bob/custom_modes.yaml`](.bob/custom_modes.yaml) | `logleak-fixer` and `logleak-auditor` modes |
| [`.bob/mcp.json`](.bob/mcp.json) | Project MCP configuration |
| [`tests/`](tests/) | Spec tests written first — implement until they pass |

## Repository layout

```
logleak/            engine (installable package)
  canaries.py       7 fake-but-valid PII canary values
  detectors.py      detect(), luhn_valid(), iban_valid(), shannon_entropy()
  redact.py         mask(), redact_text(), RedactionFilter
  capture.py        LeakCaptureHandler, capture_stdout()
  pytest_plugin.py  injects capture into the target's test run
  tracer.py         groups records into Leak objects
  sitemap.py        AST scan of every log/print call site
  report.py         Report dataclass, to_json(), to_markdown()
  scanner.py        scan_target() — runs pytest + plugin in subprocess
  verify.py         run_gate() — 6-check verification gate
  fixer.py          prepare_workspace(), run_bob()
  mcp_tools.py      plain functions Bob calls through MCP
  mcp_server.py     FastMCP wrapper (stdio transport)
  server.py         FastAPI dashboard API
  cli.py            logleak scan | fix | verify | serve

ui/
  index.html        dashboard layout
  styles.css        IBM Plex design tokens, log stream highlights, redaction bars
  app.js            fetch + SSE, renders all panels

demo/
  caredesk/         pristine target app with 7 planted leaks (never modified)
  caredesk_after/   fixed version that passes the 6-check gate (committed evidence)

tests/              86 spec tests — all passing
docs/               architecture, build plan, MCP plan, UI spec
```

## Demo app leaks (caredesk)

| # | File | Leak | Sink |
|---|---|---|---|
| L1 | `patients.py:29` | `Patient.__repr__` dumps email + phone + CNIC | log |
| L2 | `payments.py:25` | full card number in debug log | log |
| L3 | `payments.py:33` | card number in `ValueError` message | exception |
| L4 | `middleware.py:27` | full JSON request body logged | log |
| L5 | `auth.py:25` | JWT token printed to stdout | stdout |
| L6 | `notifications.py:30` | phone number in SMS retry warning | log |
| L7 | httpx (third-party) | email in URL query string at INFO level | log |

All 7 are detected and fixed. The gate passes on `demo/caredesk_after/`.
