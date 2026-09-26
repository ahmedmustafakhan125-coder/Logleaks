# LogLeak 🔒

**Your logs are shipping your customers' data. LogLeak proves it, has IBM Bob fix it, then proves the fix.**

LogLeak runs your app's own test flows, watches every log line, `print()`, and exception traceback that gets written, and flags personal data: emails, phone numbers, card numbers, CNICs, IBANs, tokens. Each leak is traced to the exact `file:line` that produced it. IBM Bob, running in a dedicated `logleak-fixer` mode, repairs the leaks. A verification gate then re-runs the same flows and only passes when the logs are clean **and** still useful.

## Planning pack (read in this order)

| File | What it covers |
|---|---|
| [`docs/00-MASTER-PLAN.md`](docs/00-MASTER-PLAN.md) | Scope, judging strategy, deliverables, video script, write-up drafts |
| [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Components, data flow, detection rules, verification gate |
| [`docs/02-BUILD-PLAN.md`](docs/02-BUILD-PLAN.md) | Hour-by-hour schedule to the Sep 27, 8:00 PM PKT deadline |
| [`docs/03-MCP-PLAN.md`](docs/03-MCP-PLAN.md) | MCP servers Bob uses while building, plus the LogLeak MCP server |
| [`docs/04-UI-FRONTEND.md`](docs/04-UI-FRONTEND.md) | Dashboard spec, API endpoints, design tokens, demo replay mode |
| [`.bob/rules/01-logleak-core.md`](.bob/rules/01-logleak-core.md) | Rules Bob follows in every conversation in this repo |
| [`.bob/rules-logleak-fixer/01-fix-protocol.md`](.bob/rules-logleak-fixer/01-fix-protocol.md) | Extra rules for the fixer mode only |
| [`.bob/custom_modes.yaml`](.bob/custom_modes.yaml) | `logleak-fixer` and `logleak-auditor` modes |
| [`.bob/mcp.json`](.bob/mcp.json) | Project MCP configuration |
| [`tests/`](tests/) | Spec tests, written first. Bob builds the engine until they pass |

## Quickstart (once built)

```bash
pip install -e ".[dev]"
logleak scan demo/caredesk            # before: find leaks
logleak fix  demo/caredesk            # Bob repairs a working copy
logleak verify demo/caredesk          # gate: clean + still useful
logleak serve                         # dashboard at http://localhost:8765
```
