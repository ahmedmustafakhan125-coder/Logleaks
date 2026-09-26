# LogLeak 🔒

> **Your logs are shipping your customers' data. LogLeak proves it, has IBM Bob fix it, then proves the fix.**

LogLeak runs your application's own test flows, watches every log line, `print()`, and exception traceback, and flags personal data leaking into them: emails, phone numbers, card numbers, CNICs, IBANs, tokens. Each leak is traced to the exact `file:line` that produced it. IBM Bob, in a dedicated `logleak-fixer` mode, repairs each one at the source. A verification gate then re-runs the same flows and only passes when the logs are clean **and** still useful.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Running LogLeak](#running-logleak)
  - [Step 1 — Scan](#step-1--scan)
  - [Step 2 — Fix](#step-2--fix)
  - [Step 3 — Verify](#step-3--verify)
  - [Step 4 — Dashboard](#step-4--dashboard)
- [CLI reference](#cli-reference)
- [Detection rules](#detection-rules)
- [Masking rules](#masking-rules)
- [Verification gate](#verification-gate)
- [MCP server](#mcp-server)
- [Files produced in `runs/`](#files-produced-in-runs)
- [Repository layout](#repository-layout)
- [Demo app — CareDesk](#demo-app--caredesk)
- [Privacy and security invariants](#privacy-and-security-invariants)
- [Tech stack](#tech-stack)
- [Further reading](#further-reading)

---

## Why this exists

Engineers log for debugging:

```python
logger.info(f"New patient: {patient}")       # dumps __repr__ → email, phone, CNIC
logger.debug("Charging card %s", card)       # PCI DSS violation
logger.exception("Card declined: %s", card)  # leak hiding in a traceback
print(f"issued token {jwt}")                 # forgotten debug print
```

Those logs don't stay local. They ship to Datadog, ELK, Sentry, and S3, are kept for months, and are readable by far more people than the production database. Under PCI DSS, GDPR, and other data protection frameworks, that is a direct compliance exposure.

**Why existing tools miss it:** static scanners look at code, not at what is actually written at runtime. A leak through an object's `__repr__`, an f-string, a third-party library's debug logs, or an exception traceback is invisible to grep. It only shows up when the code runs.

LogLeak catches it because it instruments the runtime.

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│  1. SEED      Inject canary PII into the target's test fixtures  │
│               (fake but valid: Luhn-valid card, .test email…)    │
│                                                                   │
│  2. CAPTURE   pytest plugin hooks the logging system + stdout.   │
│               Every record carries its source file:line.         │
│                                                                   │
│  3. DETECT    Canary match → confirmed. Pattern + Luhn/IBAN/     │
│               entropy validation → suspected. All values masked. │
│                                                                   │
│  4. FIX       IBM Bob (logleak-fixer mode) gets a masked report  │
│               and repairs each leak at its source. Bob never     │
│               sees raw PII.                                       │
│                                                                   │
│  5. VERIFY    Same flows run again. Gate passes only when:       │
│               zero leaks · tests pass · useful IDs kept ·        │
│               log lines not deleted · safety-net filter active   │
└─────────────────────────────────────────────────────────────────┘
```

### What makes it different

| Feature | Why it matters |
|---|---|
| **Runtime, not static** | Catches leaks through `__repr__`, tracebacks, and third-party libraries that grep can never see |
| **Canary PII** | Turns "might be a leak" into "is a leak" with zero ambiguity — a canary appearing in a log is confirmed, not guessed |
| **Bob never sees raw PII** | The AI fixing the leak must not become a new leak channel. Everything sent to Bob is masked. |
| **Anti-cheat gate** | Bob can't "fix" logs by deleting them. The gate checks that log coverage and useful IDs survive. |
| **Honest about coverage** | Unwitnessed log lines (statements your tests never executed) are reported as "not proven clean" |

---

## Installation

### Prerequisites

- **Python 3.11+** — check with `python --version`
- **IBM Bob** installed and on your PATH (required for automated `logleak fix`; optional if you use the IDE fallback)
- All commands are run from the **repo root**

### Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate          # macOS / Linux

# 2. Install the package and dev dependencies
pip install -e ".[dev]"
```

The `pip install -e ".[dev]"` command installs the `logleak` package in editable mode (changes to source files take effect immediately without reinstalling), registers the `logleak` CLI entry point, and installs the pytest plugin so it is auto-discovered in target apps.

### Verify the installation

```bash
pytest tests -q -m "not e2e"        # 86 spec tests — all should pass
logleak --help
```

All 86 spec tests must pass before proceeding. If any fail, something is wrong with the environment.

---

## Running LogLeak

### Step 1 — Scan

```bash
logleak scan demo/caredesk
```

Scans the target app for PII leaks and writes reports to `runs/`.

**What happens internally:**

1. Spawns a subprocess running `pytest -p logleak.pytest_plugin` inside the target app.
2. The plugin attaches a `LeakCaptureHandler` to the root logger at `DEBUG` level and tees stdout, recording every log line, `print()`, and exception traceback into a JSONL capture file, along with the exact `file:line` and function name of each record's origin.
3. Canary PII values are injected into the target's tests via a `canary` fixture so every canary appearing in a log is a confirmed, unambiguous leak.
4. After pytest exits, the JSONL is read back and each record is passed through the PII detector against all 7 canary values.
5. Matches are grouped by `(file, line, kind)` into `Leak` objects. **Raw PII values never leave this stage** — everything written to `runs/` contains masked samples only.

**Example output:**

```
============================================================
  7 leak(s) found in caredesk
============================================================

SEV       KIND     FILE:LINE                                  SINK       HITS  SAMPLE
----------------------------------------------------------------------------------------------------
critical  card     caredesk/payments.py:25                    log        1     Charging card ************4242 for…
critical  card     caredesk/payments.py:33                    exception  1     Card declined: ************4242
critical  jwt      caredesk/auth.py:25                        stdout     1     issued token [REDACTED:jwt]
critical  cnic     caredesk/patients.py:29                    log        1     cnic=35202-***-*
high      email    caredesk/patients.py:29                    log        1     email=c***@logleak.test
high      phone    caredesk/patients.py:29                    log        1     phone=+92*******567
high      email    httpx (third-party)                        log        1     ?email=c***@logleak.test

  18 of 21 log/print sites exercised in tests
  App tests: [PASS]

  Wrote runs/report.json
  Wrote runs/report_before.json
  Wrote runs/leak-report.md
```

---

### Step 2 — Fix

There are two modes: automated (Bob Shell) and manual (Bob IDE).

#### Option A — Prepare only, then fix in the Bob IDE

```bash
logleak fix demo/caredesk --prepare-only
```

1. Copies `demo/caredesk` → `runs/workspace/caredesk` (skipping `__pycache__`, `.pytest_cache`, `.git`, etc.). The original is **never modified**.
2. Regenerates `runs/leak-report.md` from the workspace copy so source context lines are accurate.
3. Stops and prints instructions.

Then in the Bob IDE:
1. Switch to the **`logleak-fixer`** mode.
2. Attach `runs/leak-report.md` to the conversation.
3. Prompt: *"Fix every leak listed in the report inside `runs/workspace/caredesk`. Follow the fix protocol."*

#### Option B — Fully automated (requires `bob` on PATH)

```bash
logleak fix demo/caredesk
```

After preparing the workspace, calls Bob Shell non-interactively:

```
bob --chat-mode=logleak-fixer --yolo -p "Fix every leak in @runs/leak-report.md ..."
```

Bob uses the [LogLeak MCP server](#mcp-server) to read leak context, then edits the workspace files. After each round of fixes, Bob calls the `verify_fix` MCP tool to check its own work, iterating up to 3 rounds until the gate passes. Bob's write scope is constrained to `runs/workspace/` by the mode rules.

**Fix strategies Bob applies:**

| Leak owner | Strategy |
|---|---|
| App code | Edit the call site: replace the leaking value with a redacted version or a safe identifier |
| Third-party library | Install a `RedactionFilter` on the logger that emits the library's records |
| All apps | Install a central `RedactionFilter` in `logging_config.py` as a safety net |

---

### Step 3 — Verify

```bash
logleak verify runs/workspace/caredesk
```

Re-runs the full scan on the fixed workspace and evaluates the 6-check verification gate. Exits `0` on pass, `1` on failure.

**Example output:**

```
  [PASS]  G1  No confirmed leaks remaining
  [PASS]  G2  No critical suspected leaks
  [PASS]  G3  App tests pass
  [PASS]  G4  No over-redaction (useful IDs present)
  [PASS]  G5  Log site retention >= 90%
  [PASS]  G6  Safety-net RedactionFilter active

  [GATE PASSED]
```

See [Verification gate](#verification-gate) for what each check means and what it prevents.

---

### Step 4 — Dashboard

```bash
logleak serve
# opens at http://127.0.0.1:8765/ui/
```

A FastAPI + vanilla JS dashboard showing:

- **Before/after log streams** — synced scroll, PII highlighted in yellow before and covered by redaction bars after
- **Leak table** — sortable by severity, with sink type, hit count, and masked sample
- **Gate panel** — all 6 checks with pass/fail status and failure reasons
- **Diff panel** — per-leak before/after source diff on row click
- **Unwitnessed sites** — log statements your tests never executed (honest coverage)

```bash
logleak serve --host 0.0.0.0 --port 9000   # custom bind address
```

---

## CLI reference

```
logleak scan <target>
    Scan the target app for PII leaks. Writes runs/report.json,
    runs/report_before.json, and runs/leak-report.md.

    Arguments:
      target          Path to the target app directory (must contain a
                      pytest test suite)

logleak fix <target> [--prepare-only]
    Copy target to runs/workspace/<name>, write runs/leak-report.md,
    then invoke Bob Shell to fix the leaks.

    Arguments:
      target          Path to the original app directory

    Options:
      --prepare-only  Stop after copying the workspace; do not run Bob.
                      Use this to fix manually in the Bob IDE.

logleak verify <workspace>
    Run the 6-check verification gate on a workspace. Exits 0 on pass,
    1 on failure. Writes runs/gate.json.

    Arguments:
      workspace       Path to the fixed workspace (e.g. runs/workspace/caredesk)

logleak serve [--host HOST] [--port PORT]
    Start the FastAPI dashboard server.

    Options:
      --host HOST     Bind host (default: 127.0.0.1)
      --port PORT     Bind port (default: 8765)
```

---

## Detection rules

LogLeak detects 7 kinds of PII. Each kind has a false-positive guard so it prefers a missed leak over a wrong one.

| Kind | Severity | Rule | False-positive guard |
|---|---|---|---|
| `email` | high | RFC-lite regex `local@domain.tld` | — |
| `card` | critical | 13–19 digits, optional spaces or dashes | Must pass **Luhn checksum**; must not be part of a longer digit run |
| `cnic` | critical | `DDDDD-DDDDDDD-D` (dashed form always) | Plain 13-digit form only when the word `cnic` appears within 20 characters |
| `phone` | high | `(+92\|0092\|0)3DD[- ]?DDDDDDD` or E.164 `+DDDDDDDDDD` | Not preceded by a colon (avoids timestamps) |
| `iban` | critical | `[A-Z]{2}DD[A-Z0-9]{11,30}` | Must pass **ISO 13616 mod-97 checksum** |
| `jwt` | critical | `eyJ…\.eyJ…\.…` (three base64url segments) | — |
| `secret` | critical | Keyword (`api_key`, `token`, `secret`, `password`) followed by a value | Non-`password` keywords require value length ≥ 16 and **Shannon entropy ≥ 3.5 bits/char** |

### Confidence levels

- **`confirmed`** — the exact canary value was found. Zero ambiguity.
- **`suspected`** — a pattern matched but the value is not a known canary. These are flagged for review but only `critical` suspected leaks fail the gate (G2).

Overlapping matches keep the most specific kind (higher priority wins). A card number inside a JSON body is still one `card` finding, not also an `email`.

---

## Masking rules

All values are masked before leaving the engine. Reports, MCP tool output, API responses, and Bob prompts contain only masked values.

| Kind | Masked form | Reason |
|---|---|---|
| `email` | `c***@logleak.test` | Domain kept for debugging |
| `card` | `************4242` | PCI DSS allows the last 4 digits |
| `phone` | `+92*******567` | Last 3 digits for support lookup |
| `cnic` | `[REDACTED:cnic]` | Last digit encodes gender — mask all of it |
| `iban` | `GB82******************` | Country and check digits only; padded to the original length |
| `jwt` | `[REDACTED:jwt]` | Never partial |
| `secret` | `[REDACTED:secret]` | Never partial |

`RedactionFilter` is a `logging.Filter` that rewrites `record.msg`, `record.args`, and `record.exc_text` in-flight on every log record, including from third-party loggers. It **never drops a record** — it only rewrites it.

---

## Verification gate

`logleak verify` runs 6 checks. All 6 must pass for the gate to pass.

| Check | ID | Passes when | Prevents Bob from… |
|---|---|---|---|
| No confirmed leaks | `no_confirmed_leaks` | Zero canary-matched leaks in the after-scan | Leaving leaks in place |
| No critical suspected | `no_critical_suspected` | Zero suspected critical leaks in the after-scan | Leaking non-canary data of the same type |
| Tests pass | `tests_pass` | The app's pytest suite exits 0 | Breaking the application |
| No over-redaction | `no_over_redaction` | Allowlisted useful tokens (order IDs, appointment IDs) still appear in after-logs | Masking everything indiscriminately |
| Log sites retained | `logs_retained` | `len(after executed sites) / len(before executed sites) >= 0.90` | Silently deleting log lines to game the result |
| Safety net active | `safety_net` | A probe log line containing the card canary comes out masked through the app's configured logging | Skipping the defence-in-depth filter |

The gate result is written to `runs/gate.json`:

```json
{
  "passed": true,
  "checks": {
    "no_confirmed_leaks": true,
    "no_critical_suspected": true,
    "tests_pass": true,
    "no_over_redaction": true,
    "logs_retained": true,
    "safety_net": true
  },
  "reasons": []
}
```

---

## MCP server

LogLeak ships its own MCP server that Bob uses during a fix run to read leak context, re-scan, and self-verify.

### Starting the server

The server is registered in [`.bob/mcp.json`](.bob/mcp.json) and starts automatically when Bob opens a session in this workspace:

```json
{
  "mcpServers": {
    "logleak": {
      "command": "python",
      "args": ["-m", "logleak.mcp_server"],
      "alwaysAllow": ["scan_logs", "list_leaks", "get_leak_context", "verify_fix"]
    }
  }
}
```

To run it manually (stdio transport):

```bash
python -m logleak.mcp_server
```

### Available tools

| Tool | Input | Output |
|---|---|---|
| `scan_logs` | `target: str` | Leak count by kind and severity, executed/total sites, report path |
| `list_leaks` | `severity?: str` | List of `Leak` objects: fingerprint, kind, file, line, sink, masked sample |
| `get_leak_context` | `fingerprint: str` | ±5 lines of source code, masked sample, sink, owner (`app` or `third_party`), recommended fix strategy |
| `verify_fix` | `target: str` | `GateResult`: passed, all 6 checks, failure reasons |

**Privacy invariant:** every tool return value passes through `redact_text()` before being sent to Bob. A spec test in `tests/test_mcp_tools.py` fails if any canary value appears anywhere in any tool output.

### Resource

`logleak://policy` returns the masking table so Bob always uses the same masks as the engine.

---

## Files produced in `runs/`

| File | Produced by | Contents |
|---|---|---|
| `runs/report.json` | `logleak scan` | Masked scan report (before) |
| `runs/report_before.json` | `logleak scan` | Gate's before-baseline (same content, kept separately) |
| `runs/leak-report.md` | `logleak scan` / `logleak fix` | Masked report with ±5 lines of source context per leak — Bob's input |
| `runs/workspace/<name>/` | `logleak fix` | Working copy Bob edits — original is **never** touched |
| `runs/report_after.json` | `logleak verify` | Masked scan report (after fix) |
| `runs/gate.json` | `logleak verify` | 6 boolean checks + failure reasons |

All `runs/` content is gitignored. The raw capture JSONL (the only place where unmasked values exist during a scan) lives there and is never read back after `scanner.py` processes it into a masked `Report`.

---

## Repository layout

```
logleak/                  engine (installable Python package)
  canaries.py             7 fake-but-valid PII canary values
  detectors.py            detect(), luhn_valid(), iban_valid(), shannon_entropy()
  redact.py               mask(), redact_text(), RedactionFilter
  capture.py              LeakCaptureHandler, CapturedRecord, capture_stdout()
  pytest_plugin.py        installs capture into the target app's test run
  tracer.py               groups CapturedRecords into Leak objects
  sitemap.py              AST scan of every log/print call site
  report.py               Report dataclass, to_json(), to_markdown()
  scanner.py              scan_target() — runs pytest + plugin in subprocess
  verify.py               run_gate() — 6-check verification gate
  fixer.py                prepare_workspace(), run_bob()
  mcp_tools.py            plain functions Bob calls through MCP (unit-testable)
  mcp_server.py           FastMCP wrapper (stdio transport)
  server.py               FastAPI dashboard API
  cli.py                  logleak scan | fix | verify | serve

ui/
  index.html              dashboard layout
  styles.css              IBM Plex design tokens, log stream highlights, redaction bars
  app.js                  fetch + SSE, renders all panels

demo/
  caredesk/               pristine target app with 7 planted leaks (never modified)
  caredesk_after/         Bob's fixed version that passes the 6-check gate (committed evidence)

runs/                     gitignored — reports, workspace, raw captures
tests/                    86 spec tests — all passing
docs/                     architecture, build plan, MCP plan, UI spec
.bob/
  rules/                  Bob rules active in every conversation
  rules-logleak-fixer/    Extra rules for the fixer mode
  custom_modes.yaml       logleak-fixer and logleak-auditor mode definitions
  mcp.json                Project MCP server configuration
```

---

## Demo app — CareDesk

CareDesk is a small FastAPI clinic booking and payments API with **7 intentionally planted leaks** covering every realistic leak pattern. The original (`demo/caredesk/`) is never modified. Bob fixes a copy. The fixed version (`demo/caredesk_after/`) is committed as evidence that the gate passes.

| # | File | Leak | Sink | Why it's realistic |
|---|---|---|---|---|
| L1 | `patients.py:29` | `Patient.__repr__` dumps email + phone + CNIC | log | The most common real-world leak pattern |
| L2 | `payments.py:25` | Full card number in a `DEBUG` log | log | Classic PCI DSS violation |
| L3 | `payments.py:33` | Card number in a `ValueError` message, then `logger.exception()` | exception | Invisible to grep for log calls |
| L4 | `middleware.py:27` | Full JSON request body logged by middleware | log | Leaks every field at once |
| L5 | `auth.py:25` | JWT token printed to stdout | stdout | Forgotten debug `print()` |
| L6 | `notifications.py:30` | Phone number in SMS retry warning | log | Hidden in error-handling code |
| L7 | httpx (third-party) | Email in a URL query string at INFO level | log | You don't own the code — fix needs a filter |

CareDesk also includes **decoys that must not be flagged**: order IDs like `ORD-4111111111111112` (Luhn-invalid) and appointment IDs, verifying zero false positives. These same IDs are checked by gate check G4 to ensure Bob doesn't accidentally redact them.

---

## Privacy and security invariants

These rules are enforced in code and by spec tests. They cannot be bypassed.

1. **Raw PII lives only in `runs/`**, which is in both `.gitignore` and `.bobignore`. It is never committed, never read back after `scanner.py`, and never sent anywhere.
2. **Everything after `report.py` is masked.** Reports, MCP outputs, API responses, and Bob prompts contain only masked values. `redact_text()` is called as a final sanitisation pass in both the MCP server and the dashboard API.
3. **Canary values are fake by construction.** No real personal data is ever used in the demo. The `.test` TLD is a reserved TLD that can never be a real email address.
4. **Bob's write scope is `runs/workspace/`**, enforced by the mode rules in `.bob/rules-logleak-fixer/`. Bob Shell non-interactive mode also cannot write outside its start directory.
5. **`RedactionFilter` must never drop a record.** It may only rewrite `msg`, `args`, and `exc_text`. Dropping a record would silently destroy observability.

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Python 3.11+ |
| Test runner | pytest ≥ 8 |
| Demo app | FastAPI + httpx TestClient |
| MCP server | `fastmcp` (Python, stdio transport) |
| Dashboard backend | FastAPI + uvicorn |
| Dashboard frontend | Vanilla HTML / CSS / JS (no build step) |
| Fonts | IBM Plex Sans + IBM Plex Mono |
| AI | IBM Bob 2.0 (IDE + Bob Shell) |

---

## Further reading

| Document | What it covers |
|---|---|
| [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Full component specs, data flow diagram, detection and masking rules, verification gate internals |
| [`docs/00-MASTER-PLAN.md`](docs/00-MASTER-PLAN.md) | Problem framing, differentiators, hackathon scope |
| [`docs/03-MCP-PLAN.md`](docs/03-MCP-PLAN.md) | MCP server design, tool schemas, configuration |
| [`docs/04-UI-FRONTEND.md`](docs/04-UI-FRONTEND.md) | Dashboard layout, components, API endpoints, design tokens |
| [`docs/02-BUILD-PLAN.md`](docs/02-BUILD-PLAN.md) | Build schedule and phase breakdown |
| [`.bob/rules/01-logleak-core.md`](.bob/rules/01-logleak-core.md) | Rules Bob follows in every conversation in this repo |
| [`.bob/rules-logleak-fixer/01-fix-protocol.md`](.bob/rules-logleak-fixer/01-fix-protocol.md) | Fix protocol rules active in `logleak-fixer` mode |
| [`tests/`](tests/) | 86 spec tests — written before the code; the implementation contract |
