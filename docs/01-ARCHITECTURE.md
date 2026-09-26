# 01 · Architecture — LogLeak

## 1. System overview

```mermaid
flowchart LR
    subgraph Target["Target app (demo/caredesk)"]
        T[Test suite<br/>pytest] --> A[App code<br/>logging / print / raise]
    end

    subgraph Engine["LogLeak engine (Python)"]
        C[canaries.py<br/>fake-but-valid PII] --> T
        P[pytest_plugin.py<br/>LeakCaptureHandler + stdout tee] -->|JSONL records| D[detectors.py]
        A -->|log records with file:line| P
        D --> TR[tracer.py<br/>group by file:line:kind]
        S[sitemap.py<br/>AST: all log call sites] --> R
        TR --> R[report.py<br/>masked Report]
        R --> V[verify.py<br/>6-check gate]
        R --> F[fixer.py<br/>builds masked Bob prompt]
    end

    subgraph Bob["IBM Bob"]
        F -->|bob --chat-mode=logleak-fixer -p| B[Bob Shell / IDE]
        B <-->|MCP tools| M[mcp_server.py]
        B -->|edits| W[Working copy<br/>runs/workspace/caredesk]
    end

    M --> R
    W --> T
    R --> UI[Dashboard<br/>FastAPI + ui/]
    V --> UI
```

**Key design decision:** the original `demo/caredesk` is never modified. Every fix run copies it to `runs/workspace/caredesk`, so the demo is repeatable and the before/after comparison is always honest.

## 2. Repository layout

```
logleak/
├── logleak/                    # the engine (installable package)
│   ├── __init__.py
│   ├── canaries.py             # canary PII values
│   ├── detectors.py            # detect(), luhn_valid(), iban_valid(), shannon_entropy()
│   ├── redact.py               # mask(), redact_text(), RedactionFilter
│   ├── capture.py              # LeakCaptureHandler, CapturedRecord, stdout tee
│   ├── pytest_plugin.py        # installs capture into the target's test run
│   ├── tracer.py               # records + findings -> Leak list
│   ├── sitemap.py              # AST scan of every log/print call site
│   ├── report.py               # Report model, JSON + Markdown export
│   ├── scanner.py              # scan_target(): run pytest+plugin, build a Report
│   ├── verify.py               # run_gate()
│   ├── fixer.py                # prompt builder + Bob Shell runner
│   ├── mcp_tools.py            # plain functions (testable)
│   ├── mcp_server.py           # FastMCP wrapper around mcp_tools
│   ├── server.py               # FastAPI API for the dashboard
│   └── cli.py                  # logleak scan | fix | verify | serve
├── ui/                         # index.html, app.js, styles.css
├── demo/
│   ├── caredesk/               # pristine target app with 7 planted leaks
│   └── caredesk_after/         # Bob's fixed version, committed as evidence
├── runs/                       # gitignored: before.jsonl, after.jsonl, reports
├── tests/                      # spec tests (written first)
├── docs/
├── bob_sessions/<member>/      # task session summary screenshots
├── .bob/                       # rules, custom modes, mcp.json
├── .bobignore / .gitignore     # from the IBM template
└── pyproject.toml
```

## 3. Component specs

### 3.1 `canaries.py`

Fake values that are valid in format, so validators accept them and matching is exact.

| Kind | Canary | Notes |
|---|---|---|
| email | `canary.patient@logleak.test` | `.test` is a reserved TLD and can never be real |
| card | `4242424242424242` | Well-known test card, Luhn-valid |
| cnic | `35202-1234567-9` | Valid CNIC format |
| phone | `+923001234567` | Pakistani mobile format |
| iban | `GB82WEST12345698765432` | Standard textbook IBAN with a valid checksum |
| jwt | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl` | Harmless structure |
| secret | `llk_canary_9fQ2xV7pL3mZ8rT1wY6bN4cK` | Custom prefix so GitHub push protection doesn't block it |

API: `CANARIES: dict[str, str]`, `all_canaries() -> list[str]`.

### 3.2 `detectors.py`

```python
@dataclass(frozen=True)
class Finding:
    kind: str          # email | card | cnic | phone | iban | jwt | secret
    value: str         # raw match (never leaves the engine unmasked)
    start: int
    end: int
    confidence: str    # "confirmed" (canary match) | "suspected" (pattern)

def detect(text: str, canaries: Iterable[str] | None = None) -> list[Finding]
def luhn_valid(digits: str) -> bool
def iban_valid(iban: str) -> bool
def shannon_entropy(s: str) -> float
SEVERITY: dict[str, str]   # card/cnic/iban/jwt/secret -> "critical"; email/phone -> "high"
```

| Kind | Rule | False-positive guard |
|---|---|---|
| email | RFC-lite regex | — |
| card | 13–19 digits, optional spaces or dashes | Must pass Luhn and must not be part of a longer digit run |
| cnic | `\d{5}-\d{7}-\d` | A 13-digit run without dashes counts only when the word "cnic" is within 20 characters |
| phone | `(\+92\|0092\|0)3\d{2}[- ]?\d{7}` or E.164 `\+\d{10,15}` | Not inside a timestamp or longer number |
| iban | `[A-Z]{2}\d{2}[A-Z0-9]{11,30}` | Must pass mod-97 |
| jwt | `eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+` | — |
| secret | `(api_key\|token\|secret\|password)\s*[=:]\s*\S+` with entropy ≥ 3.5 for 16+ characters; any `password=` value | — |

Overlapping matches keep the most specific kind (a card inside a JSON body is still one card finding).

### 3.3 `redact.py`

| Kind | `mask()` output | Reason |
|---|---|---|
| email | `c***@logleak.test` | Keeps the domain for debugging |
| card | `************4242` | PCI allows the last 4 digits |
| phone | `+92*******567` | Last 3 digits for support |
| cnic | `[REDACTED:cnic]` | The last digit encodes gender, so mask all of it |
| iban | `GB82******************` | Country and check digits only; same length as the original |
| jwt / secret | `[REDACTED:jwt]` / `[REDACTED:secret]` | Never partial |

`redact_text(text) -> str` masks every finding. `RedactionFilter(logging.Filter)` rewrites `record.msg`, `record.args`, and `record.exc_text` so it catches third-party loggers too. It must **never** drop a record.

### 3.4 `capture.py` + `pytest_plugin.py`

- `LeakCaptureHandler(logging.Handler)` is attached to the root logger at `DEBUG`. It stores a `CapturedRecord(logger, level, message, pathname, lineno, func_name, exc_text, sink)`.
  - `message = record.getMessage()` fully formats the args, which is where `%s` leaks become visible.
  - `exc_text` is the formatted traceback when `exc_info` is set (sink = `exception`).
- The stdout tee is the context manager `capture_stdout() -> list[CapturedRecord]`. It wraps `sys.stdout` and records `print` output with the caller's frame `file:line` (sink = `stdout`).
- `CapturedRecord.to_dict()` / `CapturedRecord.from_dict(d)` handle the JSONL round trip.
- The plugin is loaded with `pytest -p logleak.pytest_plugin`. Output goes to the path in `LOGLEAK_OUT` as JSONL. The canary values are provided to the target's tests through a `canary` fixture.
- **Important:** the handler stores raw text only in the local `runs/` folder (gitignored). Everything after `report.py` is masked.

### 3.5 `tracer.py`

```python
@dataclass
class Leak:
    fingerprint: str   # sha1(file:line:kind)[:12]
    kind: str
    severity: str
    confidence: str
    file: str          # relative to the target root
    line: int
    function: str
    logger: str
    sink: str          # log | exception | stdout
    hits: int
    sample: str        # the MASKED message
def trace(records, canaries=None, root: Path | None = None) -> list[Leak]
```

When `root` is given, `file` is made relative to it.

Groups findings by `(file, line, kind)`. A leak from a third-party library keeps that library's path. **Owner rule:** a leak is `third_party` when its path contains `site-packages` or `dist-packages`, or lies outside the target root; otherwise it is `app`. The fixer uses this to choose "filter" instead of "edit the call site".

### 3.6 `sitemap.py`

`find_log_sites(root) -> list[LogSite(file, line, call)]` walks the AST for `logger.<level>(`, `logging.<level>(`, `log.<level>(`, `.exception(`, and `print(`.

- **Executed sites** are the `(file, line)` pairs seen in the capture.
- **Unwitnessed sites** = all sites minus executed sites, via `unwitnessed(sites, executed) -> list[LogSite]`. These are reported honestly as "not proven clean".
- A call counts as a log site only when its receiver is `logging`, `log`, `logger`, `_logger`, `LOGGER`, or a name ending in `logger`, or when it is a bare `print(`. This avoids flagging `obj.info()` or `dict.get()`.

### 3.7 `report.py`

`Report(target, leaks, executed_sites, total_sites, log_text_masked, tests_exit_code)`, where `executed_sites` is a `set[tuple[str, int]]`. It exports:
- `report.json` (for the UI and MCP)
- `leak-report.md` (the prompt attachment for Bob: masked samples plus ±5 lines of code per leak)

`Report.to_json() -> str` and `Report.to_markdown(code_root) -> str`. Both are masked.

### 3.7b `scanner.py`

`scan_target(target: Path, out_dir: Path) -> Report` runs `pytest -p logleak.pytest_plugin` in a subprocess inside `target`, reads the JSONL, then detects, traces, maps sites, and returns the Report. The same function is used by the CLI, the MCP server, and the e2e tests.

### 3.8 `verify.py` — the gate

```python
def run_gate(before: Report, after: Report, *, allowlist_tokens: list[str],
             probe_masked: bool, min_site_retention: float = 0.9) -> GateResult
```

| Check | Passes when | Stops Bob from… |
|---|---|---|
| G1 `no_confirmed_leaks` | `after` has zero confirmed leaks | leaving leaks in place |
| G2 `no_critical_suspected` | Zero suspected critical leaks | leaking non-canary data |
| G3 `tests_pass` | `after.tests_exit_code == 0` | breaking the app |
| G4 `no_over_redaction` | Every allowlisted token (order IDs, appointment IDs) still appears in the after-logs | masking everything |
| G5 `logs_retained` | Executed sites after ≥ 90% of executed sites before | deleting log lines |
| G6 `safety_net` | A probe log line containing a canary comes out masked through the app's configured logging | skipping defense-in-depth |

G6 input comes from `mcp_tools.probe_safety_net(app_path) -> bool`. In a subprocess, it imports the app's logging setup (`configure_logging()` in the app's `logging_config.py`), logs a line containing the card canary, and returns `True` only if the output is masked.

`GateResult(passed, checks: dict[str, bool], reasons: list[str])` with `to_dict()`. Retention is count-based, `len(after.executed_sites) / len(before.executed_sites) >= 0.9`, because Bob's edits shift line numbers, so matching sites by `(file, line)` would be wrong.

### 3.9 `fixer.py`

1. Copy `demo/caredesk` to `runs/workspace/caredesk`.
2. Write `runs/leak-report.md`, masked.
3. Run:
   ```bash
   bob --chat-mode=logleak-fixer --yolo -p "Fix every leak in @runs/leak-report.md inside runs/workspace/caredesk. Follow the fix protocol. When done, call the logleak verify_fix tool and iterate until the gate passes (max 3 rounds)."
   ```
   Stream stdout to the UI through server-sent events (SSE).
4. Run `verify`, and save the diff with `git diff --no-index demo/caredesk runs/workspace/caredesk`.

Note that Bob Shell non-interactive mode requires API-key authentication and `--yolo` to write files. Fallback: run the same prompt in the Bob IDE.

### 3.10 `mcp_tools.py` / `mcp_server.py`

See `03-MCP-PLAN.md`. The invariant is that **no tool ever returns a raw PII value.** A spec test enforces it.

Test-facing helpers in `mcp_tools.py`: `set_current_report(report)` (loads a report without scanning) and `sanitize(obj)` (recursively applies `redact_text()` to every string in dicts, lists, and tuples). Every tool returns `sanitize(result)`.

### 3.11 `server.py` (dashboard API)

See `04-UI-FRONTEND.md` for the endpoints.

## 4. Data flow for a full run

```
logleak scan  → pytest + plugin → runs/before.jsonl → detect → trace → report(before)
logleak fix   → copy workspace → leak-report.md → Bob (mode + rules + MCP) → edits
logleak verify→ pytest + plugin on workspace → runs/after.jsonl → report(after) → gate
logleak serve → dashboard reads before/after reports, gate, diff
```

## 5. Security and privacy invariants

1. Raw captured text exists only in `runs/`, which is in both `.gitignore` and `.bobignore`.
2. Reports, the MCP output, UI payloads, and Bob prompts contain masked values only.
3. Canary values are fake by construction. No real personal data is ever used in the demo.
4. Bob's write scope is limited to `runs/workspace/` by the mode rules, and Bob Shell can't write outside its start directory.

## 6. Tech stack

| Layer | Choice |
|---|---|
| Language | Python 3.11+ |
| Test runner | pytest (≥ 8) |
| Demo app | FastAPI + httpx TestClient |
| MCP | `fastmcp` (Python) |
| Dashboard | FastAPI static files + vanilla JS, IBM Plex fonts |
| AI | IBM Bob 2.0 (IDE + Bob Shell); optional watsonx.ai Granite for triaging suspected findings |
