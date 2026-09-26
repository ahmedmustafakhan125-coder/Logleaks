# 05 · Implementation Plan — LogLeak

## Overview

Build the `logleak` Python package from scratch so that every test in `tests/`
(excluding `e2e`) passes. The architecture is described in `docs/01-ARCHITECTURE.md`.
The tests are the contract — no test is edited. Implementation proceeds module by module
in dependency order. Each module is done when its spec test is green.

---

## 1. Build Order

| Step | Module(s) | Spec test(s) | Status |
|------|-----------|--------------|--------|
| 0 | `pyproject.toml` + `logleak/__init__.py` | import succeeds | [ ] pending |
| 1 | `canaries.py` | `conftest.py` (fixtures import it) | [ ] pending |
| 2 | `detectors.py` | `test_detectors.py` | [ ] pending |
| 3 | `redact.py` | `test_redaction.py` | [ ] pending |
| 4 | `capture.py` | `test_capture_trace.py` (capture section) | [ ] pending |
| 5 | `tracer.py` | `test_capture_trace.py` (tracer section) | [ ] pending |
| 6 | `sitemap.py` | `test_capture_trace.py` (sitemap section) | [ ] pending |
| 7 | `report.py` | used by `conftest.py` fixtures; exercised by e2e | [ ] pending |
| 8 | `scanner.py` | `test_demo_app_e2e.py` (e2e) | [ ] pending |
| 9 | `verify.py` | `test_verify_gate.py` | [ ] pending |
| 10 | `mcp_tools.py` | `test_mcp_tools.py` | [ ] pending |
| 11 | `mcp_server.py` | (manual / Phase 3 smoke test) | [ ] pending |
| 12 | `pytest_plugin.py` | part of scanner / e2e | [ ] pending |
| 13 | `fixer.py` + `cli.py` | `logleak --help` + e2e | [ ] pending |
| 14 | `server.py` | Phase 4 dashboard | [ ] pending |

---

## 2. Public Interface Contract

The tables below list every symbol the tests import, its exact module, and its
signature or dataclass fields. **These are immutable — the tests own the contract.**

### 2.1 `logleak.canaries`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `CANARIES` | `dict[str, str]` | Keys: `email`, `card`, `cnic`, `phone`, `iban`, `jwt`, `secret` |
| `all_canaries` | function | `() -> list[str]` |

### 2.2 `logleak.detectors`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `Finding` | frozen dataclass | `kind: str`, `value: str`, `start: int`, `end: int`, `confidence: str` |
| `detect` | function | `(text: str, canaries: Iterable[str] \| None = None) -> list[Finding]` |
| `luhn_valid` | function | `(digits: str) -> bool` |
| `iban_valid` | function | `(iban: str) -> bool` |
| `shannon_entropy` | function | `(s: str) -> float` |
| `SEVERITY` | `dict[str, str]` | `card/cnic/iban/jwt/secret → "critical"`, `email/phone → "high"` |

### 2.3 `logleak.redact`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `mask` | function | `(kind: str, value: str) -> str` |
| `redact_text` | function | `(text: str) -> str` |
| `RedactionFilter` | class | `logging.Filter` subclass; `filter(record) -> bool` always returns `True` |

### 2.4 `logleak.capture`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `CapturedRecord` | dataclass | `logger: str`, `level: str`, `message: str`, `pathname: str`, `lineno: int`, `func_name: str`, `exc_text: str \| None`, `sink: str` |
| `CapturedRecord.to_dict` | method | `() -> dict` |
| `CapturedRecord.from_dict` | classmethod | `(d: dict) -> CapturedRecord` |
| `LeakCaptureHandler` | class | `logging.Handler`; `.records: list[CapturedRecord]` |
| `capture_stdout` | context manager | `() -> list[CapturedRecord]` (yields the list, populated in `__exit__`) |

### 2.5 `logleak.tracer`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `Leak` | dataclass | `fingerprint: str`, `kind: str`, `severity: str`, `confidence: str`, `file: str`, `line: int`, `function: str`, `logger: str`, `sink: str`, `hits: int`, `sample: str` |
| `trace` | function | `(records: Iterable[CapturedRecord], canaries: Iterable[str] \| None = None, root: Path \| None = None) -> list[Leak]` |

### 2.6 `logleak.sitemap`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `LogSite` | dataclass or namedtuple | `file: str`, `line: int`, `call: str` |
| `find_log_sites` | function | `(root: Path) -> list[LogSite]` |
| `unwitnessed` | function | `(sites: list[LogSite], executed: set[tuple[str,int]]) -> list[LogSite]` |

### 2.7 `logleak.report`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `Report` | dataclass | `target: str`, `leaks: list[Leak]`, `executed_sites: set[tuple[str,int]]`, `total_sites: int`, `log_text_masked: str`, `tests_exit_code: int` |
| `Report.to_json` | method | `() -> str` |
| `Report.to_markdown` | method | `(code_root: Path) -> str` |

### 2.8 `logleak.scanner`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `scan_target` | function | `(target: Path, out_dir: Path) -> Report` |

### 2.9 `logleak.verify`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `GateResult` | dataclass | `passed: bool`, `checks: dict[str, bool]`, `reasons: list[str]` |
| `GateResult.to_dict` | method | `() -> dict` |
| `run_gate` | function | `(before: Report, after: Report, *, allowlist_tokens: list[str], probe_masked: bool, min_site_retention: float = 0.9) -> GateResult` |

### 2.10 `logleak.mcp_tools`

| Name | Kind | Signature / fields |
|------|------|--------------------|
| `set_current_report` | function | `(report: Report) -> None` |
| `sanitize` | function | `(obj: Any) -> Any` |
| `list_leaks` | function | `(severity: str \| None = None) -> list[dict]` |
| `get_leak_context` | function | `(fingerprint: str) -> dict` — raises `KeyError` for unknown fingerprints |
| `probe_safety_net` | function | `(app_path: Path) -> bool` |

---

## 3. Gaps and Contradictions Between Docs and Tests

The following discrepancies were found by reading both carefully. **Tests win. No test is changed.**

### G1 — `capture_stdout` yield semantics
The architecture doc says `capture_stdout() -> list[CapturedRecord]` is a context manager.
`test_capture_stdout_records_print_with_caller_line` uses it as `with capture_stdout() as records:`
and then reads `records` **after** the `with` block. This means the list must be the yielded
object (populated in place), not returned after exit. Implementation: yield a mutable list
from `__enter__`, append records during the context, and leave the list in place when the
context exits.

### G2 — `trace()` scans `exc_text`, not just `message`
`test_trace_scans_exception_text` passes a record where `message = "payment failed"` but the
card canary lives in `exc_text`. The tracer must detect against both fields separately and
attribute the correct sink (`exception`) and a masked `sample` from `exc_text`.
The architecture mentions this only in passing; the test is the precise spec.

### G3 — `trace()` splits kinds per source field
When a record contains multiple canaries (e.g. email + phone in the message), `trace` returns
**one `Leak` per `(file, line, kind)` triple**, not one per record. This is correct and explicit
in `test_trace_splits_kinds_on_same_line`. The fingerprint is computed from `(file, line, kind)`.

### G4 — Fingerprint formula
`conftest.py` sets `fingerprint=f"{file}:{line}:{kind}"[-12:]`. The tests check only that it
is 12 characters and stable across different messages at the same location. The implementation
must use `sha1(f"{file}:{line}:{kind}".encode())[:12]` — or, more simply, just the last 12
characters of `f"{file}:{line}:{kind}"` as the conftest does. Use sha1 (from `hashlib`) for
determinism. **Cross-check:** `test_fingerprint_is_stable_and_short` verifies that two records
at the same `(file, line)` with the same kind but different messages produce identical fingerprints,
so the fingerprint must NOT include the message content.

> **Contradiction:** `conftest.py` uses `f"{file}:{line}:{kind}"[-12:]` as the fingerprint
> string in the `make_leak` fixture, but `test_fingerprint_is_stable_and_short` only checks
> length == 12 and stability. Using `sha1(key)[:12]` hex satisfies both and avoids the
> edge case where `f"{file}:{line}:{kind}"` is shorter than 12 characters. Use sha1.

### G5 — `mcp_tools.probe_safety_net` is imported from `mcp_tools`, not `verify`
`test_demo_app_e2e.py` line 85: `from logleak.mcp_tools import probe_safety_net`.
Architecture doc places it in `mcp_tools.py`. `verify.py` calls it as an external helper
through `probe_masked: bool` (the caller passes the result, not the function). Correct design:
`probe_safety_net` lives in `mcp_tools.py`. The `run_gate` signature stays as `probe_masked: bool`.

### G6 — `GateResult.reasons` is empty on full pass
`test_clean_fix_passes` asserts `result.reasons == []` when all checks pass. Any check that
fails must append a human-readable string to `reasons` naming the offending kind or token.
The test `test_over_redaction_fails_gate` checks `any("ORD-" in r or "PT-" in r or "APT-" in r
for r in result.reasons)`, so reasons must name the missing tokens.

### G7 — `RedactionFilter` must mask before the formatter renders `exc_text`
`test_filter_masks_exception_tracebacks` attaches the filter to the **handler** (not the logger)
and still expects the traceback to be masked. The formatter is also on the handler. Python calls
`filter(record)` before `format(record)`. So `RedactionFilter.filter()` must format the
`exc_info` tuple into `record.exc_text` itself (calling `handler.formatException` is not
available from a filter). Use `logging.Formatter().formatException(record.exc_info)` inside
`filter()` to materialise `exc_text`, then redact it, then set `record.exc_text` and clear
`record.exc_info` so the formatter doesn't re-render it.

### G8 — `find_log_sites` returns paths relative to `root`
`test_find_log_sites` writes `mod.py` to `tmp_path` and calls `find_log_sites(tmp_path)`.
It then asserts `all(s.file == "mod.py" for s in sites)` — a bare filename, not an absolute
path. Implementation must make `file` relative to the given `root`.

### G9 — `unwitnessed` takes `executed` as `set[tuple[str, int]]`
`test_unwitnessed_sites` passes `executed = {("mod.py", 6), ("mod.py", 9)}` — pairs of
(relative file name, line number). The `LogSite.file` field is also relative (see G8), so
the comparison works directly.

### G10 — `scan_target` is the only interface to `scanner.py`
`test_demo_app_e2e.py` imports only `scan_target`. No other symbol from `scanner` is tested.
The function must run `pytest -p logleak.pytest_plugin` in a subprocess inside `target`,
collect the JSONL at the path provided via `LOGLEAK_OUT`, then build and return a `Report`.

---

## 4. `pyproject.toml` Contents

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "logleak"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.111",
    "uvicorn[standard]>=0.29",
    "httpx>=0.27",
    "fastmcp>=2.0",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio"]

[project.scripts]
logleak = "logleak.cli:main"

[tool.pytest.ini_options]
markers = ["e2e: end-to-end tests that run the demo app"]
testpaths = ["tests"]

[tool.setuptools.packages.find]
where = ["."]
include = ["logleak*"]
```

Notes:
- `pytest` is listed under `[dev]`, not in main dependencies, so the installed package doesn't
  pull pytest into production environments.
- `fastmcp>=2.0` is required because the `@mcp.tool` decorator style differs between v1 and v2.
  Verify the exact API via Context7 before implementing `mcp_server.py`.
- The `e2e` marker is registered in both `pyproject.toml` (so pytest does not warn) and in
  `conftest.py` `pytest_configure` (already there — keep both for compatibility).

---

## 5. Tricky Parts and How to Handle Them

### T1 — Detector false positives: Luhn, digit boundaries, and card-vs-CNIC overlap

**Problem:** The order ID `ORD-4111111111111112` must not be flagged as a card, but
`4111111111111111` (same digits minus the last) must be. Two separate guards are needed:

1. **Luhn check:** `test_card_failing_luhn_is_ignored` and `test_order_id_decoy_is_not_a_card`
   confirm that any digit run failing Luhn is silently dropped.

2. **Digit boundary guard:** `test_long_digit_runs_are_not_cards` checks that
   `123456789012345678901` (21 digits) and `WEST4111111111111111X` (card digits preceded/followed
   by letters or more digits) are not matched. Implementation: after the raw regex match for
   13–19 digits, assert that the character immediately before `start` and immediately after `end`
   are NOT digits or word characters. Use a negative lookbehind/lookahead in the regex:
   `(?<!\d)(\d[\d -]{11,17}\d)(?!\d)` and then strip spaces/dashes before Luhn validation.
   Also assert the stripped digits count is in range 13–19.

3. **Card-inside-JSON counted once:** `test_card_inside_json_counted_once` verifies only one
   Finding for a card in a JSON string. This is the deduplication / non-overlap rule. After
   collecting all matches, sort by start position and drop any match whose span overlaps with
   a previously accepted match (prefer higher-specificity kinds: card > cnic > iban > email >
   phone > jwt > secret).

4. **CNIC plain digits need keyword:** `test_cnic_plain_digits_needs_keyword` passes `"CNIC: 6110176543213"` (matches) but `"batch 6110176543213 processed"` (no match). Rule: if the
   match is a plain 13-digit run without dashes, require the word `cnic` (case-insensitive)
   within 20 characters on either side. Dashed format `\d{5}-\d{7}-\d` is always accepted.

### T2 — Capturing the caller's `file:line` for `print()`

**Problem:** `test_capture_stdout_records_print_with_caller_line` asserts that the
`CapturedRecord` produced for a `print()` call inside the test has `pathname == THIS_FILE`
and `lineno == line` (the exact line of the `print` call). The standard `sys.stdout` wrapper
has no intrinsic concept of caller location.

**Solution:** Inside the `capture_stdout` context manager, replace `sys.stdout` with a
wrapper object whose `write(text)` method walks `inspect.stack()` to find the first frame
whose filename is NOT inside the `logleak` package itself (i.e., not `capture.py`). That
frame's `f_code.co_filename` and `f_lineno` become `pathname` and `lineno`. Specifically:

```python
import inspect, sys

class _StdoutTee:
    def __init__(self, original, records):
        self._orig = original
        self._records = records
        self._buf = ""

    def write(self, text):
        self._orig.write(text)
        # accumulate until newline, then flush as one record
        self._buf += text
        if "\n" in self._buf:
            lines = self._buf.split("\n")
            for line in lines[:-1]:
                if line:
                    frame = self._caller_frame()
                    self._records.append(CapturedRecord(
                        logger="", level="", message=line,
                        pathname=frame.f_code.co_filename,
                        lineno=frame.f_lineno,
                        func_name=frame.f_code.co_name,
                        exc_text=None, sink="stdout",
                    ))
            self._buf = lines[-1]

    def _caller_frame(self):
        for fi in inspect.stack():
            if "logleak" not in fi.filename and "capture.py" not in fi.filename:
                return fi.frame
        return inspect.stack()[-1].frame

    def flush(self):
        self._orig.flush()
```

**Edge case:** `print()` emits `text + "\n"` in two separate `write()` calls in CPython 3.11
when `end="\n"` is the default. Buffering until `"\n"` handles this correctly.

### T3 — `RedactionFilter` must mask exception tracebacks before the formatter renders them

**Problem:** `test_filter_masks_exception_tracebacks` attaches `RedactionFilter` to the
handler (not the logger) and logs with `exc_info`. Python's `logging.Handler.emit()` calls
`self.filter(record)` → then `self.format(record)`. The formatter renders `exc_info` into
`exc_text` lazily. If `filter()` tries to read `record.exc_text` it will be `None` at that
point.

**Solution inside `RedactionFilter.filter(record)`:**

1. Redact `record.msg` (the format string) via `redact_text`.
2. Redact `record.args` — if a tuple, redact each string element; if a dict, redact values.
3. If `record.exc_info` is set (and not `False`), force-render the traceback now:
   ```python
   if record.exc_info:
       if not record.exc_text:
           record.exc_text = logging.Formatter().formatException(record.exc_info)
       record.exc_text = redact_text(record.exc_text)
       record.exc_info = None  # prevent the handler's formatter re-rendering it
   ```
4. Always return `True`.

This is safe because `exc_text`, once set on the record, is used by the formatter directly
instead of re-rendering `exc_info`.

### T4 — Making paths relative to the target root in `tracer.py`

**Problem:** `test_trace_makes_paths_relative_to_root` passes `root=Path("/proj")` and a
record with `pathname="/proj/app/pay.py"`. The resulting `Leak.file` must be `"app/pay.py"`.

**Solution:** In `trace()`, when `root` is provided:
```python
try:
    file = str(Path(record.pathname).relative_to(root))
except ValueError:
    file = record.pathname  # outside root → keep absolute (third-party case)
```

The third-party detection rule (path contains `site-packages` or `dist-packages`) still
applies to the original pathname before relativisation, so `mcp_tools` can detect
third-party leaks correctly.

### T5 — `capture_stdout` yield returns list before any prints happen

The test does:
```python
with capture_stdout() as records:
    line = _line_after()
    print(...)
assert len(records) == 1
```

The context manager must `yield` an empty list from `__enter__` and populate it in-place
during the `write()` calls. Using `@contextmanager` with `yield records` (where `records`
is a local list) achieves this. The list is mutated during the context and is fully populated
when the `with` block exits.

### T6 — `test_no_tool_output_contains_raw_canaries` exhaustive check

`test_mcp_tools.py` calls `list_leaks()`, `list_leaks("critical")`, and
`get_leak_context(fp)` for every leak in the loaded report, then JSON-dumps the combined
output and asserts no canary value appears. The `sanitize()` function must walk nested
`dict`, `list`, and `tuple` structures recursively, and apply `redact_text()` to every
string. Every public function in `mcp_tools.py` must pass its return value through
`sanitize()`.

---

## Sub-Tasks for Implementation

### Sub-task 1 — Project scaffold and `canaries.py`
**Intent:** Create the installable package skeleton and the canary PII values.  
**Outcomes:** `pip install -e ".[dev]"` succeeds; `from logleak.canaries import CANARIES, all_canaries` works; `conftest.py` fixtures load.  
**Steps:**
1. Create `pyproject.toml` with the contents in §4 above.
2. Create `logleak/__init__.py` (empty, or with `__version__ = "0.1.0"`).
3. Implement `logleak/canaries.py`: `CANARIES` dict with the 7 values from the architecture doc, and `all_canaries() -> list[str]` returning `list(CANARIES.values())`.  
**Context:** `docs/01-ARCHITECTURE.md` §3.1, `tests/conftest.py`.  
**Status:** [ ] pending

### Sub-task 2 — `detectors.py`
**Intent:** Detect PII kinds in text with Luhn, IBAN mod-97, entropy, and boundary guards.  
**Outcomes:** `pytest tests/test_detectors.py` is green.  
**Steps:**
1. Implement `luhn_valid`, `iban_valid`, `shannon_entropy`.
2. Implement each kind's pattern matcher with the false-positive guards in T1 above.
3. Implement `detect()`: run all matchers, resolve canary-vs-pattern confidence, deduplicate overlapping spans (higher-specificity kind wins), return sorted list.
4. Define `SEVERITY` dict.  
**Context:** `docs/01-ARCHITECTURE.md` §3.2, §5 T1, `tests/test_detectors.py`.  
**Status:** [ ] pending

### Sub-task 3 — `redact.py`
**Intent:** Mask PII values; provide `RedactionFilter` that works on handlers.  
**Outcomes:** `pytest tests/test_redaction.py` is green.  
**Steps:**
1. Implement `mask(kind, value) -> str` for all 7 kinds.
2. Implement `redact_text(text) -> str` using `detect()` to find spans and replace.
3. Implement `RedactionFilter` as per T3 above (materialise and redact `exc_text` inside `filter()`).  
**Context:** `docs/01-ARCHITECTURE.md` §3.3, §5 T3, `tests/test_redaction.py`.  
**Status:** [ ] pending

### Sub-task 4 — `capture.py`
**Intent:** Capture log records and stdout with exact caller location.  
**Outcomes:** `pytest tests/test_capture_trace.py -k capture` is green.  
**Steps:**
1. Implement `CapturedRecord` dataclass with `to_dict()` / `from_dict()`.
2. Implement `LeakCaptureHandler`: stores `CapturedRecord` instances, sets `sink="exception"` when `exc_info` is present.
3. Implement `capture_stdout()` context manager with the `_StdoutTee` pattern from T2.  
**Context:** `docs/01-ARCHITECTURE.md` §3.4, §5 T2 and T5, `tests/test_capture_trace.py`.  
**Status:** [ ] pending

### Sub-task 5 — `tracer.py` and `sitemap.py`
**Intent:** Group captured records into `Leak` objects; map all log call sites via AST.  
**Outcomes:** `pytest tests/test_capture_trace.py -k "tracer or sitemap or trace or site"` is green.  
**Steps:**
1. Implement `Leak` dataclass.
2. Implement `trace()`: for each record, run `detect()` on `message` and on `exc_text` (if present); group by `(file, line, kind)`; compute fingerprint via `sha1`; make path relative when `root` given; set `sample` via `mask()`.
3. Implement `LogSite` dataclass.
4. Implement `find_log_sites(root) -> list[LogSite]`: walk `.py` files with `ast`; recognise logger calls by receiver name; return `file` relative to `root`.
5. Implement `unwitnessed(sites, executed) -> list[LogSite]`.  
**Context:** `docs/01-ARCHITECTURE.md` §3.5 and §3.6, gaps G1–G4 and G8–G9, T4, `tests/test_capture_trace.py`.  
**Status:** [ ] pending

### Sub-task 6 — `report.py`
**Intent:** Aggregate scan output into a serialisable `Report`.  
**Outcomes:** `conftest.py` `make_report` fixture works; `Report.to_json()` and `to_markdown()` produce masked output.  
**Steps:**
1. Implement `Report` dataclass.
2. Implement `to_json()`: serialise to JSON, ensure no raw PII (all samples already masked by `trace()`).
3. Implement `to_markdown(code_root)`: generate the prompt attachment format (masked samples + ±5 lines of code per leak).  
**Context:** `docs/01-ARCHITECTURE.md` §3.7, `tests/conftest.py`, `tests/test_demo_app_e2e.py`.  
**Status:** [ ] pending

### Sub-task 7 — `verify.py`
**Intent:** Implement the 6-check gate.  
**Outcomes:** `pytest tests/test_verify_gate.py` is green.  
**Steps:**
1. Implement `GateResult` dataclass with `to_dict()`.
2. Implement `run_gate()` with checks G1–G6 as described in the architecture and gaps G6.
3. G4 `no_over_redaction`: check that every token in `allowlist_tokens` appears in `after.log_text_masked`; append missing tokens to `reasons`.
4. G5 `logs_retained`: `len(after.executed_sites) / len(before.executed_sites) >= min_site_retention`; handle division-by-zero (pass if both are zero).
5. G6 `safety_net`: use `probe_masked` parameter directly (the caller probes and passes the bool).  
**Context:** `docs/01-ARCHITECTURE.md` §3.8, gaps G5 and G6, `tests/test_verify_gate.py`.  
**Status:** [ ] pending

### Sub-task 8 — `mcp_tools.py`
**Intent:** Implement the plain-function layer Bob calls through MCP; enforce no raw PII.  
**Outcomes:** `pytest tests/test_mcp_tools.py` is green.  
**Steps:**
1. Module-level `_current_report: Report | None = None`.
2. `set_current_report(report)`: sets `_current_report`.
3. `sanitize(obj)`: recursive walk; `redact_text()` on every string.
4. `list_leaks(severity=None)`: returns `[sanitize(dataclasses.asdict(l)) for l in ...]`, optionally filtered.
5. `get_leak_context(fingerprint)`: look up by fingerprint; read ±5 lines from the source file using `_current_report.target`; set `owner` (`app` vs `third_party`); set `strategy` text; raise `KeyError` for unknown fingerprint; wrap result in `sanitize()`.
6. `probe_safety_net(app_path)`: in a subprocess, import the app's `logging_config.configure_logging()`, attach a `StringIO` handler, log a line containing the card canary, check output is masked.  
**Context:** `docs/01-ARCHITECTURE.md` §3.10, gaps G5, `tests/test_mcp_tools.py`.  
**Status:** [ ] pending

### Sub-task 9 — `pytest_plugin.py` and `scanner.py`
**Intent:** Run the target's test suite with capture active; return a `Report`.  
**Outcomes:** `scan_target(demo/caredesk, tmp)` returns a `Report` with 7+ leaks; `test_demo_app_e2e.py` (e2e) passes.  
**Steps:**
1. `pytest_plugin.py`: register `LeakCaptureHandler` on the root logger at `DEBUG` in `pytest_sessionstart`; tee stdout; on session finish, write JSONL to `LOGLEAK_OUT`.
2. `scanner.py`: `scan_target(target, out_dir)`:
   - Set `LOGLEAK_OUT` to `out_dir / "capture.jsonl"`.
   - Run `pytest -p logleak.pytest_plugin target` as a subprocess (same Python interpreter).
   - Read the JSONL lines; deserialise to `CapturedRecord` objects.
   - Call `trace(records, canaries=all_canaries(), root=target)`.
   - Call `find_log_sites(target)` to get `total_sites`; compute `executed_sites`.
   - Build and return `Report`.  
**Context:** `docs/01-ARCHITECTURE.md` §3.4 and §3.7b, `tests/test_demo_app_e2e.py`.  
**Status:** [ ] pending

### Sub-task 10 — `mcp_server.py` and `cli.py`
**Intent:** Expose MCP tools over stdio transport; provide the `logleak` CLI entry point.  
**Outcomes:** `logleak --help` lists `scan`, `fix`, `verify`, `serve`; `python -m logleak.mcp_server` starts without error.  
**Steps:**
1. `mcp_server.py`: thin FastMCP wrappers for `scan_logs`, `list_leaks`, `get_leak_context`, `verify_fix`. Look up the current FastMCP v2 decorator syntax via Context7 before writing.
2. `cli.py`: argparse or click with sub-commands `scan <target>`, `fix`, `verify`, `serve`.  
**Context:** `docs/03-MCP-PLAN.md`, `docs/01-ARCHITECTURE.md` §3.10.  
**Status:** [ ] pending

### Sub-task 11 — `fixer.py` and `server.py` (Phase 3/4)
**Intent:** Bob Shell invocation, diff generation, and FastAPI dashboard API.  
**Outcomes:** `logleak fix` copies the workspace, runs Bob, and saves the diff; dashboard endpoints respond.  
**Steps:** Follow `docs/01-ARCHITECTURE.md` §3.9 and `docs/04-UI-FRONTEND.md`.  
**Context:** `docs/01-ARCHITECTURE.md`, `docs/04-UI-FRONTEND.md`.  
**Status:** [ ] pending

---

## 6. Open Questions / Decisions Made

| # | Question | Decision |
|---|----------|----------|
| Q1 | Fingerprint formula: `sha1` vs `[-12:]` slice? | Use `hashlib.sha1(key.encode()).hexdigest()[:12]`. Always 12 hex chars. Stable. |
| Q2 | `capture_stdout` — buffer by line or by `write()` call? | Buffer until `"\n"`. CPython `print()` issues two writes (`text` then `"\n"`). |
| Q3 | `RedactionFilter` — where to materialise `exc_text`? | Inside `filter()`, using `logging.Formatter().formatException(exc_info)`. Clear `exc_info` after. |
| Q4 | CNIC plain-digit keyword window: 20 chars? | Yes, architecture spec says "within 20 characters". Implement as `text[max(0,start-20):end+20]`. |
| Q5 | FastMCP version: v1 or v2 decorator? | Query Context7 for `fastmcp` at build time. Do not guess the decorator API. |
| Q6 | `scan_target` subprocess Python: `sys.executable`? | Yes — use `sys.executable` so the subprocess uses the same venv. |
| Q7 | `probe_safety_net` subprocess vs in-process? | Subprocess, to avoid contaminating the test process's logging state. |
