# LogLeak — Project Rules for IBM Bob

These rules apply to every conversation in this repository, in every mode.

## 1. What this project is

LogLeak finds personal data leaking into application logs at runtime, traces it to the exact source line, fixes it, and proves the fix. The architecture lives in `docs/01-ARCHITECTURE.md`. Read it before any design decision. If a request conflicts with it, say so before writing code.

## 2. Privacy rules (non-negotiable)

- Never write real personal data anywhere: code, tests, docs, commit messages, or chat. Use only the values in `logleak/canaries.py`.
- Never print, log, or return a raw detected value from engine code after `report.py`. Anything leaving the engine (reports, MCP tool output, API responses, Bob prompts) must pass through `redact_text()`.
- Do not read files in `runs/` except `runs/leak-report.md`, `runs/report*.json`, and `runs/workspace/`. Raw captures (`*.jsonl`) stay unread.
- Never add real credentials. Secrets in tests use the `llk_canary_` prefix.

## 3. Spec tests are the contract

- `tests/` was written before the code. Implement until they pass. **Do not edit a spec test to make it pass.** If you believe a test is wrong, stop and explain why.
- Keep the public interfaces exactly as the tests import them: names, signatures, and dataclass fields.
- After any change to `logleak/`, run `pytest tests -q -m "not e2e"` and report the result.

## 4. Code standards

- Python 3.11+, full type hints, and `@dataclass` for data models.
- Standard library first. Allowed dependencies: `pytest`, `fastapi`, `uvicorn`, `httpx`, `fastmcp`. Ask before adding anything else.
- Detectors must be precise: prefer a missed suspected value over a false positive. Validate cards with Luhn and IBANs with mod-97.
- A `logging.Filter` must never drop a record. It may only rewrite it.
- Every public function gets a one-line docstring saying what it does.
- Keep modules small and single-purpose, matching the layout in the architecture doc.

## 5. Working style

- For anything larger than one file, write a short plan first (files to touch, the tests that will prove it), then implement.
- Before using a library API you are unsure about (FastMCP, pytest hooks, FastAPI SSE), look it up with the context7 MCP server rather than guessing.
- For compliance questions (what may be logged or masked), check the OWASP Logging Cheat Sheet with the fetch MCP server.
- End every task with a summary: what changed, which tests pass, and anything left open.

## 6. Boundaries

- Never modify `demo/caredesk/`. It is the pristine "before" state. Fixes happen only in `runs/workspace/caredesk/`.
- `demo/caredesk_after/` is written only by copying a workspace that has passed the gate.
- Don't touch `.bobignore`, `.gitignore`, or `.bob/` unless explicitly asked.
