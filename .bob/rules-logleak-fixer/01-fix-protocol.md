# LogLeak Fixer — Fix Protocol

These rules apply only in the `logleak-fixer` mode, in addition to the core project rules.

## Scope

- Edit files only inside `runs/workspace/<target>/`. Nothing else.
- Your input is `runs/leak-report.md` plus the `logleak` MCP tools. All values you see are masked. Never try to recover or guess the original values.

## Fix order for each leak

1. Call `get_leak_context(fingerprint)` to read the code and the recommended strategy.
2. **If the code is ours (`owner: app`), fix it at the source.** In order of preference:
   - **Log an identifier instead of the data.** `patient.id` instead of `patient`; `order_id` instead of the card.
   - **Log a safe derivative** when the value is useful for debugging: last 4 digits of a card (`card_last4()`), the email domain only.
   - **Fix object representations.** Give models holding personal data a `__repr__` that shows only the ID and non-sensitive fields, or mark sensitive dataclass fields with `field(repr=False)`.
   - **Exceptions:** never put personal data in exception messages. Put identifiers in the message.
   - **`print()` debugging:** remove it, or replace it with a logger call that logs no personal data.
   - **Request/response body logging:** log method, path, status, duration, and request ID only.
3. **If the code is third-party (`owner: third_party`), don't edit the library.** Rely on the safety net and, if needed, raise that logger's level (for example, set `httpx` to WARNING).
4. **Always install the safety net once:** add `logleak`'s `RedactionFilter` (or an equivalent local filter) to the app's logging configuration so every handler gets it. The safety net is defense-in-depth, not a replacement for step 2.

## Don't game the gate

- Do not delete log statements to remove leaks. Rewrite them so they still say what happened.
- Do not mask identifiers that aren't personal data (order IDs, appointment IDs, request IDs). Logs must stay useful.
- Do not change the target's tests, except to fix a test that asserts on the leaking log text itself. In that case, update the assertion to the new safe text and say so in your summary.
- Do not weaken detectors, canaries, or the gate.

## Loop

1. Fix all leaks, highest severity first.
2. Call `verify_fix(target)`.
3. If any check fails, read the reasons, fix that specific problem, and verify again. Stop after 3 rounds and report what is still failing and why.

## Final summary format

```
LogLeak fix summary
- Leaks fixed at source: N (list file:line → technique)
- Handled by safety net: N (list logger names)
- Gate: PASSED | FAILED (list checks)
- Rounds: N
- Notes: anything a human reviewer should double-check
```
