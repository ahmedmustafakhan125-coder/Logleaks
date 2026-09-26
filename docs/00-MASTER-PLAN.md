# 00 · Master Plan — LogLeak

## 1. One-line pitch

> Your tests are green, but your logs are full of card numbers. LogLeak finds personal data your app writes to logs at runtime, traces it to the exact line, has IBM Bob fix it, and proves the logs are clean without making them useless.

## 2. The problem

- Engineers log for debugging: `logger.info(f"New patient: {patient}")`, `logger.debug("charging %s", card)`, `logger.exception(...)` with the card in the error message.
- Logs don't stay local. They ship to Datadog, ELK, Sentry, S3, and support tools, are kept for months, and are readable by far more people than the production database.
- Under GDPR, PCI DSS (full card numbers must never be stored in logs), and Pakistan's upcoming data protection rules, those logs are a breach waiting to be discovered.
- **Why existing tools miss it:** static scanners look at code, not at what is actually written at runtime. A leak through an object's `__repr__`, an f-string, a third-party library's debug logs, or an exception traceback is invisible to grep. It only shows up when the code runs.

## 3. The solution in five steps

1. **Seed** — the app's own test flows run with *canary PII*: fake but valid-format values (a Luhn-valid test card, a `.test` email, a well-formed CNIC). A canary appearing in a log is a confirmed leak, not a guess.
2. **Capture** — a pytest plugin hooks the logging system and stdout. Every record carries its source `file:line` and function, so every leak is traced exactly.
3. **Detect** — canary matching (confirmed) plus pattern detectors with validation such as Luhn, IBAN mod-97, and entropy for secrets (suspected).
4. **Fix (IBM Bob)** — Bob, in the `logleak-fixer` custom mode, gets a report that contains **only masked values** and repairs each leak at its source. It also installs a central redaction filter as a safety net.
5. **Verify** — the same flows run again. The gate passes only if there are zero leaks, the app's tests pass, the logs still contain their useful IDs, and log lines weren't simply deleted.

## 4. What makes it original (use these phrases in the pitch)

| Differentiator | Why judges will care |
|---|---|
| **Runtime, not static** | Catches leaks through `__repr__`, tracebacks, and third-party libraries that grep can never see |
| **Canary PII** | Turns "might be a leak" into "is a leak", with zero ambiguity |
| **Bob never sees raw PII** | The AI fixing the leak must not become a new leak channel. Everything sent to Bob is masked. |
| **Anti-cheat gate** | Bob can't "fix" logs by deleting them. The gate checks that log coverage and useful IDs survive. |
| **Unwitnessed log lines** | LogLeak reports log statements your tests never executed, being honest about what it *can't* prove clean |

## 5. Scope for the hackathon

**In scope:** Python apps using `logging`, `print`, and exceptions; pytest as the flow runner; one realistic demo app (**CareDesk**, a clinic booking and payments API).

**Out of scope (roadmap slide only):** JavaScript/Java adapters, a CI GitHub Action, scanning production log streams, and SARIF upload.

## 6. Demo target: CareDesk

A small FastAPI clinic app (patients, appointments, card payments, SMS reminders) with seven realistic, intentionally planted leaks:

| # | Leak | Sink | Why it's realistic |
|---|---|---|---|
| L1 | `logger.info(f"Registered {patient}")`, where the dataclass `repr` dumps email, phone, and CNIC | log | The most common real-world leak |
| L2 | `logger.debug("Charging card %s for %s", card_number, amount)` | log | Classic PCI violation |
| L3 | `raise ValueError(f"Card declined: {card}")`, then `logger.exception(...)` | exception | Invisible to grep for log calls |
| L4 | Request middleware logs the full JSON body | log | Leaks everything at once |
| L5 | `print(f"issued token {jwt}")` left over from debugging | stdout | Forgotten debug print |
| L6 | SMS retry warning includes the phone number | log | Hidden in error handling |
| L7 | An HTTP client's debug log prints a URL containing `?email=` | third-party log | You don't own the code, so the fix needs a filter |

CareDesk must set up all its logging in `caredesk/logging_config.py` through a `configure_logging()` function. This is where Bob installs the safety-net filter, and where the gate's probe checks for it. Log lines should include the IDs `PT-…`, `APT-…`, and `ORD-…` so the over-redaction check has something to verify.

It also includes decoys that must **not** be flagged, such as an order ID `ORD-4111111111111112` (fails Luhn) and appointment IDs. These prove there are no false positives.

## 7. Judging criteria → how we score

| Criterion | Our evidence |
|---|---|
| **Application of Technology** | Bob in Plan mode (architecture), Agent/Code mode (building to spec tests), two custom modes, project rules, Bob Shell `bob -p` running inside the product's fix loop, and a custom MCP server Bob calls to re-scan its own fixes |
| **Presentation** | One memorable moment: highlighted card numbers in a live log stream get covered by redaction bars, and the gate turns green |
| **Business Value** | PCI DSS and GDPR exposure, log retention, third-party log vendors. Every company with logs has this problem. |
| **Originality** | Runtime capture, canary PII, masked-only AI input, and the anti-cheat gate. No other submission covers this area. |

## 8. Deliverables checklist

- [ ] **Project title:** LogLeak — Catch Personal Data Leaking Into Your Logs
- [ ] **Short description** (below)
- [ ] **Long description**, 500 words or less (draft below)
- [ ] **IBM Bob Usage Statement**, 500 words or less (skeleton below; write it from your real session)
- [ ] **Tags:** IBM, IBM Bob, Python, Security, Privacy, DevTools, MCP, Compliance
- [ ] **Public GitHub repo**, created from the IBM hackathon template so `.bobignore` and `.gitignore` are included
- [ ] **Bob task session summary screenshots from EVERY team member**, in `bob_sessions/<name>/`
- [ ] **Demo platform + application URL**: GitHub Pages replay of the dashboard, or a Render/Railway deployment
- [ ] **Cover image**: a log line with the card number half-covered by a redaction bar
- [ ] **Video**: MP4, 3:00 or less, with at least 90 seconds of live demo
- [ ] **Slides**: 7 slides (outline below)

## 9. Submission text drafts

### Short description

LogLeak runs your app's real test flows, catches emails, card numbers, and IDs leaking into logs, traces each one to the exact line, and has IBM Bob fix them. Then it proves the logs are clean and still useful.

### Long description (draft; update the numbers after the real run)

> **The problem.** Every application logs, and almost every one of them eventually logs something it shouldn't: a customer's email inside an object dump, a card number in an exception message, a token in a forgotten `print()`. Those logs are shipped to third-party platforms, kept for months, and read by far more people than the production database. That is a direct PCI DSS and GDPR exposure, and today's tools don't catch it because they scan *code*, while leaks happen at *runtime*: through `__repr__`, f-strings, tracebacks, and third-party libraries.
>
> **The solution.** LogLeak runs your application's own test suite with *canary PII*, fake values that are valid in format, like a Luhn-valid test card or a well-formed CNIC. A pytest plugin captures every log record, printed line, and traceback along with its source location. When a canary appears in the output, that is a confirmed leak at an exact `file:line`. Pattern detectors with real validation (Luhn, IBAN checksums, entropy) catch anything the canaries didn't reach.
>
> IBM Bob then repairs each leak in a dedicated fixer mode. It fixes the call site first and adds a central redaction filter as a safety net for code you don't own. Bob only ever receives masked values: the tool that fixes leaks cannot become a leak itself.
>
> **Proof, not promises.** A verification gate re-runs the same flows. It passes only when there are zero leaks, the app's tests still pass, useful identifiers like order IDs still appear in the logs, and log lines weren't deleted to game the result. LogLeak also reports log statements the tests never executed, so teams know exactly what it could not prove clean.
>
> **Who it's for.** Engineering and security teams at any company that handles customer data (fintech, healthcare, e-commerce), running LogLeak before release or in CI.
>
> **Result on our demo app:** [X] leaks across [Y] data types found, [X] fixed by Bob, gate passed, [Z]% of log lines still intact.

### IBM Bob Usage Statement (skeleton; fill in from your actual sessions)

1. **Planning (Plan mode):** Bob read `docs/01-ARCHITECTURE.md` and produced the implementation plan and module interfaces. *(Which parts did you keep, and which did Bob change?)*
2. **Building to spec (Agent/Code mode):** the `tests/` spec suite was written first, and Bob implemented `detectors.py`, `redact.py`, `capture.py`, and the other modules until the tests passed. *(Name the files and the test counts.)*
3. **Real-time docs through MCP:** Bob used Context7 for current FastMCP, pytest, and FastAPI APIs, and Fetch for the OWASP Logging Cheat Sheet and PCI DSS guidance while writing the rules.
4. **Inside the product:** `logleak fix` calls Bob Shell (`bob --chat-mode=logleak-fixer -p ... --yolo`) with the masked leak report. Bob uses the LogLeak MCP server to get the context for each leak and re-scan its own fix.
5. **Project rules and custom modes:** `.bob/rules/` and the two custom modes enforce "never write raw PII" and "fix the source, not the symptom".
6. **Self-correction example:** *(Describe one real moment where the gate failed and Bob fixed it, for example Bob masked the order ID and the over-redaction check caught it.)*
7. **watsonx:** only include this if you actually add it (optional stretch: watsonx.ai Granite classifying ambiguous "suspected" findings).

## 10. Video script (3:00 max)

| Time | On screen | Narration |
|---|---|---|
| 0:00–0:15 | A green test run, then a log file scrolling | "All tests pass. This app is ready to ship. It's also writing card numbers to its logs." |
| 0:15–0:35 | Logs shipping to a log platform (simple diagram) | "Logs get shipped, kept, and read by everyone. That's a PCI and GDPR problem, and static scanners can't see it because it only happens at runtime." |
| 0:35–1:10 | `logleak scan`, then the dashboard with yellow highlights | "LogLeak runs the app's own tests with canary data. Seven leaks, four data types, each traced to the exact line, including one inside an exception traceback and one inside a library we don't own." |
| 1:10–2:05 | Click "Fix with Bob". The Bob Shell stream, then a diff | "IBM Bob, in our custom fixer mode, gets a masked report, never the real data. It fixes each leak at the source, then calls our MCP server to re-scan its own work." |
| 2:05–2:40 | Re-run: redaction bars cover the highlights, gate checks turn green one by one | "Same flows, zero leaks. The order IDs are still there, and every log line survived. Bob can't cheat by deleting logs." |
| 2:40–3:00 | The unwitnessed-lines panel, then the logo | "And it tells you what it couldn't prove clean. LogLeak: your logs, minus your customers." |

At least 90 seconds of this is the live demo (0:35–2:40 ≈ 125 s). ✅

## 11. Slide outline (7 slides)

1. **Title:** LogLeak, with the redaction-bar cover image
2. **Problem:** where logs go, who can read them, and the rules at stake (PCI DSS, GDPR)
3. **Why tools miss it:** static vs runtime, the seven leak types
4. **How it works:** Seed → Capture → Detect → Fix → Verify (architecture diagram)
5. **IBM Bob's role:** modes, rules, Bob Shell in the loop, MCP, masked-only input
6. **Results:** the before/after numbers and the gate checks
7. **Roadmap:** JS/Java adapters, GitHub Action, production log sampling

## 12. Risks and fallbacks

| Risk | Fallback |
|---|---|
| Bob Shell non-interactive mode needs API-key auth, and it may not be set up | Run the same prompt in the Bob IDE with the `logleak-fixer` mode, and keep the CLI path for the demo recording |
| A Bob run is slow or varies during recording | The dashboard's **replay mode** plays back a recorded real run |
| Running out of time | Follow the cut list in `02-BUILD-PLAN.md` (the UI can fall back to the CLI plus the HTML report) |
| False positives in the demo | Decoys are already covered by spec tests |
