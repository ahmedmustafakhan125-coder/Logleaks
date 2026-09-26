# 04 · UI / Frontend — LogLeak Dashboard

## 1. Purpose

The dashboard does one job: **show judges, in 30 seconds, that personal data was in the logs and now it isn't, and that the logs are still useful.** Everything else is secondary.

## 2. Design direction: "evidence under redaction"

The subject is logs as evidence and personal data as something to be redacted. The visual language borrows from a printed document that someone has marked up: yellow highlighter where data is exposed, solid redaction bars where it has been removed.

### Tokens

| Token | Hex | Use |
|---|---|---|
| `--paper` | `#F2F4F6` | Page background, cool and light, like printout paper |
| `--ink` | `#1C2433` | Text and log lines |
| `--highlighter` | `#FFE15A` | Exposed data (before) |
| `--redaction` | `#15181D` | Redaction bars (after) |
| `--breach` | `#B8322A` | Critical severity, failed gate check |
| `--cleared` | `#1E7461` | Passed gate check |
| `--rule` | `#C9CFD6` | Dividers and table borders |

**Type:** IBM Plex Sans for the interface and IBM Plex Mono for log lines and code. Plex is a fitting choice for an IBM hackathon, and monospace is needed for logs, not used as decoration.

- Scale: 14 / 16 / 20 / 28 / 44 px
- Log lines: Plex Mono 14 px, line-height 1.6
- Headline: Plex Sans 44 px, weight 600, tight tracking

### The one bold moment

When the "after" run loads, each yellow highlight in the log stream is **covered by a black redaction bar sliding in from left to right**, one leak at a time, about 120 ms apart. Then the gate checks turn green in order. Nothing else on the page animates. Respect `prefers-reduced-motion` by switching instantly.

### What to avoid

No card grid with identical shadows, no gradient washes, no all-caps eyebrow labels, and no dark "hacker terminal" theme. The page should feel like an audit document, not a SaaS template.

## 3. Layout

Desktop (1440 wide, recorded at 1080p):

```
┌──────────────────────────────────────────────────────────────────────┐
│ LogLeak   demo/caredesk                    [Scan] [Fix with Bob] [Verify] │
├──────────────────────────────────────────────────────────────────────┤
│ 7 leaks in your logs                                                 │
│ 4 critical · 3 high · 18 of 21 log lines exercised                   │
├───────────────────────────────┬──────────────────────────────────────┤
│ Before                        │ After                                │
│ 10:02:11 INFO Registered      │ 10:04:52 INFO Registered patient     │
│ Patient(email=▓canary.p…▓,    │ id=PT-1042                           │
│ phone=▓+923001234567▓ …)      │                                      │
│ 10:02:11 DEBUG Charging card  │ 10:04:52 DEBUG Charging card         │
│ ▓4242424242424242▓ for 3500   │ ████████████4242 for 3500            │
│   (log stream, synced scroll) │   (log stream, synced scroll)        │
├───────────────────────────────┴──────────────────────────────────────┤
│ Leaks                                                                │
│ Severity  Type   Where                     Sink       Hits  Status   │
│ critical  card   payments/service.py:48    log        3     fixed    │
│ critical  card   payments/service.py:61    exception  1     fixed    │
│ high      email  vendor httpx (filter)     library    2     filtered │
├───────────────────────────────┬──────────────────────────────────────┤
│ Verification gate             │ Selected leak                        │
│ ✓ No confirmed leaks          │ payments/service.py:48               │
│ ✓ No critical suspected       │ - logger.debug("Charging card %s…",  │
│ ✓ App tests pass              │ + logger.debug("Charging card …%s",  │
│ ✓ Useful IDs kept             │ +              card_last4(card), …)  │
│ ✓ 95% log lines retained      │                                      │
│ ✓ Safety net installed        │                                      │
├───────────────────────────────┴──────────────────────────────────────┤
│ Not proven clean: 3 log lines never ran in tests  [show]             │
└──────────────────────────────────────────────────────────────────────┘
```

Notes:
- The headline is a sentence, not a stat card: "7 leaks in your logs" becomes "0 leaks in your logs. Logs still useful." after verification.
- The before/after streams scroll in sync and line up by test step.
- Clicking a leak row highlights its lines in both streams and shows the diff on the right.
- In the Before stream, highlights show the canary value, which is fake by design. The dashboard never displays non-canary suspected values unmasked.
- Mobile (below 768 px): the streams stack vertically and the table scrolls horizontally inside its own container.

## 4. Components

| Component | Data | Behavior |
|---|---|---|
| `HeaderBar` | target, run state | Buttons disable while a run is active; labels stay consistent: "Fix with Bob" → "Bob is fixing…" → "Fixed" |
| `Headline` | counts | Text changes after verification |
| `LogStream` ×2 | masked records with finding spans | Highlight spans; redaction animation on after-load |
| `LeakTable` | leaks | Sortable by severity; row click selects |
| `GatePanel` | GateResult | Checks tick in sequence; failed checks show the reason |
| `DiffPanel` | per-leak diff hunk | Unified diff, Plex Mono |
| `BobStream` (drawer) | SSE lines | Live Bob Shell output during a fix run |
| `Unwitnessed` | site list | Collapsed by default |

## 5. API (served by `logleak/server.py`)

| Method | Path | Returns |
|---|---|---|
| GET | `/api/report?run=before\|after` | Report JSON (masked) |
| GET | `/api/leaks` | Leak list, merged with fix status |
| GET | `/api/leaks/{fingerprint}` | Code context + diff hunk |
| GET | `/api/gate` | Latest GateResult |
| GET | `/api/unwitnessed` | Unexecuted log sites |
| POST | `/api/scan` | Starts a scan and returns a `run_id` |
| POST | `/api/fix` | Starts the Bob fix run and returns a `run_id` |
| POST | `/api/verify` | Runs the gate |
| GET | `/api/stream/{run_id}` | SSE: progress and Bob Shell lines |

Everything leaving the API passes through `redact_text()`, the same invariant as the MCP server.

## 6. Replay mode (for recording and hosting)

- `?replay=1` loads `runs/replay/{before,after,gate,diff,bob_stream}.json` recorded from a real run. There is no backend call.
- The Bob stream replays at its real recorded timing, with a 2× speed toggle for the video.
- The static build (`ui/` + replay JSON) deploys to GitHub Pages as the public **Application URL**.
- Label it honestly in the UI: "Replaying a recorded run from Sep 27." Judges respect honesty more than a fake live demo.

## 7. Tech

- Vanilla HTML/CSS/JS (no build step): `ui/index.html`, `ui/app.js`, `ui/styles.css`
- IBM Plex from Google Fonts, with system fallbacks
- `EventSource` for SSE; `fetch` for everything else
- Accessibility: visible focus rings; severity shown as text as well as color; highlight contrast checked against `--ink`

## 8. Build order (by value)

1. Leak table + headline from `report.json` (already a usable demo)
2. Before/after streams with highlights
3. Gate panel
4. Redaction animation
5. Diff panel
6. Bob SSE drawer + replay
7. Unwitnessed panel
