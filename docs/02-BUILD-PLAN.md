# 02 · Build Plan — LogLeak

**Deadline:** Sunday Sep 27, 8:00 PM PKT. **Target submit time:** 5:30 PM PKT, which leaves 2.5 hours of buffer for lablab upload issues.

Roles below assume two people. Solo? Do Dev A's column first, then Dev B's, and use the cut list.
- **Dev A (Mustafa):** engine, Bob loop, MCP
- **Dev B (Hamza):** demo app, UI, media and submission

## Golden rules for the 30 hours

1. **Spec tests first.** `tests/` already defines the interfaces. Bob builds until they pass. This doubles as the strongest Bob evidence.
2. **Every Bob task ends with a summary screenshot**, saved to `bob_sessions/<name>/NN-task.png`. Each team member needs their own.
3. **Commit after every milestone** with messages like `bob: implement detectors (Agent mode)` so the git history shows Bob's work.
4. **Never paste real personal data anywhere.** Canaries only.

## Timeline

### Phase 0 — Setup (Sat 15:00–16:00)

| Task | Owner | Bob usage |
|---|---|---|
| Create the repo from the IBM hackathon template and make it public | A | — |
| Copy in this planning pack (`docs/`, `.bob/`, `tests/`) | A | — |
| Add `runs/` to `.gitignore` and `.bobignore` | A | — |
| Install Bob Shell and set up API-key auth for `bob -p` | A | — |
| Check that the MCP servers in `.bob/mcp.json` start | A | Ask Bob to list the available MCP tools |
| **Bob Plan mode:** "Read @docs/01-ARCHITECTURE.md and @tests. Produce an implementation plan and flag interface gaps." | A | 📸 Screenshot 01 |

### Phase 1 — Foundations (Sat 16:00–20:00)

| Task | Owner | Bob usage | Done when |
|---|---|---|---|
| `pyproject.toml`, package skeleton, `cli.py` stub | A | Agent mode | `logleak --help` runs |
| `canaries.py`, `detectors.py` | A | Agent mode: "Implement until `tests/test_detectors.py` passes" | ✅ test_detectors |
| `redact.py` | A | Agent mode | ✅ test_redaction |
| **CareDesk demo app** with the 7 planted leaks and decoys (master plan §6), plus its own pytest suite using the `canary` fixture | B | Agent mode with the leak table as the spec | CareDesk tests pass |
| 📸 Screenshots 02–03 | A, B | | |

### Phase 2 — Capture and trace (Sat 20:00–01:00)

| Task | Owner | Bob usage | Done when |
|---|---|---|---|
| `capture.py` + `pytest_plugin.py` | A | Ask mode first: "Explain how LogRecord pathname/lineno and exc_info work", then Agent mode | ✅ test_capture_trace |
| `tracer.py`, `sitemap.py`, `report.py` | A | Agent mode | ✅ tests pass |
| `logleak scan demo/caredesk` prints a leak table | A | — | **🎯 M1: all 7 leaks found, 0 decoys flagged** |
| Dashboard skeleton, static and reading `report.json` | B | Agent mode + `04-UI-FRONTEND.md` | Leak table renders |
| 📸 Screenshots 04–05 | A, B | | |

**Sleep 01:00–07:00.** This is not optional. The demo recording needs a clear head.

### Phase 3 — The Bob fix loop (Sun 07:00–11:00)

| Task | Owner | Bob usage | Done when |
|---|---|---|---|
| `mcp_tools.py` + `mcp_server.py` | A | Agent mode, using Context7 for the current FastMCP API | ✅ test_mcp_tools |
| `verify.py` gate | A | Agent mode | ✅ test_verify_gate |
| `fixer.py` (workspace copy, prompt, Bob Shell run, diff) | A | Agent mode | `logleak fix` runs end to end |
| **First real fix run** with `logleak-fixer` mode | A | **The product loop itself** | **🎯 M2: gate passes** |
| Commit the fixed copy to `demo/caredesk_after/` | A | — | ✅ test_demo_app_e2e (after) |
| Record the run for replay mode (`runs/replay/*.json`) | A | — | Replay file exists |
| 📸 Screenshots 06–08, including the gate failing and Bob self-correcting | A | | |

### Phase 4 — Dashboard (Sun 09:00–14:00, parallel with Phase 3)

| Task | Owner | Done when |
|---|---|---|
| Before/after log stream with highlights | B | Highlights line up with the findings |
| Redaction animation (the one bold moment) | B | Looks good at 1080p |
| Gate panel, unwitnessed-lines panel, diff viewer | B | All wired to the API |
| SSE stream of the Bob run, plus replay mode | A+B | `?replay=1` works offline |
| Deploy: GitHub Pages (replay) or Render | B | Public URL works |

### Phase 5 — Submission (Sun 14:00–17:30)

| Time | Task | Owner |
|---|---|---|
| 14:00–15:00 | Record the video (replay mode, rehearsed script) | B records, A narrates |
| 15:00–15:45 | Edit the video to ≤ 3:00 and export MP4 | B |
| 14:00–15:30 | Long description + Bob usage statement (each ≤ 500 words, counted) | A |
| 15:30–16:15 | Slides (7) + cover image | B |
| 16:15–16:45 | README polish, GIF, screenshots folder check | A |
| 16:45–17:30 | Fill the lablab form and submit | A |
| 17:30–20:00 | Buffer | — |

## Cut list (drop from the top if behind)

1. watsonx.ai triage (stretch; don't start before M2)
2. Deployed live URL: use the GitHub Pages replay instead
3. SSE live streaming: replay only
4. Diff viewer in the UI: show the GitHub diff in the video instead
5. IBAN/JWT detectors: keep email, card, CNIC, phone, and secret

**Never cut:** the gate, masked-only Bob input, the before/after proof, or the screenshots.

## Definition of done

- [ ] `pytest tests/` is green
- [ ] `logleak scan` → 7 leaks, 0 decoys; `logleak fix` → gate passes
- [ ] `demo/caredesk_after/` committed; `bob_sessions/` has screenshots from every member
- [ ] Video ≤ 3:00, with 90 s or more of demo; both statements ≤ 500 words
- [ ] Repo public; application URL opens in an incognito window
