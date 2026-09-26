"""server.py — FastAPI dashboard API for the LogLeak UI.

Endpoints (all values pass through redact_text before leaving this module):
  GET  /api/report?run=before|after  — Report JSON (masked)
  GET  /api/leaks                    — Leak list with fix status
  GET  /api/leaks/{fingerprint}      — Code context + diff hunk
  GET  /api/gate                     — Latest GateResult
  GET  /api/unwitnessed              — Unexecuted log sites
  POST /api/scan                     — Start a scan
  POST /api/fix                      — Start the Bob fix run
  POST /api/verify                   — Run the gate
  GET  /api/stream/{run_id}          — SSE: progress lines

Start with:
    logleak serve          (uses CLI entry point)
    uvicorn logleak.server:app --port 8765
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from logleak.redact import redact_text

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_RUNS_DIR = _REPO_ROOT / "runs"
_UI_DIR = _REPO_ROOT / "ui"

# ---------------------------------------------------------------------------
# In-memory SSE queues keyed by run_id
# ---------------------------------------------------------------------------

_streams: dict[str, asyncio.Queue[str | None]] = {}

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="LogLeak Dashboard API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static UI files if the ui/ folder exists
if _UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_UI_DIR), html=True), name="ui")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_json(obj):
    """Recursively redact all strings in obj."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_json(v) for v in obj]
    return obj


def _load_json_file(path: Path) -> dict | list | None:
    """Load and parse a JSON file, returning None if missing."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


async def _run_in_thread(fn, *args):
    """Run a blocking function in the default thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)


# ---------------------------------------------------------------------------
# GET /api/report
# ---------------------------------------------------------------------------

@app.get("/api/report")
async def get_report(run: str = "before"):
    """Return the masked scan report for a given run (before or after)."""
    if run == "before":
        filename = "report_before.json"
    else:
        # Prefer the post-fix scan saved by verify_fix; fall back to report.json
        filename = "report_after.json" if (_RUNS_DIR / "report_after.json").exists() else "report.json"
    data = _load_json_file(_RUNS_DIR / filename)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No {run} report found. Run a scan first.")
    return JSONResponse(_sanitize_json(data))


# ---------------------------------------------------------------------------
# GET /api/leaks
# ---------------------------------------------------------------------------

@app.get("/api/leaks")
async def get_leaks():
    """Return the leak list with a fix_status field derived from before/after reports."""
    before_data = _load_json_file(_RUNS_DIR / "report_before.json")
    # Use report_after.json (written by verify_fix) when available
    after_path = _RUNS_DIR / "report_after.json"
    after_data = _load_json_file(after_path if after_path.exists() else _RUNS_DIR / "report.json")

    if before_data is None:
        raise HTTPException(status_code=404, detail="No scan report found. Run a scan first.")

    before_leaks: list[dict] = before_data.get("leaks", [])

    # Build a set of fingerprints still present in the after-report
    after_fps: set[str] = set()
    if after_data:
        for lk in after_data.get("leaks", []):
            after_fps.add(lk.get("fingerprint", ""))

    result = []
    for lk in before_leaks:
        fp = lk.get("fingerprint", "")
        entry = dict(lk)
        # fix_status: "fixed" if not present in after; "filtered" if third-party; "open" otherwise
        if after_data and fp not in after_fps:
            fp_file = lk.get("file", "")
            entry["fix_status"] = "filtered" if "site-packages" in fp_file else "fixed"
        else:
            entry["fix_status"] = "open"
        result.append(entry)

    return JSONResponse(_sanitize_json(result))


# ---------------------------------------------------------------------------
# GET /api/leaks/{fingerprint}
# ---------------------------------------------------------------------------

@app.get("/api/leaks/{fingerprint}")
async def get_leak_context(fingerprint: str):
    """Return code context and fix strategy for one leak by fingerprint."""
    from logleak import mcp_tools
    try:
        ctx = mcp_tools.get_leak_context(fingerprint)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown fingerprint: {fingerprint}")
    return JSONResponse(_sanitize_json(ctx))


# ---------------------------------------------------------------------------
# GET /api/gate
# ---------------------------------------------------------------------------

@app.get("/api/gate")
async def get_gate():
    """Return the latest gate result."""
    data = _load_json_file(_RUNS_DIR / "gate.json")
    if data is None:
        raise HTTPException(status_code=404, detail="No gate result found. Run verify first.")
    return JSONResponse(_sanitize_json(data))


# ---------------------------------------------------------------------------
# GET /api/unwitnessed
# ---------------------------------------------------------------------------

@app.get("/api/unwitnessed")
async def get_unwitnessed():
    """Return log sites that were not exercised during the scan."""
    before_data = _load_json_file(_RUNS_DIR / "report_before.json")
    if before_data is None:
        raise HTTPException(status_code=404, detail="No scan report found. Run a scan first.")

    from logleak.sitemap import find_log_sites, unwitnessed

    target_str = before_data.get("target", "")
    if not target_str:
        return JSONResponse([])

    target = Path(target_str)
    if not target.exists():
        return JSONResponse([])

    executed_sites: set[tuple[str, int]] = {
        (pair[0], pair[1]) for pair in before_data.get("executed_sites", [])
    }
    sites = find_log_sites(target)
    uw = unwitnessed(sites, executed_sites)
    result = [{"file": s.file, "line": s.line, "call": s.call} for s in uw]
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# POST /api/scan
# ---------------------------------------------------------------------------

@app.post("/api/scan")
async def post_scan(body: dict = None):
    """Start a scan of the target app. Returns a run_id for SSE streaming."""
    if body is None:
        body = {}
    target = body.get("target", "demo/caredesk")
    run_id = str(uuid.uuid4())
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    _streams[run_id] = queue

    async def _do_scan():
        from logleak import mcp_tools
        try:
            await queue.put("data: Scanning target...\n\n")
            result = await _run_in_thread(mcp_tools.scan_logs, target)
            await queue.put(f"data: Found {result.get('total_leaks', 0)} leaks\n\n")
            await queue.put(f"data: DONE\n\n")
        except Exception as exc:  # noqa: BLE001
            await queue.put(f"data: ERROR: {exc}\n\n")
        finally:
            await queue.put(None)  # sentinel

    asyncio.create_task(_do_scan())
    return JSONResponse({"run_id": run_id})


# ---------------------------------------------------------------------------
# POST /api/fix
# ---------------------------------------------------------------------------

@app.post("/api/fix")
async def post_fix(body: dict = None):
    """Prepare the workspace and start the Bob fix run. Returns a run_id."""
    if body is None:
        body = {}
    target = body.get("target", "demo/caredesk")
    run_id = str(uuid.uuid4())
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    _streams[run_id] = queue

    async def _do_fix():
        from logleak.fixer import prepare_workspace, run_bob
        try:
            target_path = Path(target)
            if not target_path.is_absolute():
                target_path = _REPO_ROOT / target_path
            await queue.put("data: Preparing workspace...\n\n")
            workspace = await _run_in_thread(prepare_workspace, target_path)
            await queue.put(f"data: Workspace ready at {workspace}\n\n")
            await queue.put("data: Starting Bob Shell...\n\n")
            exit_code = await _run_in_thread(run_bob, workspace)
            await queue.put(f"data: Bob exited with code {exit_code}\n\n")
            await queue.put("data: DONE\n\n")
        except Exception as exc:  # noqa: BLE001
            await queue.put(f"data: ERROR: {exc}\n\n")
        finally:
            await queue.put(None)

    asyncio.create_task(_do_fix())
    return JSONResponse({"run_id": run_id})


# ---------------------------------------------------------------------------
# POST /api/verify
# ---------------------------------------------------------------------------

@app.post("/api/verify")
async def post_verify(body: dict = None):
    """Run the 6-check verification gate. Returns the gate result."""
    if body is None:
        body = {}
    target = body.get("target", "runs/workspace/caredesk")
    from logleak import mcp_tools
    result = await _run_in_thread(mcp_tools.verify_fix, target)
    return JSONResponse(_sanitize_json(result))


# ---------------------------------------------------------------------------
# GET /api/stream/{run_id}
# ---------------------------------------------------------------------------

@app.get("/api/stream/{run_id}")
async def stream_run(run_id: str):
    """SSE endpoint: yields progress lines for a running scan or fix job."""
    queue = _streams.get(run_id)
    if queue is None:
        raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=60.0)
                if msg is None:
                    yield "data: [DONE]\n\n"
                    break
                yield msg
        except asyncio.TimeoutError:
            yield "data: [TIMEOUT]\n\n"
        finally:
            _streams.pop(run_id, None)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
