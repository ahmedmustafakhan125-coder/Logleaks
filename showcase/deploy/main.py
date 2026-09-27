"""main.py — LogLeak showcase host.

Starts two child uvicorn processes:
  • app_leaky  on :8001
  • app_clean  on :8002

Exposes on :8080:
  GET  /              → browser tester UI (static HTML)
  POST /leaky/<path>  → proxy → :8001/<path>, returns {response, logs}
  POST /clean/<path>  → proxy → :8002/<path>, returns {response, logs}
  GET  /logs/stream   → SSE stream of live log lines from both servers
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE     = Path(__file__).parent
_APP_DIR  = _HERE.parent          # showcase/  (contains app_leaky.py, app_clean.py)
_UI_DIR   = _HERE / "ui"

LEAKY_PORT = 8001
CLEAN_PORT = 8002

# ---------------------------------------------------------------------------
# Shared log ring-buffer (last 200 lines from each child)
# ---------------------------------------------------------------------------

_log_buffer: deque[str] = deque(maxlen=200)
_log_subscribers: list[asyncio.Queue[str]] = []


def _push_log(line: str) -> None:
    """Append a log line and fan it out to all SSE subscribers."""
    _log_buffer.append(line)
    for q in _log_subscribers:
        q.put_nowait(line)


# ---------------------------------------------------------------------------
# Child process management
# ---------------------------------------------------------------------------

_children: list[subprocess.Popen] = []


async def _stream_child_output(proc: subprocess.Popen, tag: str) -> None:
    """Read a child process stdout/stderr line-by-line and push to the buffer."""
    assert proc.stdout is not None
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, proc.stdout.readline)
        if not line:
            break
        _push_log(f"[{tag}] {line.decode(errors='replace').rstrip()}")


def _start_child(module: str, port: int, tag: str) -> subprocess.Popen:
    """Start a uvicorn child and return the Popen handle."""
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            f"{module}:app",
            "--host", "127.0.0.1",
            "--port", str(port),
            "--log-level", "debug",
        ],
        cwd=str(_APP_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _children.append(proc)
    return proc


# ---------------------------------------------------------------------------
# Lifespan: start children, register background readers
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start child servers, stream their logs, yield, then terminate."""
    leaky_proc = _start_child("app_leaky", LEAKY_PORT, "LEAKY")
    clean_proc = _start_child("app_clean",  CLEAN_PORT, "CLEAN")

    # Give them a moment to bind before we start accepting proxy requests
    await asyncio.sleep(1.5)

    tasks = [
        asyncio.create_task(_stream_child_output(leaky_proc, "LEAKY")),
        asyncio.create_task(_stream_child_output(clean_proc,  "CLEAN")),
    ]

    yield  # app is live

    for task in tasks:
        task.cancel()
    for proc in _children:
        proc.terminate()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="LogLeak Showcase", lifespan=lifespan)


# ---------------------------------------------------------------------------
# SSE log stream
# ---------------------------------------------------------------------------

@app.get("/logs/stream")
async def log_stream() -> StreamingResponse:
    """Server-Sent Events stream of child server log lines."""
    queue: asyncio.Queue[str] = asyncio.Queue()
    _log_subscribers.append(queue)

    # Replay the last N buffered lines so a freshly opened browser tab
    # sees recent history immediately.
    for line in list(_log_buffer):
        queue.put_nowait(line)

    async def generator() -> AsyncIterator[str]:
        try:
            while True:
                line = await queue.get()
                yield f"data: {json.dumps(line)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _log_subscribers.remove(queue)

    return StreamingResponse(generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------

async def _proxy(target_port: int, path: str, request: Request) -> dict:
    """Forward a request to a child server and return {status, body}."""
    body = await request.body()
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    url = f"http://127.0.0.1:{target_port}/{path}"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.request(
            method=request.method,
            url=url,
            content=body,
            headers=headers,
        )
    try:
        body_out = resp.json()
    except Exception:
        body_out = resp.text
    return {"status": resp.status_code, "body": body_out}


@app.api_route("/leaky/{path:path}", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
async def proxy_leaky(path: str, request: Request) -> dict:
    """Proxy to the leaky server."""
    return await _proxy(LEAKY_PORT, path, request)


@app.api_route("/clean/{path:path}", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
async def proxy_clean(path: str, request: Request) -> dict:
    """Proxy to the clean server."""
    return await _proxy(CLEAN_PORT, path, request)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def ui() -> HTMLResponse:
    """Serve the browser tester UI."""
    return HTMLResponse((_UI_DIR / "index.html").read_text(encoding="utf-8"))

@app.get("/docs", response_class=HTMLResponse)
async def docs() -> HTMLResponse:
    """Serve the documentation page."""
    return HTMLResponse((_UI_DIR / "docs.html").read_text(encoding="utf-8"))

@app.get("/api/docs/content")
async def docs_content() -> dict:
    """Return the raw README.md content."""
    readme_path = Path("/app/README.md")
    if not readme_path.exists():
        readme_path = _APP_DIR.parent / "README.md"
    content = readme_path.read_text(encoding="utf-8") if readme_path.exists() else "# Documentation not found"
    return {"content": content}
