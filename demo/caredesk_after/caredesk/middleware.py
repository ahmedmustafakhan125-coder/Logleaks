"""middleware.py — request logging middleware for CareDesk."""
from __future__ import annotations

import logging

from fastapi import Request

logger = logging.getLogger(__name__)


async def log_request_body(request: Request, call_next):
    """Middleware that logs request metadata (method, path, content-type) — no body."""
    body_bytes = await request.body()
    if body_bytes:
        content_type = request.headers.get("content-type", "")
        logger.info(
            "Incoming request: %s %s (%s)",
            request.method,
            request.url.path,
            content_type,
        )

    # Re-create the receive channel so FastAPI can still parse the body
    async def _receive():
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    request._receive = _receive
    response = await call_next(request)
    return response
