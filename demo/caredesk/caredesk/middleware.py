"""middleware.py — request logging middleware for CareDesk.

Leak L4: logs the full JSON request body, which may contain PII.
"""
from __future__ import annotations

import json
import logging

from fastapi import Request

logger = logging.getLogger(__name__)


async def log_request_body(request: Request, call_next):
    """Middleware that logs the full JSON request body before routing.

    LEAK L4: the raw body is logged, exposing any PII in the payload.
    """
    body_bytes = await request.body()
    if body_bytes:
        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError:
            body = body_bytes.decode(errors="replace")
        # LEAK L4: full body logged — may contain card numbers, emails, CNICs
        logger.info("Incoming request body: %s", body)

    # Re-create the receive channel so FastAPI can still parse the body
    async def _receive():
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    request._receive = _receive
    response = await call_next(request)
    return response
