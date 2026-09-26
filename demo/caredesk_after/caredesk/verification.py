"""verification.py — email address verification via an external API.

Uses httpx with a MockTransport so no real network call is made.
httpx's own logger emits an INFO record containing the full request URL,
which includes ?email=<address>. This is Leak L7.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_VERIFY_BASE = "https://verify.caredesk.internal/check"


def _mock_transport() -> httpx.MockTransport:
    """Return a mock transport that accepts any request and returns 200."""
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"valid": True})

    return httpx.MockTransport(_handler)


def verify_email(email: str) -> bool:
    """Verify an email address via the external verification service.

    The httpx INFO log for this request will contain the full URL including
    the ?email= query parameter — Leak L7.
    """
    url = f"{_VERIFY_BASE}?email={email}"
    # httpx logs "HTTP Request: GET <url> ..." at INFO level via the httpx logger.
    # logging_config.py sets httpx to INFO, so this record is emitted.
    with httpx.Client(transport=_mock_transport()) as client:
        resp = client.get(url)

    valid = resp.status_code == 200
    logger.info("Email verification for registration completed, valid=%s", valid)
    return valid
