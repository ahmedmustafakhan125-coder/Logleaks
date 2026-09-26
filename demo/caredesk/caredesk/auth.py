"""auth.py — JWT token issuance for clinic staff."""
from __future__ import annotations

import base64
import logging
import time

logger = logging.getLogger(__name__)

# Minimal HS256-like fake token (no real crypto — demo only)
_HEADER = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()


def _make_payload(sub: str) -> str:
    payload = f'{{"sub":"{sub}","iat":{int(time.time())}}}'.encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def issue_token(username: str) -> str:
    """Issue a JWT-like access token for a clinic staff user."""
    payload = _make_payload(username)
    sig = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
    token = f"{_HEADER}.{payload}.{sig}"
    # LEAK L5: forgotten debug print exposes the token to stdout
    print(f"issued token {token}")
    logger.info("Token issued for user %s", username)
    return token


def verify_token(token: str) -> bool:
    """Verify a token has the expected three-part structure."""
    parts = token.split(".")
    if len(parts) != 3:
        logger.warning("Invalid token structure: wrong number of segments")
        return False
    return True
