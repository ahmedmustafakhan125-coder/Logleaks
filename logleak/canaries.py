"""canaries.py — fake-but-valid PII values used as runtime canaries."""
from __future__ import annotations

# Every value is fake by construction. None of these are real personal data.
CANARIES: dict[str, str] = {
    "email":  "canary.patient@logleak.test",
    "card":   "4242424242424242",
    "cnic":   "35202-1234567-9",
    "phone":  "+923001234567",
    "iban":   "GB82WEST12345698765432",
    "jwt":    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl",
    "secret": "llk_canary_9fQ2xV7pL3mZ8rT1wY6bN4cK",
}


def all_canaries() -> list[str]:
    """Return all canary values as a flat list."""
    return list(CANARIES.values())
