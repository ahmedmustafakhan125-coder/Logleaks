"""redact.py — mask PII values and provide a logging filter."""
from __future__ import annotations

import logging
from typing import Any


def mask(kind: str, value: str) -> str:
    """Return a masked representation of value for the given PII kind."""
    if kind == "email":
        at = value.find("@")
        if at > 0:
            return value[0] + "***" + value[at:]
        return "[REDACTED:email]"

    if kind == "card":
        digits = value.replace(" ", "").replace("-", "")
        return "*" * (len(digits) - 4) + digits[-4:]

    if kind == "phone":
        # Keep "+92" prefix (3 chars) and last 3 digits
        # Handle +92XXXXXXXXX (13 chars total) -> +92*******567
        if value.startswith("+92") and len(value) >= 6:
            prefix = value[:3]
            last3 = value[-3:]
            middle = "*" * (len(value) - 6)
            return prefix + middle + last3
        # Generic: keep first 3, mask middle, keep last 3
        if len(value) > 6:
            return value[:3] + "*" * (len(value) - 6) + value[-3:]
        return "[REDACTED:phone]"

    if kind == "cnic":
        return "[REDACTED:cnic]"

    if kind == "iban":
        # Keep country code (2) + check digits (2) = 4 chars, mask the rest
        return value[:4] + "*" * (len(value) - 4)

    if kind in ("jwt", "secret"):
        return f"[REDACTED:{kind}]"

    # Unknown kind — full redaction
    return f"[REDACTED:{kind}]"


def redact_text(text: str) -> str:
    """Replace every detected PII span in text with its masked form."""
    from logleak.detectors import detect
    from logleak.canaries import all_canaries

    findings = detect(text, canaries=all_canaries())
    if not findings:
        return text

    result = []
    prev = 0
    for f in sorted(findings, key=lambda x: x.start):
        result.append(text[prev:f.start])
        result.append(mask(f.kind, f.value))
        prev = f.end
    result.append(text[prev:])
    return "".join(result)


class RedactionFilter(logging.Filter):
    """A logging filter that masks PII in log records before they are formatted.

    Must never drop a record — always returns True.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        """Redact PII from record.msg, record.args, and record.exc_text."""
        # Redact the format string (msg)
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)

        # Redact args so that %-formatted messages come out clean.
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    redact_text(a) if isinstance(a, str) else a
                    for a in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: redact_text(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }

        # Materialise and redact the exception traceback BEFORE the formatter sees it.
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            record.exc_text = redact_text(record.exc_text)
            record.exc_info = None  # prevent the formatter from re-rendering

        return True
