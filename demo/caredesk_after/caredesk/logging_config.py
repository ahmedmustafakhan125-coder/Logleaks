"""logging_config.py — central logging setup for CareDesk.

Call configure_logging() once at application startup.
Installs a RedactionFilter safety net on the root logger so that any PII
that escapes source-level fixes is still masked before reaching handlers.
"""
from __future__ import annotations

import logging
import sys

# Guard flag — prevents double-installation if configure_logging() is called
# more than once (e.g. during test collection).
_logleak_redacting = False


def configure_logging() -> None:
    """Configure root logger and install the RedactionFilter safety net."""
    global _logleak_redacting

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s  %(message)s"
            )
        )
        root.addHandler(handler)

    # Install the LogLeak RedactionFilter safety net (idempotent).
    if not _logleak_redacting:
        try:
            from logleak.redact import RedactionFilter
            redaction_filter = RedactionFilter()
            # Attach to all existing handlers
            for h in root.handlers:
                h.addFilter(redaction_filter)
            # Also hook setLogRecordFactory so handlers added AFTER startup
            # (e.g. by pytest's caplog) receive already-redacted records.
            _orig_factory = logging.getLogRecordFactory()

            def _redacting_factory(*args, **kwargs):
                record = _orig_factory(*args, **kwargs)
                redaction_filter.filter(record)
                return record

            logging.setLogRecordFactory(_redacting_factory)
            _logleak_redacting = True
        except ImportError:
            # logleak not installed — skip silently
            pass

    # httpx logs embed PII in URL query strings at INFO level (L7).
    # Raise to WARNING to suppress those lines without losing error visibility.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Suppress noisy uvicorn access logs in tests
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
