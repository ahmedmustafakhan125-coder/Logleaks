"""logging_config.py — central logging setup for CareDesk.

Call configure_logging() once at application startup.
This is also the integration point for the LogLeak safety-net RedactionFilter.
"""
from __future__ import annotations

import logging
import sys


def configure_logging() -> None:
    """Configure root logger and per-library levels for the CareDesk app."""
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

    # httpx is chatty at DEBUG; keep it at INFO so we still see request logs
    # (which is where L7 leaks the email in the URL).
    logging.getLogger("httpx").setLevel(logging.INFO)

    # Suppress noisy uvicorn access logs in tests
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
