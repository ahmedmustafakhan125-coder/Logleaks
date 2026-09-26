"""watch_handler.py — in-process PII breach detection for deployed apps.

Attaches a LeakWatchHandler to the root logger so that every log record
is scanned for PII the moment it is emitted.  The handler never drops
records and never modifies them (that is RedactionFilter's job).

Usage (programmatic, e.g. in your app's logging_config.py)::

    from logleak.watch_handler import install_watch_handler
    from logleak.notifier import SmtpConfig

    # Console-only
    install_watch_handler()

    # Console + email
    install_watch_handler(
        smtp=SmtpConfig(
            host="smtp.gmail.com", port=587, use_tls=True,
            username="alerts@example.com", password="app-password",
            to_addrs=["security@example.com"],
        )
    )

Usage (via the CLI)::

    logleak watch --attach <app_module:app_factory> \\
        --smtp-host smtp.gmail.com --smtp-to security@example.com ...
"""
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from logleak.notifier import SmtpConfig

from logleak.detectors import SEVERITY, detect
from logleak.redact import mask

# ---------------------------------------------------------------------------
# BreachEvent — the notification payload
# ---------------------------------------------------------------------------


@dataclass
class BreachEvent:
    """A single PII breach detected in a live log record."""

    kind: str        # email | card | cnic | phone | iban | jwt | secret
    severity: str    # critical | high
    confidence: str  # confirmed | suspected
    masked_value: str
    logger_name: str
    level: str
    masked_line: str  # the full log message with PII already masked
    pathname: str
    lineno: int

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (safe to pass over queues / JSON)."""
        return {
            "kind": self.kind,
            "severity": self.severity,
            "confidence": self.confidence,
            "masked_value": self.masked_value,
            "logger_name": self.logger_name,
            "level": self.level,
            "masked_line": self.masked_line,
            "pathname": self.pathname,
            "lineno": self.lineno,
        }


# ---------------------------------------------------------------------------
# Default on_breach callback — coloured stderr alert
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"

_SEV_COLOUR = {"critical": _RED, "high": _YELLOW}


def _default_on_breach(event: BreachEvent) -> None:
    """Print a coloured breach alert to stderr."""
    col = _SEV_COLOUR.get(event.severity, _YELLOW)
    print(
        f"\n{col}{_BOLD}[LOGLEAK BREACH]{_RESET} "
        f"{col}{event.severity.upper()}{_RESET} "
        f"{_CYAN}{event.kind}{_RESET} ({event.confidence})\n"
        f"  masked : {event.masked_value}\n"
        f"  line   : {event.masked_line}\n"
        f"  source : {event.pathname}:{event.lineno}",
        file=sys.stderr,
        flush=True,
    )


# ---------------------------------------------------------------------------
# LeakWatchHandler
# ---------------------------------------------------------------------------


class LeakWatchHandler(logging.Handler):
    """Logging handler that scans every record for PII and fires on_breach.

    Must never drop records; emit() always returns without raising.
    """

    def __init__(
        self,
        on_breach: Callable[[BreachEvent], None] = _default_on_breach,
        canaries_only: bool = False,
    ) -> None:
        """Initialise with a breach callback and optional canaries-only flag."""
        super().__init__(level=logging.DEBUG)
        self._on_breach = on_breach
        self._canaries_only = canaries_only
        from logleak.canaries import all_canaries
        self._canaries = all_canaries()

    def emit(self, record: logging.LogRecord) -> None:
        """Scan the formatted record message and fire on_breach for each finding."""
        try:
            message = record.getMessage()
            findings = detect(message, canaries=self._canaries)
            if self._canaries_only:
                findings = [f for f in findings if f.confidence == "confirmed"]
            if not findings:
                return
            from logleak.redact import redact_text
            masked_line = redact_text(message)
            for f in findings:
                event = BreachEvent(
                    kind=f.kind,
                    severity=SEVERITY.get(f.kind, "high"),
                    confidence=f.confidence,
                    masked_value=mask(f.kind, f.value),
                    logger_name=record.name,
                    level=record.levelname,
                    masked_line=masked_line,
                    pathname=record.pathname,
                    lineno=record.lineno,
                )
                self._on_breach(event)
        except Exception:  # noqa: BLE001 — never crash the app's logging
            self.handleError(record)


# ---------------------------------------------------------------------------
# Public convenience installer
# ---------------------------------------------------------------------------


def install_watch_handler(
    on_breach: Callable[[BreachEvent], None] | None = None,
    canaries_only: bool = False,
    smtp: "SmtpConfig | None" = None,
    app_name: str = "LogLeak",
    email_cooldown: float = 300.0,
) -> LeakWatchHandler:
    """Attach a LeakWatchHandler to the root logger and return it.

    When ``smtp`` is supplied an EmailNotifier is composed alongside the
    console callback so every breach fires both a stderr alert and an email.

    Safe to call multiple times — won't add a duplicate handler.
    """
    root = logging.getLogger()
    for h in root.handlers:
        if isinstance(h, LeakWatchHandler):
            return h  # already installed

    # Build the composed callback list
    callbacks: list[Callable[[BreachEvent], None]] = [
        on_breach if on_breach is not None else _default_on_breach
    ]

    if smtp is not None:
        from logleak.notifier import EmailNotifier
        callbacks.append(
            EmailNotifier(smtp, app_name=app_name, cooldown=email_cooldown)
        )

    def _dispatch(event: BreachEvent) -> None:
        """Call every registered breach callback in order."""
        for cb in callbacks:
            try:
                cb(event)
            except Exception:  # noqa: BLE001
                pass

    handler = LeakWatchHandler(
        on_breach=_dispatch,
        canaries_only=canaries_only,
    )
    root.addHandler(handler)
    return handler
