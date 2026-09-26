"""notifier.py — email alerts for live PII breaches.

Sends a styled HTML email (like a deployment-failure alert) the first time
a breach is detected at a given source location.  Subsequent hits from the
same file:line:kind are suppressed for ``cooldown`` seconds so a flooding
log line doesn't fill up an inbox.

Usage::

    from logleak.notifier import EmailNotifier, SmtpConfig

    cfg = SmtpConfig(
        host="smtp.gmail.com",
        port=587,
        use_tls=True,
        username="alerts@example.com",
        password="app-password",
        from_addr="alerts@example.com",
        to_addrs=["security@example.com", "oncall@example.com"],
    )
    notifier = EmailNotifier(cfg)
    install_watch_handler(on_breach=notifier)   # callable via __call__

All values that leave this module pass through redact_text(), so no raw
PII ever appears in the email body.
"""
from __future__ import annotations

import smtplib
import threading
import time
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from logleak.watch_handler import BreachEvent

# ---------------------------------------------------------------------------
# SmtpConfig
# ---------------------------------------------------------------------------


@dataclass
class SmtpConfig:
    """SMTP connection and addressing configuration."""

    host: str
    port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Derive from_addr from username when not supplied explicitly."""
        if not self.from_addr and self.username:
            self.from_addr = self.username


# ---------------------------------------------------------------------------
# HTML email builder
# ---------------------------------------------------------------------------

_SEV_BG   = {"critical": "#b91c1c", "high": "#b45309"}
_SEV_TEXT = {"critical": "#fee2e2", "high": "#fef3c7"}


def build_breach_email(
    event: "BreachEvent",
    app_name: str = "LogLeak",
) -> tuple[str, str, str]:
    """Return (subject, plain_text, html) for a breach notification email.

    All values in the email are already masked — no raw PII leaves this
    function.
    """
    sev_bg   = _SEV_BG.get(event.severity, "#1e40af")
    sev_text = _SEV_TEXT.get(event.severity, "#dbeafe")
    subject  = (
        f"[{app_name}] PII BREACH · {event.severity.upper()} · "
        f"{event.kind} in {event.pathname.split('/')[-1].split(chr(92))[-1]}"
    )

    plain = (
        f"LogLeak detected a PII breach in your running application.\n\n"
        f"  Severity  : {event.severity.upper()}\n"
        f"  Kind      : {event.kind}\n"
        f"  Confidence: {event.confidence}\n"
        f"  Value     : {event.masked_value}\n"
        f"  Logger    : {event.logger_name}  [{event.level}]\n"
        f"  Message   : {event.masked_line}\n"
        f"  Source    : {event.pathname}:{event.lineno}\n\n"
        f"This email was generated automatically by LogLeak.\n"
        f"No raw personal data is included — all values are masked.\n"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{subject}</title>
</head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:#f3f4f6;padding:32px 0;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0"
           style="background:#ffffff;border-radius:8px;
                  border:1px solid #e5e7eb;overflow:hidden;">

      <!-- Header bar -->
      <tr>
        <td style="background:{sev_bg};padding:20px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td>
                <span style="color:#ffffff;font-size:11px;font-weight:600;
                             letter-spacing:0.08em;text-transform:uppercase;">
                  LogLeak · Privacy Breach Alert
                </span>
              </td>
              <td align="right">
                <span style="background:{sev_text};color:{sev_bg};
                             font-size:11px;font-weight:700;
                             padding:3px 10px;border-radius:999px;
                             letter-spacing:0.06em;">
                  {event.severity.upper()}
                </span>
              </td>
            </tr>
          </table>
          <p style="margin:12px 0 0;color:#ffffff;font-size:22px;
                    font-weight:700;line-height:1.3;">
            PII detected in live logs
          </p>
          <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">
            A <strong>{event.kind}</strong> value ({event.confidence})
            was found in a running log record.
          </p>
        </td>
      </tr>

      <!-- Body -->
      <tr>
        <td style="padding:32px;">

          <!-- Detail table -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="border:1px solid #e5e7eb;border-radius:6px;
                        overflow:hidden;font-size:14px;">
            <tr style="background:#f9fafb;">
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;
                         width:130px;border-bottom:1px solid #e5e7eb;">
                Severity
              </td>
              <td style="padding:10px 16px;color:#1f2328;
                         border-bottom:1px solid #e5e7eb;">
                <span style="background:{sev_bg};color:{sev_text};
                             font-size:11px;font-weight:700;
                             padding:2px 8px;border-radius:4px;">
                  {event.severity.upper()}
                </span>
              </td>
            </tr>
            <tr>
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;
                         border-bottom:1px solid #e5e7eb;">Kind</td>
              <td style="padding:10px 16px;color:#1f2328;
                         border-bottom:1px solid #e5e7eb;font-family:monospace;">
                {event.kind}
              </td>
            </tr>
            <tr style="background:#f9fafb;">
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;
                         border-bottom:1px solid #e5e7eb;">Confidence</td>
              <td style="padding:10px 16px;color:#1f2328;
                         border-bottom:1px solid #e5e7eb;">
                {event.confidence}
              </td>
            </tr>
            <tr>
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;
                         border-bottom:1px solid #e5e7eb;">Masked value</td>
              <td style="padding:10px 16px;color:#1f2328;font-family:monospace;
                         border-bottom:1px solid #e5e7eb;">
                {event.masked_value}
              </td>
            </tr>
            <tr style="background:#f9fafb;">
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;
                         border-bottom:1px solid #e5e7eb;">Logger</td>
              <td style="padding:10px 16px;color:#1f2328;font-family:monospace;
                         border-bottom:1px solid #e5e7eb;">
                {event.logger_name} &nbsp;
                <span style="background:#e5e7eb;color:#374151;font-size:11px;
                             padding:1px 6px;border-radius:3px;">
                  {event.level}
                </span>
              </td>
            </tr>
            <tr>
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;
                         border-bottom:1px solid #e5e7eb;">Log message</td>
              <td style="padding:10px 16px;color:#1f2328;font-family:monospace;
                         font-size:13px;border-bottom:1px solid #e5e7eb;
                         word-break:break-all;">
                {event.masked_line}
              </td>
            </tr>
            <tr style="background:#f9fafb;">
              <td style="padding:10px 16px;color:#6b7280;font-weight:600;">
                Source
              </td>
              <td style="padding:10px 16px;color:#1f2328;font-family:monospace;
                         font-size:13px;">
                {event.pathname}:{event.lineno}
              </td>
            </tr>
          </table>

          <!-- Note -->
          <p style="margin:24px 0 0;font-size:13px;color:#6b7280;
                    border-top:1px solid #e5e7eb;padding-top:20px;">
            All values in this email are masked. No raw personal data was
            included. This alert was generated by
            <strong>LogLeak</strong> running inside your application process.
          </p>

        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#f9fafb;padding:16px 32px;
                   border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:12px;color:#9ca3af;text-align:center;">
            LogLeak Privacy Guard &mdash; automated breach notification
          </p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    return subject, plain, html


# ---------------------------------------------------------------------------
# EmailNotifier
# ---------------------------------------------------------------------------


class EmailNotifier:
    """Callable that sends a styled HTML breach-alert email via SMTP.

    Deduplicates: the same file:line:kind combination is suppressed for
    ``cooldown`` seconds after the first alert, preventing inbox floods
    from a single leaking log site.
    """

    def __init__(
        self,
        config: SmtpConfig,
        app_name: str = "LogLeak",
        cooldown: float = 300.0,
    ) -> None:
        """Initialise with SMTP config, optional app name, and dedup cooldown."""
        self._cfg = config
        self._app_name = app_name
        self._cooldown = cooldown
        self._sent: dict[str, float] = {}   # key → last sent timestamp
        self._lock = threading.Lock()

    # Make the instance directly callable so it matches the on_breach signature.
    def __call__(self, event: "BreachEvent") -> None:
        """Send a breach-alert email unless this site is still in cooldown."""
        key = f"{event.pathname}:{event.lineno}:{event.kind}"
        now = time.monotonic()
        with self._lock:
            last = self._sent.get(key, 0.0)
            if now - last < self._cooldown:
                return
            self._sent[key] = now
        self._send(event)

    def _send(self, event: "BreachEvent") -> None:
        """Build and dispatch the MIME email for one breach event."""
        subject, plain, html = build_breach_email(event, app_name=self._app_name)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = self._cfg.from_addr
        msg["To"]      = ", ".join(self._cfg.to_addrs)
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html,  "html",  "utf-8"))

        try:
            if self._cfg.use_tls:
                with smtplib.SMTP(self._cfg.host, self._cfg.port, timeout=15) as s:
                    s.ehlo()
                    s.starttls()
                    s.ehlo()
                    if self._cfg.username:
                        s.login(self._cfg.username, self._cfg.password)
                    s.sendmail(
                        self._cfg.from_addr,
                        self._cfg.to_addrs,
                        msg.as_bytes(),
                    )
            else:
                with smtplib.SMTP(self._cfg.host, self._cfg.port, timeout=15) as s:
                    if self._cfg.username:
                        s.login(self._cfg.username, self._cfg.password)
                    s.sendmail(
                        self._cfg.from_addr,
                        self._cfg.to_addrs,
                        msg.as_bytes(),
                    )
        except Exception as exc:  # noqa: BLE001 — never crash the app
            import sys
            print(
                f"[LogLeak] WARNING: could not send breach email: {exc}",
                file=sys.stderr,
                flush=True,
            )
