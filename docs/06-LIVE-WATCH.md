# 06 · Live Watch — Real-Time PII Breach Detection

> **The scan/fix/verify pipeline proves the code is clean before deployment.  
> `logleak watch` catches anything that slips through the moment it hits a live log line.**

---

## Table of contents

1. [What this document covers](#1-what-this-document-covers)
2. [Core concept](#2-core-concept)
3. [Architecture](#3-architecture)
   - [3.1 How a record travels through the system](#31-how-a-record-travels-through-the-system)
   - [3.2 Why `record.getMessage()` matters](#32-why-recordgetmessage-matters)
   - [3.3 The three deployment modes](#33-the-three-deployment-modes)
4. [Module reference](#4-module-reference)
   - [4.1 `watch_handler.py`](#41-watch_handlerpy)
   - [4.2 `notifier.py`](#42-notifierpy)
   - [4.3 `cli.py` — `watch` subcommand](#43-clipy--watch-subcommand)
5. [Email alert pipeline](#5-email-alert-pipeline)
   - [5.1 BreachEvent construction](#51-breachevent-construction)
   - [5.2 Cooldown deduplication](#52-cooldown-deduplication)
   - [5.3 MIME message assembly](#53-mime-message-assembly)
   - [5.4 SMTP transmission](#54-smtp-transmission)
   - [5.5 Failure handling](#55-failure-handling)
6. [SMTP provider setup](#6-smtp-provider-setup)
   - [6.1 Gmail with App Password](#61-gmail-with-app-password)
   - [6.2 SendGrid](#62-sendgrid)
   - [6.3 AWS SES](#63-aws-ses)
   - [6.4 Microsoft 365 / Outlook SMTP](#64-microsoft-365--outlook-smtp)
   - [6.5 Local / test SMTP (no credentials)](#65-local--test-smtp-no-credentials)
7. [Deployment manual](#7-deployment-manual)
   - [7.1 Option A — Pipe stdout/stderr](#71-option-a--pipe-stdoutstderr)
   - [7.2 Option B — Tail a log file](#72-option-b--tail-a-log-file)
   - [7.3 Option C — In-process handler (recommended)](#73-option-c--in-process-handler-recommended)
   - [7.4 Platform recipes](#74-platform-recipes)
     - [systemd](#systemd)
     - [Docker / docker-compose](#docker--docker-compose)
     - [Heroku / Railway / Render](#heroku--railway--render)
     - [Kubernetes sidecar](#kubernetes-sidecar)
     - [GitHub Actions](#github-actions)
8. [Custom callbacks — Slack, PagerDuty, webhooks](#8-custom-callbacks--slack-pagerduty-webhooks)
9. [Security and privacy guarantees](#9-security-and-privacy-guarantees)
10. [CLI reference](#10-cli-reference)
11. [Environment variable reference](#11-environment-variable-reference)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What this document covers

This document is the complete technical manual for the **live watch subsystem** — the part of LogLeak that monitors a running application in real time rather than in a test harness. It covers:

- How detection works inside a live process
- All three deployment patterns with exact code and config
- SMTP setup for every major provider
- The full email alert pipeline from log record to inbox
- Custom notification callbacks
- Security invariants
- A complete CLI and environment variable reference
- Troubleshooting

For the scan / fix / verify pipeline (used in CI before deployment), see [`01-ARCHITECTURE.md`](01-ARCHITECTURE.md).

---

## 2. Core concept

Python's `logging` module works through a chain of `Handler` objects attached to loggers. Every call to `logger.info(...)`, `logger.debug(...)`, `logger.error(...)`, etc. produces a `LogRecord` and dispatches it to every handler on the matching logger and its ancestors, up to the root logger.

`install_watch_handler()` adds one more handler — [`LeakWatchHandler`](../logleak/watch_handler.py) — to the **root logger**. Because the root is the ancestor of every named logger, it sees every record emitted anywhere in the process, including from third-party libraries.

The handler:

1. Calls `record.getMessage()` to fully format the log message (resolving `%s`, `%d`, etc.).
2. Passes the formatted string to `detect()` — the same engine used by the scan pipeline.
3. If findings exist, constructs a `BreachEvent` containing **only masked values** and fires every registered callback.
4. **Never modifies the record. Never drops it.** The app's normal log output is completely unaffected.

This means the check happens **synchronously, inside the logging call, before the record is written to any output**. There is no polling, no file watching, no external process — the latency is the time for one `detect()` call (under 1 millisecond for typical log lines).

---

## 3. Architecture

### 3.1 How a record travels through the system

```
Application code
────────────────
logger.debug("Charging card %s", card_number)
         │
         │  Python logging machinery
         ▼
   LogRecord created
   record.msg  = "Charging card %s"
   record.args = (card_number,)
   record.pathname = "payments.py"
   record.lineno   = 25
         │
         │  Dispatched to all handlers on root logger
         │
   ┌─────┴──────────────────────────────────────┐
   │                                            │
   ▼                                            ▼
StreamHandler                          LeakWatchHandler
(writes formatted line                 .emit(record)
 to stdout / file)                          │
                                    record.getMessage()
                                    → "Charging card 4242424242424242"
                                            │
                                    detect(message, canaries)
                                            │
                                    Finding(kind="card",
                                            value="4242424242424242",
                                            confidence="confirmed")
                                            │
                                    mask("card", "4242424242424242")
                                    → "************4242"
                                            │
                                    BreachEvent(
                                      kind="card",
                                      severity="critical",
                                      confidence="confirmed",
                                      masked_value="************4242",
                                      logger_name="myapp.payments",
                                      level="DEBUG",
                                      masked_line="Charging card ************4242",
                                      pathname="payments.py",
                                      lineno=25,
                                    )
                                            │
                                    _dispatch(event)
                                      │              │
                                      ▼              ▼
                              console alert    EmailNotifier
                              (stderr)         cooldown check
                                               → smtplib send
```

The `StreamHandler` path and the `LeakWatchHandler` path are completely independent. The application log is written as normal; the breach alert fires in the same thread without interfering.

---

### 3.2 Why `record.getMessage()` matters

The single most important line in [`LeakWatchHandler.emit()`](../logleak/watch_handler.py:128) is:

```python
message = record.getMessage()
```

Python's `%`-style logging defers string formatting until a handler actually needs the message. This means:

```python
# What the developer wrote:
logger.debug("Charging card %s for patient %s", card_number, patient_id)

# record.msg  = "Charging card %s for patient %s"   ← grep sees this
# record.args = ("4242424242424242", "P-001")

# record.getMessage() = "Charging card 4242424242424242 for patient P-001"
#                                        ↑
#                               detect() scans THIS string
```

Static analysis and grep-based scanners can only see the format string. `LeakWatchHandler` sees the fully-rendered value — which is exactly what gets written to the log file or shipped to Datadog/ELK/Sentry.

The same applies to `f`-strings (formatting happens at call time, so `record.msg` already contains the value) and to `str.format()` calls used as the format argument.

---

### 3.3 The three deployment modes

| Mode | How it works | Latency | Source info | Code change required |
|---|---|---|---|---|
| **A — Pipe** | App stdout/stderr piped into `logleak watch -` | < 1 ms after newline | Log file path + line 0 | None |
| **B — File tail** | `logleak watch /path/to/app.log` polls the file | 0–200 ms (configurable) | Log file path + line 0 | None |
| **C — In-process** | `install_watch_handler()` in `logging_config.py` | < 1 ms inside logging call | Exact source `file:line` | ~10 lines in logging setup |

Mode C is recommended for production because:
- Latency is lowest (synchronous, in-process)
- Source information is exact (`payments.py:25`, not `app.log:0`)
- No external process to manage or restart
- Works even when the app does not write to a file

---

## 4. Module reference

### 4.1 `watch_handler.py`

**[`logleak/watch_handler.py`](../logleak/watch_handler.py)**

#### `BreachEvent`

```python
@dataclass
class BreachEvent:
    kind: str           # email | card | cnic | phone | iban | jwt | secret
    severity: str       # critical | high
    confidence: str     # confirmed | suspected
    masked_value: str   # e.g. "************4242"
    logger_name: str    # e.g. "myapp.payments"
    level: str          # e.g. "DEBUG"
    masked_line: str    # full log message with all PII masked
    pathname: str       # source file path
    lineno: int         # source line number

    def to_dict(self) -> dict[str, Any]: ...
```

`BreachEvent` is the object passed to every `on_breach` callback. All fields that could contain PII (`masked_value`, `masked_line`) are already processed through `mask()` and `redact_text()` before the event is constructed. Raw values are never stored in the event.

#### `LeakWatchHandler`

```python
class LeakWatchHandler(logging.Handler):
    def __init__(
        self,
        on_breach: Callable[[BreachEvent], None],
        canaries_only: bool = False,
    ) -> None: ...

    def emit(self, record: logging.LogRecord) -> None: ...
```

A standard `logging.Handler`. Attach it to any logger with `logger.addHandler(handler)` or install it on the root logger with `install_watch_handler()`. The `emit()` method wraps all work in `try/except` and calls `self.handleError(record)` on failure — which logs a warning to stderr and returns, so the application never crashes due to a detection error.

**`canaries_only=True`** restricts alerts to findings where `confidence == "confirmed"` — i.e. an exact canary value was found. Useful in environments where suspected pattern matches are too noisy (e.g. a log that contains many long digit sequences that are not card numbers).

#### `install_watch_handler()`

```python
def install_watch_handler(
    on_breach: Callable[[BreachEvent], None] | None = None,
    canaries_only: bool = False,
    smtp: SmtpConfig | None = None,
    app_name: str = "LogLeak",
    email_cooldown: float = 300.0,
) -> LeakWatchHandler:
```

Attaches a `LeakWatchHandler` to `logging.getLogger()` (the root logger) and returns it. **Idempotent** — calling it a second time returns the existing handler without adding a duplicate.

When `smtp` is supplied, an `EmailNotifier` is composed alongside the console callback using an internal `_dispatch` function. Both fire for every breach; the email notifier applies its own per-location cooldown independently of the console alert.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `on_breach` | `Callable[[BreachEvent], None]` | `_default_on_breach` | Console alert callback. Replace to suppress console output or redirect it. |
| `canaries_only` | `bool` | `False` | If `True`, only confirmed canary matches fire callbacks. |
| `smtp` | `SmtpConfig \| None` | `None` | If set, email alerts are enabled. |
| `app_name` | `str` | `"LogLeak"` | Used in the email subject line. |
| `email_cooldown` | `float` | `300.0` | Seconds to suppress repeat emails for the same `file:line:kind`. |

---

### 4.2 `notifier.py`

**[`logleak/notifier.py`](../logleak/notifier.py)**

#### `SmtpConfig`

```python
@dataclass
class SmtpConfig:
    host: str
    port: int = 587
    use_tls: bool = True        # uses STARTTLS on the plain port
    username: str = ""
    password: str = ""
    from_addr: str = ""         # defaults to username if empty
    to_addrs: list[str] = field(default_factory=list)
```

Plain dataclass. No validation at construction time — errors surface when the first email is sent.

#### `build_breach_email()`

```python
def build_breach_email(
    event: BreachEvent,
    app_name: str = "LogLeak",
) -> tuple[str, str, str]:   # (subject, plain_text, html)
```

Produces three representations of the alert. The HTML version is a self-contained email template with inline CSS — no external resources. Colour coding: red header for `critical`, amber for `high`. The plain text version is used as the fallback part for mail clients that block HTML.

All field values in the email come from the `BreachEvent`, which already contains only masked data. This function is testable in isolation without any SMTP infrastructure.

#### `EmailNotifier`

```python
class EmailNotifier:
    def __init__(
        self,
        config: SmtpConfig,
        app_name: str = "LogLeak",
        cooldown: float = 300.0,
    ) -> None: ...

    def __call__(self, event: BreachEvent) -> None: ...
```

A callable (not a handler — it is a callback). Manages a thread-safe `dict[str, float]` keyed by `"pathname:lineno:kind"` to track when each location was last alerted. The `threading.Lock` ensures correctness under multi-threaded WSGI/ASGI servers (gunicorn workers, uvicorn with multiple workers).

The SMTP connection is opened, used, and closed for each email send. No persistent connection is held, which avoids issues with long-lived processes and SMTP server idle timeouts.

---

### 4.3 `cli.py` — `watch` subcommand

**[`logleak/cli.py`](../logleak/cli.py)**

The `watch` subcommand handles the pipe and file-tail modes (Options A and B). The in-process mode (Option C) is installed programmatically and does not use the CLI.

```
logleak watch <log> [options]
```

See [§10 CLI reference](#10-cli-reference) for the full flag table.

Internal flow for file-tail mode:

```python
with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
    fh.seek(0, 2)           # jump to end — do not replay old lines
    while True:
        raw_line = fh.readline()
        if raw_line:
            findings = detect(raw_line, canaries=canaries)
            if findings:
                _handle_findings(raw_line, findings)   # console + email
        else:
            time.sleep(poll)                           # default 0.2 s
```

`errors="replace"` handles binary log lines (e.g. from a C extension) without crashing. The `seek(0, 2)` means LogLeak only ever watches lines written after it started — it never re-processes the existing file contents.

---

## 5. Email alert pipeline

### 5.1 BreachEvent construction

Inside `LeakWatchHandler.emit()`:

```python
message = record.getMessage()          # fully formats %s, %d, etc.
findings = detect(message, canaries)   # runs all 7 detectors

for f in findings:
    event = BreachEvent(
        kind          = f.kind,
        severity      = SEVERITY[f.kind],
        confidence    = f.confidence,
        masked_value  = mask(f.kind, f.value),   # raw value used here only
        logger_name   = record.name,
        level         = record.levelname,
        masked_line   = redact_text(message),    # entire line re-scanned and masked
        pathname      = record.pathname,
        lineno        = record.lineno,
    )
    self._on_breach(event)
```

After `mask(f.kind, f.value)` is called, the raw value `f.value` is no longer referenced anywhere. It exists briefly on the call stack and is garbage-collected. It is never stored, logged, or passed to any callback.

### 5.2 Cooldown deduplication

```python
# In EmailNotifier.__call__()
key = f"{event.pathname}:{event.lineno}:{event.kind}"
# e.g. "/opt/myapp/payments.py:25:card"

now = time.monotonic()   # monotonic clock — immune to NTP adjustments

with self._lock:                        # thread-safe
    last = self._sent.get(key, 0.0)
    if now - last < self._cooldown:     # still in window?
        return                          # suppress — console already fired
    self._sent[key] = now              # record send time
# Lock released — SMTP call happens outside the lock
self._send(event)
```

`time.monotonic()` is used rather than `time.time()` because monotonic time never goes backwards (e.g. after an NTP correction), which prevents a clock step from accidentally resetting all cooldowns to zero.

The dict grows by one entry per unique breach location. In practice this is bounded by the number of log call sites in the application — typically tens to low hundreds.

### 5.3 MIME message assembly

```python
msg = MIMEMultipart("alternative")
msg["Subject"] = "[MyApp] PII BREACH · CRITICAL · card in payments.py"
msg["From"]    = "alerts@example.com"
msg["To"]      = "security@example.com, oncall@example.com"

msg.attach(MIMEText(plain, "plain", "utf-8"))   # part 1 — plain text fallback
msg.attach(MIMEText(html,  "html",  "utf-8"))   # part 2 — HTML (preferred)
```

`MIMEMultipart("alternative")` is the correct MIME subtype for messages that provide both plain text and HTML versions of the same content. Mail clients that render HTML (Gmail, Outlook, Apple Mail) display the HTML part. Clients that block HTML (some corporate mail systems, text-based clients like mutt) display the plain text part. The plain text part always contains the same information as the HTML part.

### 5.4 SMTP transmission

```python
# With STARTTLS (default, use_tls=True):
with smtplib.SMTP(host, port, timeout=15) as s:
    s.ehlo()           # identify ourselves to the server
    s.starttls()       # upgrade the connection to TLS
    s.ehlo()           # re-identify over TLS
    s.login(username, password)
    s.sendmail(from_addr, to_addrs, msg.as_bytes())

# Without TLS (use_tls=False, not recommended):
with smtplib.SMTP(host, port, timeout=15) as s:
    s.login(username, password)
    s.sendmail(from_addr, to_addrs, msg.as_bytes())
```

The `timeout=15` means if the SMTP server does not respond within 15 seconds, a `socket.timeout` exception is raised, caught, and logged as a warning. The application is never blocked for more than 15 seconds by a slow or unreachable mail server.

### 5.5 Failure handling

```python
except Exception as exc:    # catches socket.timeout, SMTPException, etc.
    print(
        f"[LogLeak] WARNING: could not send breach email: {exc}",
        file=sys.stderr,
        flush=True,
    )
```

This is intentionally broad. Any SMTP failure — wrong credentials, network unavailability, rate limiting, server error — is caught, printed as a warning, and discarded. The application process continues running. The console alert has already fired at this point. Email delivery failure is non-fatal by design.

---

## 6. SMTP provider setup

### 6.1 Gmail with App Password

Gmail has blocked regular password authentication for SMTP since May 2022. You must use an **App Password**.

**Prerequisites:**
- 2-Step Verification must be enabled on the Google Account

**Steps:**
1. Go to [myaccount.google.com](https://myaccount.google.com) → **Security**
2. Under "How you sign in to Google", click **2-Step Verification** and ensure it is on
3. Go back to Security, search for **App passwords** (or go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords))
4. Select **Mail** and **Other (custom name)**, enter `LogLeak`, click **Generate**
5. Copy the 16-character password (shown once — save it)

```bash
logleak watch /var/log/app.log \
  --smtp-host smtp.gmail.com \
  --smtp-port 587 \
  --smtp-user your.address@gmail.com \
  --smtp-password "abcd efgh ijkl mnop" \
  --smtp-to security@yourcompany.com
```

> The App Password can contain spaces — that is normal. Pass it as a quoted string.

**Environment variable approach (safer for scripts):**

```bash
export SMTP_PASS="abcd efgh ijkl mnop"
logleak watch /var/log/app.log \
  --smtp-host smtp.gmail.com \
  --smtp-user your.address@gmail.com \
  --smtp-password "$SMTP_PASS" \
  --smtp-to security@yourcompany.com
```

---

### 6.2 SendGrid

SendGrid is the recommended provider for production because it has better deliverability, rate limits, and a free tier (100 emails/day).

**Steps:**
1. Create a [SendGrid account](https://sendgrid.com)
2. Go to **Settings → API Keys → Create API Key**
3. Choose **Restricted Access**, grant **Mail Send** only
4. Copy the key (starts with `SG.`)
5. Go to **Settings → Sender Authentication** and verify your from domain or a single sender email address

```bash
logleak watch /var/log/app.log \
  --smtp-host smtp.sendgrid.net \
  --smtp-port 587 \
  --smtp-user apikey \
  --smtp-password "$SENDGRID_API_KEY" \
  --smtp-from alerts@yourcompany.com \
  --smtp-to security@yourcompany.com
```

> The username is literally the string `apikey` for all SendGrid accounts. The actual key goes in `--smtp-password`.

---

### 6.3 AWS SES

**Steps:**
1. Go to **SES Console → Verified identities** and verify your sending domain or address
2. If your account is in SES sandbox, also verify each recipient address (or request production access)
3. Go to **SES Console → SMTP settings** → **Create SMTP credentials** (this creates an IAM user with limited permissions — do not use regular IAM access keys here)
4. Note the SMTP endpoint for your region (e.g. `email-smtp.us-east-1.amazonaws.com`)

```bash
logleak watch /var/log/app.log \
  --smtp-host email-smtp.us-east-1.amazonaws.com \
  --smtp-port 587 \
  --smtp-user AKIAIOSFODNN7EXAMPLE \
  --smtp-password "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  --smtp-from alerts@yourcompany.com \
  --smtp-to security@yourcompany.com
```

> SES SMTP credentials are **different from regular AWS access keys**. Always generate them through the SES console, not IAM.

---

### 6.4 Microsoft 365 / Outlook SMTP

**Steps:**
1. In Microsoft 365 admin, ensure **Authenticated SMTP** (SMTP AUTH) is enabled for the sending account: **Admin Center → Users → Active users → [user] → Mail → Manage email apps → Authenticated SMTP** ✓
2. Use `smtp.office365.com` on port 587

```bash
logleak watch /var/log/app.log \
  --smtp-host smtp.office365.com \
  --smtp-port 587 \
  --smtp-user alerts@yourcompany.onmicrosoft.com \
  --smtp-password "$M365_PASSWORD" \
  --smtp-to security@yourcompany.com
```

> If your organisation enforces Conditional Access or MFA on SMTP, you may need a dedicated service account with those policies exempted, or use an Exchange connector instead.

---

### 6.5 Local / test SMTP (no credentials)

For local development or CI, run a local SMTP server that accepts everything and writes to stdout (no real delivery):

```bash
# Python's built-in debug SMTP server (Python 3.x)
python -m smtpd -n -c DebuggingServer localhost:1025

# or: mailhog (Docker)
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
```

Then point LogLeak at it:

```bash
logleak watch - \
  --smtp-host localhost \
  --smtp-port 1025 \
  --smtp-no-tls \
  --smtp-to dev@localhost
```

`--smtp-no-tls` disables STARTTLS. No credentials are needed. The email is printed to the local server's stdout (DebuggingServer) or viewable at http://localhost:8025 (MailHog).

---

## 7. Deployment manual

### 7.1 Option A — Pipe stdout/stderr

Redirect the application's stdout and stderr through `logleak watch -` using a shell pipe. This requires no changes to application code.

```
Application process
─────────────────────────────────────────────────────────
uvicorn myapp.app:app ...
         │  stdout + stderr (fd 1 + fd 2)
         │  shell: 2>&1 merges stderr into stdout
         ▼
      OS pipe (kernel buffer, ~64 KB)
         │
         ▼
logleak watch - (stdin)
  reads line by line as newlines arrive
  detect() on each line
  breach → console + email
```

**Latency:** the line is processed the moment the newline character arrives in the pipe. The kernel delivers bytes from the pipe buffer to the reader as fast as they are written. Typical end-to-end latency from `logger.info()` to breach alert is under 5 milliseconds.

**Limitation:** source information is unavailable. `pathname` in the `BreachEvent` is the literal string `-` and `lineno` is `0`. The detector still finds PII and fires alerts — you just know it came from the app's log output, not the exact line of code.

**Basic usage:**

```bash
uvicorn myapp.app:app --host 0.0.0.0 --port 8000 2>&1 | \
  logleak watch - \
    --smtp-host smtp.sendgrid.net \
    --smtp-user apikey \
    --smtp-password "$SENDGRID_KEY" \
    --smtp-to security@example.com
```

---

### 7.2 Option B — Tail a log file

Use when the application writes logs to a file via a `FileHandler`, a log rotation daemon, or a sidecar log shipper.

```
Application process                  logleak watch
────────────────────                 ──────────────────────────
logging.FileHandler                  open("/var/log/app/app.log")
  → /var/log/app/app.log             fh.seek(0, 2)   ← go to end
                                     loop:
                                       line = fh.readline()
                                       if line:
                                           detect(line)
                                       else:
                                           sleep(0.2)
```

**Startup behaviour:** `logleak watch` seeks to the end of the file when it opens it. It never replays historical log entries. Only lines written after watch started are scanned.

**Log rotation:** if the file is rotated (renamed and replaced with a new empty file), the file handle becomes stale. `readline()` returns empty string indefinitely on the old inode. For robustness with log rotation, prefer Option C (in-process) or Option A (pipe).

**Usage:**

```bash
logleak watch /var/log/myapp/app.log \
  --poll 0.05 \
  --smtp-host smtp.gmail.com \
  --smtp-user alerts@example.com \
  --smtp-password "$SMTP_PASS" \
  --smtp-to security@example.com
```

---

### 7.3 Option C — In-process handler (recommended)

Integrates `LeakWatchHandler` directly into the application's logging setup. Requires editing one file in the application.

**Step 1 — Edit `logging_config.py`**

Find the function that configures the root logger (typically called `configure_logging()` or `setup_logging()`). Add the highlighted lines:

```python
# logging_config.py
import logging
import os
import sys

from logleak.watch_handler import install_watch_handler
from logleak.notifier import SmtpConfig


def configure_logging() -> None:
    """Configure root logger and attach LogLeak live breach monitor."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # ── Your existing handler setup ─────────────────────────────────────────
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s  %(message)s")
        )
        root.addHandler(handler)
    # ────────────────────────────────────────────────────────────────────────

    # ── LogLeak live watch ───────────────────────────────────────────────────
    smtp_host = os.getenv("LOGLEAK_SMTP_HOST")
    if smtp_host:
        install_watch_handler(
            smtp=SmtpConfig(
                host=smtp_host,
                port=int(os.getenv("LOGLEAK_SMTP_PORT", "587")),
                use_tls=os.getenv("LOGLEAK_SMTP_TLS", "true").lower() != "false",
                username=os.getenv("LOGLEAK_SMTP_USER", ""),
                password=os.getenv("LOGLEAK_SMTP_PASS", ""),
                to_addrs=[
                    a.strip()
                    for a in os.getenv("LOGLEAK_ALERT_TO", "").split(",")
                    if a.strip()
                ],
            ),
            app_name=os.getenv("LOGLEAK_APP_NAME", "MyApp"),
            email_cooldown=float(os.getenv("LOGLEAK_COOLDOWN", "300")),
        )
    else:
        # No SMTP configured — console-only alerts (good for local dev)
        install_watch_handler()
    # ────────────────────────────────────────────────────────────────────────
```

**Step 2 — Set environment variables**

Never hardcode SMTP credentials in source code. Use your platform's secrets manager, a `.env` file (not committed), or environment variables injected at deploy time.

```bash
# .env — chmod 600, in .gitignore
LOGLEAK_SMTP_HOST=smtp.sendgrid.net
LOGLEAK_SMTP_PORT=587
LOGLEAK_SMTP_TLS=true
LOGLEAK_SMTP_USER=apikey
LOGLEAK_SMTP_PASS=SG.xxxxxxxxxxxxxxxxxxxxxxxx
LOGLEAK_ALERT_TO=security@example.com,oncall@example.com
LOGLEAK_APP_NAME=MyApp Production
LOGLEAK_COOLDOWN=300
```

**Step 3 — Verify**

Start the application and emit a test log line containing a canary value:

```python
import logging
logging.getLogger("test").info(
    "card: 4242424242424242"   # canary card number
)
```

You should immediately see in stderr:

```
[LOGLEAK BREACH] CRITICAL card (confirmed)
  masked : ************4242
  line   : card: ************4242
  source : test_script.py:2
```

And within a few seconds an email should arrive at your configured recipient.

---

### 7.4 Platform recipes

#### systemd

Two approaches: embed the pipe in the app unit, or run watch as a companion unit.

**Embedded pipe (Option A, single unit):**

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=MyApp with LogLeak Watch
After=network.target

[Service]
User=appuser
WorkingDirectory=/opt/myapp
EnvironmentFile=/opt/myapp/.env
ExecStart=/bin/bash -c \
  'exec /opt/myapp/.venv/bin/uvicorn myapp.app:app \
        --host 0.0.0.0 --port 8000 2>&1 | \
   exec /opt/myapp/.venv/bin/logleak watch - \
        --smtp-host ${LOGLEAK_SMTP_HOST} \
        --smtp-user ${LOGLEAK_SMTP_USER} \
        --smtp-password ${LOGLEAK_SMTP_PASS} \
        --smtp-to ${LOGLEAK_ALERT_TO}'
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Companion unit (Option B, separate unit that restarts with the app):**

```ini
# /etc/systemd/system/logleak-watch.service
[Unit]
Description=LogLeak live breach monitor
After=myapp.service
BindsTo=myapp.service   # stops automatically when myapp stops

[Service]
User=appuser
EnvironmentFile=/opt/myapp/.env
ExecStart=/opt/myapp/.venv/bin/logleak watch /var/log/myapp/app.log \
  --smtp-host ${LOGLEAK_SMTP_HOST} \
  --smtp-user ${LOGLEAK_SMTP_USER} \
  --smtp-password ${LOGLEAK_SMTP_PASS} \
  --smtp-to ${LOGLEAK_ALERT_TO} \
  --smtp-app-name "MyApp Production"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable logleak-watch
sudo systemctl start logleak-watch
sudo systemctl status logleak-watch
```

---

#### Docker / docker-compose

**Option A — pipe inside the container:**

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt logleak
COPY . .
CMD ["/bin/sh", "-c", \
     "uvicorn myapp.app:app --host 0.0.0.0 --port 8000 2>&1 | \
      logleak watch - \
        --smtp-host ${LOGLEAK_SMTP_HOST} \
        --smtp-user ${LOGLEAK_SMTP_USER} \
        --smtp-password ${LOGLEAK_SMTP_PASS} \
        --smtp-to ${LOGLEAK_ALERT_TO}"]
```

```yaml
# docker-compose.yml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env          # contains LOGLEAK_SMTP_* vars
```

**Option C — in-process via environment variables (preferred):**

```dockerfile
# Dockerfile — no change to CMD, just install logleak
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt logleak
COPY . .
CMD ["uvicorn", "myapp.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.yml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      LOGLEAK_SMTP_HOST: smtp.sendgrid.net
      LOGLEAK_SMTP_USER: apikey
      LOGLEAK_SMTP_PASS: ${SENDGRID_KEY}      # from host env or .env file
      LOGLEAK_ALERT_TO: security@example.com
      LOGLEAK_APP_NAME: MyApp Production
```

The `logging_config.py` reads these at startup and installs the watch handler — no changes to the Dockerfile or CMD needed.

---

#### Heroku / Railway / Render

These platforms inject environment variables and capture stdout/stderr automatically. Option C (in-process) works without any Procfile changes. Option A works by wrapping the command.

**Option C — set env vars in the dashboard:**

```bash
# heroku
heroku config:set \
  LOGLEAK_SMTP_HOST=smtp.sendgrid.net \
  LOGLEAK_SMTP_USER=apikey \
  LOGLEAK_SMTP_PASS="$SENDGRID_KEY" \
  LOGLEAK_ALERT_TO=security@example.com \
  LOGLEAK_APP_NAME="MyApp (Heroku)"

# railway / render — set in the platform dashboard under Environment Variables
```

No Procfile change needed when Option C is wired into `logging_config.py`.

**Option A — Procfile pipe:**

```
# Procfile
web: uvicorn myapp.app:app --host 0.0.0.0 --port $PORT 2>&1 | \
     logleak watch - \
       --smtp-host $LOGLEAK_SMTP_HOST \
       --smtp-user $LOGLEAK_SMTP_USER \
       --smtp-password $LOGLEAK_SMTP_PASS \
       --smtp-to $LOGLEAK_ALERT_TO
```

---

#### Kubernetes sidecar

The sidecar pattern runs `logleak watch` as a second container in the same pod, sharing a log volume with the main container.

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:

      # ── Main application container ─────────────────────────────────────────
      - name: app
        image: myapp:latest
        ports:
          - containerPort: 8000
        env:
          - name: LOG_FILE
            value: /var/log/app/app.log
        volumeMounts:
          - name: logs
            mountPath: /var/log/app

      # ── LogLeak sidecar ────────────────────────────────────────────────────
      - name: logleak-watch
        image: python:3.11-slim
        command:
          - sh
          - -c
          - |
            pip install logleak --quiet
            exec logleak watch /var/log/app/app.log \
              --smtp-host "$(LOGLEAK_SMTP_HOST)" \
              --smtp-user "$(LOGLEAK_SMTP_USER)" \
              --smtp-password "$(LOGLEAK_SMTP_PASS)" \
              --smtp-to "$(LOGLEAK_ALERT_TO)" \
              --smtp-app-name "$(LOGLEAK_APP_NAME)"
        env:
          - name: LOGLEAK_SMTP_HOST
            valueFrom:
              secretKeyRef:
                name: logleak-secrets
                key: smtp-host
          - name: LOGLEAK_SMTP_USER
            valueFrom:
              secretKeyRef:
                name: logleak-secrets
                key: smtp-user
          - name: LOGLEAK_SMTP_PASS
            valueFrom:
              secretKeyRef:
                name: logleak-secrets
                key: smtp-pass
          - name: LOGLEAK_ALERT_TO
            valueFrom:
              secretKeyRef:
                name: logleak-secrets
                key: alert-to
          - name: LOGLEAK_APP_NAME
            value: "MyApp (k8s)"
        volumeMounts:
          - name: logs
            mountPath: /var/log/app

      volumes:
        - name: logs
          emptyDir: {}
```

**Create the secret:**

```bash
kubectl create secret generic logleak-secrets \
  --from-literal=smtp-host=smtp.sendgrid.net \
  --from-literal=smtp-user=apikey \
  --from-literal=smtp-pass="$SENDGRID_KEY" \
  --from-literal=alert-to=security@example.com
```

> For production Kubernetes deployments, prefer Option C (in-process) — it avoids the shared volume and the `pip install` in the sidecar init. The sidecar pattern is shown here for completeness.

---

#### GitHub Actions

Use `logleak watch` as a background process during integration tests to catch any canary leaks in the staging smoke test run.

```yaml
# .github/workflows/integration.yml
name: Integration tests with leak detection

on: [push, pull_request]

jobs:
  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -e ".[dev]" logleak

      - name: Start app + LogLeak watch
        run: |
          uvicorn myapp.app:app --host 127.0.0.1 --port 8000 \
            > /tmp/app.log 2>&1 &
          echo $! > /tmp/app.pid

          logleak watch /tmp/app.log \
            --canaries-only \
            --smtp-host ${{ secrets.SMTP_HOST }} \
            --smtp-user ${{ secrets.SMTP_USER }} \
            --smtp-password ${{ secrets.SMTP_PASS }} \
            --smtp-to ${{ secrets.SECURITY_EMAIL }} \
            > /tmp/watch.log 2>&1 &
          echo $! > /tmp/watch.pid

          sleep 3   # wait for app to start

      - name: Run smoke tests
        run: pytest tests/smoke/ -v

      - name: Stop app and watch
        if: always()
        run: |
          kill $(cat /tmp/app.pid) 2>/dev/null || true
          WATCH_EXIT=$(kill $(cat /tmp/watch.pid) 2>/dev/null; echo $?)
          cat /tmp/watch.log   # print any breach alerts to CI log

      - name: Check for breaches
        if: always()
        run: |
          # logleak watch exits 1 if any breach was detected
          if grep -q "BREACH" /tmp/watch.log; then
            echo "::error::LogLeak detected PII in logs during integration test"
            exit 1
          fi
```

---

## 8. Custom callbacks — Slack, PagerDuty, webhooks

`install_watch_handler(on_breach=...)` accepts any callable with signature `(BreachEvent) -> None`. This replaces the default console alert. To keep both console and a custom callback, call the default manually:

```python
from logleak.watch_handler import install_watch_handler, BreachEvent, _default_on_breach
import requests

def slack_on_breach(event: BreachEvent) -> None:
    """Fire a console alert AND post to Slack."""
    _default_on_breach(event)   # keep the console output
    try:
        requests.post(
            "https://hooks.slack.com/services/T.../B.../xxx",
            json={
                "text": (
                    f":rotating_light: *PII BREACH* — {event.severity.upper()} "
                    f"`{event.kind}` ({event.confidence})\n"
                    f"*Value:* `{event.masked_value}`\n"
                    f"*Source:* `{event.pathname}:{event.lineno}`\n"
                    f"*Message:* `{event.masked_line}`"
                ),
            },
            timeout=5,
        )
    except Exception:
        pass   # never crash the app

install_watch_handler(on_breach=slack_on_breach)
```

**PagerDuty Events API v2:**

```python
import requests
from logleak.watch_handler import install_watch_handler, BreachEvent

def pagerduty_on_breach(event: BreachEvent) -> None:
    try:
        requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json={
                "routing_key": "your-integration-key",
                "event_action": "trigger",
                "payload": {
                    "summary": (
                        f"PII breach: {event.kind} ({event.severity}) "
                        f"in {event.pathname}:{event.lineno}"
                    ),
                    "severity": "critical" if event.severity == "critical" else "warning",
                    "source": event.pathname,
                    "custom_details": event.to_dict(),
                },
            },
            timeout=5,
        )
    except Exception:
        pass

install_watch_handler(on_breach=pagerduty_on_breach)
```

**Combine email + Slack + PagerDuty:**

```python
from logleak.watch_handler import install_watch_handler, BreachEvent
from logleak.notifier import EmailNotifier, SmtpConfig

email = EmailNotifier(SmtpConfig(host=..., to_addrs=[...]))

def all_channels(event: BreachEvent) -> None:
    email(event)             # HTML email with cooldown
    slack_on_breach(event)   # Slack (define as above)
    if event.severity == "critical":
        pagerduty_on_breach(event)   # PagerDuty only for critical

install_watch_handler(on_breach=all_channels)
```

---

## 9. Security and privacy guarantees

These are enforced in code, not just documentation.

| Guarantee | Where enforced |
|---|---|
| Raw PII value is never stored | `LeakWatchHandler.emit()` — `mask()` is called immediately; the raw `f.value` is only on the call stack and is not stored in `BreachEvent` |
| `BreachEvent` contains only masked fields | `BreachEvent` dataclass has no `raw_value` field; `masked_value` and `masked_line` are set from `mask()` and `redact_text()` outputs |
| Email contains no raw PII | `build_breach_email()` receives a `BreachEvent` — it cannot access raw values even if it wanted to |
| Handler never drops or modifies records | `emit()` is `try/except`; returns without raising; does not modify `record` in any way |
| Handler never crashes the application | `emit()` calls `self.handleError(record)` on exception, which prints a warning and returns |
| SMTP failures are non-fatal | All `smtplib` calls are wrapped in `except Exception` with a warning print |
| Cooldown dict never contains PII | Keys are `"pathname:lineno:kind"` — no values, no messages |
| Thread safety | `EmailNotifier._lock` (threading.Lock) guards the cooldown dict for multi-threaded WSGI/ASGI servers |

**What LogLeak watch does NOT do:**

- It does not modify the log record — `RedactionFilter` does that, and it is a separate opt-in
- It does not write to disk
- It does not send data to any external service other than the configured SMTP server
- It does not transmit anything to LogLeak, IBM, or any third party
- It does not require network access except to reach the configured SMTP host

---

## 10. CLI reference

```
logleak watch <log> [options]

Positional arguments:
  log                   Path to the log file to tail, or '-' to read stdin.
                        Examples:
                          logleak watch /var/log/app/app.log
                          uvicorn myapp:app 2>&1 | logleak watch -

General options:
  --canaries-only       Only alert on confirmed canary matches. Suppresses
                        suspected pattern findings. Useful in production
                        environments with noisy logs.
  --poll SECONDS        How often to check for new lines when tailing a file.
                        Default: 0.2 (200 ms). Minimum useful value: 0.01.
                        Has no effect when reading stdin.

Email alert options:
  All email options are optional. Email is disabled unless --smtp-host is set.
  --smtp-host HOST      SMTP server hostname.
                        Examples: smtp.gmail.com, smtp.sendgrid.net,
                                  email-smtp.us-east-1.amazonaws.com
  --smtp-port PORT      SMTP port. Default: 587.
                        Use 465 for implicit TLS (rare); 587 for STARTTLS.
                        Use 25 for unauthenticated local relays.
  --smtp-no-tls         Disable STARTTLS. Not recommended for remote servers.
                        Required for local test SMTP servers on port 25/1025.
  --smtp-user USER      SMTP authentication username.
                        For SendGrid: use the literal string "apikey".
  --smtp-password PASS  SMTP authentication password or app password.
                        Always pass via environment variable in scripts.
  --smtp-from ADDR      The From: address shown in the email.
                        Defaults to --smtp-user when not set.
  --smtp-to ADDR        Recipient address. Repeat the flag for multiple:
                          --smtp-to a@example.com --smtp-to b@example.com
  --smtp-app-name NAME  Name shown in the email subject line.
                        Default: "LogLeak"
                        Example: "CareDesk Production"
  --smtp-cooldown SECS  Minimum seconds between repeat emails for the same
                        file:line:kind location. Default: 300 (5 minutes).
                        Set to 0 to disable deduplication (not recommended).

Exit codes:
  0   Stopped cleanly (Ctrl-C) with no breaches detected.
  1   At least one breach was detected, or the log path does not exist.

Notes:
  - When reading stdin (-), logleak watch processes each line as it arrives.
    There is no buffering delay beyond the pipe buffer.
  - When tailing a file, logleak watch seeks to the end of the file on
    startup. It does not process lines written before it started.
  - Console alerts always fire on every breach. Email alerts are subject to
    the cooldown window per location.
  - logleak watch can be safely killed with SIGINT (Ctrl-C) or SIGTERM.
    It prints a summary line on exit.
```

---

## 11. Environment variable reference

When using Option C (in-process handler) with the `logging_config.py` pattern shown in §7.3, these environment variables control all behaviour. No environment variables are read directly by `LeakWatchHandler` or `EmailNotifier` — they are read in the integration code you write.

| Variable | Type | Default | Description |
|---|---|---|---|
| `LOGLEAK_SMTP_HOST` | string | — | SMTP server hostname. If unset, no email is sent and console-only mode is used. |
| `LOGLEAK_SMTP_PORT` | integer | `587` | SMTP port. |
| `LOGLEAK_SMTP_TLS` | `"true"` / `"false"` | `"true"` | Whether to use STARTTLS. Set to `"false"` for local test servers. |
| `LOGLEAK_SMTP_USER` | string | `""` | SMTP username. |
| `LOGLEAK_SMTP_PASS` | string | `""` | SMTP password. Always use a secrets manager or env injection — never commit this. |
| `LOGLEAK_ALERT_TO` | comma-separated string | `""` | Recipient addresses. Example: `"a@example.com,b@example.com"` |
| `LOGLEAK_APP_NAME` | string | `"MyApp"` | Name shown in the email subject. |
| `LOGLEAK_COOLDOWN` | float | `300` | Cooldown in seconds between repeat emails per location. |

---

## 12. Troubleshooting

**No console alert appears when a canary value is logged.**

1. Confirm `install_watch_handler()` is called before any log records are emitted. If it is called after the first record, it is installed but those first records are already past.
2. Check `canaries_only` — if `True`, only `confidence == "confirmed"` findings fire. The canary value must be one of the 7 values in `logleak/canaries.py`.
3. Add a test log line explicitly:
   ```python
   import logging
   logging.getLogger("test").critical("4242424242424242")
   ```
4. Confirm the handler is installed: `logging.getLogger().handlers` should contain a `LeakWatchHandler`.

---

**Email is not received.**

1. Check stderr for `[LogLeak] WARNING: could not send breach email: ...` — this means the SMTP call failed. The error message contains the SMTP exception.
2. Common causes:
   - Wrong host or port
   - Firewall blocking outbound port 587 from the server
   - Gmail: app password not enabled, or 2FA not active on the account
   - SendGrid: sender identity not verified, or account in sandbox mode
   - AWS SES: account still in sandbox (recipients must be verified), or wrong region endpoint
3. Test SMTP connectivity independently:
   ```python
   import smtplib
   with smtplib.SMTP("smtp.sendgrid.net", 587, timeout=10) as s:
       s.ehlo(); s.starttls(); s.ehlo()
       s.login("apikey", "SG.xxx")
       print("SMTP OK")
   ```
4. Check spam folder — automated breach alert emails may trigger spam filters. Adding the from address to contacts resolves this.

---

**Email is sent once but then stops for the same breach location.**

This is the cooldown deduplication working as designed. The same `file:line:kind` combination will not send another email until `email_cooldown` seconds have elapsed. Default: 300 seconds (5 minutes).

To check: the console alert fires on **every** hit regardless of cooldown. If you see console alerts but no email, cooldown is active.

To change the window: pass `--smtp-cooldown 60` (CLI) or `email_cooldown=60.0` (programmatic).

---

**Suspected findings are too noisy.**

Use `--canaries-only` (CLI) or `canaries_only=True` (programmatic) to suppress pattern-matched findings and only alert on exact canary value matches.

Alternatively, review the `suspected` findings to determine if they are real data or benign sequences that happen to match a pattern (e.g. a long order ID that passes Luhn). If they are false positives, open an issue — the detector may need a more specific rule.

---

**The application slows down when a breach is detected.**

The SMTP call in `EmailNotifier._send()` is synchronous and blocks the thread that emitted the log record for up to 15 seconds (the SMTP timeout). This is acceptable when breaches are rare (as they should be), but if a hot log path is leaking continuously, each hit blocks the thread.

Solutions:
1. Fix the leak — that is what LogLeak is for.
2. Increase `email_cooldown` so the SMTP call fires at most once per window per location. The console alert is non-blocking and fires on every hit.
3. Replace the email callback with an async queue that sends in a background thread:
   ```python
   import queue, threading
   from logleak.notifier import EmailNotifier, SmtpConfig

   _email_queue: queue.Queue = queue.Queue()
   _notifier = EmailNotifier(SmtpConfig(...))

   def _worker():
       while True:
           event = _email_queue.get()
           _notifier(event)
           _email_queue.task_done()

   threading.Thread(target=_worker, daemon=True).start()

   def async_email(event):
       _email_queue.put_nowait(event)

   install_watch_handler(on_breach=async_email)
   ```

---

**`logleak watch` is not found after `pip install logleak`.**

The `logleak` console script is registered in [`pyproject.toml`](../pyproject.toml) under `[project.scripts]`. Ensure the package was installed (not just the source copied) and that the virtual environment's `bin/` or `Scripts/` directory is on `PATH`:

```bash
pip install -e .          # installs and registers the entry point
which logleak             # should resolve to .venv/bin/logleak
logleak watch --help
```

On Windows: `.venv\Scripts\logleak.exe`.
