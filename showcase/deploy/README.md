# LogLeak Showcase — Deploy to Fly.io

A single Docker container that runs both the leaky and clean clinic APIs
side by side, with a live browser UI to send requests and watch PII appear
(or not) in the log stream in real time.

## Architecture

```
                ┌─────────────────────────────────────────┐
Browser ──────▶ │  main.py  :8080                         │
                │   GET /          → browser UI            │
                │   GET /logs/stream → SSE log stream      │
                │   /leaky/*  proxy ──▶  app_leaky :8001   │
                │   /clean/*  proxy ──▶  app_clean :8002   │
                └─────────────────────────────────────────┘
```

Both child servers log to stdout; `main.py` captures every line and fans it
out to every browser tab that has `/logs/stream` open.

---

## Prerequisites

1. [Install flyctl](https://fly.io/docs/hands-on/install-flyctl/)
2. `fly auth login`
3. Docker desktop running locally (for the optional local test)

---

## Quick deploy (from repo root)

```bash
# 1. Create the Fly app (first time only)
#    Change "logleaks-showcase" to any unique name you like.
fly launch \
  --name logleaks-showcase \
  --copy-config \
  --config showcase/deploy/fly.toml \
  --no-deploy \
  --region iad

# 2. Deploy (every time)
fly deploy --config showcase/deploy/fly.toml

# 3. Open in browser
fly open --config showcase/deploy/fly.toml
```

> **Note:** `fly launch` uses the repo root as the Docker build context
> (required so the Dockerfile can COPY both `showcase/` and `logleak/`).

---

## Local test before deploying

```bash
# From repo root
docker build -f showcase/deploy/Dockerfile -t logleaks-showcase .
docker run --rm -p 8080:8080 logleaks-showcase

# Visit http://localhost:8080
```

---

## What to try in the UI

| Endpoint | Panel | What you see in the log |
|---|---|---|
| POST /patients | LEAKY | full email + phone in INFO line |
| POST /patients | CLEAN | only patient ID |
| POST /payments | LEAKY | full 16-digit card in DEBUG line |
| POST /payments | CLEAN | last-4 only |
| POST /payments (decline) | LEAKY | full card in exception message |
| POST /payments (decline) | CLEAN | "ending 4242" only |
| POST /auth/login | LEAKY | full JWT printed to stdout |
| POST /auth/login | CLEAN | nothing printed — token returned only |

PII values in log lines are colour-highlighted in the browser log panel:
- 🟠 email  · 🔴 card  · 🟣 phone  · 🟡 JWT  · 🔴 secret

---

## Update an existing deploy

```bash
fly deploy --config showcase/deploy/fly.toml
```

## Scale to zero (save credits)

The `fly.toml` already sets `auto_stop_machines = true` and
`min_machines_running = 0`, so the machine hibernates when idle and wakes
on the next HTTP request.
