# ── Stage 1: build deps ────────────────────────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /build

# Build context is the repo root; requirements live under showcase/deploy/
COPY showcase/deploy/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy the logleak engine (needed for the detector import in run_demo.py,
# and for the app modules' own imports — only the package itself, no tests)
COPY logleak/ /app/logleak/

# Copy the showcase source files
COPY README.md               /app/README.md
COPY showcase/app_leaky.py   /app/app_leaky.py
COPY showcase/app_clean.py   /app/app_clean.py
COPY showcase/deploy/main.py /app/main.py
COPY showcase/deploy/ui/     /app/ui/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
