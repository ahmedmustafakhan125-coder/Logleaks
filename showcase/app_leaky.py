"""app_leaky.py — Tiny clinic API with 4 deliberate PII leaks.

This file is the BEFORE state. Run LogLeak against it to find all four leaks,
then compare with app_clean.py to see the fixes.
"""
from __future__ import annotations

import base64
import logging
import sys
import time
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Logging setup — stdout only, DEBUG so every log line is visible
# ---------------------------------------------------------------------------

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
)
logger = logging.getLogger("clinic")

# ---------------------------------------------------------------------------
# Tiny in-memory store
# ---------------------------------------------------------------------------

_patients: dict[str, dict] = {}   # patient_id -> {name, email, phone}
_orders:   dict[str, dict] = {}   # order_id   -> {patient_id, amount}
_pat_seq   = 0
_ord_seq   = 0

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class PatientIn(BaseModel):
    name:  str
    email: str
    phone: str


class PaymentIn(BaseModel):
    patient_id:  str
    card_number: str
    cvv:         str
    amount:      int


class LoginIn(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Business logic helpers (where the leaks live)
# ---------------------------------------------------------------------------

def register_patient(name: str, email: str, phone: str) -> dict:
    """Register a new patient and return their record."""
    global _pat_seq
    _pat_seq += 1
    pid = f"P-{_pat_seq:04d}"
    _patients[pid] = {"name": name, "email": email, "phone": phone}

    # ❌ LEAK L1 — email logged directly at INFO
    logger.info("Registered patient %s with email %s and phone %s", pid, email, phone)

    return {"patient_id": pid, "name": name}


def charge_card(patient_id: str, card_number: str, cvv: str, amount: int) -> dict:
    """Charge a card and return the order."""
    global _ord_seq

    # ❌ LEAK L2 — full card number logged at DEBUG
    logger.debug("Charging card %s for patient %s, amount %s", card_number, patient_id, amount)

    if cvv == "000":
        # ❌ LEAK L3 — card number embedded in the exception message
        raise ValueError(f"Card declined: {card_number}")

    _ord_seq += 1
    oid = f"ORD-{_ord_seq:04d}"
    _orders[oid] = {"patient_id": patient_id, "amount": amount}
    logger.info("Order %s created for patient %s: %s paise", oid, patient_id, amount)
    return {"order_id": oid, "amount": amount}


def issue_token(username: str) -> str:
    """Issue a minimal JWT-like token for a staff user."""
    header  = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        f'{{"sub":"{username}","iat":{int(time.time())}}}'.encode()
    ).rstrip(b"=").decode()
    sig   = base64.urlsafe_b64encode(b"demo-sig").rstrip(b"=").decode()
    token = f"{header}.{payload}.{sig}"

    # ❌ LEAK L4 — forgotten debug print exposes the full JWT to stdout
    print(f"[debug] issued token {token}")

    logger.info("Token issued for user %s", username)
    return token


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="Clinic API (LEAKY)", description="Before — 4 PII leaks planted")


@app.get("/health")
def health():
    """Health check."""
    return {"status": "ok"}


@app.post("/patients", status_code=201)
def create_patient(body: PatientIn):
    """Register a patient — triggers L1."""
    return register_patient(body.name, body.email, body.phone)


@app.post("/payments", status_code=201)
def make_payment(body: PaymentIn):
    """Charge a card — triggers L2 and L3 on decline."""
    try:
        return charge_card(body.patient_id, body.card_number, body.cvv, body.amount)
    except ValueError as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc


@app.post("/auth/login")
def login(body: LoginIn):
    """Issue a token — triggers L4."""
    if not body.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = issue_token(body.username)
    return {"access_token": token, "token_type": "bearer"}
