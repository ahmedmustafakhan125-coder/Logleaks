"""app_clean.py — Tiny clinic API with all PII leaks removed.

This is the AFTER state produced by LogLeak + Bob.
Compare with app_leaky.py to see what changed and why.
"""
from __future__ import annotations

import base64
import logging
import sys
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Logging setup
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

_patients: dict[str, dict] = {}
_orders:   dict[str, dict] = {}
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
# Business logic helpers (all leaks removed)
# ---------------------------------------------------------------------------

def register_patient(name: str, email: str, phone: str) -> dict:
    """Register a new patient and return their record."""
    global _pat_seq
    _pat_seq += 1
    pid = f"P-{_pat_seq:04d}"
    _patients[pid] = {"name": name, "email": email, "phone": phone}

    # ✅ FIX L1 — log only the patient ID; no email or phone
    logger.info("Registered patient %s", pid)

    return {"patient_id": pid, "name": name}


def charge_card(patient_id: str, card_number: str, cvv: str, amount: int) -> dict:
    """Charge a card and return the order."""
    global _ord_seq

    # ✅ FIX L2 — log only the last 4 digits, not the full card number
    last4 = card_number[-4:]
    logger.debug("Charging card ending %s for patient %s, amount %s", last4, patient_id, amount)

    if cvv == "000":
        # ✅ FIX L3 — exception message uses last4 only, never the full number
        raise ValueError(f"Card declined (ending {last4})")

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

    # ✅ FIX L4 — debug print removed entirely; token is returned, not printed
    logger.info("Token issued for user %s", username)
    return token


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="Clinic API (CLEAN)", description="After — all 4 PII leaks fixed")


@app.get("/health")
def health():
    """Health check."""
    return {"status": "ok"}


@app.post("/patients", status_code=201)
def create_patient(body: PatientIn):
    """Register a patient — L1 is now clean."""
    return register_patient(body.name, body.email, body.phone)


@app.post("/payments", status_code=201)
def make_payment(body: PaymentIn):
    """Charge a card — L2 and L3 are now clean."""
    try:
        return charge_card(body.patient_id, body.card_number, body.cvv, body.amount)
    except ValueError as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc


@app.post("/auth/login")
def login(body: LoginIn):
    """Issue a token — L4 is now clean."""
    if not body.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = issue_token(body.username)
    return {"access_token": token, "token_type": "bearer"}
