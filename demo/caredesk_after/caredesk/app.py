"""app.py — CareDesk FastAPI application."""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from caredesk.logging_config import configure_logging
from caredesk.middleware import log_request_body

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Create and configure the CareDesk FastAPI application."""
    configure_logging()

    app = FastAPI(title="CareDesk", description="Clinic booking and payments API")

    # L4 middleware: logs every request body
    app.add_middleware(BaseHTTPMiddleware, dispatch=log_request_body)
    app.add_middleware(CORSMiddleware, allow_origins=["*"])

    _register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class PatientIn(BaseModel):
    name: str
    email: str
    phone: str
    cnic: str


class AppointmentIn(BaseModel):
    patient_id: str
    doctor: str
    date: str
    reason: str
    phone: str


class PaymentIn(BaseModel):
    patient_id: str
    card_number: str
    expiry: str
    cvv: str
    amount: int
    description: str


class LoginIn(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def _register_routes(app: FastAPI) -> None:
    from caredesk import patients, appointments, payments, auth, verification
    from caredesk.models import PaymentCard

    @app.get("/health")
    def health():
        """Health check endpoint."""
        return {"status": "ok"}

    # --- Patients ---

    @app.post("/patients", status_code=201)
    def create_patient(body: PatientIn):
        """Register a new patient (triggers L1 and L7 leaks)."""
        # L7: verification.verify_email logs ?email= via httpx
        verification.verify_email(body.email)
        patient = patients.register_patient(
            name=body.name,
            email=body.email,
            phone=body.phone,
            cnic=body.cnic,
        )
        return {"patient_id": patient.patient_id, "name": patient.name}

    @app.get("/patients/{patient_id}")
    def get_patient(patient_id: str):
        """Fetch a patient by ID."""
        patient = patients.get_patient(patient_id)
        if patient is None:
            raise HTTPException(status_code=404, detail="Patient not found")
        return {"patient_id": patient.patient_id, "name": patient.name}

    # --- Appointments ---

    @app.post("/appointments", status_code=201)
    def create_appointment(body: AppointmentIn):
        """Book an appointment (triggers L6 if SMS fails)."""
        appt = appointments.book_appointment(
            patient_id=body.patient_id,
            doctor=body.doctor,
            date=body.date,
            reason=body.reason,
            phone=body.phone,
        )
        return {"appointment_id": appt.appointment_id}

    @app.delete("/appointments/{apt_id}")
    def cancel_appointment(apt_id: str):
        """Cancel an appointment."""
        ok = appointments.cancel_appointment(apt_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Appointment not found")
        return {"cancelled": apt_id}

    # --- Payments ---

    @app.post("/payments", status_code=201)
    def make_payment(body: PaymentIn):
        """Process a card payment (triggers L2 and possibly L3)."""
        card = PaymentCard(
            card_number=body.card_number,
            expiry=body.expiry,
            cvv=body.cvv,
        )
        try:
            order = payments.charge_card(
                patient_id=body.patient_id,
                card=card,
                amount=body.amount,
                description=body.description,
            )
        except ValueError as exc:
            raise HTTPException(status_code=402, detail=str(exc)) from exc
        return {
            "order_id": order.order_id,
            "amount": order.amount,
            "description": order.description,
        }

    # --- Auth ---

    @app.post("/auth/login")
    def login(body: LoginIn):
        """Issue an access token (triggers L5 debug print)."""
        if body.password == "":
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = auth.issue_token(body.username)
        return {"access_token": token, "token_type": "bearer"}

    @app.get("/auth/verify")
    def verify_token(authorization: Annotated[str | None, Header()] = None):
        """Verify a bearer token."""
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing token")
        token = authorization.split(" ", 1)[1]
        if not auth.verify_token(token):
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"valid": True}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

app = create_app()
