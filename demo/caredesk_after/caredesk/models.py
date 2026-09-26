"""models.py — CareDesk data models."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Patient:
    """A registered clinic patient."""

    patient_id: str    # PT-XXXX
    name: str
    email: str = field(repr=False)
    phone: str = field(repr=False)
    cnic: str  = field(repr=False)

    def __repr__(self) -> str:  # noqa: D105
        return f"Patient(patient_id={self.patient_id!r}, name={self.name!r})"


@dataclass
class Appointment:
    """A booked clinic appointment."""

    appointment_id: str   # APT-XX
    patient_id: str
    doctor: str
    date: str
    reason: str


@dataclass
class Order:
    """A payment order for a clinic service."""

    order_id: str     # ORD-XXXX
    patient_id: str
    amount: int       # pence / paisa
    description: str


@dataclass
class PaymentCard:
    """A payment card submitted with an order."""

    card_number: str
    expiry: str
    cvv: str
