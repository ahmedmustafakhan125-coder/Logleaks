"""models.py — CareDesk data models.

NOTE: Patient uses the DEFAULT dataclass __repr__, which dumps all fields including
email, phone, and CNIC.  This is intentional — it is Leak L1.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Patient:
    """A registered clinic patient.

    WARNING: default __repr__ exposes PII — see Leak L1.
    """

    patient_id: str    # PT-XXXX
    name: str
    email: str
    phone: str
    cnic: str


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
