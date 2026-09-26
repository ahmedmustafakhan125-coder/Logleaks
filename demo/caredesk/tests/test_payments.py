"""tests/test_payments.py — payment flow including L2, L3, and decoy checks."""
from __future__ import annotations


def _register(client, canary):
    resp = client.post("/patients", json={
        "name": "Paying Patient",
        "email": canary["email"],
        "phone": canary["phone"],
        "cnic": canary["cnic"],
    })
    return resp.json()["patient_id"]


def test_successful_payment(client, canary):
    """Normal card payment — triggers L2 (logger.debug with card number)."""
    patient_id = _register(client, canary)
    resp = client.post("/payments", json={
        "patient_id": patient_id,
        "card_number": canary["card"],
        "expiry": "12/28",
        "cvv": "123",
        "amount": 5000,
        "description": "Consultation fee",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["order_id"].startswith("ORD-")
    assert data["amount"] == 5000


def test_declined_card_returns_402(client, canary):
    """Declined card — triggers L3 (ValueError with canary card, then logger.exception)."""
    patient_id = _register(client, canary)
    resp = client.post("/payments", json={
        "patient_id": patient_id,
        "card_number": canary["card"],  # canary card + cvv "000" -> simulated decline
        "expiry": "12/28",
        "cvv": "000",
        "amount": 1000,
        "description": "Declined payment",
    })
    assert resp.status_code == 402


def test_decoy_order_id_format(client, canary):
    """Order IDs use ORD- prefix; the decoy ORD-4111111111111112 should not be flagged."""
    patient_id = _register(client, canary)
    # Create a real order
    resp = client.post("/payments", json={
        "patient_id": patient_id,
        "card_number": canary["card"],
        "expiry": "12/28",
        "cvv": "123",
        "amount": 3500,
        "description": "ORD-4111111111111112 reference decoy",
    })
    assert resp.status_code == 201
    # The order_id assigned by the system is sequential, not the Luhn-failing one.
    assert resp.json()["order_id"].startswith("ORD-")
