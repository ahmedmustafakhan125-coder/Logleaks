"""tests/test_appointments.py — appointment booking flow."""
from __future__ import annotations


def _register(client, canary):
    resp = client.post("/patients", json={
        "name": "Test Patient",
        "email": canary["email"],
        "phone": canary["phone"],
        "cnic": canary["cnic"],
    })
    return resp.json()["patient_id"]


def test_book_appointment(client, canary):
    patient_id = _register(client, canary)
    resp = client.post("/appointments", json={
        "patient_id": patient_id,
        "doctor": "Dr. Ahmed",
        "date": "2026-10-01",
        "reason": "Routine checkup",
        "phone": canary["phone"],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["appointment_id"].startswith("APT-")


def test_cancel_appointment(client, canary):
    patient_id = _register(client, canary)
    r = client.post("/appointments", json={
        "patient_id": patient_id,
        "doctor": "Dr. Ali",
        "date": "2026-10-05",
        "reason": "Follow-up",
        "phone": canary["phone"],
    })
    apt_id = r.json()["appointment_id"]
    resp = client.delete(f"/appointments/{apt_id}")
    assert resp.status_code == 200
    assert resp.json()["cancelled"] == apt_id


def test_cancel_nonexistent_appointment(client):
    resp = client.delete("/appointments/APT-0")
    assert resp.status_code == 404
