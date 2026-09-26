"""tests/test_patients.py — patient registration and lookup."""
from __future__ import annotations


def test_register_patient_returns_id(client, canary):
    resp = client.post("/patients", json={
        "name": "Test User",
        "email": canary["email"],
        "phone": canary["phone"],
        "cnic": canary["cnic"],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["patient_id"].startswith("PT-")
    assert data["name"] == "Test User"


def test_register_patient_id_unique(client, canary):
    r1 = client.post("/patients", json={
        "name": "Alice",
        "email": canary["email"],
        "phone": canary["phone"],
        "cnic": canary["cnic"],
    })
    r2 = client.post("/patients", json={
        "name": "Bob",
        "email": canary["email"],
        "phone": canary["phone"],
        "cnic": canary["cnic"],
    })
    assert r1.json()["patient_id"] != r2.json()["patient_id"]


def test_get_patient_not_found(client):
    resp = client.get("/patients/PT-0000")
    assert resp.status_code == 404


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
