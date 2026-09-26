"""tests/test_auth.py — token issuance and verification (L5 lives here)."""
from __future__ import annotations


def test_login_issues_token(client):
    """Login triggers L5: print(f"issued token {token}") goes to stdout."""
    resp = client.post("/auth/login", json={"username": "staff01", "password": "secret"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    token = data["access_token"]
    # Token has the expected JWT structure (3 base64url segments)
    assert len(token.split(".")) == 3


def test_login_empty_password_rejected(client):
    resp = client.post("/auth/login", json={"username": "staff01", "password": ""})
    assert resp.status_code == 401


def test_verify_valid_token(client):
    r = client.post("/auth/login", json={"username": "staff01", "password": "pw"})
    token = r.json()["access_token"]
    resp = client.get("/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"valid": True}


def test_verify_missing_token(client):
    resp = client.get("/auth/verify")
    assert resp.status_code == 401
