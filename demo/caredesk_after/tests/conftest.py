"""conftest.py — pytest fixtures for CareDesk tests.

The `canary` fixture is provided by the logleak pytest plugin (auto-loaded
because logleak is installed). The `client` fixture creates a fresh
FastAPI TestClient for the session.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client() -> TestClient:
    """A FastAPI TestClient for the CareDesk app (fresh app per session)."""
    from caredesk.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)
