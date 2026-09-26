"""patients.py — patient registration and lookup."""
from __future__ import annotations

import logging

from caredesk.models import Patient

logger = logging.getLogger(__name__)

# In-memory store keyed by patient_id
_patients: dict[str, Patient] = {}
_counter = 1000


def register_patient(name: str, email: str, phone: str, cnic: str) -> Patient:
    """Register a new patient and return the created record."""
    global _counter
    _counter += 1
    patient_id = f"PT-{_counter}"
    patient = Patient(
        patient_id=patient_id,
        name=name,
        email=email,
        phone=phone,
        cnic=cnic,
    )
    _patients[patient_id] = patient
    logger.info("Registered patient %s", patient_id)
    return patient


def get_patient(patient_id: str) -> Patient | None:
    """Return the patient with the given ID, or None."""
    patient = _patients.get(patient_id)
    if patient is None:
        # Unwitnessed log path: only reached when a patient is not found
        logger.warning("Patient %s not found", patient_id)
    return patient


def list_patients() -> list[Patient]:
    """Return all registered patients."""
    logger.debug("Listing %d patients", len(_patients))
    return list(_patients.values())
