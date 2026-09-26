"""appointments.py — appointment booking and management."""
from __future__ import annotations

import logging

from caredesk.models import Appointment
from caredesk.notifications import send_appointment_reminder

logger = logging.getLogger(__name__)

_appointments: dict[str, Appointment] = {}
_counter = 10


def book_appointment(
    patient_id: str,
    doctor: str,
    date: str,
    reason: str,
    phone: str,
) -> Appointment:
    """Book a new appointment and send an SMS reminder."""
    global _counter
    _counter += 1
    apt_id = f"APT-{_counter}"
    appt = Appointment(
        appointment_id=apt_id,
        patient_id=patient_id,
        doctor=doctor,
        date=date,
        reason=reason,
    )
    _appointments[apt_id] = appt
    logger.info(
        "Appointment %s booked for patient %s with Dr %s on %s",
        apt_id, patient_id, doctor, date,
    )
    send_appointment_reminder(phone, apt_id, date)
    return appt


def cancel_appointment(apt_id: str) -> bool:
    """Cancel an appointment. Returns True on success."""
    if apt_id not in _appointments:
        logger.warning("Cancellation failed: appointment %s not found", apt_id)
        return False
    del _appointments[apt_id]
    logger.info("Appointment %s cancelled", apt_id)
    return True


def get_appointment(apt_id: str) -> Appointment | None:
    """Return the appointment with the given ID, or None."""
    return _appointments.get(apt_id)
