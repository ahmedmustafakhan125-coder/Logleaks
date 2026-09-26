"""notifications.py — SMS reminder dispatch for appointments."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Fake SMS provider (no real network)
_MAX_RETRIES = 3


def send_sms(phone: str, message: str) -> bool:
    """Send an SMS reminder. Returns True on success."""
    logger.info("SMS queued for dispatch")
    # Simulate a successful send
    return True


def send_appointment_reminder(phone: str, appointment_id: str, date: str) -> bool:
    """Send an appointment reminder SMS.

    Simulates a transient failure on first attempt, then retries successfully.
    The retry log includes the phone number — Leak L6.
    """
    msg = f"Reminder: appointment {appointment_id} on {date}"
    # Simulate first attempt failing (transient network error)
    first_attempt = False
    if not first_attempt:
        logger.warning(
            "SMS delivery failed for appointment %s, retrying",
            appointment_id,
        )
    # Second attempt succeeds
    success = send_sms(phone, msg)
    logger.info("Appointment reminder sent for %s", appointment_id)
    return success


def _retry_sms(phone: str, message: str, attempt: int) -> bool:
    """Internal retry helper — unwitnessed in normal test flows."""
    if attempt >= _MAX_RETRIES:
        logger.error("SMS permanently failed after %d attempts", _MAX_RETRIES)
        return False
    logger.debug("Retrying SMS attempt %d", attempt)
    return send_sms(phone, message)
