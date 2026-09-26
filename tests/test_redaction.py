"""Spec: logleak.redact — mask personal data while keeping logs useful."""
from __future__ import annotations

import io
import logging

import pytest

from logleak.redact import RedactionFilter, mask, redact_text


# ---------------------------------------------------------------- mask()

def test_mask_email_keeps_first_char_and_domain():
    assert mask("email", "canary.patient@logleak.test") == "c***@logleak.test"


def test_mask_card_keeps_last4_only():
    assert mask("card", "4242424242424242") == "************4242"


def test_mask_phone_keeps_prefix_and_last3():
    assert mask("phone", "+923001234567") == "+92*******567"


def test_mask_cnic_fully():
    assert mask("cnic", "35202-1234567-9") == "[REDACTED:cnic]"


def test_mask_iban_keeps_country_and_check_digits():
    value = "GB82WEST12345698765432"
    masked = mask("iban", value)
    assert masked.startswith("GB82")
    assert len(masked) == len(value)
    assert set(masked[4:]) == {"*"}


@pytest.mark.parametrize("kind", ["jwt", "secret"])
def test_mask_tokens_fully(kind):
    assert mask(kind, "anything-at-all") == f"[REDACTED:{kind}]"


# ---------------------------------------------------------------- redact_text()

def test_redact_text_removes_every_canary(canary_values):
    text = " | ".join(canary_values)
    out = redact_text(text)
    for value in canary_values:
        assert value not in out


def test_redact_text_keeps_non_pii_intact():
    text = "order ORD-1001 for appointment APT-77 took 182ms"
    assert redact_text(text) == text


def test_redact_text_is_idempotent(canary_values):
    once = redact_text(" ".join(canary_values))
    assert redact_text(once) == once


# ---------------------------------------------------------------- RedactionFilter

def _attach(logger: logging.Logger) -> io.StringIO:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)
    return stream


def test_filter_masks_percent_args(isolated_logger, canaries):
    stream = _attach(isolated_logger)
    isolated_logger.info("Charging card %s for %s", canaries["card"], 3500)
    out = stream.getvalue()
    assert canaries["card"] not in out
    assert "************4242" in out
    assert "3500" in out


def test_filter_masks_fstring_message(isolated_logger, canaries):
    stream = _attach(isolated_logger)
    isolated_logger.warning(f"SMS to {canaries['phone']} failed, retrying")
    out = stream.getvalue()
    assert canaries["phone"] not in out
    assert "retrying" in out


def test_filter_masks_exception_tracebacks(isolated_logger, canaries):
    stream = _attach(isolated_logger)
    try:
        raise ValueError(f"Card declined: {canaries['card']}")
    except ValueError:
        isolated_logger.exception("payment failed")
    out = stream.getvalue()
    assert "Traceback" in out
    assert "payment failed" in out
    assert canaries["card"] not in out


def test_filter_never_drops_records(isolated_logger, canaries):
    stream = _attach(isolated_logger)
    isolated_logger.info("one %s", canaries["email"])
    isolated_logger.info("two")
    isolated_logger.info("three %s", canaries["cnic"])
    assert len(stream.getvalue().strip().splitlines()) == 3


def test_filter_returns_true():
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "hello", None, None)
    assert RedactionFilter().filter(record) is True


def test_filter_protects_third_party_logger_via_handler(canaries):
    """The safety net lives on the handler, so it also covers loggers we don't own."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactionFilter())
    lib_logger = logging.getLogger("httpx.test_third_party")
    lib_logger.setLevel(logging.INFO)
    lib_logger.propagate = False
    lib_logger.addHandler(handler)
    try:
        lib_logger.info('HTTP Request: GET https://verify.example/check?email=%s "200 OK"',
                        canaries["email"])
    finally:
        lib_logger.removeHandler(handler)
    assert canaries["email"] not in stream.getvalue()
    assert "HTTP Request" in stream.getvalue()
