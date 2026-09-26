"""Spec: logleak.detectors — find personal data in text, precisely."""
from __future__ import annotations

import pytest

from logleak.detectors import SEVERITY, Finding, detect, iban_valid, luhn_valid, shannon_entropy


def kinds(findings: list[Finding]) -> list[str]:
    return sorted(f.kind for f in findings)


# ---------------------------------------------------------------- validators

@pytest.mark.parametrize(
    "number, expected",
    [
        ("4242424242424242", True),
        ("4111111111111111", True),
        ("5555555555554444", True),
        ("4242424242424241", False),
        ("4111111111111112", False),
    ],
)
def test_luhn_valid(number, expected):
    assert luhn_valid(number) is expected


def test_iban_valid():
    assert iban_valid("GB82WEST12345698765432") is True
    assert iban_valid("GB82WEST12345698765431") is False


def test_entropy_orders_random_above_repetitive():
    assert shannon_entropy("llk_canary_9fQ2xV7pL3mZ8rT1wY6bN4cK") > 3.5
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0


def test_severity_mapping():
    for k in ("card", "cnic", "iban", "jwt", "secret"):
        assert SEVERITY[k] == "critical"
    for k in ("email", "phone"):
        assert SEVERITY[k] == "high"


# ---------------------------------------------------------------- canaries

def test_every_canary_is_detected_as_confirmed(canaries, canary_values):
    for kind, value in canaries.items():
        text = f"something happened with {value} here"
        found = detect(text, canaries=canary_values)
        assert len(found) == 1, (kind, found)
        f = found[0]
        assert f.kind == kind
        assert f.value == value
        assert f.confidence == "confirmed"
        assert text[f.start:f.end] == value


def test_patterns_without_canaries_are_suspected():
    found = detect("contact ali@example.com now")
    assert kinds(found) == ["email"]
    assert found[0].confidence == "suspected"


# ---------------------------------------------------------------- cards

@pytest.mark.parametrize(
    "text",
    [
        "card 4111111111111111 declined",
        "card 4111 1111 1111 1111 declined",
        "card 4111-1111-1111-1111 declined",
    ],
)
def test_card_formats_detected(text):
    assert kinds(detect(text)) == ["card"]


def test_card_failing_luhn_is_ignored():
    assert detect("card 4111111111111112") == []


def test_order_id_decoy_is_not_a_card():
    assert detect("order ORD-4111111111111112 created") == []


def test_long_digit_runs_are_not_cards():
    assert detect("txn 123456789012345678901 settled") == []
    assert detect("ref WEST4111111111111111X") == []


def test_card_inside_json_counted_once():
    body = '{"card": "4242424242424242", "amount": 3500}'
    assert kinds(detect(body)) == ["card"]


# ---------------------------------------------------------------- cnic / phone

def test_cnic_dashed_detected():
    assert kinds(detect("cnic on file 61101-7654321-3")) == ["cnic"]


def test_cnic_plain_digits_needs_keyword():
    assert kinds(detect("CNIC: 6110176543213")) == ["cnic"]
    assert detect("batch 6110176543213 processed") == []


@pytest.mark.parametrize("text", ["+923001234567", "03001234567", "0300-1234567"])
def test_pakistani_mobile_formats(text):
    assert kinds(detect(f"sms to {text} failed")) == ["phone"]


def test_timestamps_and_uuids_are_not_pii():
    line = "2026-09-27 10:02:11,482 req=3f2b8c1e-9a4d-4e7b-bf31-0c9d2e6a1f55 done in 1734ms"
    assert detect(line) == []


# ---------------------------------------------------------------- iban / jwt / secrets

def test_iban_detected_and_invalid_iban_ignored():
    assert kinds(detect("refund to GB82WEST12345698765432")) == ["iban"]
    assert detect("refund to GB82WEST12345698765431") == []


def test_jwt_detected():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123DEF456"
    assert kinds(detect(f"issued token {token}")) == ["jwt"]


def test_high_entropy_secret_after_keyword():
    assert kinds(detect("api_key=llk_canary_9fQ2xV7pL3mZ8rT1wY6bN4cK")) == ["secret"]


def test_low_entropy_token_value_ignored():
    assert detect("token=null") == []


def test_password_value_always_flagged():
    assert kinds(detect("login failed password=hunter2")) == ["secret"]


# ---------------------------------------------------------------- mixed

def test_multiple_kinds_in_one_line(canary_values):
    line = (
        "Patient(email='canary.patient@logleak.test', phone='+923001234567', "
        "cnic='35202-1234567-9')"
    )
    found = detect(line, canaries=canary_values)
    assert kinds(found) == ["cnic", "email", "phone"]
    assert all(f.confidence == "confirmed" for f in found)


def test_findings_do_not_overlap(canary_values):
    line = "cnic 35202-1234567-9 card 4242424242424242 iban GB82WEST12345698765432"
    found = sorted(detect(line, canaries=canary_values), key=lambda f: f.start)
    assert kinds(found) == ["card", "cnic", "iban"]
    for a, b in zip(found, found[1:]):
        assert a.end <= b.start
