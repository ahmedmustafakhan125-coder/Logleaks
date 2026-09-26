"""Spec: logleak.verify — the 6-check gate. Clean logs that are still useful, or it fails."""
from __future__ import annotations

import json

import pytest

from logleak.verify import GateResult, run_gate

ALLOW = ["PT-", "APT-", "ORD-"]
USEFUL_LOGS = "Registered patient PT-1042\nBooked APT-77\nOrder ORD-1001 paid"
SITES_BEFORE = {("app/a.py", n) for n in range(1, 21)}  # 20 executed log sites


@pytest.fixture
def before(make_report, make_leak):
    return make_report(
        [make_leak("card"), make_leak("email", severity="high", line=20)],
        executed_sites=SITES_BEFORE,
        log_text_masked=USEFUL_LOGS,
    )


@pytest.fixture
def clean_after(make_report):
    return make_report([], executed_sites=SITES_BEFORE, log_text_masked=USEFUL_LOGS)


def gate(before, after, probe_masked=True) -> GateResult:
    return run_gate(before, after, allowlist_tokens=ALLOW, probe_masked=probe_masked)


EXPECTED_CHECKS = {
    "no_confirmed_leaks",
    "no_critical_suspected",
    "tests_pass",
    "no_over_redaction",
    "logs_retained",
    "safety_net",
}


def test_clean_fix_passes(before, clean_after):
    result = gate(before, clean_after)
    assert result.passed is True
    assert set(result.checks) == EXPECTED_CHECKS
    assert all(result.checks.values())
    assert result.reasons == []


def test_remaining_confirmed_leak_fails(before, make_report, make_leak):
    after = make_report([make_leak("email", severity="high")],
                        executed_sites=SITES_BEFORE, log_text_masked=USEFUL_LOGS)
    result = gate(before, after)
    assert result.passed is False
    assert result.checks["no_confirmed_leaks"] is False
    assert any("email" in r for r in result.reasons)


def test_critical_suspected_fails_but_high_suspected_passes(before, make_report, make_leak):
    crit = make_report([make_leak("iban", confidence="suspected")],
                       executed_sites=SITES_BEFORE, log_text_masked=USEFUL_LOGS)
    assert gate(before, crit).checks["no_critical_suspected"] is False

    high = make_report([make_leak("email", severity="high", confidence="suspected")],
                       executed_sites=SITES_BEFORE, log_text_masked=USEFUL_LOGS)
    assert gate(before, high).checks["no_critical_suspected"] is True


def test_broken_app_tests_fail_gate(before, make_report):
    after = make_report([], executed_sites=SITES_BEFORE, log_text_masked=USEFUL_LOGS,
                        tests_exit_code=1)
    result = gate(before, after)
    assert result.passed is False
    assert result.checks["tests_pass"] is False


def test_over_redaction_fails_gate(before, make_report):
    """Bob masked the order IDs too. Logs are no longer useful."""
    after = make_report([], executed_sites=SITES_BEFORE,
                        log_text_masked="Registered patient [REDACTED]\nBooked [REDACTED]")
    result = gate(before, after)
    assert result.passed is False
    assert result.checks["no_over_redaction"] is False
    assert any("ORD-" in r or "PT-" in r or "APT-" in r for r in result.reasons)


def test_deleting_log_lines_fails_gate(before, make_report):
    """Bob 'fixed' leaks by deleting half the log statements."""
    after = make_report([], executed_sites=set(list(SITES_BEFORE)[:10]),
                        log_text_masked=USEFUL_LOGS)
    result = gate(before, after)
    assert result.passed is False
    assert result.checks["logs_retained"] is False


def test_retention_threshold_is_90_percent(before, make_report):
    kept_18 = set(sorted(SITES_BEFORE)[:18])  # exactly 90%
    after = make_report([], executed_sites=kept_18, log_text_masked=USEFUL_LOGS)
    assert gate(before, after).checks["logs_retained"] is True

    kept_17 = set(sorted(SITES_BEFORE)[:17])  # 85%
    after = make_report([], executed_sites=kept_17, log_text_masked=USEFUL_LOGS)
    assert gate(before, after).checks["logs_retained"] is False


def test_missing_safety_net_fails_gate(before, clean_after):
    result = gate(before, clean_after, probe_masked=False)
    assert result.passed is False
    assert result.checks["safety_net"] is False


def test_gate_result_serializes(before, clean_after):
    data = json.loads(json.dumps(gate(before, clean_after).to_dict()))
    assert data["passed"] is True
    assert set(data["checks"]) == EXPECTED_CHECKS
