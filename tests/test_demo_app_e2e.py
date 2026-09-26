"""Spec: end-to-end on the CareDesk demo app.

Run with:  pytest tests -m e2e
The "after" test only runs once Bob's gate-passing fix has been committed
to demo/caredesk_after/ (see docs/02-BUILD-PLAN.md, Phase 3).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logleak.canaries import all_canaries
from logleak.scanner import scan_target
from logleak.verify import run_gate

REPO = Path(__file__).resolve().parents[1]
BEFORE_APP = REPO / "demo" / "caredesk"
AFTER_APP = REPO / "demo" / "caredesk_after"
ALLOW = ["PT-", "APT-", "ORD-"]

pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def before_report(tmp_path_factory):
    if not BEFORE_APP.exists():
        pytest.skip("demo/caredesk not built yet")
    return scan_target(BEFORE_APP, tmp_path_factory.mktemp("before"))


def test_demo_app_own_tests_pass(before_report):
    assert before_report.tests_exit_code == 0


def test_all_seven_planted_leaks_found(before_report):
    sites = {(l.file, l.line) for l in before_report.leaks}
    assert len(sites) >= 7


def test_all_expected_data_types_found(before_report):
    kinds = {l.kind for l in before_report.leaks}
    assert {"email", "card", "cnic", "phone", "jwt"} <= kinds


def test_all_three_sinks_covered(before_report):
    sinks = {l.sink for l in before_report.leaks}
    assert {"log", "exception", "stdout"} <= sinks


def test_third_party_leak_found(before_report):
    assert any(l.logger.startswith("httpx") for l in before_report.leaks)


def test_decoys_not_flagged(before_report):
    for leak in before_report.leaks:
        assert "ORD-" not in leak.sample or leak.kind != "card"


def test_report_is_masked(before_report):
    blob = before_report.to_json() + before_report.log_text_masked
    for value in all_canaries():
        assert value not in blob


def test_useful_ids_present_before_fix(before_report):
    for token in ALLOW:
        assert token in before_report.log_text_masked


def test_unwitnessed_count_is_reported(before_report):
    assert before_report.total_sites >= len(before_report.executed_sites) > 0


# ---------------------------------------------------------------- after Bob's fix

@pytest.fixture(scope="module")
def after_report(tmp_path_factory):
    if not AFTER_APP.exists():
        pytest.skip("demo/caredesk_after not committed yet (run `logleak fix` first)")
    return scan_target(AFTER_APP, tmp_path_factory.mktemp("after"))


def test_bob_fix_passes_gate(before_report, after_report):
    from logleak.mcp_tools import probe_safety_net  # probes the app's own logging config

    result = run_gate(
        before_report,
        after_report,
        allowlist_tokens=ALLOW,
        probe_masked=probe_safety_net(AFTER_APP),
    )
    assert result.passed, result.reasons


def test_original_demo_app_untouched():
    """Fixes happen in a workspace copy; the pristine app must still leak."""
    if not BEFORE_APP.exists():
        pytest.skip("demo/caredesk not built yet")
    source = "\n".join(p.read_text() for p in BEFORE_APP.rglob("*.py"))
    assert "logger.debug(\"Charging card %s" in source or "logger.debug('Charging card %s" in source
