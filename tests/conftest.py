"""Shared fixtures for the LogLeak spec suite.

These tests were written BEFORE the implementation. They define the public
interfaces described in docs/01-ARCHITECTURE.md. Implement until they pass;
do not edit them to make them pass.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from logleak.canaries import CANARIES, all_canaries
from logleak.report import Report
from logleak.tracer import Leak

REPO_ROOT = Path(__file__).resolve().parents[1]


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: end-to-end tests that run the demo app")


@pytest.fixture
def canaries() -> dict[str, str]:
    return dict(CANARIES)


@pytest.fixture
def canary_values() -> list[str]:
    return all_canaries()


@pytest.fixture
def make_leak():
    def _make(
        kind: str = "card",
        *,
        severity: str = "critical",
        confidence: str = "confirmed",
        file: str = "app/payments.py",
        line: int = 10,
        sink: str = "log",
        hits: int = 1,
        sample: str = "Charging card ************4242",
        logger: str = "caredesk.payments",
        function: str = "charge",
    ) -> Leak:
        return Leak(
            fingerprint=f"{file}:{line}:{kind}"[-12:],
            kind=kind,
            severity=severity,
            confidence=confidence,
            file=file,
            line=line,
            function=function,
            logger=logger,
            sink=sink,
            hits=hits,
            sample=sample,
        )

    return _make


@pytest.fixture
def make_report():
    def _make(
        leaks=None,
        *,
        executed_sites=None,
        total_sites: int = 20,
        log_text_masked: str = "",
        tests_exit_code: int = 0,
        target: str = "demo/caredesk",
    ) -> Report:
        return Report(
            target=target,
            leaks=list(leaks or []),
            executed_sites=set(executed_sites or set()),
            total_sites=total_sites,
            log_text_masked=log_text_masked,
            tests_exit_code=tests_exit_code,
        )

    return _make


@pytest.fixture
def isolated_logger():
    """A fresh logger that does not propagate, cleaned up after the test."""
    logger = logging.getLogger(f"logleak.test.{id(object())}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield logger
    for h in list(logger.handlers):
        logger.removeHandler(h)
    for f in list(logger.filters):
        logger.removeFilter(f)
