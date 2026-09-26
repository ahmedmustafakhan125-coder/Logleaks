"""Spec: logleak.mcp_tools — what Bob sees through MCP. Rule #1: never a raw value."""
from __future__ import annotations

import json

import pytest

from logleak import mcp_tools


def _dump(obj) -> str:
    return json.dumps(obj, default=str)


@pytest.fixture
def target(tmp_path, canaries):
    """A tiny target app whose source contains a leaking log line."""
    app = tmp_path / "app"
    app.mkdir()
    (app / "pay.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "\n"
        "def charge(card, amount):\n"
        "    logger.debug('Charging card %s for %s', card, amount)\n"
        "    return True\n"
    )
    return tmp_path


@pytest.fixture
def loaded(target, make_report, make_leak):
    leak = make_leak("card", file="app/pay.py", line=5, sample="Charging card ************4242 for 3500")
    third_party = make_leak("email", severity="high", file="site-packages/httpx/_client.py",
                            line=1013, logger="httpx", sample="HTTP Request: GET ...?email=c***@logleak.test")
    report = make_report([leak, third_party], target=str(target), total_sites=2,
                         executed_sites={("app/pay.py", 5)})
    mcp_tools.set_current_report(report)
    return report


# ---------------------------------------------------------------- sanitize

def test_sanitize_walks_nested_structures(canaries, canary_values):
    raw = {"a": [canaries["card"], {"b": (canaries["email"], 7)}], "c": canaries["jwt"], "n": 3}
    out = _dump(mcp_tools.sanitize(raw))
    for value in canary_values:
        assert value not in out
    assert '"n": 3' in out


# ---------------------------------------------------------------- tools

def test_list_leaks_returns_all_and_filters_by_severity(loaded):
    assert len(mcp_tools.list_leaks()) == 2
    critical = mcp_tools.list_leaks("critical")
    assert [l["kind"] for l in critical] == ["card"]


def test_list_leaks_entries_have_required_fields(loaded):
    required = {"fingerprint", "kind", "severity", "confidence", "file", "line", "sink", "hits", "sample"}
    for entry in mcp_tools.list_leaks():
        assert required <= set(entry)


def test_get_leak_context_returns_code_and_strategy(loaded):
    fp = next(l["fingerprint"] for l in mcp_tools.list_leaks() if l["kind"] == "card")
    ctx = mcp_tools.get_leak_context(fp)
    assert ctx["owner"] == "app"
    assert "logger.debug('Charging card %s for %s', card, amount)" in ctx["code"]
    assert ctx["line"] == 5
    assert ctx["strategy"]  # non-empty recommendation


def test_third_party_leak_is_marked_for_filter(loaded):
    fp = next(l["fingerprint"] for l in mcp_tools.list_leaks() if l["kind"] == "email")
    ctx = mcp_tools.get_leak_context(fp)
    assert ctx["owner"] == "third_party"
    assert "filter" in ctx["strategy"].lower()


def test_unknown_fingerprint_gives_clear_error(loaded):
    with pytest.raises(KeyError):
        mcp_tools.get_leak_context("doesnotexist")


def test_no_tool_output_contains_raw_canaries(loaded, canary_values):
    outputs = [mcp_tools.list_leaks(), mcp_tools.list_leaks("critical")]
    outputs += [mcp_tools.get_leak_context(l["fingerprint"]) for l in mcp_tools.list_leaks()]
    blob = _dump(outputs)
    for value in canary_values:
        assert value not in blob
