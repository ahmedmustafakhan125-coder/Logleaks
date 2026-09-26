"""Spec: logleak.capture, logleak.tracer, logleak.sitemap — know exactly where a leak came from."""
from __future__ import annotations

import inspect
import json
import logging
from pathlib import Path

from logleak.capture import CapturedRecord, LeakCaptureHandler, capture_stdout
from logleak.sitemap import find_log_sites, unwitnessed
from logleak.tracer import trace

THIS_FILE = Path(__file__).resolve()


def _line_after() -> int:
    """Line number of the statement right after the caller's call to this helper."""
    return inspect.currentframe().f_back.f_lineno + 1


# ---------------------------------------------------------------- capture

def test_handler_records_formatted_message_and_source(isolated_logger, canaries):
    handler = LeakCaptureHandler()
    isolated_logger.addHandler(handler)

    line = _line_after()
    isolated_logger.debug("Charging card %s for %s", canaries["card"], 3500)

    assert len(handler.records) == 1
    rec = handler.records[0]
    assert isinstance(rec, CapturedRecord)
    assert rec.message == f"Charging card {canaries['card']} for 3500"
    assert Path(rec.pathname).resolve() == THIS_FILE
    assert rec.lineno == line
    assert rec.func_name == "test_handler_records_formatted_message_and_source"
    assert rec.level == "DEBUG"
    assert rec.sink == "log"


def test_handler_captures_exception_text(isolated_logger, canaries):
    handler = LeakCaptureHandler()
    isolated_logger.addHandler(handler)
    try:
        raise ValueError(f"Card declined: {canaries['card']}")
    except ValueError:
        line = _line_after()
        isolated_logger.exception("payment failed")

    rec = handler.records[0]
    assert rec.sink == "exception"
    assert rec.lineno == line
    assert canaries["card"] in rec.exc_text


def test_capture_stdout_records_print_with_caller_line(canaries):
    with capture_stdout() as records:
        line = _line_after()
        print(f"issued token {canaries['jwt']}")

    assert len(records) == 1
    rec = records[0]
    assert rec.sink == "stdout"
    assert canaries["jwt"] in rec.message
    assert Path(rec.pathname).resolve() == THIS_FILE
    assert rec.lineno == line


def test_record_roundtrips_through_json():
    rec = CapturedRecord(
        logger="caredesk", level="INFO", message="hello", pathname="/x/app.py",
        lineno=3, func_name="f", exc_text=None, sink="log",
    )
    restored = CapturedRecord.from_dict(json.loads(json.dumps(rec.to_dict())))
    assert restored == rec


# ---------------------------------------------------------------- tracer

def _rec(message: str, line: int = 10, sink: str = "log", path: str = "/proj/app/pay.py",
         exc_text: str | None = None, logger: str = "caredesk.pay") -> CapturedRecord:
    return CapturedRecord(logger=logger, level="INFO", message=message, pathname=path,
                          lineno=line, func_name="charge", exc_text=exc_text, sink=sink)


def test_trace_groups_hits_on_same_line(canaries, canary_values):
    recs = [_rec(f"card {canaries['card']}"), _rec(f"card {canaries['card']}")]
    leaks = trace(recs, canaries=canary_values)
    assert len(leaks) == 1
    assert leaks[0].hits == 2
    assert leaks[0].kind == "card"
    assert leaks[0].severity == "critical"
    assert leaks[0].confidence == "confirmed"


def test_trace_splits_kinds_on_same_line(canaries, canary_values):
    recs = [_rec(f"{canaries['email']} {canaries['phone']}")]
    leaks = trace(recs, canaries=canary_values)
    assert sorted(l.kind for l in leaks) == ["email", "phone"]


def test_trace_sample_is_masked(canaries, canary_values):
    leaks = trace([_rec(f"card {canaries['card']}")], canaries=canary_values)
    assert canaries["card"] not in leaks[0].sample
    assert "4242" in leaks[0].sample


def test_trace_scans_exception_text(canaries, canary_values):
    rec = _rec("payment failed", sink="exception",
               exc_text=f"ValueError: Card declined: {canaries['card']}")
    leaks = trace([rec], canaries=canary_values)
    assert [l.kind for l in leaks] == ["card"]
    assert leaks[0].sink == "exception"
    assert canaries["card"] not in leaks[0].sample


def test_trace_makes_paths_relative_to_root(canaries, canary_values):
    leaks = trace([_rec(f"x {canaries['email']}")], canaries=canary_values, root=Path("/proj"))
    assert leaks[0].file == "app/pay.py"
    assert leaks[0].line == 10


def test_fingerprint_is_stable_and_short(canaries, canary_values):
    a = trace([_rec(f"x {canaries['email']}")], canaries=canary_values)[0]
    b = trace([_rec(f"y {canaries['email']}")], canaries=canary_values)[0]
    assert a.fingerprint == b.fingerprint
    assert len(a.fingerprint) == 12


def test_clean_records_produce_no_leaks(canary_values):
    recs = [_rec("order ORD-4111111111111112 created"), _rec("appointment APT-77 booked")]
    assert trace(recs, canaries=canary_values) == []


# ---------------------------------------------------------------- sitemap

SAMPLE_SOURCE = '''\
import logging
logger = logging.getLogger(__name__)
log = logging.getLogger("x")

def f(obj, d, self_logger):
    logger.info("a")
    logging.warning("b")
    log.debug("c")
    print("d")
    obj.info("not a log call")
    d.get("not a log call")
    try:
        pass
    except Exception:
        logger.exception("e")
    self_logger.error("f")
'''


def test_find_log_sites(tmp_path):
    (tmp_path / "mod.py").write_text(SAMPLE_SOURCE)
    sites = find_log_sites(tmp_path)
    lines = sorted(s.line for s in sites)
    assert lines == [6, 7, 8, 9, 15, 16]
    assert all(s.file == "mod.py" for s in sites)


def test_unwitnessed_sites(tmp_path):
    (tmp_path / "mod.py").write_text(SAMPLE_SOURCE)
    sites = find_log_sites(tmp_path)
    executed = {("mod.py", 6), ("mod.py", 9)}
    missing = sorted(s.line for s in unwitnessed(sites, executed))
    assert missing == [7, 8, 15, 16]
