"""capture.py — LeakCaptureHandler and stdout capture (stub)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CapturedRecord:
    """A single captured log record or stdout line."""

    logger: str
    level: str
    message: str
    pathname: str
    lineno: int
    func_name: str
    exc_text: str | None
    sink: str  # log | exception | stdout

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSONL storage."""
        return {
            "logger": self.logger,
            "level": self.level,
            "message": self.message,
            "pathname": self.pathname,
            "lineno": self.lineno,
            "func_name": self.func_name,
            "exc_text": self.exc_text,
            "sink": self.sink,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CapturedRecord":
        """Deserialise from a plain dict."""
        return cls(
            logger=d["logger"],
            level=d["level"],
            message=d["message"],
            pathname=d["pathname"],
            lineno=d["lineno"],
            func_name=d["func_name"],
            exc_text=d.get("exc_text"),
            sink=d["sink"],
        )


import logging
import sys
import inspect
from contextlib import contextmanager


class LeakCaptureHandler(logging.Handler):
    """A logging handler that captures records as CapturedRecord objects."""

    def __init__(self) -> None:
        """Initialise with an empty records list."""
        super().__init__()
        self.records: list[CapturedRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Store a CapturedRecord for each emitted log record."""
        message = record.getMessage()
        exc_text: str | None = None
        sink = "log"
        if record.exc_info:
            exc_text = logging.Formatter().formatException(record.exc_info)
            sink = "exception"
        self.records.append(CapturedRecord(
            logger=record.name,
            level=record.levelname,
            message=message,
            pathname=record.pathname,
            lineno=record.lineno,
            func_name=record.funcName,
            exc_text=exc_text,
            sink=sink,
        ))


class _StdoutTee:
    """Replaces sys.stdout during capture_stdout; records print() calls."""

    def __init__(self, original, records: list[CapturedRecord]) -> None:
        """Initialise with the original stdout and the target records list."""
        self._orig = original
        self._records = records
        self._buf = ""

    def write(self, text: str) -> int:
        """Write to original stdout and buffer text for record creation."""
        self._orig.write(text)
        self._buf += text
        if "\n" in self._buf:
            parts = self._buf.split("\n")
            for part in parts[:-1]:
                if part:
                    frame = self._caller_frame()
                    self._records.append(CapturedRecord(
                        logger="",
                        level="",
                        message=part,
                        pathname=frame.f_code.co_filename,
                        lineno=frame.f_lineno,
                        func_name=frame.f_code.co_name,
                        exc_text=None,
                        sink="stdout",
                    ))
            self._buf = parts[-1]
        return len(text)

    def _caller_frame(self):
        """Return the first stack frame outside the logleak package."""
        logleak_path = __file__
        for info in inspect.stack():
            filename = info.filename
            if filename != logleak_path and "logleak" not in filename.replace("\\", "/").split("/")[-2:-1]:
                return info.frame
        return inspect.stack()[-1].frame

    def flush(self) -> None:
        """Flush the original stdout."""
        self._orig.flush()

    def __getattr__(self, name: str):
        """Delegate unknown attribute access to the original stdout."""
        return getattr(self._orig, name)


@contextmanager
def capture_stdout():
    """Context manager that captures print() output as CapturedRecord objects."""
    records: list[CapturedRecord] = []
    original = sys.stdout
    sys.stdout = _StdoutTee(original, records)
    try:
        yield records
    finally:
        sys.stdout = original
