"""tracer.py — group CapturedRecords + findings into Leak objects."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class Leak:
    """A confirmed or suspected PII leak traced to an exact source location."""

    fingerprint: str   # sha1(file:line:kind)[:12]
    kind: str          # email | card | cnic | phone | iban | jwt | secret
    severity: str      # critical | high
    confidence: str    # confirmed | suspected
    file: str          # relative to target root (or absolute for third-party)
    line: int
    function: str
    logger: str
    sink: str          # log | exception | stdout
    hits: int
    sample: str        # masked message


def trace(
    records: Iterable,
    canaries: Iterable[str] | None = None,
    root: Path | None = None,
) -> list[Leak]:
    """Detect PII in captured records and group findings into Leak objects."""
    # Deferred import to avoid circular dependency at stub stage.
    from logleak.detectors import detect, SEVERITY
    from logleak.redact import mask

    canary_list = list(canaries) if canaries is not None else None

    # Map (file, line, kind) -> aggregated data
    groups: dict[tuple[str, int, str], dict] = {}

    for rec in records:
        # Determine the file path, making relative when root is given.
        raw_path = rec.pathname
        try:
            file_path = Path(raw_path).relative_to(root).as_posix() if root else raw_path
        except ValueError:
            file_path = raw_path  # outside root (third-party)

        # Detect in message
        for text, sink in [(rec.message, rec.sink),
                           (rec.exc_text, "exception") if rec.exc_text else (None, None)]:
            if text is None:
                continue
            findings = detect(text, canaries=canary_list)
            for f in findings:
                key = (file_path, rec.lineno, f.kind)
                masked_sample = _mask_text(text, findings, mask)
                if key not in groups:
                    groups[key] = {
                        "kind": f.kind,
                        "severity": SEVERITY.get(f.kind, "high"),
                        "confidence": f.confidence,
                        "file": file_path,
                        "line": rec.lineno,
                        "function": rec.func_name,
                        "logger": rec.logger,
                        "sink": sink,
                        "hits": 0,
                        "sample": masked_sample,
                    }
                groups[key]["hits"] += 1
                # Upgrade confidence: confirmed > suspected
                if f.confidence == "confirmed":
                    groups[key]["confidence"] = "confirmed"

    leaks = []
    for (file, line, kind), data in groups.items():
        fp = hashlib.sha1(f"{file}:{line}:{kind}".encode()).hexdigest()[:12]
        leaks.append(Leak(
            fingerprint=fp,
            kind=data["kind"],
            severity=data["severity"],
            confidence=data["confidence"],
            file=data["file"],
            line=data["line"],
            function=data["function"],
            logger=data["logger"],
            sink=data["sink"],
            hits=data["hits"],
            sample=data["sample"],
        ))

    return leaks


def _mask_text(text: str, findings, mask_fn) -> str:
    """Replace all finding spans with their masked equivalents."""
    result = []
    prev = 0
    for f in sorted(findings, key=lambda x: x.start):
        result.append(text[prev:f.start])
        result.append(mask_fn(f.kind, f.value))
        prev = f.end
    result.append(text[prev:])
    return "".join(result)
