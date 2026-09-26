"""report.py — Report model and JSON/Markdown export."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from logleak.tracer import Leak


def _leak_from_dict(d: dict) -> "Leak":
    """Reconstruct a Leak dataclass from a plain dict (as produced by dataclasses.asdict)."""
    from logleak.tracer import Leak
    return Leak(
        fingerprint=d["fingerprint"],
        kind=d["kind"],
        severity=d["severity"],
        confidence=d["confidence"],
        file=d["file"],
        line=d["line"],
        function=d["function"],
        logger=d["logger"],
        sink=d["sink"],
        hits=d["hits"],
        sample=d["sample"],
    )


@dataclass
class Report:
    """Aggregated result of a LogLeak scan run."""

    target: str
    leaks: list["Leak"] = field(default_factory=list)
    executed_sites: set[tuple[str, int]] = field(default_factory=set)
    total_sites: int = 0
    log_text_masked: str = ""
    tests_exit_code: int = 0

    def to_json(self) -> str:
        """Serialise the report to a JSON string (all values already masked)."""
        import dataclasses

        def _default(obj):
            if isinstance(obj, set):
                return sorted(obj)
            raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")

        data = {
            "target": self.target,
            "leaks": [dataclasses.asdict(l) for l in self.leaks],
            "executed_sites": sorted(self.executed_sites),
            "total_sites": self.total_sites,
            "log_text_masked": self.log_text_masked,
            "tests_exit_code": self.tests_exit_code,
        }
        return json.dumps(data, default=_default, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Report":
        """Deserialise a Report from a JSON string produced by to_json()."""
        data = json.loads(text)
        leaks = [_leak_from_dict(d) for d in data.get("leaks", [])]
        executed_sites: set[tuple[str, int]] = {
            (pair[0], pair[1]) for pair in data.get("executed_sites", [])
        }
        return cls(
            target=data["target"],
            leaks=leaks,
            executed_sites=executed_sites,
            total_sites=data.get("total_sites", 0),
            log_text_masked=data.get("log_text_masked", ""),
            tests_exit_code=data.get("tests_exit_code", 0),
        )

    def to_markdown(self, code_root: Path) -> str:
        """Produce a masked leak report in Markdown for the Bob prompt attachment."""
        lines = ["# LogLeak Report\n"]
        lines.append(f"**Target:** `{self.target}`  \n")
        lines.append(f"**Leaks:** {len(self.leaks)}  \n")
        lines.append(f"**Executed sites:** {len(self.executed_sites)} / {self.total_sites}  \n\n")
        for leak in self.leaks:
            lines.append(f"## [{leak.fingerprint}] {leak.kind} — {leak.severity} ({leak.confidence})\n")
            lines.append(f"- **File:** `{leak.file}:{leak.line}` in `{leak.function}`\n")
            lines.append(f"- **Sink:** {leak.sink}  \n")
            lines.append(f"- **Hits:** {leak.hits}  \n")
            lines.append(f"- **Sample:** `{leak.sample}`\n\n")
            # ±5 lines of source context
            src_file = code_root / leak.file
            if src_file.exists():
                src_lines = src_file.read_text(errors="replace").splitlines()
                start = max(0, leak.line - 6)
                end = min(len(src_lines), leak.line + 4)
                lines.append("```python\n")
                for i, src_line in enumerate(src_lines[start:end], start=start + 1):
                    marker = ">>>" if i == leak.line else "   "
                    lines.append(f"{marker} {i:4d} | {src_line}\n")
                lines.append("```\n\n")
        return "".join(lines)
