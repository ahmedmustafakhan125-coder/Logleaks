"""verify.py — the 6-check verification gate."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from logleak.report import Report


@dataclass
class GateResult:
    """Result of running the verification gate."""

    passed: bool
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to a plain dict."""
        return {
            "passed": self.passed,
            "checks": self.checks,
            "reasons": self.reasons,
        }


def run_gate(
    before: "Report",
    after: "Report",
    *,
    allowlist_tokens: list[str],
    probe_masked: bool,
    min_site_retention: float = 0.9,
) -> GateResult:
    """Evaluate the 6-check gate between a before and after report."""
    checks: dict[str, bool] = {}
    reasons: list[str] = []

    # G1: No confirmed leaks remaining
    confirmed_leaks = [l for l in after.leaks if l.confidence == "confirmed"]
    g1 = len(confirmed_leaks) == 0
    checks["no_confirmed_leaks"] = g1
    if not g1:
        for leak in confirmed_leaks:
            reasons.append(f"Confirmed {leak.kind} leak remains at {leak.file}:{leak.line}")

    # G2: No critical suspected leaks remaining
    critical_suspected = [
        l for l in after.leaks
        if l.confidence == "suspected" and l.severity == "critical"
    ]
    g2 = len(critical_suspected) == 0
    checks["no_critical_suspected"] = g2
    if not g2:
        for leak in critical_suspected:
            reasons.append(f"Suspected critical {leak.kind} leak remains at {leak.file}:{leak.line}")

    # G3: App tests pass
    g3 = after.tests_exit_code == 0
    checks["tests_pass"] = g3
    if not g3:
        reasons.append(f"App tests failed with exit code {after.tests_exit_code}")

    # G4: No over-redaction — allowlisted tokens still appear in logs
    missing_tokens = [t for t in allowlist_tokens if t not in after.log_text_masked]
    g4 = len(missing_tokens) == 0
    checks["no_over_redaction"] = g4
    if not g4:
        for token in missing_tokens:
            reasons.append(f"Allowlisted token '{token}' missing from after-logs (over-redacted?)")

    # G5: Log sites retained at >= min_site_retention
    # Only count app-owned sites (exclude third-party / stdlib paths) so that
    # raising a library's log level (a legitimate PII fix) doesn't penalise
    # the retention score.
    _is_third_party = lambda p: (  # noqa: E731
        "site-packages" in str(p)
        or "dist-packages" in str(p)
        or "\\Lib\\" in str(p)
        or "/lib/python" in str(p)
    )
    before_app = {s for s in before.executed_sites if not _is_third_party(s[0])}
    after_app  = {s for s in after.executed_sites  if not _is_third_party(s[0])}
    before_count = len(before_app)
    after_count  = len(after_app)
    if before_count == 0:
        g5 = (after_count == 0)
    else:
        g5 = (after_count / before_count) >= min_site_retention
    checks["logs_retained"] = g5
    if not g5:
        pct = (after_count / before_count * 100) if before_count else 0
        reasons.append(
            f"Log site retention {after_count}/{before_count} ({pct:.0f}%) "
            f"is below {min_site_retention * 100:.0f}%"
        )

    # G6: Safety net filter is in place
    g6 = probe_masked
    checks["safety_net"] = g6
    if not g6:
        reasons.append("Safety net (RedactionFilter) not detected in app's logging config")

    passed = all(checks.values())
    return GateResult(passed=passed, checks=checks, reasons=reasons)
