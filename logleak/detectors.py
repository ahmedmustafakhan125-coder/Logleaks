"""detectors.py — detect PII kinds in text with precision over recall."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

SEVERITY: dict[str, str] = {
    "card":   "critical",
    "cnic":   "critical",
    "iban":   "critical",
    "jwt":    "critical",
    "secret": "critical",
    "email":  "high",
    "phone":  "high",
}

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """A single PII span found in text."""

    kind: str        # email | card | cnic | phone | iban | jwt | secret
    value: str       # raw matched text (never leaves the engine unmasked)
    start: int       # byte offset in the source text
    end: int
    confidence: str  # "confirmed" | "suspected"


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def luhn_valid(digits: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    s = digits.replace(" ", "").replace("-", "")
    if not s.isdigit():
        return False
    total = 0
    reverse = s[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_valid(iban: str) -> bool:
    """Return True if the IBAN string passes the ISO 13616 mod-97 check."""
    iban = iban.replace(" ", "").upper()
    if len(iban) < 5:
        return False
    # Move first 4 chars to the end
    rearranged = iban[4:] + iban[:4]
    # Replace letters with digits: A=10, B=11, …
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    return int(numeric) % 97 == 1


def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits per character) of the string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Per-kind matchers
# Each matcher returns a list of (start, end, value) tuples.
# ---------------------------------------------------------------------------

# Email: RFC-lite
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Card: 13–19 digits, optional single spaces or dashes between groups.
# Must NOT be preceded or followed by a word character (letter, digit, _).
_CARD_RE = re.compile(r"(?<!\w)(\d[\d \-]{11,17}\d)(?!\w)")

# CNIC: dashed form DDDDD-DDDDDDD-D (always accepted)
_CNIC_DASHED_RE = re.compile(r"\d{5}-\d{7}-\d")
# CNIC: plain 13 digits (only when keyword "cnic" nearby)
_CNIC_PLAIN_RE = re.compile(r"(?<!\d)\d{13}(?!\d)")

# Phone: Pakistani mobile or E.164
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(\+92|0092|0)3\d{2}[- ]?\d{7}"
    r"|"
    r"\+\d{10,15}"
    r"(?!\d)"
)

# IBAN: 2-letter country, 2 check digits, 11-30 alphanumeric
_IBAN_RE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}")

# JWT: three base64url segments, first two start with eyJ
_JWT_RE = re.compile(r"eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+")

# Secrets: keyword = value with high entropy OR any password= value
_SECRET_KW_RE = re.compile(
    r"(?i)(api_key|token|secret|password)\s*[=:]\s*(\S+)"
)


def _match_email(text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group()) for m in _EMAIL_RE.finditer(text)]


def _match_card(text: str) -> list[tuple[int, int, str]]:
    results = []
    for m in _CARD_RE.finditer(text):
        raw = m.group(1)
        digits = raw.replace(" ", "").replace("-", "")
        # Must be 13-19 digits exactly
        if not digits.isdigit() or not (13 <= len(digits) <= 19):
            continue
        # Must pass Luhn
        if not luhn_valid(digits):
            continue
        results.append((m.start(1), m.end(1), raw))
    return results


def _match_cnic(text: str) -> list[tuple[int, int, str]]:
    results = []
    # Dashed form: always accepted
    for m in _CNIC_DASHED_RE.finditer(text):
        results.append((m.start(), m.end(), m.group()))
    # Plain 13-digit form: only when "cnic" keyword nearby
    for m in _CNIC_PLAIN_RE.finditer(text):
        start, end = m.start(), m.end()
        window_start = max(0, start - 20)
        window_end = min(len(text), end + 20)
        window = text[window_start:window_end]
        if re.search(r"(?i)cnic", window):
            results.append((start, end, m.group()))
    return results


def _match_phone(text: str) -> list[tuple[int, int, str]]:
    results = []
    for m in _PHONE_RE.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        # Reject if inside a timestamp (surrounded by colons/hyphens in a date context)
        # Simple guard: must not be preceded by a colon
        before = text[start - 1:start] if start > 0 else ""
        if before == ":":
            continue
        results.append((start, end, val))
    return results


def _match_iban(text: str) -> list[tuple[int, int, str]]:
    results = []
    for m in _IBAN_RE.finditer(text):
        val = m.group()
        if iban_valid(val):
            results.append((m.start(), m.end(), val))
    return results


def _match_jwt(text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group()) for m in _JWT_RE.finditer(text)]


def _match_secret(text: str) -> list[tuple[int, int, str]]:
    results = []
    for m in _SECRET_KW_RE.finditer(text):
        keyword = m.group(1).lower()
        value = m.group(2)
        # password= is always flagged regardless of entropy
        if keyword == "password":
            results.append((m.start(), m.end(), m.group()))
            continue
        # Other keywords: require entropy >= 3.5 and length >= 16
        if len(value) >= 16 and shannon_entropy(value) >= 3.5:
            results.append((m.start(), m.end(), m.group()))
    return results


# Kind priority for overlap resolution (higher index = higher specificity wins)
_KIND_PRIORITY: dict[str, int] = {
    "email":  1,
    "phone":  2,
    "secret": 3,
    "jwt":    4,
    "iban":   5,
    "cnic":   6,
    "card":   7,
}

_MATCHERS = [
    ("email",  _match_email),
    ("card",   _match_card),
    ("cnic",   _match_cnic),
    ("phone",  _match_phone),
    ("iban",   _match_iban),
    ("jwt",    _match_jwt),
    ("secret", _match_secret),
]


# ---------------------------------------------------------------------------
# Main detect() function
# ---------------------------------------------------------------------------


# Map each canary value to its kind (built from CANARIES on first use)
_CANARY_KIND_MAP: dict[str, str] = {}


def _build_canary_kind_map() -> None:
    """Populate _CANARY_KIND_MAP from CANARIES on first call."""
    if _CANARY_KIND_MAP:
        return
    from logleak.canaries import CANARIES
    _CANARY_KIND_MAP.update({v: k for k, v in CANARIES.items()})


def detect(
    text: str,
    canaries: Iterable[str] | None = None,
) -> list[Finding]:
    """Detect PII in text; canary matches are 'confirmed', patterns are 'suspected'."""
    canary_list: list[str] = list(canaries) if canaries is not None else []
    canary_set: set[str] = set(canary_list)

    raw_findings: list[Finding] = []

    # --- Step 1: Exact canary matches (confirmed) ---
    # Find each canary value as a literal substring; determine kind from the
    # CANARIES mapping so that canaries with no pattern (e.g. bare secret value)
    # are still found.
    if canary_set:
        _build_canary_kind_map()
        for value in canary_list:
            kind = _CANARY_KIND_MAP.get(value)
            if kind is None:
                continue  # Unknown canary value, skip
            start = 0
            while True:
                idx = text.find(value, start)
                if idx == -1:
                    break
                raw_findings.append(Finding(
                    kind=kind,
                    value=value,
                    start=idx,
                    end=idx + len(value),
                    confidence="confirmed",
                ))
                start = idx + len(value)

    # --- Step 2: Pattern-based matches (suspected unless already confirmed) ---
    for kind, matcher in _MATCHERS:
        for start, end, value in matcher(text):
            # Skip if this span is already covered by a confirmed canary finding
            already_confirmed = any(
                f.confidence == "confirmed" and f.start == start and f.end == end
                for f in raw_findings
            )
            if already_confirmed:
                continue
            confidence = "confirmed" if value in canary_set else "suspected"
            raw_findings.append(Finding(
                kind=kind,
                value=value,
                start=start,
                end=end,
                confidence=confidence,
            ))

    # Resolve overlapping spans: sort by start, then by priority (desc) to prefer
    # higher-specificity kinds; keep first non-overlapping match at each position.
    raw_findings.sort(key=lambda f: (f.start, -_KIND_PRIORITY.get(f.kind, 0)))

    accepted: list[Finding] = []
    furthest_end = 0
    for f in raw_findings:
        if f.start >= furthest_end:
            accepted.append(f)
            furthest_end = f.end
        else:
            # Overlap: check if the new finding has higher priority than the last accepted
            if accepted and _KIND_PRIORITY.get(f.kind, 0) > _KIND_PRIORITY.get(accepted[-1].kind, 0):
                # Replace last accepted if the new one starts at the same position
                if f.start == accepted[-1].start:
                    accepted[-1] = f
                    furthest_end = f.end

    return accepted
