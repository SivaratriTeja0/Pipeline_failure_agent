"""Raw-signal normalization (spec Part E). Raw text is always preserved alongside the signal."""

import re
from dataclasses import dataclass
from enum import Enum


class NormalizedSignal(str, Enum):
    SCHEMA_COLUMN_MISMATCH = "SCHEMA_COLUMN_MISMATCH"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    RESOURCE_MEMORY_FAILURE = "RESOURCE_MEMORY_FAILURE"
    NETWORK_CONNECTIVITY_FAILURE = "NETWORK_CONNECTIVITY_FAILURE"
    TIMEOUT = "TIMEOUT"
    MISSING_OBJECT = "MISSING_OBJECT"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    DQ_GATE_FAILURE = "DQ_GATE_FAILURE"
    UPSTREAM_FAILED = "UPSTREAM_FAILED"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    UNRECOGNIZED = "UNRECOGNIZED"


_PATTERNS: tuple[tuple[NormalizedSignal, re.Pattern[str]], ...] = (
    (
        NormalizedSignal.SCHEMA_COLUMN_MISMATCH,
        re.compile(
            r"column\s+\S*\s*not\s+found|cannot\s+resolve\s+(?:column|'|\")|unresolved\s+column"
            r"|invalid\s+column\s+reference|column\s+not\s+found",
            re.IGNORECASE,
        ),
    ),
    (
        NormalizedSignal.AUTHORIZATION_FAILURE,
        re.compile(r"permission\s+denied|access\s+denied|403\s+forbidden", re.IGNORECASE),
    ),
    (
        NormalizedSignal.RESOURCE_MEMORY_FAILURE,
        re.compile(r"out\s+of\s+memory|\bOOM(?:Killed)?\b|memory\s+limit\s+exceeded", re.IGNORECASE),
    ),
    (
        NormalizedSignal.NETWORK_CONNECTIVITY_FAILURE,
        re.compile(r"connection\s+refused|connection\s+reset|unable\s+to\s+connect", re.IGNORECASE),
    ),
    (NormalizedSignal.TIMEOUT, re.compile(r"\btime[d]?\s?out\b|\btimeout\b", re.IGNORECASE)),
    (
        NormalizedSignal.MISSING_OBJECT,
        re.compile(r"table\s+(?:\S+\s+){0,3}not\s+found|object\s+(?:\S+\s+){0,2}does\s+not\s+exist", re.IGNORECASE),
    ),
    (
        NormalizedSignal.QUOTA_EXCEEDED,
        re.compile(r"quota\s+exceeded|rate\s+limit|\bthrottl(?:ed|ing)\b", re.IGNORECASE),
    ),
    (
        NormalizedSignal.DQ_GATE_FAILURE,
        re.compile(r"\bDQ\s+gate\s+failed|expectation\s+failed", re.IGNORECASE),
    ),
    (NormalizedSignal.UPSTREAM_FAILED, re.compile(r"\bupstream_failed\b", re.IGNORECASE)),
    (
        NormalizedSignal.DUPLICATE_KEY,
        re.compile(r"duplicate\s+key|unique\s+constraint", re.IGNORECASE),
    ),
)


@dataclass(frozen=True)
class SignalMatch:
    raw_signal: str
    normalized_signal: NormalizedSignal
    matched_text: str


def _matching_line(text: str, start: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    return text[line_start : len(text) if line_end == -1 else line_end].strip()


def normalize(text: str) -> list[SignalMatch]:
    """Return one match per distinct normalized signal found, in table order.

    ``raw_signal`` is the full original line containing the first match (never rewritten).
    """
    matches: list[SignalMatch] = []
    for signal, pattern in _PATTERNS:
        found = pattern.search(text)
        if found:
            matches.append(
                SignalMatch(
                    raw_signal=_matching_line(text, found.start()),
                    normalized_signal=signal,
                    matched_text=found.group(0),
                )
            )
    return matches


def signature_patterns() -> tuple[re.Pattern[str], ...]:
    """Patterns usable as 'matching signatures' for log extraction."""
    return tuple(p for _, p in _PATTERNS)
