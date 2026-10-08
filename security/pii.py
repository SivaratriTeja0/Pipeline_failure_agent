"""Deterministic PII masking with stable placeholders (spec Part M).

The same value always maps to the same placeholder within one masker (``<EMAIL_1>``), so
the LLM can still correlate occurrences without seeing the value. Covers emails, phone
numbers, customer IDs, labeled/honorific names and street addresses.
"""

import re

from pydantic import BaseModel, Field

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(
    r"(?<![\w\-])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)\s?|\d{3}[\s.\-])\d{3}[\s.\-]\d{4}(?![\w\-])"
    r"|(?<![\w])\+\d{1,3}[\s\-]?\d{6,12}(?![\w])"
)
_CUSTOMER_ID = re.compile(
    r"\b(?:CUST(?:OMER)?[-_]?\d{4,}|C\d{6,})\b"
    r"|(?i:(?<=customer_id[=:])\s*[A-Za-z0-9\-]+|(?<=customer id[=:])\s*[A-Za-z0-9\-]+)"
)
_LABELED_NAME = re.compile(
    r"(?i:(?:customer[_ ]name|full[_ ]name|first[_ ]name|last[_ ]name|\bname))\s*[:=]\s*"
    r"[\"']?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})"
)
_HONORIFIC_NAME = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)")
_ADDRESS = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?"
)


class MaskResult(BaseModel):
    text: str
    counts: dict[str, int] = Field(default_factory=dict)


class PIIMasker:
    """Stateful masker: placeholders are stable across calls on the same instance."""

    def __init__(self) -> None:
        self._mapping: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def _placeholder(self, kind: str, value: str) -> str:
        key = (kind, value.strip())
        if key not in self._mapping:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            self._mapping[key] = f"<{kind}_{self._counters[kind]}>"
        return self._mapping[key]

    def mask(self, text: str) -> MaskResult:
        counts: dict[str, int] = {}

        def bump(kind: str) -> None:
            counts[kind] = counts.get(kind, 0) + 1

        def whole(kind: str):
            def _sub(m: re.Match[str]) -> str:
                bump(kind)
                return self._placeholder(kind, m.group(0))
            return _sub

        def group1(kind: str):
            def _sub(m: re.Match[str]) -> str:
                bump(kind)
                start, end = m.span(1)
                s0 = m.start(0)
                full = m.group(0)
                return full[: start - s0] + self._placeholder(kind, m.group(1)) + full[end - s0 :]
            return _sub

        out = _EMAIL.sub(whole("EMAIL"), text)
        out = _ADDRESS.sub(whole("ADDRESS"), out)
        out = _CUSTOMER_ID.sub(whole("CUSTOMER_ID"), out)
        out = _PHONE.sub(whole("PHONE"), out)
        out = _LABELED_NAME.sub(group1("NAME"), out)
        out = _HONORIFIC_NAME.sub(group1("NAME"), out)
        return MaskResult(text=out, counts=counts)


def mask_pii(text: str) -> MaskResult:
    """Mask with a fresh masker (placeholders stable within this text only)."""
    return PIIMasker().mask(text)
