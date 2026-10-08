"""Evidence pipeline between collection and the LLM: freshness, secret scrubbing, PII masking
and prompt-injection detection. Stored/reported evidence is masked too, so credentials and PII
never persist in reports or reach the LLM."""

import json
from typing import Any

from pydantic import BaseModel, Field

from core.evidence.freshness import FreshnessContext, apply_freshness
from core.models.evidence import EvidenceItem
from security.pii import PIIMasker
from security.prompt_injection import detect_injection, wrap_evidence
from security.secrets import scrub_secrets

PER_ITEM_CHARS = 6000


def _flatten(value: Any) -> str:
    """All string leaves, newline-separated, so line-anchored injection patterns still apply."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return "\n".join(_flatten(v) for v in value)
    return "" if value is None else str(value)


class SanitizeReport(BaseModel):
    secrets_found: dict[str, int] = Field(default_factory=dict)
    pii_found: dict[str, int] = Field(default_factory=dict)
    injection_evidence_ids: list[str] = Field(default_factory=list)
    injection_patterns: list[str] = Field(default_factory=list)


class EvidencePipeline:
    """One instance per incident so PII placeholders stay stable across cycles."""

    def __init__(self) -> None:
        self._masker = PIIMasker()
        self.report = SanitizeReport()

    def clean_text(self, text: str) -> str:
        scrubbed = scrub_secrets(text)
        for kind, n in scrubbed.findings.items():
            self.report.secrets_found[kind] = self.report.secrets_found.get(kind, 0) + n
        masked = self._masker.mask(scrubbed.text)
        for kind, n in masked.counts.items():
            self.report.pii_found[kind] = self.report.pii_found.get(kind, 0) + n
        return masked.text

    def _clean_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.clean_text(value)
        if isinstance(value, list):
            return [self._clean_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._clean_value(v) for k, v in value.items()}
        return value

    def sanitize(self, items: list[EvidenceItem]) -> list[EvidenceItem]:
        """Masked copies. Metadata (structured, adapter-produced facts) is kept as-is."""
        out = []
        for item in items:
            cleaned = item.model_copy(update={
                "value": self._clean_value(item.value),
                "description": self.clean_text(item.description),
                "raw_signal": self.clean_text(item.raw_signal) if item.raw_signal else None,
            })
            scan = detect_injection(_flatten(cleaned.value) + "\n" + cleaned.description)
            if scan.suspected:
                self.report.injection_evidence_ids.append(item.evidence_id)
                for pattern in scan.matches:
                    if pattern not in self.report.injection_patterns:
                        self.report.injection_patterns.append(pattern)
            out.append(cleaned)
        return out

    def scan_text(self, source_id: str, text: str) -> str:
        """Scrub/mask untrusted free text that is not an EvidenceItem (e.g. the failure message a
        webhook delivered) and record any injection-like content under ``source_id``."""
        cleaned = self.clean_text(text)
        scan = detect_injection(cleaned)
        if scan.suspected:
            self.report.injection_evidence_ids.append(source_id)
            for pattern in scan.matches:
                if pattern not in self.report.injection_patterns:
                    self.report.injection_patterns.append(pattern)
        return cleaned

    @staticmethod
    def label(items: list[EvidenceItem], ctx: FreshnessContext) -> list[EvidenceItem]:
        return apply_freshness(items, ctx)

    @staticmethod
    def wrap(items: list[EvidenceItem]) -> list[str]:
        blocks = []
        for item in items:
            body = json.dumps({
                "category": item.category.value,
                "description": item.description,
                "reliability": item.reliability.value,
                "temporal_label": item.temporal_label.value,
                "attempt": item.attempt_number,
                "normalized_signal": item.normalized_signal,
                "value": item.value,
            }, default=str)
            if len(body) > PER_ITEM_CHARS:
                body = body[:PER_ITEM_CHARS] + "...[truncated]"
            blocks.append(wrap_evidence(item.evidence_id, body))
        return blocks
