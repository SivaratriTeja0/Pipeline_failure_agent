"""Single entry point that prepares untrusted text for the LLM: secrets, then PII, then
injection scan, then delimiting. Credentials and PII never reach the LLM."""

from pydantic import BaseModel, Field

from security.pii import PIIMasker
from security.prompt_injection import detect_injection, wrap_evidence
from security.secrets import scrub_secrets


class SanitizedEvidence(BaseModel):
    evidence_id: str
    wrapped: str
    secrets_found: dict[str, int] = Field(default_factory=dict)
    pii_found: dict[str, int] = Field(default_factory=dict)
    injection_matches: list[str] = Field(default_factory=list)

    @property
    def injection_suspected(self) -> bool:
        return bool(self.injection_matches)


def sanitize_for_llm(evidence_id: str, text: str, masker: PIIMasker) -> SanitizedEvidence:
    scrubbed = scrub_secrets(text)
    masked = masker.mask(scrubbed.text)
    scan = detect_injection(masked.text)
    return SanitizedEvidence(
        evidence_id=evidence_id,
        wrapped=wrap_evidence(evidence_id, masked.text),
        secrets_found=scrubbed.findings,
        pii_found=masked.counts,
        injection_matches=scan.matches,
    )
