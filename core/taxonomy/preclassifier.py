"""Deterministic pre-classifier (spec Part E).

Produces candidate categories per signal, never a final root cause. Ambiguous signals
(more than one candidate) populate ``needs_evidence`` with read capabilities to collect.
"""

from pydantic import BaseModel, Field

from core.evidence.normalizer import NormalizedSignal, normalize
from core.models.enums import ReadCapability
from core.taxonomy.categories import FailureCategory

FC = FailureCategory
RC = ReadCapability

CANDIDATES: dict[NormalizedSignal, tuple[FailureCategory, ...]] = {
    NormalizedSignal.SCHEMA_COLUMN_MISMATCH: (FC.SOURCE_SCHEMA_DRIFT, FC.CODE_LOGIC_BUG, FC.CONFIGURATION),
    NormalizedSignal.AUTHORIZATION_FAILURE: (FC.SECURITY_AUTHORIZATION,),
    NormalizedSignal.RESOURCE_MEMORY_FAILURE: (FC.RESOURCE_QUOTA, FC.VOLUME_ANOMALY, FC.CODE_LOGIC_BUG),
    NormalizedSignal.NETWORK_CONNECTIVITY_FAILURE: (FC.NETWORK_CONNECTIVITY, FC.INFRASTRUCTURE),
    NormalizedSignal.TIMEOUT: (FC.NETWORK_CONNECTIVITY, FC.RESOURCE_QUOTA, FC.UPSTREAM_DEPENDENCY),
    NormalizedSignal.MISSING_OBJECT: (FC.CONFIGURATION, FC.SOURCE_SCHEMA_DRIFT, FC.UPSTREAM_DEPENDENCY),
    NormalizedSignal.QUOTA_EXCEEDED: (FC.RESOURCE_QUOTA,),
    NormalizedSignal.DQ_GATE_FAILURE: (FC.DATA_QUALITY,),
    NormalizedSignal.UPSTREAM_FAILED: (FC.UPSTREAM_DEPENDENCY,),
    NormalizedSignal.DUPLICATE_KEY: (FC.DATA_QUALITY, FC.CODE_LOGIC_BUG, FC.CONCURRENCY, FC.ORCHESTRATION_STATE),
    NormalizedSignal.UNRECOGNIZED: (FC.OTHER_UNKNOWN,),
}

# Read capabilities that discriminate between candidates.
DISAMBIGUATING_EVIDENCE: dict[NormalizedSignal, tuple[ReadCapability, ...]] = {
    NormalizedSignal.SCHEMA_COLUMN_MISMATCH: (RC.SCHEMA, RC.CODE_CHANGES, RC.CONFIGURATION),
    NormalizedSignal.AUTHORIZATION_FAILURE: (RC.PERMISSIONS,),
    NormalizedSignal.RESOURCE_MEMORY_FAILURE: (RC.ROW_COUNTS, RC.CODE_CHANGES, RC.INFRASTRUCTURE_EVENTS),
    NormalizedSignal.NETWORK_CONNECTIVITY_FAILURE: (RC.RUN_HISTORY, RC.INFRASTRUCTURE_EVENTS),
    NormalizedSignal.TIMEOUT: (RC.RUN_HISTORY, RC.INFRASTRUCTURE_EVENTS, RC.UPSTREAM_STATUS),
    NormalizedSignal.MISSING_OBJECT: (RC.CONFIGURATION, RC.SCHEMA, RC.UPSTREAM_STATUS),
    NormalizedSignal.QUOTA_EXCEEDED: (RC.INFRASTRUCTURE_EVENTS,),
    NormalizedSignal.DQ_GATE_FAILURE: (RC.DATA_QUALITY, RC.ROW_COUNTS),
    NormalizedSignal.UPSTREAM_FAILED: (RC.UPSTREAM_STATUS, RC.LINEAGE),
    NormalizedSignal.DUPLICATE_KEY: (RC.DATA_QUALITY, RC.CODE_CHANGES, RC.RUN_HISTORY, RC.STATE_TRACKING),
    NormalizedSignal.UNRECOGNIZED: (RC.RUN_LOGS, RC.RUN_HISTORY),
}


class PreClassifiedSignal(BaseModel):
    raw_signal: str
    normalized_signal: NormalizedSignal
    candidate_categories: list[FailureCategory]
    needs_evidence: list[ReadCapability] = Field(default_factory=list)

    @property
    def ambiguous(self) -> bool:
        return len(self.candidate_categories) > 1


def preclassify(text: str) -> list[PreClassifiedSignal]:
    """Pre-classify an error message / log excerpt. Never empty: unknown text -> UNRECOGNIZED."""
    matches = normalize(text)
    if not matches:
        stripped = text.strip()
        first_line = stripped.splitlines()[0] if stripped else ""
        return [
            PreClassifiedSignal(
                raw_signal=first_line,
                normalized_signal=NormalizedSignal.UNRECOGNIZED,
                candidate_categories=list(CANDIDATES[NormalizedSignal.UNRECOGNIZED]),
                needs_evidence=list(DISAMBIGUATING_EVIDENCE[NormalizedSignal.UNRECOGNIZED]),
            )
        ]
    results = []
    for m in matches:
        candidates = list(CANDIDATES[m.normalized_signal])
        needs = list(DISAMBIGUATING_EVIDENCE[m.normalized_signal]) if len(candidates) > 1 else []
        results.append(
            PreClassifiedSignal(
                raw_signal=m.raw_signal,
                normalized_signal=m.normalized_signal,
                candidate_categories=candidates,
                needs_evidence=needs,
            )
        )
    return results
