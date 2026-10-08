"""Helpers for adapters to build EvidenceItems with full provenance and demo labeling."""

from datetime import datetime
from typing import Any

from core.canonical import canonical_hash
from core.evidence.normalizer import normalize
from core.models.enums import EvidenceCategory, Reliability, Sensitivity
from core.models.evidence import EvidenceItem, Provenance
from core.models.reads import ReadRequest

DEMO_LABEL = "FAKE AIRFLOW (DEMO)"


def evidence_id(*parts: Any) -> str:
    """Deterministic id: re-collecting the same signal in the same cycle yields the same id."""
    return "ev-" + canonical_hash([str(p) for p in parts])[:16]


def build_evidence(
    *,
    adapter: str,
    platform: str,
    capability: str,
    tool: str,
    source: str,
    req: ReadRequest,
    category: EvidenceCategory,
    description: str,
    value: Any,
    reliability: Reliability,
    collected_at: datetime,
    key: str,
    timestamp: datetime | None = None,
    attempt_number: int | None = None,
    signal_text: str | None = None,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    demo_label: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> EvidenceItem:
    meta: dict[str, Any] = {"pipeline_id": req.pipeline_id, **(metadata or {})}
    if demo_label:
        meta["demo"] = True
        meta["demo_label"] = demo_label
    raw_signal = normalized_signal = None
    if signal_text:
        matches = normalize(signal_text)
        if matches:
            raw_signal = matches[0].raw_signal
            normalized_signal = matches[0].normalized_signal.value
    return EvidenceItem(
        evidence_id=evidence_id(platform, tool, req.pipeline_id, req.execution_id, key, req.investigation_cycle),
        category=category,
        source=source,
        platform=platform,
        timestamp=timestamp,
        execution_id=req.execution_id,
        attempt_number=attempt_number if attempt_number is not None else req.attempt_number,
        description=(f"[{demo_label}] " if demo_label else "") + description,
        value=value,
        raw_signal=raw_signal,
        normalized_signal=normalized_signal,
        reliability=reliability,
        sensitivity=sensitivity,
        provenance=Provenance(
            adapter=adapter,
            capability=capability,
            tool=tool,
            source=source,
            collected_at=collected_at,
            investigation_cycle=req.investigation_cycle,
        ),
        metadata=meta,
    )
