"""Evidence models (spec C2-C4): EvidenceItem, Provenance, StateEvidence."""

from datetime import datetime
from typing import Any

from pydantic import Field, model_validator

from core.models.base import StrictModel
from core.models.enums import (
    EvidenceCategory,
    Reliability,
    Sensitivity,
    StateMechanism,
    StateStatus,
    TemporalLabel,
)


class Provenance(StrictModel):
    """Answers 'where did this come from?': Adapter -> Capability -> Tool -> Source."""

    adapter: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    source: str = Field(min_length=1)
    collected_at: datetime
    investigation_cycle: int = Field(ge=1)


class EvidenceItem(StrictModel):
    """A collected signal. LLM output, hypotheses and recommendations are never evidence."""

    evidence_id: str = Field(min_length=1)
    category: EvidenceCategory
    source: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    timestamp: datetime | None = None
    execution_id: str = Field(min_length=1)
    attempt_number: int | None = Field(default=None, ge=0)
    description: str
    value: Any = None
    raw_signal: str | None = None
    normalized_signal: str | None = None
    reliability: Reliability
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    temporal_label: TemporalLabel = TemporalLabel.CURRENT
    provenance: Provenance
    metadata: dict[str, Any] = Field(default_factory=dict)


_CONCRETE_MECHANISMS = frozenset(StateMechanism) - {StateMechanism.NONE, StateMechanism.UNKNOWN}


class StateEvidence(StrictModel):
    """Abstract state (Rule 5): a watermark is one mechanism among many, never assumed.

    Invariants:
    - mechanism ``none``  <=> status NOT_APPLICABLE
    - mechanism ``unknown`` => status UNKNOWN or UNAVAILABLE (cannot be 'available')
    - AVAILABLE_* statuses require a concrete mechanism.
    """

    mechanism: StateMechanism
    status: StateStatus
    before_value: Any = None
    after_value: Any = None
    source: str = Field(min_length=1)
    timestamp: datetime | None = None
    execution_id: str = Field(min_length=1)
    reliability: Reliability
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _mechanism_status_consistency(self) -> "StateEvidence":
        if self.mechanism is StateMechanism.NONE and self.status is not StateStatus.NOT_APPLICABLE:
            raise ValueError("mechanism 'none' requires status NOT_APPLICABLE")
        if self.status is StateStatus.NOT_APPLICABLE and self.mechanism is not StateMechanism.NONE:
            raise ValueError("status NOT_APPLICABLE is only valid for mechanism 'none'")
        if self.mechanism is StateMechanism.UNKNOWN and self.status not in (
            StateStatus.UNKNOWN,
            StateStatus.UNAVAILABLE,
        ):
            raise ValueError("mechanism 'unknown' can only have status UNKNOWN or UNAVAILABLE")
        if (
            self.status in (StateStatus.AVAILABLE_BUT_UNCHANGED, StateStatus.AVAILABLE_AND_CHANGED)
            and self.mechanism not in _CONCRETE_MECHANISMS
        ):
            raise ValueError("AVAILABLE_* statuses require a concrete state mechanism")
        return self
