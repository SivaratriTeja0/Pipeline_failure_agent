"""AuditEvent (C11): append-only, hash-chained."""

from typing import Any

from pydantic import AwareDatetime, ConfigDict, Field

from core.models.base import StrictModel
from core.models.enums import AuditEventType

ACTOR_PATTERN = r"^(SYSTEM|LLM|HUMAN:[A-Za-z0-9][A-Za-z0-9_.@\-]{0,127})$"
GENESIS_HASH = "0" * 64


class AuditEvent(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int = Field(ge=1)
    timestamp: AwareDatetime
    incident_id: str = Field(min_length=1)
    remediation_id: str | None = None
    actor: str = Field(pattern=ACTOR_PATTERN)
    event_type: AuditEventType
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_hash: str
    prev_hash: str
    hash: str
