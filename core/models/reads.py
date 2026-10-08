"""Platform-neutral read request / result models shared by adapters and investigation tools."""

from enum import Enum

from pydantic import Field

from core.models.base import StrictModel
from core.models.evidence import EvidenceItem


class ReadStatus(str, Enum):
    AVAILABLE = "AVAILABLE"        # the read ran and returned evidence (possibly empty)
    UNAVAILABLE = "UNAVAILABLE"    # the capability is not supported; nothing was called
    ERROR = "ERROR"                # the read was attempted and failed; no evidence fabricated


class ReadRequest(StrictModel):
    """Input to every read-only tool. Identifiers come from the incident, never from LLM text."""

    pipeline_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    task_id: str | None = None
    attempt_number: int | None = Field(default=None, ge=0)
    investigation_cycle: int = Field(default=1, ge=1)
    limit: int = Field(default=5, ge=1, le=25)


class ReadResult(StrictModel):
    tool: str
    status: ReadStatus
    evidence: list[EvidenceItem] = Field(default_factory=list)
    detail: str = ""

    @classmethod
    def unavailable(cls, tool: str, detail: str = "capability not supported") -> "ReadResult":
        return cls(tool=tool, status=ReadStatus.UNAVAILABLE, detail=detail)

    @classmethod
    def error(cls, tool: str, detail: str) -> "ReadResult":
        return cls(tool=tool, status=ReadStatus.ERROR, detail=detail)
