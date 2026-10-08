"""TaskExecutionPolicy (C5) and capability declarations (C6)."""

from pydantic import Field

from core.models.base import StrictModel
from core.models.enums import ActionCapability, ReadCapability, StateMechanism, TaskType, WriteMode


class TaskExecutionPolicy(StrictModel):
    """Supplied at pipeline registration. ``idempotent=None`` means unknown."""

    task_type: TaskType
    write_mode: WriteMode = WriteMode.UNKNOWN
    idempotent: bool | None = None
    state_mechanism: StateMechanism = StateMechanism.UNKNOWN
    retry_behavior: str = "unknown"
    duplicate_risk: str = "unknown"
    partial_write_risk: str = "unknown"
    concurrency_behavior: str = Field(
        default="unknown", description="e.g. 'forbid_overlap', 'allow_overlap', 'unknown'"
    )


class Capabilities(StrictModel):
    """Read capabilities (adapter) plus action capabilities (declared by the executor).

    Generic / unsupported platforms declare no action capabilities, so healing is NOT_APPLICABLE.
    """

    read: frozenset[ReadCapability] = frozenset()
    action: frozenset[ActionCapability] = frozenset()

    @property
    def healing_applicable(self) -> bool:
        return bool(self.action)
