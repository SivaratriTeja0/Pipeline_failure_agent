"""Pipeline registration: environment, healing switches, approvers and task execution policies."""

from pydantic import Field

from core.models.base import PIPELINE_ID_PATTERN, StrictModel
from core.models.enums import ActionType, StateMechanism, TaskType, WriteMode
from core.models.policy import TaskExecutionPolicy

UNKNOWN_POLICY = TaskExecutionPolicy(
    task_type=TaskType.APPEND, write_mode=WriteMode.UNKNOWN, idempotent=None,
    state_mechanism=StateMechanism.UNKNOWN,
)


class PipelineRegistration(StrictModel):
    pipeline_id: str = Field(pattern=PIPELINE_ID_PATTERN)
    pipeline_name: str | None = None
    platform: str
    environment: str | None = None
    healing_enabled: bool = False
    allowed_actions: list[ActionType] = Field(default_factory=list)
    approver_ids: list[str] = Field(default_factory=list)
    task_policies: dict[str, TaskExecutionPolicy] = Field(default_factory=dict)
    default_policy: TaskExecutionPolicy | None = None

    def policy_for(self, task_id: str | None) -> TaskExecutionPolicy:
        """The registered policy for a task. Unregistered tasks get an all-unknown policy."""
        if task_id is not None and task_id in self.task_policies:
            return self.task_policies[task_id]
        return self.default_policy or UNKNOWN_POLICY
