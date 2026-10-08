"""ActionRegistry / ActionSpec (spec L2): exactly two V1 actions.

Both actions recover the same failed execution by clearing its enumerated failed task instances
(only_failed). Neither creates a new run. ``ActionType`` has exactly two members, so a third
action cannot even be named without a spec change; the registry is frozen after construction.
"""

from collections.abc import Callable
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.models.enums import ActionCapability, ActionType, RecoveryScope, RiskLevel
from core.models.remediation import ACTION_SCOPE, PlanParameters
from core.remediation.classification import AUTOMATABLE_SUBCATEGORIES, MANUAL_CATEGORIES
from core.remediation.plan_builder import PRECONDITION_CHECKS
from core.remediation.risk import ROLLBACK_DESCRIPTION, compute_risk_level
from core.taxonomy.categories import FailureCategory


class ActionRegistrationError(RuntimeError):
    """Raised when an action would violate the healing invariants."""


class ActionSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: ActionType
    description: str = Field(min_length=1)
    recovery_scope: RecoveryScope
    parameter_schema: dict[str, Any]
    risk_function: Callable[[str | None, RecoveryScope], RiskLevel]
    mutating: Literal[True] = True
    requires_approval: bool = True
    rollback_description: str = Field(min_length=1)
    eligible_categories: frozenset[FailureCategory]
    required_action_capability: ActionCapability
    precondition_checks: frozenset[str]

    @field_validator("requires_approval")
    @classmethod
    def _approval_is_immutable(cls, value: bool) -> bool:
        if value is not True:
            raise ActionRegistrationError("every action requires approval; requires_approval=False is refused")
        return value


class ActionRegistry:
    def __init__(self) -> None:
        self._specs: dict[ActionType, ActionSpec] = {}
        self._frozen = False

    def register(self, spec: ActionSpec) -> None:
        if self._frozen:
            raise ActionRegistrationError("the action registry is frozen; adding an action requires a spec change")
        if not spec.requires_approval or not spec.mutating:
            raise ActionRegistrationError("actions are mutating and always require approval")
        if spec.name in self._specs:
            raise ActionRegistrationError(f"{spec.name.value} already registered")
        if ACTION_SCOPE[spec.name] is not spec.recovery_scope:
            raise ActionRegistrationError(f"{spec.name.value} must use scope {ACTION_SCOPE[spec.name].value}")
        unknown = spec.precondition_checks - PRECONDITION_CHECKS
        if unknown:
            raise ActionRegistrationError(f"unknown precondition checks {sorted(unknown)}")
        self._specs[spec.name] = spec

    def freeze(self) -> "ActionRegistry":
        self._frozen = True
        return self

    def get(self, name: ActionType) -> ActionSpec | None:
        return self._specs.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return sorted(n.value for n in self._specs)

    @property
    def specs(self) -> MappingProxyType[ActionType, ActionSpec]:
        return MappingProxyType(self._specs)


# Manual categories are eligible only after an engineer attests the fix (L10); classification
# enforces that, the registry only lists what an action could ever apply to.
_ELIGIBLE = frozenset(AUTOMATABLE_SUBCATEGORIES) | MANUAL_CATEGORIES


def _build_default() -> ActionRegistry:
    registry = ActionRegistry()
    common: dict[str, Any] = {
        "parameter_schema": PlanParameters.model_json_schema(),
        "risk_function": compute_risk_level,
        "rollback_description": ROLLBACK_DESCRIPTION,
        "eligible_categories": _ELIGIBLE,
        "precondition_checks": PRECONDITION_CHECKS,
    }
    registry.register(ActionSpec(
        name=ActionType.RETRY_FAILED_TASK, recovery_scope=RecoveryScope.FAILED_TASK,
        description="Clear the enumerated failed task instance(s) of one primary failure (and its cascade "
                    "symptoms) in the existing run, only_failed. No new run is created.",
        required_action_capability=ActionCapability.RETRY_FAILED_TASK, **common))
    registry.register(ActionSpec(
        name=ActionType.RETRY_FAILED_DAG_RUN, recovery_scope=RecoveryScope.FAILED_DAG_RUN,
        description="Clear the enumerated failed/upstream_failed task instances of the existing failed run, "
                    "only_failed. No new run is created.",
        required_action_capability=ActionCapability.RETRY_FAILED_DAG_RUN, **common))
    return registry.freeze()


ACTION_REGISTRY = _build_default()
