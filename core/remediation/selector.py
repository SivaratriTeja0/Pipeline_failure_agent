"""Deterministic action selection (spec L3).

The LLM never chooses the action, scope, target or task list. This module computes them
from an observed run snapshot. Any unreadable state, a run that is not failed, or a
cascade that cannot be explained yields no plan.
"""

from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, Field

from core.canonical import canonical_hash
from core.models.enums import ActionType, RecoveryScope
from core.models.remediation import PlanTarget, TaskInstanceRef

FAILED = "failed"
UPSTREAM_FAILED = "upstream_failed"
CLEARABLE_STATES = frozenset({FAILED, UPSTREAM_FAILED})


class TaskInstanceSnapshot(BaseModel):
    """An observed task instance. ``state``/``try_number`` of None means unreadable."""

    task_id: str
    map_index: int | None = None
    try_number: int | None = None
    state: str | None = None
    upstream_task_ids: list[str] = Field(default_factory=list)
    end_date: datetime | None = None

    @property
    def key(self) -> tuple[str, int]:
        return (self.task_id, -1 if self.map_index is None else self.map_index)


class RunSnapshot(BaseModel):
    """Observed state of one execution (Airflow: a DAG run). ``run_state`` None = unreadable."""

    dag_id: str
    dag_run_id: str
    run_state: str | None = None
    task_instances: list[TaskInstanceSnapshot] = Field(default_factory=list)


class SelectionResult(BaseModel):
    selected: bool
    action_type: ActionType | None = None
    recovery_scope: RecoveryScope | None = None
    target: PlanTarget | None = None
    task_instances_to_clear: list[TaskInstanceRef] = Field(default_factory=list)
    primary_failures: list[str] = Field(default_factory=list)
    cascade_symptoms: list[str] = Field(default_factory=list)
    block_reason: str | None = None
    signature: str | None = None


def action_signature(
    action_type: ActionType, target: PlanTarget, task_instances: Iterable[TaskInstanceRef]
) -> str:
    """Identity of an action for 'do not re-propose an identical failed action' (L3)."""
    keys = sorted({(ti.task_id, -1 if ti.map_index is None else ti.map_index) for ti in task_instances})
    return canonical_hash(
        {"action": action_type.value, "target": target.model_dump(mode="json"), "tasks": keys}
    )


def _no_plan(reason: str) -> SelectionResult:
    return SelectionResult(selected=False, block_reason=reason)


def _downstream_closure(roots: set[str], children: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        for child in children.get(node, ()):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen


def _to_ref(ti: TaskInstanceSnapshot) -> TaskInstanceRef:
    if ti.try_number is None or ti.state not in CLEARABLE_STATES:
        raise ValueError(f"task instance {ti.task_id} is not clearable")
    return TaskInstanceRef(
        task_id=ti.task_id, map_index=ti.map_index, try_number=ti.try_number, observed_state=ti.state
    )


def select_action(
    snapshot: RunSnapshot,
    *,
    previously_failed_signatures: frozenset[str] = frozenset(),
    new_current_evidence: bool = False,
) -> SelectionResult:
    if snapshot.run_state is None:
        return _no_plan("run state unreadable")
    if snapshot.run_state != FAILED:
        return _no_plan(f"run is not in a failed state (observed {snapshot.run_state!r})")

    for ti in snapshot.task_instances:
        if ti.state is None or ti.try_number is None:
            return _no_plan(f"task instance {ti.task_id}[{ti.map_index}] state unreadable")

    keys = [ti.key for ti in snapshot.task_instances]
    if len(keys) != len(set(keys)):
        return _no_plan("duplicate task instances in snapshot")

    children: dict[str, set[str]] = {}
    for ti in snapshot.task_instances:
        for parent in ti.upstream_task_ids:
            children.setdefault(parent, set()).add(ti.task_id)

    primary_task_ids = sorted({ti.task_id for ti in snapshot.task_instances if ti.state == FAILED})
    if not primary_task_ids:
        return _no_plan("no failed task instances in the run")

    reachable = _downstream_closure(set(primary_task_ids), children)
    upstream_failed = [ti for ti in snapshot.task_instances if ti.state == UPSTREAM_FAILED]
    unexplained = sorted({ti.task_id for ti in upstream_failed if ti.task_id not in reachable})
    if unexplained:
        return _no_plan(f"upstream_failed tasks {unexplained} do not trace back to a primary failure")

    if len(primary_task_ids) == 1:
        primary = primary_task_ids[0]
        own_reach = _downstream_closure({primary}, children)
        chosen = [
            ti
            for ti in snapshot.task_instances
            if (ti.task_id == primary and ti.state == FAILED)
            or (ti.task_id in own_reach and ti.state in CLEARABLE_STATES)
        ]
        action, scope = ActionType.RETRY_FAILED_TASK, RecoveryScope.FAILED_TASK
        target = PlanTarget(dag_id=snapshot.dag_id, dag_run_id=snapshot.dag_run_id, task_id=primary)
    else:
        chosen = [ti for ti in snapshot.task_instances if ti.state in CLEARABLE_STATES]
        action, scope = ActionType.RETRY_FAILED_DAG_RUN, RecoveryScope.FAILED_DAG_RUN
        target = PlanTarget(dag_id=snapshot.dag_id, dag_run_id=snapshot.dag_run_id)

    refs = [_to_ref(ti) for ti in sorted(chosen, key=lambda t: t.key)]
    signature = action_signature(action, target, refs)
    if signature in previously_failed_signatures and not new_current_evidence:
        return _no_plan("an identical action already failed in this incident and no new CURRENT evidence")

    cascade = sorted({ti.task_id for ti in chosen if ti.state == UPSTREAM_FAILED})
    return SelectionResult(
        selected=True,
        action_type=action,
        recovery_scope=scope,
        target=target,
        task_instances_to_clear=refs,
        primary_failures=primary_task_ids,
        cascade_symptoms=cascade,
        signature=signature,
    )
