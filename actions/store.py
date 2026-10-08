"""Persistence for the healing boundary: incidents, plans, approvals, executions, kill switch.

``HealingStore`` is the contract; ``InMemoryHealingStore`` implements it with a lock so every
check-then-write is atomic. Phase 5 provides a database-backed store with the same contract
(compare-and-set becomes a conditional UPDATE).

Write-ahead (L8): ``write_ahead`` atomically moves a plan NOT_EXECUTED -> QUEUED, stamps the
action_execution_id and idempotency key, and consumes the approvals, before any HTTP call. A
second caller cannot pass the compare-and-set, so a plan executes at most once (I6).
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from threading import RLock
from typing import Any

from pydantic import BaseModel, Field

from core.models.enums import ExecutionMode, ExecutionStatus, IncidentState
from core.models.events import PipelineFailureEvent
from core.models.evidence import EvidenceItem
from core.models.pipeline import PipelineRegistration
from core.models.remediation import ApprovalRecord, RemediationPlan, compute_plan_hash
from core.taxonomy.categories import FailureCategory


class StoreError(RuntimeError):
    """The store could not be read or written. Callers in the healing path fail closed."""


class IncidentRecord(BaseModel):
    incident_id: str
    event: PipelineFailureEvent
    registration: PipelineRegistration
    state: IncidentState
    investigation_cycle: int = 1
    category: FailureCategory | None = None
    plan_ids: list[str] = Field(default_factory=list)
    failed_signatures: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)


class ExecutionRecord(BaseModel):
    """One write-ahead execution (DRY_RUN or LIVE). Used for cycle and rate limits."""

    action_execution_id: str
    remediation_id: str
    incident_id: str
    dag_id: str
    idempotency_key: str
    execution_mode: ExecutionMode
    queued_at: datetime


class HealingStore(ABC):
    # ---------------------------------------------------------------- incidents
    @abstractmethod
    def save_incident(self, record: IncidentRecord) -> None: ...

    @abstractmethod
    def get_incident(self, incident_id: str) -> IncidentRecord: ...

    @abstractmethod
    def set_incident_state(self, incident_id: str, state: IncidentState) -> None: ...

    # ---------------------------------------------------------------- plans
    @abstractmethod
    def save_plan(self, plan: RemediationPlan) -> None: ...

    @abstractmethod
    def get_plan(self, remediation_id: str) -> RemediationPlan: ...

    @abstractmethod
    def plans_with_status(self, statuses: set[ExecutionStatus]) -> list[RemediationPlan]: ...

    @abstractmethod
    def all_plans(self) -> list[RemediationPlan]: ...

    # ---------------------------------------------------------------- approvals (append-only)
    @abstractmethod
    def add_approval(self, record: ApprovalRecord) -> None: ...

    @abstractmethod
    def approvals_for(self, remediation_id: str) -> list[ApprovalRecord]: ...

    # ---------------------------------------------------------------- execution
    @abstractmethod
    def write_ahead(
        self,
        remediation_id: str,
        *,
        expected_hash: str,
        approval_ids: list[str],
        action_execution_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> RemediationPlan | None:
        """Atomic compare-and-set NOT_EXECUTED -> QUEUED. Returns None if it does not apply."""

    @abstractmethod
    def executions(self) -> list[ExecutionRecord]: ...

    # ---------------------------------------------------------------- kill switch
    @abstractmethod
    def set_halted(self, halted: bool) -> None: ...

    @abstractmethod
    def is_halted(self) -> bool: ...

    # ---------------------------------------------------------------- derived counts
    def executions_for_incident(self, incident_id: str) -> int:
        return sum(1 for e in self.executions() if e.incident_id == incident_id)

    def actions_for_dag_since(self, dag_id: str, since: datetime) -> int:
        return sum(1 for e in self.executions() if e.dag_id == dag_id and e.queued_at > since)

    def actions_for_dag_last_hour(self, dag_id: str, now: datetime) -> int:
        return self.actions_for_dag_since(dag_id, now - timedelta(hours=1))


def revalidated(plan: RemediationPlan, **updates: Any) -> RemediationPlan:
    """Apply updates and re-run validation (recomputes plan_hash and the derived ``executed``)."""
    data = plan.model_dump()
    data.update(updates)
    data.pop("plan_hash", None)
    data.pop("executed", None)
    return RemediationPlan.model_validate(data)


class InMemoryHealingStore(HealingStore):
    def __init__(self) -> None:
        self._lock = RLock()
        self._incidents: dict[str, IncidentRecord] = {}
        self._plans: dict[str, RemediationPlan] = {}
        self._plan_history: list[RemediationPlan] = []
        self._approvals: dict[str, list[ApprovalRecord]] = {}
        self._executions: list[ExecutionRecord] = []
        self._idempotency_keys: set[str] = set()
        self._halted = False

    def save_incident(self, record: IncidentRecord) -> None:
        with self._lock:
            self._incidents[record.incident_id] = record.model_copy(deep=True)

    def get_incident(self, incident_id: str) -> IncidentRecord:
        with self._lock:
            if incident_id not in self._incidents:
                raise StoreError(f"unknown incident {incident_id}")
            return self._incidents[incident_id].model_copy(deep=True)

    def set_incident_state(self, incident_id: str, state: IncidentState) -> None:
        with self._lock:
            if incident_id not in self._incidents:
                raise StoreError(f"unknown incident {incident_id}")
            self._incidents[incident_id] = self._incidents[incident_id].model_copy(update={"state": state})

    def save_plan(self, plan: RemediationPlan) -> None:
        with self._lock:
            self._plans[plan.remediation_id] = plan
            self._plan_history.append(plan)

    def get_plan(self, remediation_id: str) -> RemediationPlan:
        with self._lock:
            if remediation_id not in self._plans:
                raise StoreError(f"unknown plan {remediation_id}")
            return self._plans[remediation_id]

    def plans_with_status(self, statuses: set[ExecutionStatus]) -> list[RemediationPlan]:
        with self._lock:
            return [p for p in self._plans.values() if p.execution_status in statuses]

    def all_plans(self) -> list[RemediationPlan]:
        with self._lock:
            return list(self._plans.values())

    def plan_history(self, remediation_id: str) -> list[RemediationPlan]:
        with self._lock:
            return [p for p in self._plan_history if p.remediation_id == remediation_id]

    def add_approval(self, record: ApprovalRecord) -> None:
        with self._lock:
            self._approvals.setdefault(record.remediation_id, []).append(record)

    def approvals_for(self, remediation_id: str) -> list[ApprovalRecord]:
        with self._lock:
            return list(self._approvals.get(remediation_id, []))

    def write_ahead(
        self,
        remediation_id: str,
        *,
        expected_hash: str,
        approval_ids: list[str],
        action_execution_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> RemediationPlan | None:
        with self._lock:
            plan = self._plans.get(remediation_id)
            if plan is None or plan.execution_status is not ExecutionStatus.NOT_EXECUTED:
                return None
            if plan.action_execution_id is not None or idempotency_key in self._idempotency_keys:
                return None
            if compute_plan_hash(plan) != expected_hash:
                return None
            records = self._approvals.get(remediation_id, [])
            chosen = [r for r in records if r.approval_id in approval_ids]
            if len(chosen) != len(set(approval_ids)) or any(r.consumed for r in chosen):
                return None
            queued = revalidated(plan, execution_status=ExecutionStatus.QUEUED,
                                 action_execution_id=action_execution_id, idempotency_key=idempotency_key)
            self._approvals[remediation_id] = [
                r.model_copy(update={"consumed": True}) if r.approval_id in approval_ids else r for r in records]
            self._idempotency_keys.add(idempotency_key)
            self._executions.append(ExecutionRecord(
                action_execution_id=action_execution_id, remediation_id=remediation_id,
                incident_id=plan.incident_id, dag_id=plan.target.dag_id if plan.target else "",
                idempotency_key=idempotency_key, execution_mode=plan.execution_mode, queued_at=now))
            self._plans[remediation_id] = queued
            self._plan_history.append(queued)
            return queued

    def executions(self) -> list[ExecutionRecord]:
        with self._lock:
            return list(self._executions)

    def set_halted(self, halted: bool) -> None:
        with self._lock:
            self._halted = halted

    def is_halted(self) -> bool:
        with self._lock:
            return self._halted
