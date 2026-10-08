"""Repository: SQL implementations of the stores the healing boundary, audit log and auth layer use.

- ``SqlHealingStore`` implements ``actions.store.HealingStore``. ``write_ahead`` is a single
  transaction of conditional UPDATEs (plan NOT_EXECUTED -> QUEUED only if still NOT_EXECUTED with no
  action_execution_id; each approval consumed only if still unconsumed) plus an INSERT whose
  idempotency key is UNIQUE. If any part does not apply, the whole transaction rolls back.
- ``SqlAuditStore`` implements ``AuditStore``: append and read only.
- ``SqlPrincipalStore`` implements ``PrincipalStore``: token hashes only, never raw tokens.
- ``Repository`` holds pipelines, reports, evidence and feedback.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import create_engine, func, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from actions.store import ExecutionRecord, HealingStore, IncidentRecord, StoreError, revalidated
from core.models.audit import AuditEvent
from core.models.auth import Principal
from core.models.base import utcnow
from core.models.enums import ExecutionStatus, IncidentState, PrincipalType, Role
from core.models.evidence import EvidenceItem
from core.models.pipeline import PipelineRegistration
from core.models.remediation import ApprovalRecord, RemediationPlan, compute_plan_hash
from core.models.report import UniversalTriageReport
from core.remediation.audit import AuditStore
from database.models import (
    ApprovalRow,
    AuditRow,
    Base,
    EvidenceRow,
    ExecutionRow,
    FeedbackRow,
    FlagRow,
    IncidentRow,
    PipelineRow,
    PlanHistoryRow,
    PlanRow,
    PrincipalRow,
    ReportRow,
)
from security.auth import PrincipalStore, StoredPrincipal

HALTED_FLAG = "healing_halted"


class Database:
    def __init__(self, url: str) -> None:
        kwargs: dict[str, Any] = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if url in ("sqlite://", "sqlite:///:memory:"):
                kwargs["poolclass"] = StaticPool
        self.engine: Engine = create_engine(url, **kwargs)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._sessions()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            raise StoreError(f"database error: {type(exc).__name__}") from exc
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def ping(self) -> bool:
        try:
            with self.session() as s:
                s.execute(select(1))
            return True
        except StoreError:
            return False


def _iso(value: datetime) -> str:
    return value.isoformat()


# ----------------------------------------------------------------------------- healing store


class SqlHealingStore(HealingStore):
    def __init__(self, db: Database) -> None:
        self._db = db

    # incidents
    def save_incident(self, record: IncidentRecord) -> None:
        data = record.model_dump(mode="json")
        evidence = data.pop("evidence")
        with self._db.session() as s:
            row = s.get(IncidentRow, record.incident_id)
            if row is None:
                s.add(IncidentRow(incident_id=record.incident_id, pipeline_id=record.event.pipeline_id,
                                  state=record.state.value, data=data, created_at=_iso(utcnow())))
            else:
                row.state, row.data = record.state.value, data
            s.flush()
            known = set(s.scalars(select(EvidenceRow.evidence_id).where(EvidenceRow.incident_id == record.incident_id)))
            for item in record.evidence:
                if item.evidence_id not in known:
                    known.add(item.evidence_id)
                    s.add(EvidenceRow(incident_id=record.incident_id, evidence_id=item.evidence_id,
                                      investigation_cycle=item.provenance.investigation_cycle,
                                      data=item.model_dump(mode="json")))

    def _evidence(self, s: Session, incident_id: str) -> list[EvidenceItem]:
        rows = s.scalars(select(EvidenceRow).where(EvidenceRow.incident_id == incident_id).order_by(EvidenceRow.id))
        return [EvidenceItem.model_validate(r.data) for r in rows]

    def get_incident(self, incident_id: str) -> IncidentRecord:
        with self._db.session() as s:
            row = s.get(IncidentRow, incident_id)
            if row is None:
                raise StoreError(f"unknown incident {incident_id}")
            return IncidentRecord.model_validate({**row.data, "state": row.state,
                                                  "evidence": [e.model_dump(mode="json") for e in self._evidence(s, incident_id)]})

    def set_incident_state(self, incident_id: str, state: IncidentState) -> None:
        with self._db.session() as s:
            row = s.get(IncidentRow, incident_id)
            if row is None:
                raise StoreError(f"unknown incident {incident_id}")
            row.state = state.value
            row.data = {**row.data, "state": state.value}

    def list_incidents(self) -> list[IncidentRecord]:
        with self._db.session() as s:
            ids = list(s.scalars(select(IncidentRow.incident_id).order_by(IncidentRow.created_at.desc())))
        return [self.get_incident(i) for i in ids]

    # plans
    def save_plan(self, plan: RemediationPlan) -> None:
        data = plan.model_dump(mode="json")
        with self._db.session() as s:
            row = s.get(PlanRow, plan.remediation_id)
            values = dict(incident_id=plan.incident_id, plan_version=plan.plan_version,
                          execution_status=plan.execution_status.value, approval_status=plan.approval_status.value,
                          action_execution_id=plan.action_execution_id, data=data)
            if row is None:
                s.add(PlanRow(remediation_id=plan.remediation_id, **values))
            else:
                for key, value in values.items():
                    setattr(row, key, value)
            s.add(PlanHistoryRow(remediation_id=plan.remediation_id, plan_version=plan.plan_version, data=data))

    def get_plan(self, remediation_id: str) -> RemediationPlan:
        with self._db.session() as s:
            row = s.get(PlanRow, remediation_id)
            if row is None:
                raise StoreError(f"unknown plan {remediation_id}")
            return RemediationPlan.model_validate(row.data)

    def plans_with_status(self, statuses: set[ExecutionStatus]) -> list[RemediationPlan]:
        with self._db.session() as s:
            rows = s.scalars(select(PlanRow).where(PlanRow.execution_status.in_([x.value for x in statuses])))
            return [RemediationPlan.model_validate(r.data) for r in rows]

    def all_plans(self) -> list[RemediationPlan]:
        with self._db.session() as s:
            return [RemediationPlan.model_validate(r.data) for r in s.scalars(select(PlanRow))]

    def plans_for_incident(self, incident_id: str) -> list[RemediationPlan]:
        with self._db.session() as s:
            rows = s.scalars(select(PlanRow).where(PlanRow.incident_id == incident_id))
            return [RemediationPlan.model_validate(r.data) for r in rows]

    def plan_history(self, remediation_id: str) -> list[RemediationPlan]:
        with self._db.session() as s:
            rows = s.scalars(select(PlanHistoryRow).where(PlanHistoryRow.remediation_id == remediation_id)
                             .order_by(PlanHistoryRow.id))
            return [RemediationPlan.model_validate(r.data) for r in rows]

    # approvals (append-only, except the single-use ``consumed`` flag set by write_ahead)
    def add_approval(self, record: ApprovalRecord) -> None:
        with self._db.session() as s:
            s.add(ApprovalRow(approval_id=record.approval_id, remediation_id=record.remediation_id,
                              consumed=record.consumed, data=record.model_dump(mode="json")))

    def approvals_for(self, remediation_id: str) -> list[ApprovalRecord]:
        with self._db.session() as s:
            rows = s.scalars(select(ApprovalRow).where(ApprovalRow.remediation_id == remediation_id)
                             .order_by(ApprovalRow.approval_id))
            return [ApprovalRecord.model_validate({**r.data, "consumed": r.consumed}) for r in rows]

    # execution
    def write_ahead(self, remediation_id: str, *, expected_hash: str, approval_ids: list[str],
                    action_execution_id: str, idempotency_key: str, now: datetime) -> RemediationPlan | None:
        session = self._db._sessions()
        try:
            row = session.get(PlanRow, remediation_id)
            if row is None or row.execution_status != ExecutionStatus.NOT_EXECUTED.value or row.action_execution_id:
                session.rollback()
                return None
            plan = RemediationPlan.model_validate(row.data)
            if compute_plan_hash(plan) != expected_hash or not approval_ids:
                session.rollback()
                return None
            queued = revalidated(plan, execution_status=ExecutionStatus.QUEUED,
                                 action_execution_id=action_execution_id, idempotency_key=idempotency_key)
            changed = session.execute(
                update(PlanRow)
                .where(PlanRow.remediation_id == remediation_id,
                       PlanRow.execution_status == ExecutionStatus.NOT_EXECUTED.value,
                       PlanRow.action_execution_id.is_(None))
                .values(execution_status=ExecutionStatus.QUEUED.value, action_execution_id=action_execution_id,
                        data=queued.model_dump(mode="json")))
            if changed.rowcount != 1:
                session.rollback()
                return None
            for approval_id in set(approval_ids):
                consumed = session.execute(
                    update(ApprovalRow)
                    .where(ApprovalRow.approval_id == approval_id, ApprovalRow.remediation_id == remediation_id,
                           ApprovalRow.consumed.is_(False))
                    .values(consumed=True))
                if consumed.rowcount != 1:
                    session.rollback()
                    return None
            session.add(ExecutionRow(action_execution_id=action_execution_id, remediation_id=remediation_id,
                                     incident_id=plan.incident_id, dag_id=plan.target.dag_id if plan.target else "",
                                     idempotency_key=idempotency_key, execution_mode=plan.execution_mode.value,
                                     queued_at=_iso(now)))
            session.add(PlanHistoryRow(remediation_id=remediation_id, plan_version=queued.plan_version,
                                       data=queued.model_dump(mode="json")))
            session.commit()
            return queued
        except IntegrityError:
            session.rollback()
            return None
        except SQLAlchemyError as exc:
            session.rollback()
            raise StoreError(f"write-ahead failed: {type(exc).__name__}") from exc
        finally:
            session.close()

    def executions(self) -> list[ExecutionRecord]:
        with self._db.session() as s:
            return [ExecutionRecord(action_execution_id=r.action_execution_id, remediation_id=r.remediation_id,
                                    incident_id=r.incident_id, dag_id=r.dag_id, idempotency_key=r.idempotency_key,
                                    execution_mode=r.execution_mode, queued_at=datetime.fromisoformat(r.queued_at))
                    for r in s.scalars(select(ExecutionRow))]

    # kill switch
    def set_halted(self, halted: bool) -> None:
        with self._db.session() as s:
            row = s.get(FlagRow, HALTED_FLAG)
            if row is None:
                s.add(FlagRow(key=HALTED_FLAG, value=str(halted).lower()))
            else:
                row.value = str(halted).lower()

    def is_halted(self) -> bool:
        with self._db.session() as s:
            row = s.get(FlagRow, HALTED_FLAG)
            return row is not None and row.value == "true"


# ----------------------------------------------------------------------------- audit


class SqlAuditStore(AuditStore):
    """Append-only. There is deliberately no update or delete method."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def append(self, event: AuditEvent) -> None:
        with self._db.session() as s:
            s.add(AuditRow(seq=event.seq, incident_id=event.incident_id, event_type=event.event_type.value,
                           hash=event.hash, data=event.model_dump(mode="json")))

    def all(self) -> tuple[AuditEvent, ...]:
        with self._db.session() as s:
            return tuple(AuditEvent.model_validate(r.data) for r in s.scalars(select(AuditRow).order_by(AuditRow.seq)))

    def last(self) -> AuditEvent | None:
        with self._db.session() as s:
            row = s.scalars(select(AuditRow).order_by(AuditRow.seq.desc()).limit(1)).first()
            return AuditEvent.model_validate(row.data) if row else None

    def for_incident(self, incident_id: str) -> tuple[AuditEvent, ...]:
        with self._db.session() as s:
            rows = s.scalars(select(AuditRow).where(AuditRow.incident_id == incident_id).order_by(AuditRow.seq))
            return tuple(AuditEvent.model_validate(r.data) for r in rows)


# ----------------------------------------------------------------------------- principals


def _stored(row: PrincipalRow) -> StoredPrincipal:
    return StoredPrincipal(
        principal=Principal(principal_id=row.principal_id, principal_type=PrincipalType(row.principal_type),
                            roles=frozenset(Role(r) for r in row.roles), auth_method="token"),
        token_hash=row.token_hash, disabled=row.disabled)


class SqlPrincipalStore(PrincipalStore):
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, stored: StoredPrincipal) -> None:
        p = stored.principal
        try:
            with self._db.session() as s:
                if s.get(PrincipalRow, p.principal_id) is not None:
                    raise ValueError(f"principal {p.principal_id!r} already exists")
                s.add(PrincipalRow(principal_id=p.principal_id, principal_type=p.principal_type.value,
                                   roles=sorted(r.value for r in p.roles), token_hash=stored.token_hash,
                                   disabled=stored.disabled, created_at=_iso(utcnow())))
        except StoreError as exc:
            raise ValueError(f"could not add principal {p.principal_id!r}") from exc

    def find_by_token_hash(self, token_hash: str) -> StoredPrincipal | None:
        with self._db.session() as s:
            row = s.scalars(select(PrincipalRow).where(PrincipalRow.token_hash == token_hash)).first()
            return _stored(row) if row else None

    def find_by_id(self, principal_id: str) -> StoredPrincipal | None:
        with self._db.session() as s:
            row = s.get(PrincipalRow, principal_id)
            return _stored(row) if row else None

    def update(self, principal_id: str, *, roles: frozenset[Role] | None = None, disabled: bool | None = None) -> None:
        with self._db.session() as s:
            row = s.get(PrincipalRow, principal_id)
            if row is None:
                raise KeyError(principal_id)
            if roles is not None:
                row.roles = sorted(r.value for r in roles)
            if disabled is not None:
                row.disabled = disabled

    def list(self) -> list[Principal]:
        with self._db.session() as s:
            return [_stored(r).principal for r in s.scalars(select(PrincipalRow).order_by(PrincipalRow.principal_id))]


# ----------------------------------------------------------------------------- pipelines, reports, feedback


class Repository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save_pipeline(self, registration: PipelineRegistration, registered_by: str) -> None:
        with self._db.session() as s:
            row = s.get(PipelineRow, registration.pipeline_id)
            data = registration.model_dump(mode="json")
            if row is None:
                s.add(PipelineRow(pipeline_id=registration.pipeline_id, platform=registration.platform, data=data,
                                  registered_by=registered_by, registered_at=_iso(utcnow())))
            else:
                row.platform, row.data, row.registered_by = registration.platform, data, registered_by

    def get_pipeline(self, pipeline_id: str) -> PipelineRegistration | None:
        with self._db.session() as s:
            row = s.get(PipelineRow, pipeline_id)
            return PipelineRegistration.model_validate(row.data) if row else None

    def list_pipelines(self) -> list[PipelineRegistration]:
        with self._db.session() as s:
            return [PipelineRegistration.model_validate(r.data)
                    for r in s.scalars(select(PipelineRow).order_by(PipelineRow.pipeline_id))]

    def save_report(self, report: UniversalTriageReport) -> int:
        cycle = report.investigation_cycles[-1].cycle if report.investigation_cycles else 1
        with self._db.session() as s:
            row = ReportRow(incident_id=report.incident_id, investigation_cycle=cycle,
                            created_at=_iso(report.created_at), data=report.model_dump(mode="json"))
            s.add(row)
            s.flush()
            return row.id

    def update_latest_report(self, incident_id: str, **fields: Any) -> UniversalTriageReport | None:
        with self._db.session() as s:
            row = s.scalars(select(ReportRow).where(ReportRow.incident_id == incident_id)
                            .order_by(ReportRow.id.desc()).limit(1)).first()
            if row is None:
                return None
            report = UniversalTriageReport.model_validate({**row.data, **fields})
            row.data = report.model_dump(mode="json")
            return report

    def latest_report(self, incident_id: str) -> UniversalTriageReport | None:
        with self._db.session() as s:
            row = s.scalars(select(ReportRow).where(ReportRow.incident_id == incident_id)
                            .order_by(ReportRow.id.desc()).limit(1)).first()
            return UniversalTriageReport.model_validate(row.data) if row else None

    def reports(self, incident_id: str | None = None) -> list[UniversalTriageReport]:
        with self._db.session() as s:
            query = select(ReportRow).order_by(ReportRow.id.desc())
            if incident_id:
                query = query.where(ReportRow.incident_id == incident_id)
            return [UniversalTriageReport.model_validate(r.data) for r in s.scalars(query)]

    def latest_reports(self) -> list[UniversalTriageReport]:
        with self._db.session() as s:
            latest = select(func.max(ReportRow.id)).group_by(ReportRow.incident_id)
            rows = s.scalars(select(ReportRow).where(ReportRow.id.in_(latest)).order_by(ReportRow.id.desc()))
            return [UniversalTriageReport.model_validate(r.data) for r in rows]

    def add_feedback(self, incident_id: str, principal_id: str, data: dict[str, Any]) -> None:
        with self._db.session() as s:
            s.add(FeedbackRow(incident_id=incident_id, principal_id=principal_id, created_at=_iso(utcnow()), data=data))

    def feedback(self, incident_id: str) -> list[dict[str, Any]]:
        with self._db.session() as s:
            rows = s.scalars(select(FeedbackRow).where(FeedbackRow.incident_id == incident_id).order_by(FeedbackRow.id))
            return [{"principal_id": r.principal_id, "created_at": r.created_at, **r.data} for r in rows]
