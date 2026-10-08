"""SQLAlchemy models (SQLite by default, DATABASE_URL).

Domain objects are stored as validated Pydantic JSON (``data``) next to the columns that queries and
compare-and-set conditions need. Rows are re-validated through the Pydantic models when read, so a
hand-edited row that breaks a model invariant fails loudly instead of flowing into the healing path.

The audit table is append-only: the repository exposes no update or delete for it, and each row
carries the hash chain so tampering is detectable (``verify_audit_chain``).
"""

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class PipelineRow(Base):
    __tablename__ = "pipelines"

    pipeline_id: Mapped[str] = mapped_column(String(250), primary_key=True)
    platform: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)
    registered_by: Mapped[str] = mapped_column(String(128))
    registered_at: Mapped[str] = mapped_column(String(40))


class IncidentRow(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    pipeline_id: Mapped[str] = mapped_column(String(250), index=True)
    state: Mapped[str] = mapped_column(String(40), index=True)
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40))


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id"), index=True)
    evidence_id: Mapped[str] = mapped_column(String(128))
    investigation_cycle: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSON)

    __table_args__ = (Index("ux_evidence_incident_id", "incident_id", "evidence_id", unique=True),)


class ReportRow(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    investigation_cycle: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class PlanRow(Base):
    __tablename__ = "plans"

    remediation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    plan_version: Mapped[int] = mapped_column(Integer)
    execution_status: Mapped[str] = mapped_column(String(20), index=True)
    approval_status: Mapped[str] = mapped_column(String(20), index=True)
    action_execution_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[dict] = mapped_column(JSON)


class PlanHistoryRow(Base):
    __tablename__ = "plan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    remediation_id: Mapped[str] = mapped_column(String(128), index=True)
    plan_version: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSON)


class ApprovalRow(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    remediation_id: Mapped[str] = mapped_column(String(128), index=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[dict] = mapped_column(JSON)


class ExecutionRow(Base):
    __tablename__ = "executions"

    action_execution_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    remediation_id: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    dag_id: Mapped[str] = mapped_column(String(250), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True)
    execution_mode: Mapped[str] = mapped_column(String(10))
    queued_at: Mapped[str] = mapped_column(String(40))


class AuditRow(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    data: Mapped[dict] = mapped_column(JSON)


class FeedbackRow(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    principal_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class PrincipalRow(Base):
    __tablename__ = "principals"

    principal_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_type: Mapped[str] = mapped_column(String(10))
    roles: Mapped[list] = mapped_column(JSON)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[str] = mapped_column(String(40))


class FlagRow(Base):
    """Operational switches persisted across restarts (e.g. the admin healing halt)."""

    __tablename__ = "flags"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
