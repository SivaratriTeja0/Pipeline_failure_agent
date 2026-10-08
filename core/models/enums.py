"""Enumerations for the universal data model (spec Part C, F, G, L)."""

from enum import Enum

from core.config import AuthProviderName, ExecutionMode

__all__ = [
    "ActionCapability",
    "ActionType",
    "ApprovalDecision",
    "ApprovalStatus",
    "AuditEventType",
    "AuthProviderName",
    "ClaimKind",
    "ConcurrencyStatus",
    "ConfidenceLevel",
    "DQGateFinding",
    "EvidenceCategory",
    "ExecutionMode",
    "ExecutionStatus",
    "FailureStage",
    "HypothesisStatus",
    "IncidentState",
    "LLMMode",
    "PrincipalType",
    "ReadCapability",
    "RecoveryScope",
    "Reliability",
    "RemediationClass",
    "ReportStatus",
    "RerunSafety",
    "RiskLevel",
    "Role",
    "Sensitivity",
    "StateMechanism",
    "StateStatus",
    "TargetWrite",
    "TaskType",
    "TemporalLabel",
    "VerificationDepth",
    "VerificationStatus",
    "WriteMode",
]


class EvidenceCategory(str, Enum):
    LOG = "LOG"
    ERROR = "ERROR"
    STACK_TRACE = "STACK_TRACE"
    RUN_HISTORY = "RUN_HISTORY"
    SCHEMA = "SCHEMA"
    DATA_QUALITY = "DATA_QUALITY"
    ROW_COUNT = "ROW_COUNT"
    STATE = "STATE"
    TRANSACTION = "TRANSACTION"
    CODE_CHANGE = "CODE_CHANGE"
    LINEAGE = "LINEAGE"
    UPSTREAM = "UPSTREAM"
    DOWNSTREAM = "DOWNSTREAM"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    CONFIGURATION = "CONFIGURATION"
    PERMISSION = "PERMISSION"
    NETWORK = "NETWORK"
    RESOURCE = "RESOURCE"
    OTHER = "OTHER"


class Reliability(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Sensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class TemporalLabel(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    STALE = "STALE"
    MISMATCHED = "MISMATCHED"


class StateMechanism(str, Enum):
    WATERMARK = "watermark"
    CHECKPOINT = "checkpoint"
    BATCH_ID = "batch_id"
    KAFKA_OFFSET = "kafka_offset"
    DELTA_VERSION = "delta_version"
    CURSOR = "cursor"
    TRANSACTION_ID = "transaction_id"
    CONTROL_TABLE = "control_table"
    PARTITION_STATE = "partition_state"
    JOB_STATE = "job_state"
    NONE = "none"
    UNKNOWN = "unknown"


class StateStatus(str, Enum):
    """Five distinct statuses. UNAVAILABLE and UNKNOWN are never 'unchanged'."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    AVAILABLE_BUT_UNCHANGED = "AVAILABLE_BUT_UNCHANGED"
    AVAILABLE_AND_CHANGED = "AVAILABLE_AND_CHANGED"


class TaskType(str, Enum):
    INCREMENTAL_MERGE = "incremental_merge"
    APPEND = "append"
    OVERWRITE = "overwrite"
    FULL_REFRESH = "full_refresh"
    UPSERT = "upsert"
    STREAMING = "streaming"
    VALIDATION_ONLY = "validation_only"
    SNAPSHOT = "snapshot"


class WriteMode(str, Enum):
    NONE = "none"
    APPEND = "append"
    OVERWRITE = "overwrite"
    MERGE = "merge"
    UPSERT = "upsert"
    UNKNOWN = "unknown"


class TargetWrite(str, Enum):
    NONE_CONFIRMED = "NONE_CONFIRMED"
    COMMITTED = "COMMITTED"
    PARTIAL_CONFIRMED = "PARTIAL_CONFIRMED"
    PARTIAL_POSSIBLE = "PARTIAL_POSSIBLE"
    UNKNOWN = "UNKNOWN"


class ConcurrencyStatus(str, Enum):
    NONE_CONFIRMED = "NONE_CONFIRMED"
    OVERLAP_CONFIRMED = "OVERLAP_CONFIRMED"
    UNKNOWN = "UNKNOWN"


class FailureStage(str, Enum):
    PRE_WRITE = "PRE_WRITE"
    MID_WRITE = "MID_WRITE"
    POST_WRITE = "POST_WRITE"
    UNKNOWN = "UNKNOWN"


class DQGateFinding(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PASSED = "PASSED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class RerunSafety(str, Enum):
    SAFE = "SAFE"
    SAFE_WITH_CONDITIONS = "SAFE_WITH_CONDITIONS"
    UNKNOWN = "UNKNOWN"
    UNSAFE = "UNSAFE"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HypothesisStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ClaimKind(str, Enum):
    FACT = "FACT"
    INFERENCE = "INFERENCE"
    RECOMMENDATION = "RECOMMENDATION"


class ReadCapability(str, Enum):
    RUN_LOGS = "run_logs"
    RUN_HISTORY = "run_history"
    SCHEMA = "schema"
    ROW_COUNTS = "row_counts"
    DATA_QUALITY = "data_quality"
    LINEAGE = "lineage"
    STATE_TRACKING = "state_tracking"
    TRANSACTION_HISTORY = "transaction_history"
    CODE_CHANGES = "code_changes"
    INFRASTRUCTURE_EVENTS = "infrastructure_events"
    CONFIGURATION = "configuration"
    PERMISSIONS = "permissions"
    UPSTREAM_STATUS = "upstream_status"
    DOWNSTREAM_STATUS = "downstream_status"


class ActionCapability(str, Enum):
    RETRY_FAILED_TASK = "retry_failed_task"
    RETRY_FAILED_DAG_RUN = "retry_failed_dag_run"


class RemediationClass(str, Enum):
    AUTOMATABLE = "AUTOMATABLE"
    MANUAL_FIX_REQUIRED = "MANUAL_FIX_REQUIRED"
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
    BLOCKED = "BLOCKED"


class ActionType(str, Enum):
    """Exactly two V1 actions (spec L2). Adding a third requires a spec change."""

    RETRY_FAILED_TASK = "RETRY_FAILED_TASK"
    RETRY_FAILED_DAG_RUN = "RETRY_FAILED_DAG_RUN"


class RecoveryScope(str, Enum):
    """V1 allows only these two scopes. DAG and PIPELINE scopes do not exist."""

    FAILED_TASK = "FAILED_TASK"
    FAILED_DAG_RUN = "FAILED_DAG_RUN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class ApprovalDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ExecutionStatus(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    UNCERTAIN = "UNCERTAIN"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class VerificationStatus(str, Enum):
    NOT_VERIFIED = "NOT_VERIFIED"
    VERIFIED = "VERIFIED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationDepth(str, Enum):
    STATE_ONLY = "STATE_ONLY"
    STATE_AND_DATA_CHECKS = "STATE_AND_DATA_CHECKS"


class PrincipalType(str, Enum):
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"


class Role(str, Enum):
    VIEWER = "VIEWER"
    ENGINEER = "ENGINEER"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class LLMMode(str, Enum):
    LIVE = "LIVE"
    MOCK = "MOCK"


class ReportStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE_UNGROUNDED = "INCOMPLETE_UNGROUNDED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class IncidentState(str, Enum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    DIAGNOSED = "DIAGNOSED"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    POLICY_VALIDATING = "POLICY_VALIDATING"
    REVALIDATING = "REVALIDATING"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    EXECUTION_UNCERTAIN = "EXECUTION_UNCERTAIN"
    RECONCILING = "RECONCILING"
    RESOLVED = "RESOLVED"
    RE_INVESTIGATING = "RE_INVESTIGATING"
    ESCALATED = "ESCALATED"
    BLOCKED = "BLOCKED"
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
    MANUAL_FIX_REQUIRED = "MANUAL_FIX_REQUIRED"
    AWAITING_FIX_CONFIRMATION = "AWAITING_FIX_CONFIRMATION"


class AuditEventType(str, Enum):
    # Hero-run sequence (spec Part R)
    FAILURE_RECEIVED = "FAILURE_RECEIVED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    INJECTION_SCAN_COMPLETED = "INJECTION_SCAN_COMPLETED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    ROOT_CAUSE_DETERMINED = "ROOT_CAUSE_DETERMINED"
    RERUN_SAFETY_COMPUTED = "RERUN_SAFETY_COMPUTED"
    REMEDIATION_CONFIDENCE_COMPUTED = "REMEDIATION_CONFIDENCE_COMPUTED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    POLICY_VALIDATED = "POLICY_VALIDATED"
    LIVE_STATE_REVALIDATED = "LIVE_STATE_REVALIDATED"
    EXECUTION_QUEUED = "EXECUTION_QUEUED"
    EXECUTION_DISPATCHED = "EXECUTION_DISPATCHED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_PASSED = "VERIFICATION_PASSED"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"
    # Lifecycle and refusal events
    INCIDENT_STATE_CHANGED = "INCIDENT_STATE_CHANGED"
    PLAN_REVISED = "PLAN_REVISED"
    APPROVAL_RECORDED = "APPROVAL_RECORDED"  # one of several required approvals (HIGH risk)
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_CANCELLED = "APPROVAL_CANCELLED"
    APPROVAL_VOIDED = "APPROVAL_VOIDED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    REVALIDATION_BLOCKED = "REVALIDATION_BLOCKED"
    EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
    EXECUTION_DRY_RUN = "EXECUTION_DRY_RUN"
    EXECUTION_UNCERTAIN = "EXECUTION_UNCERTAIN"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    RECONCILIATION_STARTED = "RECONCILIATION_STARTED"
    RECONCILIATION_COMPLETED = "RECONCILIATION_COMPLETED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    VERIFICATION_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"
    INCIDENT_ESCALATED = "INCIDENT_ESCALATED"
    FIX_APPLIED = "FIX_APPLIED"
    MANUAL_CLOSE = "MANUAL_CLOSE"
    HEALING_HALTED = "HEALING_HALTED"
    PIPELINE_REGISTERED = "PIPELINE_REGISTERED"
    SUSPICIOUS_REQUEST = "SUSPICIOUS_REQUEST"
    AUTH_FAILURE = "AUTH_FAILURE"
