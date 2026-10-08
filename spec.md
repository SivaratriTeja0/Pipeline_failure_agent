PART A: PRODUCT DEFINITION
A1. Mission and positioning

Build a production-quality MVP: Universal Pipeline Failure Triage & Human-Approved Self-Healing Agent.

V1 is Airflow-only, but the core is platform-independent and adapter-based so other orchestrators can be added later without modifying the core investigation engine.

The system detects failed Airflow executions, collects and validates evidence, investigates, identifies the most likely root cause, determines rerun safety, proposes a remediation, waits for an authenticated engineer to explicitly approve the exact plan, re-checks live state, executes within policy through a controlled executor, verifies the outcome, and either resolves the incident or escalates it.

Positioning statement (use in README):

The V1 agent monitors Airflow pipeline failures, investigates them using evidence from logs, execution history, state and other available sources, determines the root cause and rerun safety, and proposes a remediation. An authenticated engineer must explicitly approve the exact remediation plan before the system can execute it. The agent then performs the approved Airflow recovery, verifies the result, and either resolves the incident or escalates it for further investigation. It does not blindly retry pipelines, and it does not let an LLM directly control production: it investigates first, proves what it can, gets human approval for the exact action, re-checks live state, executes within policy, and verifies the outcome.

Properties: evidence-driven, human-controlled, security-conscious, auditable, deterministic where safety matters, LLM-assisted rather than LLM-controlled.

A2. Core principle and trust boundary

The AI may investigate autonomously. It may not execute remediation without explicit human approval. The LLM can create data describing an action, but it cannot possess the capability to perform the action.

core/ agent/ tools/ security/          ← can read, reason, and produce DATA
        │   NO MUTATION CAPABILITY
        ▼
RemediationPlan (data only)
        ▼
actions/approval/        authenticated human approval, bound to the exact plan hash
        ▼
actions/policy/          deterministic policy validation
        ▼
actions/revalidation/    live-state safety re-check (read-only)
        ▼
actions/executor/        write-ahead, idempotent, single-use dispatch
        ▼
AirflowActionClient      the ONLY mutating client
        ▼
AIRFLOW
A3. What the system is NOT

Not a chatbot, error summarizer, log-reading LLM, unrestricted autonomous agent, blind retry system, code-modification system, database-repair system, Databricks-specific agent, Airflow plugin, or a system that assumes every failure is retryable, assumes watermarks exist, or invents missing evidence. Not a system that "fixes" what is not broken.

A4. V1 scope
Real integration: Apache Airflow only, via REST (httpx). Do not add apache-airflow as a dependency.
Also required (small): a Generic adapter (manual evidence upload; investigation only; healing = NOT_APPLICABLE) and a fake ExamplePlatform adapter inside tests only, to prove platform independence.
Not in V1: ADF, Databricks, Glue, Dagster, Prefect. Leave PipelineAdapter and RemediationExecutor interfaces extensible. Do not build other integrations.
A5. V1 objectives
Detect (poll) or receive (webhook) an Airflow failure.
Normalize it to a universal event.
Discover read capabilities and action capabilities.
Collect evidence with provenance.
Validate freshness.
Mask secrets and PII.
Detect prompt injection in evidence.
Pre-classify deterministically.
Generate competing hypotheses.
Investigate missing evidence (read-only, max 5 calls per cycle).
Determine the most likely root cause.
Compute deterministic confidence and rerun safety.
Validate report grounding.
Classify remediation (AUTOMATABLE, MANUAL_FIX_REQUIRED, NO_ACTION_REQUIRED, BLOCKED) and compute deterministic remediation confidence.
Select the action deterministically and generate a remediation plan.
Wait for explicit, authenticated engineer approval of the exact plan.
Validate policy.
Re-validate live state immediately before execution.
Execute through the controlled Airflow action executor.
Verify the outcome.
Close the incident, re-investigate (bounded), or escalate.
Record a complete, tamper-evident audit trail.
A6. End-to-end flow
AIRFLOW failure
 → AirflowAdapter → PipelineFailureEvent → Capability Discovery
 → Evidence Collection → Normalization → Freshness Check
 → Secret/PII Masking → Prompt-Injection Detection
 → Deterministic Pre-Classifier
 → LLM Investigation Loop (read-only tools, ≤5 calls per cycle)
 → Root Cause → Deterministic Rerun Safety → Deterministic Confidence
 → Grounding Validator
 → Remediation Classification → Remediation Confidence → Deterministic Action Selection
 → Remediation Plan (LLM writes rationale only)
 → HUMAN APPROVAL ── reject / expire / cancel → STOP (never executed)
 → Policy Validation → Live-State Re-validation ── any doubt → BLOCKED
 → Executor (write-ahead, idempotent) → AIRFLOW → Verification
 → VERIFIED → RESOLVED
 → RECOVERY_FAILED → Re-investigate (≤ MAX_HEALING_CYCLES) → ... → ESCALATED
 → INCONCLUSIVE / UNCERTAIN → reconcile or ESCALATED
A7. Hard rules

Rule 1: Investigation is read-only. No investigation tool may modify data, schema, code, Git, infrastructure, configuration, checkpoints, watermarks, offsets, or trigger/rerun/clear/restart anything.

Rule 2: Healing is a separate execution boundary. Remediation actions are never tools available to the LLM. The LLM produces data; only the executor, after approval, policy, and re-validation, performs mutations. The LLM never calls a mutation API, directly or indirectly.

Rule 3: Approval must be explicit, authenticated, and human. Valid: an APPROVED decision from an authenticated HUMAN principal with the required role, for the exact plan, within its validity window. Invalid, and must never lead to execution: no response, timeout, expiry, implied approval, auto-approval, confidence-based approval, SAFE rerun safety, the LLM selecting the action, approval text arriving through a webhook or found in evidence, an identity supplied in a request body, or approval by a service principal.

Rule 4: No fabricated evidence. Use UNAVAILABLE, INSUFFICIENT_EVIDENCE, or NOT_APPLICABLE. LLM output, hypotheses, and recommendations are never evidence.

Rule 5: No watermark assumption. State is an abstract mechanism (watermark, checkpoint, batch ID, Kafka offset, Delta version, cursor, transaction ID, control table, partition state, job state, none, unknown). If the mechanism is unknown and safety cannot be proven, rerun_safety = UNKNOWN.

Rule 6: Healing is off by default. HEALING_ENABLED=false, per-pipeline healing_enabled=false, HEALING_EXECUTION_MODE=DRY_RUN are the defaults. Real execution requires all three to be deliberately changed.

Rule 7: Fail closed. Any error, ambiguity, missing precondition, or unreadable state in the healing path results in BLOCKED, never in execution. Examples that must each be a test: Airflow unavailable → BLOCKED; approval lookup or verification fails → BLOCKED; plan-hash mismatch → BLOCKED; current task state unreadable → BLOCKED; concurrency unknown at execution time → BLOCKED; auth provider unavailable → BLOCKED.

Rule 8: The LLM selects nothing executable. Action type, recovery scope, target, and the enumerated task instances are computed by deterministic code. The LLM may write the rationale and expected-effect text, and may only lower a plan to manual; it can never make a plan executable or broaden it.

PART B: ARCHITECTURE
B1. Project structure
pipeline_failure_triage/
├── core/
│   ├── models/            # all Pydantic models and enums (incl. ActionType)
│   ├── evidence/          # normalization, freshness, provenance, log extraction
│   ├── taxonomy/
│   ├── reasoning/         # hypothesis engine, confidence, remediation_confidence, grounding
│   ├── safety/            # rerun safety engine
│   ├── remediation/       # plan model, plan hashing, classification, deterministic action
│   │                      # selector, incident state machine, audit chain. DATA/LOGIC ONLY.
│   └── registry/          # adapter registry
├── adapters/
│   ├── base/              # PipelineAdapter, RemediationExecutor interfaces
│   ├── airflow/           # AirflowReadClient + AirflowAdapter (GET only)
│   └── generic/
├── tools/                 # READ-ONLY investigation tools + registry
├── security/{sql_policy,pii,secrets,prompt_injection,auth}.py
├── agent/{triage_agent,investigation,remediation,prompts,llm_provider}.py
├── actions/               # ══ APPROVAL-GATED HEALING BOUNDARY ══
│   ├── registry.py        # ActionRegistry / ActionSpec
│   ├── approval/          # approval service
│   ├── policy/            # policy engine
│   ├── revalidation/      # live-state re-check
│   ├── executor/          # executor + reconciliation
│   ├── verification/
│   └── airflow_actions.py # AirflowActionClient + Airflow RemediationExecutor
├── api/{routes,webhooks,orchestrator}.py
├── database/{models,repository}.py
├── notifications/
├── frontend/streamlit_app.py
├── evaluation/{scenarios,evaluator}.py
├── demo/{fake_airflow,live_test,scenarios}/
├── tests/{unit,integration,security,architecture,remediation,eval}/
├── requirements.txt  .env.example  Dockerfile  docker-compose.yml  README.md  SPEC.md
B2. Platform independence and import boundaries (enforced by AST/import-linter tests)
core/, agent/, tools/, security/ must not import any platform SDK, any adapters/<platform>/ module, or anything under actions/.
actions/ must not import platform SDKs. Only actions/airflow_actions.py may speak Airflow HTTP (via httpx, no Airflow package).
agent/ and tools/ can never import actions/. core/remediation/ contains no executor, no HTTP client, and no capability to mutate anything.
AirflowActionClient may be constructed only inside actions/. Only api/ (approval handler / orchestrator) may call actions.executor.
No if platform == "airflow" in core.
B3. Stack

Python 3.11+, FastAPI, Streamlit, Pydantic v2, SQLAlchemy + SQLite, httpx, pytest, python-dotenv, structured logging.

LLM: LLMProvider → AnthropicProvider, MockLLMProvider. Model from ANTHROPIC_MODEL. No API key → llm_mode = MOCK; mock output is scripted and clearly labeled. Never hard-code keys.

B4. Credential separation
AIRFLOW_READ_* → AirflowReadClient: GET only. A test asserts it has no code path issuing non-GET requests.
AIRFLOW_WRITE_* → AirflowActionClient: used only by the executor.
README documents least-privilege Airflow roles: read-only for the read client; for the action client, only the permission to clear task instances.
B5. Environment variables (put all in .env.example with safe defaults)
DEMO_MODE=true
AUTH_PROVIDER=demo                  # demo | token
HEALING_ENABLED=false
HEALING_EXECUTION_MODE=DRY_RUN      # DRY_RUN | LIVE
MAX_HEALING_CYCLES=2
APPROVAL_TTL_MINUTES=60
HIGH_RISK_APPROVALS=2
MAX_TASKS_CLEARED=25
MAX_ACTIONS_PER_DAG_PER_HOUR=2
VERIFY_POLL_SECONDS=10
VERIFY_TIMEOUT_SECONDS=600
RECONCILE_ATTEMPTS=3
RECONCILE_INTERVAL_SECONDS=5
AIRFLOW_API_BASE_URL=
AIRFLOW_API_VERSION=                # set per target Airflow version
AIRFLOW_READ_USERNAME= / AIRFLOW_READ_PASSWORD= (or token)
AIRFLOW_WRITE_USERNAME= / AIRFLOW_WRITE_PASSWORD= (or token)
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=
WEBHOOK_SECRET=
DATABASE_URL=sqlite:///./triage.db
MAX_LOG_BYTES= / MAX_EVIDENCE_BYTES= / MAX_LLM_INPUT_TOKENS=
NOTIFY_SLACK_WEBHOOK_URL=

Startup validation (fail fast): AUTH_PROVIDER=demo is refused when HEALING_EXECUTION_MODE=LIVE (see L5); LIVE requires HEALING_ENABLED=true, write credentials, and DEMO_MODE=false.

PART C: UNIVERSAL DATA MODELS (Pydantic v2, fully typed)
C1. PipelineFailureEvent

event_id, platform, orchestrator?, compute_engine?, pipeline_id, pipeline_name?, task_id?, task_name?, execution_id, platform_run_id?, attempt_number?, status, failure_time?, start_time?, end_time?, error_message?, stack_trace?, log_reference?, environment?, source_system?, target_system?, metadata

execution_id is the universal execution identifier; platform_run_id is the original Airflow identifier (dag_run_id). No other platform-specific execution-ID fields in universal models; Airflow-specific IDs (try_number, map_index) go in metadata.

C2. EvidenceItem

evidence_id, category, source, platform, timestamp?, execution_id, attempt_number?, description, value, raw_signal?, normalized_signal?, reliability, sensitivity, temporal_label, provenance, metadata

Categories: LOG, ERROR, STACK_TRACE, RUN_HISTORY, SCHEMA, DATA_QUALITY, ROW_COUNT, STATE, TRANSACTION, CODE_CHANGE, LINEAGE, UPSTREAM, DOWNSTREAM, INFRASTRUCTURE, CONFIGURATION, PERMISSION, NETWORK, RESOURCE, OTHER.
reliability: HIGH | MEDIUM | LOW | UNKNOWN. Defaults: current platform error log HIGH; current state/transaction read HIGH; recent relevant commit MEDIUM/HIGH; old monitoring record LOW/MEDIUM; user-provided description or attestation MEDIUM.
temporal_label: CURRENT | HISTORICAL | STALE | MISMATCHED.
provenance: {adapter, capability, tool, source, collected_at, investigation_cycle}.
C3. Evidence provenance

Every item answers "where did this come from?": Adapter → Capability → Tool → Source → EvidenceItem. Only collected signals are evidence. FACT and INFERENCE claims may cite only EvidenceItems.

C4. StateEvidence

mechanism, status, before_value?, after_value?, source, timestamp?, execution_id, reliability, metadata

Mechanisms: watermark, checkpoint, batch_id, kafka_offset, delta_version, cursor, transaction_id, control_table, partition_state, job_state, none, unknown. Statuses (always distinct): NOT_APPLICABLE, UNAVAILABLE, UNKNOWN, AVAILABLE_BUT_UNCHANGED, AVAILABLE_AND_CHANGED. Never convert UNAVAILABLE or UNKNOWN into unchanged.

C5. TaskExecutionPolicy

task_type, write_mode, idempotent: bool|None, state_mechanism, retry_behavior, duplicate_risk, partial_write_risk, concurrency_behavior. Task types: incremental_merge, append, overwrite, full_refresh, upsert, streaming, validation_only, snapshot. Supplied at pipeline registration; idempotent=None = unknown.

C6. Capabilities

Read: run_logs, run_history, schema, row_counts, data_quality, lineage, state_tracking, transaction_history, code_changes, infrastructure_events, configuration, permissions, upstream_status, downstream_status.

Action (ActionCapabilities, declared by the executor): retry_failed_task, retry_failed_dag_run. Generic/unsupported platforms declare none → healing NOT_APPLICABLE.

C7. Hypothesis

hypothesis_id, category, subcategory, statement, status (OPEN|CONFIRMED|REJECTED|INCONCLUSIVE), supporting_evidence_ids, contradicting_evidence_ids, missing_evidence, rank

C8. Claim

claim_id, text, kind (FACT|INFERENCE|RECOMMENDATION), evidence_ids, evidence_categories. FACT and INFERENCE require ≥1 evidence ID.

C9. RemediationPlan (first-class)
remediation_id, incident_id, investigation_cycle, plan_version
plan_hash                     # ALWAYS computed server-side from the persisted plan; never accepted from a client
remediation_class             # AUTOMATABLE | MANUAL_FIX_REQUIRED | NO_ACTION_REQUIRED | BLOCKED
action_type                   # RETRY_FAILED_TASK | RETRY_FAILED_DAG_RUN (null unless AUTOMATABLE)
recovery_scope                # FAILED_TASK | FAILED_DAG_RUN (V1 allows only these)
target                        # {dag_id, dag_run_id, task_id? (FAILED_TASK only)}
task_instances_to_clear       # explicit enumerated list: [{task_id, map_index?, try_number, observed_state}]
parameters                    # derived by code; only_failed is fixed true
reason: Claim                 # grounded; LLM-written text, deterministic facts
supporting_evidence_ids
cause_cleared_evidence_ids    # required for AUTOMATABLE (see L1)
remediation_confidence        # HIGH | MEDIUM | LOW (deterministic)
remediation_confidence_basis
rerun_safety, rerun_safety_rule_trace
preconditions                 # machine-checkable
conditions                    # from SAFE_WITH_CONDITIONS; each must be acknowledged by the approver
risk_level                    # LOW | MEDIUM | HIGH (deterministic, L2)
expected_effect, rollback_description
requires_approval             # ALWAYS true; a validator rejects false
approval_status               # PENDING | APPROVED | REJECTED | EXPIRED | CANCELLED
approved_by?, approved_at?, rejected_by?, rejected_at?, rejection_reason?, expires_at
action_execution_id?, idempotency_key?
execution_status              # NOT_EXECUTED | QUEUED | RUNNING | UNCERTAIN | SUCCESS | FAILED | BLOCKED
execution_mode                # DRY_RUN | LIVE
execution_started_at?, execution_completed_at?, execution_result?, block_reason?
verification_status           # NOT_VERIFIED | VERIFIED | RECOVERY_FAILED | INCONCLUSIVE
verification_depth            # STATE_ONLY | STATE_AND_DATA_CHECKS
verification_result?
executed                      # derived: true only if a LIVE dispatch was confirmed

plan_hash = SHA-256 over canonical JSON of: incident_id, investigation_cycle, action_type, recovery_scope, target, task_instances_to_clear, parameters, preconditions, conditions, risk_level, supporting_evidence_ids, cause_cleared_evidence_ids, rerun_safety, remediation_confidence, execution_mode. Any change creates a new plan_version, a new hash, and voids prior approvals.

Hash trust rule: the executor must recompute the canonical plan hash from the persisted plan immediately before execution and compare it with the hash recorded in the approval record. A hash supplied by a client is never trusted; it may be used only to detect that the engineer's view was stale (HTTP 409).

Non-AUTOMATABLE plans carry no action_type and can never be executed.

C10. ApprovalRecord

approval_id, remediation_id, plan_version, plan_hash (server-computed), decision (APPROVED|REJECTED), decided_by (principal_id from the auth layer), principal_type (HUMAN), role, decided_at, conditions_acknowledged, comment?, expires_at, consumed (bool).

Approval is valid only for the exact plan_hash, exact incident, exact target and scope, and within its validity window:

if now >= expires_at: approval = EXPIRED; execution = BLOCKED

Single-use: consumed by exactly one execution.

C11. AuditEvent (append-only, hash-chained)

seq, timestamp, incident_id, remediation_id?, actor (SYSTEM | LLM | HUMAN:<id>), event_type, payload, payload_hash, prev_hash, hash. verify_audit_chain() detects tampering. No update or delete path exists.

C12. Incident lifecycle (enforced state machine)

States: DETECTED → INVESTIGATING → DIAGNOSED → PLAN_PROPOSED → AWAITING_APPROVAL → (APPROVED | REJECTED | EXPIRED | CANCELLED) → POLICY_VALIDATING → REVALIDATING → EXECUTING → (VERIFYING | EXECUTION_UNCERTAIN → RECONCILING) → (RESOLVED | RE_INVESTIGATING | ESCALATED | BLOCKED), plus NO_ACTION_REQUIRED, MANUAL_FIX_REQUIRED, AWAITING_FIX_CONFIRMATION.

A transition table in core/remediation/ raises on illegal transitions. REJECTED, EXPIRED, CANCELLED, BLOCKED are terminal for that plan and never lead to execution. Every transition writes an AuditEvent.

C13. UniversalTriageReport

incident_id, pipeline_id, pipeline_name, platform, orchestrator, compute_engine, task_id, execution_id, platform_run_id, attempt_number, failure_category, failure_subcategory, confidence, confidence_basis, root_cause: Claim, primary_failure: Claim, contributing_causes[], downstream_symptoms[], evidence[], hypotheses[], rejected_hypotheses[], suggested_fix: Claim (human-readable; literal flag executed=false), remediation_class, remediation_confidence, remediation_confidence_basis, rerun_safety, rerun_safety_reason, rerun_safety_rule_trace, impact, affected_assets[], state_mechanism, available_capabilities, action_capabilities, capability_status, missing_evidence[], limitations[], tool_calls[], llm_mode (LIVE|MOCK), status (COMPLETE|INCOMPLETE_UNGROUNDED|INSUFFICIENT_EVIDENCE), incident_state, created_at, feedback_status, actual_root_cause, human_note, remediation_plan?, approval_status, healing_status, verification_status, verification_depth, investigation_cycles[]

suggested_fix is human-readable guidance. remediation_plan is the structured, possibly executable object (null for manual/no-action).

PART D: FAILURE TAXONOMY (exactly 14 top-level categories)
#	Category	Example subcategories
1	SOURCE_SCHEMA_DRIFT	column_missing, column_renamed, type_changed
2	DATA_QUALITY	rule_violation, null_spike, duplicate_keys, rejected_records
3	VOLUME_ANOMALY	row_count_drop, row_count_spike, empty_source
4	CODE_LOGIC_BUG	recent_change, unhandled_case
5	INFRASTRUCTURE	node_loss, cluster_terminated, disk_full
6	ORCHESTRATION_STATE	stuck_state, bad_checkpoint, scheduler_issue
7	UPSTREAM_DEPENDENCY	upstream_failed, source_unavailable, late_arrival
8	CONFIGURATION	missing_object, wrong_parameter, bad_connection_config
9	SECURITY_AUTHORIZATION	permission_denied, expired_credential
10	NETWORK_CONNECTIVITY	connection_refused, dns, timeout_network
11	RESOURCE_QUOTA	memory, quota_exceeded, throttling
12	CONCURRENCY	overlapping_run, lock_contention, write_conflict
13	TRANSIENT_RECOVERED	succeeded_on_retry
14	OTHER_UNKNOWN	(always valid)
PART E: DETERMINISTIC PRE-CLASSIFIER

Output per signal: raw_signal, normalized_signal, candidate_categories, needs_evidence. Never a final root cause. Raw text is always preserved.

Raw patterns	Normalized signal	Candidates
column not found, cannot resolve column, unresolved column, invalid column reference	SCHEMA_COLUMN_MISMATCH	SOURCE_SCHEMA_DRIFT, CODE_LOGIC_BUG, CONFIGURATION
permission denied, access denied, 403 forbidden	AUTHORIZATION_FAILURE	SECURITY_AUTHORIZATION
out of memory, OOM, memory limit exceeded	RESOURCE_MEMORY_FAILURE	RESOURCE_QUOTA, VOLUME_ANOMALY, CODE_LOGIC_BUG
connection refused, connection reset, unable to connect	NETWORK_CONNECTIVITY_FAILURE	NETWORK_CONNECTIVITY, INFRASTRUCTURE
timeout, timed out	TIMEOUT	NETWORK_CONNECTIVITY, RESOURCE_QUOTA, UPSTREAM_DEPENDENCY
table not found, object does not exist	MISSING_OBJECT	CONFIGURATION, SOURCE_SCHEMA_DRIFT, UPSTREAM_DEPENDENCY
quota exceeded, rate limit, throttled	QUOTA_EXCEEDED	RESOURCE_QUOTA
DQ gate failed, expectation failed	DQ_GATE_FAILURE	DATA_QUALITY
upstream_failed	UPSTREAM_FAILED	UPSTREAM_DEPENDENCY
duplicate key, unique constraint	DUPLICATE_KEY	DATA_QUALITY, CODE_LOGIC_BUG, CONCURRENCY, ORCHESTRATION_STATE

Ambiguous signals must populate needs_evidence and trigger additional collection.

PART F: DETERMINISTIC RERUN SAFETY

The LLM never determines rerun safety.

Inputs: StateEvidence, TaskExecutionPolicy, target_write (NONE_CONFIRMED | COMMITTED | PARTIAL_CONFIRMED | PARTIAL_POSSIBLE | UNKNOWN), concurrency (NONE_CONFIRMED | OVERLAP_CONFIRMED | UNKNOWN), failure_stage (PRE_WRITE | MID_WRITE | POST_WRITE | UNKNOWN), DQ gate finding.

Ordering (most conservative wins): UNSAFE > UNKNOWN > SAFE_WITH_CONDITIONS > SAFE. Evaluate every applicable rule, record each in rerun_safety_rule_trace, return the most conservative.

Rule	Condition	Outcome
R1	COMMITTED and non-idempotent or idempotency unknown	UNSAFE
R2	COMMITTED and idempotent	SAFE_WITH_CONDITIONS
R3	PARTIAL_CONFIRMED and non-idempotent	UNSAFE
R4	PARTIAL_CONFIRMED and idempotent	SAFE_WITH_CONDITIONS
R5	PARTIAL_POSSIBLE and non-idempotent → UNSAFE; idempotency unknown → UNKNOWN	as stated
R6	OVERLAP_CONFIRMED and non-idempotent → UNSAFE; otherwise UNKNOWN	as stated
R7	Concurrency UNKNOWN	caps at SAFE_WITH_CONDITIONS at planning time (condition: confirm no concurrent run). At execution time the live check must resolve it; unresolved → BLOCKED.
R8	Target write UNKNOWN	UNKNOWN
R9	Applicable state mechanism UNAVAILABLE or UNKNOWN	UNKNOWN
R10	Mechanism unknown and write safety not otherwise proven	UNKNOWN
R11	DQ gate failed PRE_WRITE and retry supported	SAFE_WITH_CONDITIONS
R12	NONE_CONFIRMED write, idempotent, state unchanged or NOT_APPLICABLE (mechanism none)	SAFE
R13	No rule matched	UNKNOWN

Never: infer SAFE from FAILED status; treat unavailable state as unchanged; assume a watermark; infer state from an unrelated mechanism.

PART G: DETERMINISTIC DIAGNOSTIC CONFIDENCE

The LLM may lower confidence, never raise it. Store confidence_basis listing each condition passed or failed.

HIGH: ≥2 supporting items from ≥2 categories; ≥1 HIGH-reliability item; no unresolved MEDIUM/HIGH contradiction; all supporting evidence CURRENT; no unavailable capability that would have tested the top rival hypothesis.
MEDIUM: one HIGH or two MEDIUM supporting items; contradictions only LOW reliability.
LOW: everything else, including any UNKNOWN root cause.

Remediation confidence is separate and defined in L4.

PART H: EVIDENCE MANAGEMENT
Freshness: every item tracks execution_id, attempt, timestamp, source, platform. Detect STALE, MISMATCHED_EXECUTION, MISMATCHED_ATTEMPT, UNRELATED_RUN. Useful old evidence is labeled HISTORICAL. Mismatched evidence never influences confidence. Never silently mix executions.
Huge logs: configurable max log bytes, evidence bytes, token limits; extract error region, stack trace, N surrounding lines, matching signatures; keep a reference to the original; never send unlimited logs to the LLM.
Primary vs symptoms: one primary failure per independent failed task; upstream_failed and skipped tasks are downstream symptoms (use dependency/lineage evidence). Multiple causes only with evidence.
Transient recovered: attempt 1 FAILED + attempt 2 SUCCESS → TRANSIENT_RECOVERED; preserve both attempts' evidence; remediation_class = NO_ACTION_REQUIRED. Never "retry again".
DQ failures are not automatically bugs. Check rule, severity, affected rows, rejected records, target writes, downstream impact. "The DQ gate appears to have worked as designed" is a valid conclusion → NO_ACTION_REQUIRED when no target corruption and bad records were quarantined; otherwise manual.
Re-investigation: earlier-cycle evidence is retained and labeled HISTORICAL; each new cycle's evidence is CURRENT for that cycle.
PART I: INVESTIGATION LOOP

The LLM acts as an investigator and receives only sanitized, delimited evidence. It must: inspect candidate signals → generate hypotheses → identify missing evidence → choose from the capability-filtered, read-only allowlist → evaluate returned evidence → confirm/reject/revise → stop when sufficient.

Max 5 investigative tool calls per investigation cycle. Initial context collection does not count. Deduplicate repeated requests. If insufficient → root cause UNKNOWN.
The LLM cannot select unavailable tools, create tools, execute mutation tools, override safety, override deterministic confidence, or invent evidence. Tool names outside the allowlist and malformed output are rejected.
Record every step as Hypothesis → Tool → Evidence → Decision.
A failed healing attempt starts a new cycle with its own 5-call budget, bounded by MAX_HEALING_CYCLES (default 2) per incident.
PART J: AIRFLOW ADAPTER (read side)
Real integration via REST (httpx) when credentials exist; AIRFLOW_API_BASE_URL and AIRFLOW_API_VERSION configurable. Do not guess endpoints: inspect the target version's OpenAPI spec and write contract tests against recorded fixtures.
Provides: failure normalization; get_capabilities(); get_run_output (task logs), get_run_history, get_task_state, get_pipeline_state, get_configuration, get_upstream_status, get_downstream_status; other read-only capabilities where practical.
Uses only AirflowReadClient (GET only).
No credentials → DEMO MODE with clearly labeled mock fixtures and the fake Airflow server (Part R).
PART K: INVESTIGATION TOOL REGISTRY (read-only)

Tools: get_run_output, get_run_history, get_task_state, get_pipeline_state, get_schema, compare_schema, get_row_counts, get_data_quality_results, get_transaction_history, get_state, get_code_changes, get_lineage, get_upstream_status, get_downstream_status, get_infrastructure_events, get_configuration, get_permissions.

Each declares: name, description, input schema, output schema, read_only=True, required capability.

Enforcement:

Registering a tool with read_only=False, or a name beginning with a mutation verb (create, insert, update, delete, merge, drop, alter, truncate, run, rerun, retry, trigger, restart, clear, set, write, grant, revoke, pause, unpause, approve, execute, heal, remediate), raises at import time.
LLM-facing allowlist = registry ∩ adapter capabilities. Unsupported → record UNAVAILABLE; never call; never fabricate.
A test asserts the LLM-facing registry contains zero action names.
PART L: HEALING (APPROVAL-CONTROLLED)
L1. Remediation classes and eligibility

remediation_class is shown on every report:

Class	Meaning
AUTOMATABLE	Executable plan exists; approval required.
MANUAL_FIX_REQUIRED	A human must fix the cause first. No executable plan.
NO_ACTION_REQUIRED	Nothing is broken (recovered, or a gate worked as designed).
BLOCKED	Would be automatable but is unsafe or unprovable (e.g. rerun safety UNSAFE/UNKNOWN).

Classification (deterministic, in core/remediation/):

Failure	Diagnosis	V1 result
Transient task failure, cause cleared	any	AUTOMATABLE → retry after approval
Task stuck / scheduler issue, cause cleared	any	AUTOMATABLE → retry after approval
Network / transient infra / throttling, cause cleared	any	AUTOMATABLE → retry after approval
Upstream failure, upstream now succeeded	any	AUTOMATABLE → retry after approval
Concurrency, overlapping run finished	any	AUTOMATABLE; overlapping run still active → BLOCKED
Transient recovered (attempt 2 succeeded)	any	NO_ACTION_REQUIRED
DQ gate worked as designed	any	NO_ACTION_REQUIRED
Schema drift, code bug, bad transformation, config, permission, data corruption	any	MANUAL_FIX_REQUIRED
Data quality violation with target corruption or unquarantined bad data	any	MANUAL_FIX_REQUIRED
Volume anomaly	any	MANUAL_FIX_REQUIRED
Unknown failure	low	MANUAL_FIX_REQUIRED (no plan)
Automatable category but rerun safety UNSAFE or UNKNOWN	any	BLOCKED
Unsafe partial write, non-idempotent committed write	any	BLOCKED
Automatable category but remediation confidence LOW	any	MANUAL_FIX_REQUIRED

Cause-cleared evidence (required for AUTOMATABLE). At least one CURRENT evidence item, collected after the failure time, showing the cause has changed. Examples by category: NETWORK/INFRASTRUCTURE: a later successful task sharing the same connection, pool or queue; UPSTREAM: the upstream task/DAG run now success; CONCURRENCY: the overlapping run reached a terminal state; ORCHESTRATION_STATE: the task instance state is stuck while newer runs of the DAG schedule normally. These ids go in cause_cleared_evidence_ids. Without them the class is MANUAL_FIX_REQUIRED.

Rerun-type actions are always blocked when rerun_safety is UNSAFE or UNKNOWN. There is no override in V1.

L2. Action model (exactly two V1 actions)

Intent-level actions, mapped internally to exact Airflow operations:

Action	Recovery scope	Airflow operation (internal mapping)	Default risk
RETRY_FAILED_TASK	FAILED_TASK	Clear the enumerated failed task instance(s) in the existing DAG run (only_failed)	MEDIUM
RETRY_FAILED_DAG_RUN	FAILED_DAG_RUN	Clear the enumerated failed task instances of the existing failed DAG run (only_failed)	MEDIUM

Both recover the same failed execution. Neither creates a new DAG run.

RecoveryScope is restricted to FAILED_TASK and FAILED_DAG_RUN. DAG and PIPELINE scopes do not exist in V1. A plan approved for one failed task can never execute against the entire DAG: the executor operates only on the plan's enumerated task_instances_to_clear, and approval is bound to incident + plan hash + action + target + scope.

Deterministic risk level: MEDIUM baseline; LOW if environment is non-production and scope is FAILED_TASK; HIGH if environment is production and scope is FAILED_DAG_RUN. HIGH requires HIGH_RISK_APPROVALS distinct approvers (default 2).

Rollback: clearing cannot be undone by the system. rollback_description must say so honestly and state the mitigations (enumerated scope, pre-checks, verification).

Forbidden, must not exist anywhere in the codebase: triggering a new DAG run, pausing/unpausing DAGs, marking tasks or runs success/failed, deleting DAG runs or metadata, setting Variables/Connections, editing DAG code, running SQL or DML, writing XCom, Git operations, modifying checkpoints/watermarks/offsets, acting on any DAG other than the incident's, shell execution. The ActionRegistry contains exactly the two actions above; adding a third requires a spec change.

ActionSpec: name, description, parameter_schema, risk_function, mutating=true, requires_approval=true (immutable), rollback_description, eligible_categories, required_action_capability, precondition_checks. Registering with requires_approval=False raises.

L3. Deterministic action selection and the planner

Selection is code in core/remediation/selector.py:

Compute the set of primary failed task instances in the incident's DAG run (cascade symptoms are those in upstream_failed whose upstream chain leads to a primary failure).
Exactly one primary failure → RETRY_FAILED_TASK, scope FAILED_TASK; task_instances_to_clear = the primary instance plus its cascade symptoms (downstream, same run, in failed or upstream_failed state).
More than one independent primary failure in the same run → RETRY_FAILED_DAG_RUN, scope FAILED_DAG_RUN; task_instances_to_clear = all failed/upstream_failed instances in that run.
Tasks in success are never in the list. If the DAG run is not in a failed state, or any observed state cannot be read → no plan (BLOCKED).
Mapped tasks: enumerate each failed mapped instance with its map_index.

The LLM planner (agent/remediation.py) receives the deterministic selection as data and writes only: the rationale reason (a grounded Claim), expected_effect, and plain-language conditions text. It may recommend downgrading to manual; it cannot change action, scope, target, parameters, or the task list. Output that attempts to is rejected.

Do not re-propose an action with an identical signature (action + target + task list) that already failed in this incident unless new CURRENT evidence supports it.

L4. Remediation confidence (deterministic, separate from diagnostic confidence)

Computed in core/reasoning/. The LLM may lower it, never raise it. Store remediation_confidence_basis.

HIGH: diagnostic confidence HIGH; rerun_safety == SAFE; cause_cleared_evidence_ids contains a HIGH-reliability CURRENT item; the same action has not previously failed in this incident; no unavailable capability that would have tested whether the cause cleared.
MEDIUM: diagnostic confidence ≥ MEDIUM; rerun_safety ∈ {SAFE, SAFE_WITH_CONDITIONS}; cause-cleared evidence present (any reliability ≥ MEDIUM); same action has not previously failed.
LOW: everything else.

Only MEDIUM or HIGH may yield an AUTOMATABLE plan. LOW → MANUAL_FIX_REQUIRED. The report and UI show root-cause confidence, remediation confidence, and rerun safety side by side.

L5. Approval

Authentication. security/auth.py defines AuthProvider.authenticate(request) -> Principal | None with Principal{principal_id, principal_type (HUMAN|SERVICE), roles, auth_method}.

DemoAuthProvider: fixed demo principals (e.g. demo-engineer, HUMAN, role PIPELINE_ENGINEER/APPROVER), selected by a demo header. Constructing it raises at startup if HEALING_EXECUTION_MODE=LIVE or DEMO_MODE=false.
TokenAuthProvider: real implementation using hashed bearer tokens stored in the database, with a CLI command to create principals. The design must allow an OIDC provider to be added later without touching approval code.
The approval API never accepts an identity from the request body. decided_by comes only from the authenticated principal. Any approved_by field in a body is ignored and logged as suspicious.
Roles: VIEWER, ENGINEER (run triage, feedback, fix attestation, manual close), APPROVER (approve/reject), ADMIN (kill switches, config, principals). A pipeline has approver_ids; the approver must be listed there or be ADMIN. SERVICE principals (including the agent) can never approve.

Binding. The approval request carries plan_version, the hash the engineer saw (for stale-view detection → HTTP 409 on mismatch), and conditions_acknowledged. The server recomputes the hash from the persisted plan and stores its own value in the ApprovalRecord.

Rules.

Each condition in conditions[] must be acknowledged.
HIGH risk needs HIGH_RISK_APPROVALS distinct approvers.
Expiry (expires_at = created + APPROVAL_TTL_MINUTES) is checked at execution time, not only by a sweeper: if now >= expires_at → EXPIRED → BLOCKED.
Reject and cancel are always available and record a reason. Approval is single-use. Plan edits void approvals.
Approval can occur only through the authenticated UI/API. Notifications never carry links that approve without authentication.
L6. Policy validation (actions/policy/, deterministic)

All must pass, else BLOCKED with block_reason:

Global HEALING_ENABLED and the pipeline's healing_enabled are true; action ∈ pipeline allowed_actions.
Action ∈ ActionRegistry and the adapter declares the required action capability.
Remediation class is AUTOMATABLE; remediation confidence ∈ {MEDIUM, HIGH}; rerun safety ∈ {SAFE, SAFE_WITH_CONDITIONS}.
Risk-level approval count satisfied; approver authorized for this pipeline.
Limits: ≤ MAX_HEALING_CYCLES per incident; ≤ MAX_ACTIONS_PER_DAG_PER_HOUR; len(task_instances_to_clear) ≤ MAX_TASKS_CLEARED.
Parameters valid and bound to the incident: dag_id/dag_run_id/task_ids belong to the incident; IDs match strict patterns before use in URLs; scope matches action.
L7. Live-state re-validation (actions/revalidation/, read-only, immediately before execution)

Using the read client, require all of:

Persisted plan hash recomputed and equal to the approval record's hash; approval APPROVED, unexpired, unconsumed; approver principal still holds the role.
The DAG run is still in the failed state; every enumerated task instance is still in its observed state and the same try number; nobody already cleared or reran it.
The live set of failed/upstream_failed instances for the scope equals the approved enumerated list exactly. Any difference (more, fewer, different) → BLOCKED. Never "adjust" the plan.
No newer or overlapping active run that the task's concurrency policy forbids; if concurrency cannot be determined → BLOCKED.
rerun_safety recomputed from fresh state still permits the action (e.g. SAFE → UNKNOWN means BLOCKED).
Machine-checkable conditions are still true; human-acknowledged conditions were acknowledged.
Kill switches and execution mode are valid.

Any error, timeout, or unreadable state → BLOCKED + audit event (Rule 7).

L8. Executor (actions/executor/)

Single entry point execute_approved(plan_id):

Load persisted plan; recompute hash; run L6 then L7.
Write-ahead: atomically (compare-and-set) transition execution_status NOT_EXECUTED → QUEUED, generate action_execution_id, set idempotency_key = SHA-256(incident_id ‖ plan_hash), consume the approval, and persist all of it before any HTTP call. A second call cannot pass the compare-and-set, so a plan executes at most once.
Mode: DRY_RUN (default) records "would have cleared X" and the dry-run listing, leaves executed=false, execution_status=NOT_EXECUTED; LIVE dispatches via AirflowActionClient.
Transition to RUNNING; dispatch only the enumerated task instances; record the response.
Never auto-retry a mutating call.
Ambiguous outcome (timeout, connection drop, unparseable response, process crash): set UNCERTAIN and do not resend. Reconcile by reading Airflow state (RECONCILE_ATTEMPTS × RECONCILE_INTERVAL_SECONDS): if the enumerated instances show evidence of the clear (new try number, state reset, queued/running/success after the clear) → treat as dispatched and proceed to verification; if unchanged or unreadable → ESCALATED for a human decision. Any new attempt needs a new plan version, a new hash, and fresh approval.
On startup, any plan found in QUEUED, RUNNING, or UNCERTAIN is reconciled, never re-dispatched.
Every step writes an AuditEvent. Exceptions → FAILED or BLOCKED, never silent partial success.
L9. Verification (actions/verification/)

After a LIVE dispatch, poll with the read client every VERIFY_POLL_SECONDS up to VERIFY_TIMEOUT_SECONDS:

VERIFIED: the cleared task instances reach success and the DAG run reaches success (or all remaining tasks are as expected).
RECOVERY_FAILED: any enumerated instance reaches failed or upstream_failed.
INCONCLUSIVE: still running or unreadable at timeout. Extend once, then escalate. INCONCLUSIVE never closes the incident.

verification_depth: STATE_ONLY by default; STATE_AND_DATA_CHECKS when row-count or DQ capabilities exist and are checked. A task reaching success does not prove the data is correct. State this limitation in the README and UI; it is a known V1 limitation.

L10. Re-investigation, manual-fix loop, cycle limit
VERIFIED → RESOLVED.
RECOVERY_FAILED → new investigation cycle. The failed remediation is context, not evidence of cause; new logs are fresh evidence; earlier evidence is HISTORICAL. After MAX_HEALING_CYCLES (default 2) → ESCALATED with the full trail. Never retry, retry, retry.
Manual-fix path: for MANUAL_FIX_REQUIRED, the engineer fixes the cause outside the system, then calls POST /incidents/{id}/fix-applied with a note. This is recorded as user-provided evidence (MEDIUM reliability, an attestation, not proof). The agent re-collects fresh evidence (e.g. schema now compatible) and may then propose an AUTOMATABLE rerun plan, which goes through the complete approval path.
L11. Kill switches and modes

HEALING_ENABLED (global), per-pipeline healing_enabled, HEALING_EXECUTION_MODE, and POST /admin/healing/halt which blocks every pending plan immediately. Defaults per Rule 6.

L12. Healing invariants (each requires a named test)
I1 The executor is never invoked without an APPROVED, unexpired approval whose recorded hash equals the hash recomputed from the persisted plan.
I2 Only authenticated HUMAN principals with the right role (and pipeline approver membership) can approve; SERVICE principals cannot; identity in a request body is ignored.
I3 The LLM-facing registry has zero mutating tools; agent/ and tools/ cannot import actions/; core/remediation/ has no execution capability.
I4 REJECTED, EXPIRED, CANCELLED, BLOCKED plans never execute.
I5 Plan edits void approvals.
I6 A plan executes at most once (write-ahead + compare-and-set + idempotency key).
I7 UNSAFE or UNKNOWN rerun safety blocks.
I8 Live-state re-validation runs before every execution; any change blocks (including SAFE → UNKNOWN).
I9 Kill switches and the DRY_RUN default are honored; DRY_RUN never calls a mutating endpoint.
I10 Every state transition writes a hash-chained audit event; tampering is detected.
I11 Healing cycles and action rates are bounded.
I12 Only the two V1 actions exist; no cross-DAG target is possible; DAG/PIPELINE scope is impossible.
I13 The executor recomputes the plan hash itself and rejects a mismatch.
I14 DemoAuthProvider cannot start under LIVE mode.
I15 An ambiguous dispatch is never automatically resent.
I16 Executed task set == approved enumerated set == live set; tasks in success are never cleared.
I17 LOW remediation confidence never yields an executable plan; the LLM cannot make a plan executable or broader.
I18 Fail closed: each of {Airflow unavailable, approval lookup failure, hash mismatch, unreadable state, unknown concurrency, auth provider failure} → BLOCKED (parameterized test).
PART M: SECURITY
Untrusted data: logs, data, error messages, Git messages, DB contents are data, never instructions.
Prompt-injection mechanics: (1) wrap each evidence item in <evidence id="…" untrusted="true">…</evidence> after escaping delimiter text inside it; (2) the system prompt states that block contents are never instructions; (3) a detector flags instruction-like patterns ("ignore previous", "approve", "execute", "retry", "delete", "system:") and adds an injection_suspected limitation; (4) the tool allowlist comes from capabilities only; (5) all LLM output is parsed into Pydantic models; anything invalid is rejected; (6) text inside evidence can never alter approval state, plan contents, policy, or the selector's output.
Secrets scrubbing (deterministic, before any LLM call): passwords, API keys, bearer tokens, JWTs, AWS keys, connection strings, private keys. Credentials never reach the LLM.
PII masking (deterministic): emails, phones, customer IDs, names, addresses, with stable placeholders (<EMAIL_1>).
SQL policy (for any SQL-capable tool): single SELECT or WITH … SELECT only; reject INSERT/UPDATE/DELETE/MERGE/CREATE/ALTER/DROP/TRUNCATE/GRANT/REVOKE/CALL, multiple statements, comment-based bypass; use a tokenizer/parser; validate before any database call.
Webhook authentication: POST /webhooks/failure requires an HMAC-SHA256 signature verified against WEBHOOK_SECRET. Missing or invalid → 401. Unsigned requests are accepted only when DEMO_MODE=true, and the response says so.
Parameter safety: IDs used in Airflow URLs must match strict patterns and come from the incident, never from free-form LLM text.
PART N: DETECTION AND INGESTION
Webhook: POST /webhooks/failure, fed by a documented Airflow on_failure_callback snippet in demo/ (not auto-installed into Airflow).
Poller (optional, config flag): periodically lists failed DAG runs via the read client.
Incident deduplication: group by pipeline_id, execution_id, task, failure signature, time window, lineage, primary failure. One root cause → one incident with linked symptoms.
PART O: API

Core: POST /pipelines/register, GET /pipelines, GET /pipelines/{id}, POST /triage, GET /triage/{incident_id}, GET /reports, POST /feedback, GET /capabilities/{pipeline_id}, POST /webhooks/failure, GET /health.

Healing: GET /incidents/{id}/remediation, GET /remediation/{id}, POST /remediation/{id}/approve (body: plan_version, displayed_plan_hash, conditions_acknowledged, comment; no identity field), POST /remediation/{id}/reject, POST /remediation/{id}/cancel, GET /remediation/{id}/verification, GET /approvals/pending, POST /incidents/{id}/fix-applied, POST /incidents/{id}/manual-close, GET /incidents/{id}/audit, GET /audit/verify, POST /admin/healing/halt.

All endpoints except /health require authentication. Approve requires principal type HUMAN and role APPROVER/ADMIN plus pipeline approver membership.

PART P: UI (Streamlit, generic terminology)

Pages: Overview, Pipelines, Register Pipeline (includes healing_enabled, allowed actions, approvers, task execution policies, environment), Run Triage, Incident Details, Approvals Queue, Evidence Explorer, Audit Log, Reports, Evaluation, Settings.

Incident Details shows: platform, pipeline, task, execution, status, category, root-cause confidence / remediation confidence / rerun safety side by side, remediation class (AUTOMATABLE / MANUAL_FIX_REQUIRED / NO_ACTION_REQUIRED / BLOCKED), root cause, evidence trail (Hypothesis → Tool → Evidence → Decision), rejected hypotheses, suggested fix, rerun safety with rule trace, impact, missing evidence, human review, and a Remediation panel: action, scope, target, the enumerated task instances, risk, preconditions, conditions (checkboxes), rollback description (stating it is not reversible), expiry countdown, Approve/Reject (only for permitted principals), execution timeline, verification result and depth.

Display rules: NOT EXECUTED on every plan until a LIVE dispatch is confirmed; UNCERTAIN shown prominently when applicable; the actual state mechanism (never "Watermark" unless it is one); persistent banners for llm_mode=MOCK, DEMO MODE, DRY_RUN, FAKE AIRFLOW, and the "State-only verification" caveat; Settings shows kill-switch, mode, and auth-provider status.

PART Q: NOTIFICATIONS

Console by default; Slack/email via env vars. Triage notification: pipeline, task, category, confidence, root cause, remediation class, rerun safety, report ID. Approval-request notification: plan summary, scope, risk, expiry, link to the authenticated UI. Also notify on execution result, verification result, uncertain execution, and escalation. Never hard-code credentials.

PART R: DEMO AND FAKE AIRFLOW

demo/fake_airflow/: a small FastAPI app implementing the subset of the Airflow REST API used by the adapter and action client (DAG runs, task instances, task logs, clear task instances). Scenario fixtures control outcomes ("clear → success", "clear → fails again", "state changes before execution", "timeout after receiving", "Airflow down"). It logs every request so tests can assert which mutating endpoints were or were not called. Label it FAKE AIRFLOW (DEMO) everywhere.

Hero demo (scenario 1, build and polish this first)
Airflow task fails transiently (connection reset)
 → Agent investigates: attempts, logs, run history, later successes on the same connection
 → Root cause NETWORK_CONNECTIVITY; rerun safety SAFE; remediation class AUTOMATABLE
 → Plan: RETRY_FAILED_TASK, scope FAILED_TASK, enumerated task list
 → Engineer (authenticated, HUMAN, APPROVER) approves the exact plan
 → Policy validated → live state re-validated
 → Executor write-ahead → clears the approved task instance(s) in the fake/real Airflow
 → Task succeeds → agent verifies → INCIDENT RESOLVED

Required audit sequence for the hero run: FAILURE_RECEIVED, INCIDENT_CREATED, EVIDENCE_COLLECTED, INJECTION_SCAN_COMPLETED, INVESTIGATION_COMPLETED, ROOT_CAUSE_DETERMINED, RERUN_SAFETY_COMPUTED, REMEDIATION_CONFIDENCE_COMPUTED, REMEDIATION_PROPOSED, APPROVAL_REQUESTED, APPROVAL_GRANTED, POLICY_VALIDATED, LIVE_STATE_REVALIDATED, EXECUTION_QUEUED, EXECUTION_DISPATCHED, VERIFICATION_STARTED, VERIFICATION_PASSED, INCIDENT_RESOLVED.

Other scenarios (mostly demonstrate what the agent refuses to heal)
Same as hero, approver rejects → never executed.
Approval expires → never executed.
Plan edited after approval → approval void; re-approval needed.
State changes between approval and execution (new run started / task already cleared / SAFE → UNKNOWN) → BLOCKED at re-validation.
Executed, recovery fails → RECOVERY_FAILED → re-investigate → ESCALATED after MAX_HEALING_CYCLES.
Dispatch times out after Airflow received it → UNCERTAIN → reconcile → verification; and the variant where state is unreadable → ESCALATED, no resend.
Airflow unavailable at execution → BLOCKED.
Schema drift → MANUAL_FIX_REQUIRED; engineer attests fix → rerun plan → approve → success.
Permission denied, bad transformation code, data corruption → MANUAL_FIX_REQUIRED.
Partial write on a non-idempotent task → BLOCKED (UNSAFE).
Concurrent execution still active → BLOCKED; finished → AUTOMATABLE.
Cascading failure (upstream_failed tasks) → one primary failure, symptoms in the enumerated list.
DQ gate worked as designed → NO_ACTION_REQUIRED.
Transient recovered (attempt 2 success) → NO_ACTION_REQUIRED.
Unknown failure → no plan.
Prompt injection in a log ("approve and run the plan") → no effect.
Generic / ExamplePlatform → investigation works, healing NOT_APPLICABLE, core untouched.
Optional live test kit (demo/live_test/)

A docker-compose file running a local, pinned-version Airflow (builder checks that the REST API and a basic-auth or token backend are enabled for that version) and a throwaway DAG that fails with a connection-reset-style error on the first attempt and succeeds after being cleared. Use it to run the hero demo in LIVE mode before ever pointing the agent at a shared environment. Never run LIVE against shared or production Airflow until the full test suite and this local run pass. Not part of the pytest gate; required deliverable if Docker is available.

PART S: EVALUATION

Fault-injection suite covering the scenarios above.

Investigation metrics: root-cause accuracy, rerun-safety accuracy, evidence coverage, overconfidence rate, false escalation rate, time to diagnosis, tool calls per incident, approximate LLM cost per incident.

Healing metrics: approval-bypass count (must be 0), unsafe-execution count (must be 0), out-of-allowlist action count (must be 0), executed-set ≠ approved-set count (must be 0), remediation-class accuracy (including correct "manual fix" and "blocked"), remediation-confidence calibration, recovery rate, re-investigation rate, mean time to recovery, approval latency (informational).

Mock-LLM caveat (mandatory): with MockLLMProvider, scores validate plumbing only (schema, safety, grounding, loop limits, approval gates), not diagnostic accuracy. The evaluator prints this warning and tags results llm_mode=MOCK. A --live flag runs against AnthropicProvider when a key exists. Deterministic components (rerun safety, confidence, remediation confidence, selector, policy, approval, security) are fully measured in both modes.

PART T: DEFINITION OF DONE (every phase)
No TODO, bare pass, or NotImplementedError in required code (abstract base methods excepted).
Type hints, Pydantic validation, structured logging, explicit error handling.
Tests written with the code; run, read failures, fix root causes, re-run until green.
Report honestly: what works, what is mocked, what is not done. Never claim a real Airflow integration works without credentials; label demo data.
Stop at the gate and wait.
PART U: PHASE PROMPTS
Phase 1: Core models, deterministic logic, security

Build: skeleton; all models (Part C) including RemediationPlan, ApprovalRecord, AuditEvent; plan hashing; incident state machine; taxonomy; normalizer and pre-classifier; state abstraction; rerun safety (Part F); diagnostic confidence (Part G); remediation classification, cause-cleared check, remediation confidence (L1, L4), deterministic action selector (L3); freshness and log extraction; security modules (SQL, PII, secrets, prompt injection); AuthProvider interface with DemoAuthProvider and TokenAuthProvider; grounding validator; hash-chained audit log.

Tests: one per rerun rule R1–R13 plus conflicts (most conservative wins); five state statuses stay distinct; SQL allow/deny matrix; PII and secret masking; injection detector; confidence cases; remediation confidence cases (HIGH/MEDIUM/LOW; LOW → manual); classification table cases; selector cases (one failure, multiple failures, cascade, success tasks excluded, unreadable state → no plan); RemediationPlan(requires_approval=False) rejected; plan hash changes with every hashed field; hash computed server-side; state machine rejects illegal transitions; audit chain detects tampering; DemoAuthProvider refuses LIVE; architecture tests for B2.

Gate: pytest green. Report files, test counts, deferrals. Stop.

Phase 2: Airflow read adapter, tools, fake Airflow

Build: PipelineAdapter and RemediationExecutor interfaces; AirflowReadClient (GET only); AirflowAdapter; Generic adapter; ExamplePlatform fake (tests only); tool registry with import-time enforcement; demo/fake_airflow (read endpoints and fixtures first); capability discovery including action capabilities.

Tests: read client has no non-GET path; unsupported tools absent from the allowlist and yield UNAVAILABLE; registry rejects mutation-named or non-read-only tools; contract tests against recorded Airflow fixtures; mock data labeled; architecture tests still pass.

Gate: pytest green. Report the capability matrix. Stop.

Phase 3: Investigation agent and report

Build: LLMProvider (Anthropic, Mock); prompts; investigation loop (≤5 calls/cycle, dedup, early stop); primary-vs-symptom and cascade analysis; DQ and transient logic; claim generation; report assembly where deterministic safety, confidence, class and remediation confidence override the LLM; grounding validation; incident deduplication; planner producing rationale-only text.

Tests: call cap and dedup; non-allowlisted tool rejected; LLM claiming SAFE over UNSAFE is overridden; LLM HIGH above the ceiling is lowered; LLM attempting to change action/scope/task list is rejected; injection text cannot change the allowlist or plan; ungrounded claim blocks COMPLETE; cascade and transient scenarios; Generic and ExamplePlatform produce the same report schema; ExamplePlatform runs with zero changes under core/ and agent/ (checksum/git-diff assertion).

Gate: pytest green. Sample report and evidence trail. Stop.

Phase 4: Healing boundary (highest-risk phase; build in this order)

4a. Hero path first. actions/registry.py (two actions), approval/, policy/, revalidation/, executor/ (write-ahead, compare-and-set, idempotency key), airflow_actions.py (AirflowActionClient), verification/; fake Airflow write endpoints. Make the hero demo pass end to end against fake Airflow, including the required audit sequence, and in DRY_RUN with no mutating call.

4b. Everything that must refuse. Reject, cancel, expiry, plan edit, hash mismatch, SERVICE approver, identity in body, missing role, unacknowledged condition, HIGH-risk two-approver rule, kill switches, changed live state, unknown concurrency, Airflow unavailable.

4c. Failure handling. RECOVERY_FAILED → re-investigation → escalation at max cycles; UNCERTAIN dispatch and reconciliation; startup reconciliation; RETRY_FAILED_DAG_RUN; fix-applied attestation loop; verification outcomes.

Tests: every invariant I1–I18 maps to at least one named test; plus full scenarios 1–8 and 9, 11, 12 from Part R against fake Airflow; request-log assertions (DRY_RUN makes zero mutating calls; no second dispatch on double submit; no resend after UNCERTAIN; only enumerated tasks cleared).

Gate: pytest green and an invariant-to-test mapping table in the report. Stop.

Phase 5: Persistence, API, auth, UI, notifications

Build: SQLAlchemy models/repository (incidents, evidence, reports, plans, approvals, audit, feedback, principals); all endpoints in Part O with authentication and roles; HMAC webhook; optional poller; Streamlit pages in Part P with the remediation panel, confidence trio, remediation class, and banners; notifications; startup validation from B5.

Tests: every endpoint; auth matrix (VIEWER/ENGINEER/APPROVER/ADMIN × HUMAN/SERVICE, pipeline-approver membership); webhook signature; approve endpoint ignores body identity, returns 409 on stale hash/version, enforces TTL; audit endpoints; startup refuses unsafe configuration combinations; both servers start.

Gate: pytest green. Run instructions. Stop.

Phase 6: Evaluation, remaining scenarios, README, live kit

Build: all Part R scenarios; evaluation framework (Part S) with the mock caveat; full security test suite; README; .env.example, Dockerfile, docker-compose; optional demo/live_test/ kit.

README must include Mermaid diagrams and sections: overview and positioning statement, problem, architecture (investigation vs healing boundary and the trust-boundary diagram), why adapters, capability discovery, evidence model and provenance, taxonomy, hypothesis loop, state abstraction, rerun safety rule table, remediation classes and eligibility table, deterministic action selection, recovery scope, remediation confidence, approval workflow and auth providers, policy and live re-validation, executor write-ahead and idempotency, verification and its limits (state-only), re-investigation and cycle limit, kill switches and modes, security model (PII, secrets, injection, SQL, auth, HMAC), Airflow least-privilege roles, first-live-test procedure, generic onboarding, API, UI, demos, evaluation (with caveat), installation, env vars, running locally, running tests, adding a new platform (adapter + RemediationExecutor, core untouched), limitations, roadmap.

Gate: pytest green; all demos run in DEMO MODE; hero demo documented step by step. Stop.

PART V: FINAL VALIDATION CHECKLIST (prove each with test output)
 core/, agent/, tools/, security/ import nothing from actions/, adapters, or platform SDKs
 core/remediation/ has no execution capability
 Read client is GET-only; AirflowActionClient constructed only in actions/
 LLM-facing registry has zero mutating tools
 Capability-aware tool selection; no fabricated evidence
 Normalization keeps raw and normalized signals; provenance on every evidence item
 Freshness and reliability tracked; mismatched evidence excluded from confidence
 Watermark optional; five state statuses distinct
 Rerun safety deterministic with rule trace; LLM cannot override
 Diagnostic confidence and remediation confidence deterministic; LLM cannot raise either
 Remediation class correct for every row of the L1 table
 Action, scope, target, and task list chosen by code; LLM cannot change them
 Only two actions exist; no trigger/pause/mark-success anywhere
 Plans always requires_approval=true; hash server-computed; executor recomputes it
 Only authenticated HUMAN approvers can approve; body identity ignored; demo auth impossible in LIVE
 Rejected/expired/cancelled/blocked plans never execute; expiry enforced at execution time
 UNSAFE/UNKNOWN rerun safety blocks; no override
 Live-state re-validation blocks changed worlds; executed set == approved set == live set
 Executor is write-ahead, single-use, idempotent; ambiguous dispatch never resent
 Fail-closed tests pass for every Rule 7 example
 DRY_RUN default; kill switches work
 Verification outcomes work; state-only limitation documented; bounded re-investigation; escalation after max cycles
 Audit chain complete and tamper-evident; hero audit sequence matches
 SQL, injection, PII, secrets tests pass; webhook HMAC enforced
 Grounding blocks COMPLETE on unsupported claims
 Feedback, dedup, NO_ACTION_REQUIRED, and manual-fix loop work
 All demos run in DEMO MODE with mock data labeled; hero demo works end to end
 ExamplePlatform works with zero core changes; healing NOT_APPLICABLE for it
 pytest passes; README complete
PART W: FINAL OUTPUT

Provide: project structure; architecture explanation (investigation vs healing boundary, trust-boundary diagram); adapter and executor explanation; capability model; evidence and state models; rerun safety; remediation classes, confidence, and action selection; approval workflow and auth; policy and live re-validation; executor semantics; verification and its limits; agent reasoning flow; security model; how to run locally; demo commands (hero first); test results mapped to invariants I1–I18; one example triage report with remediation plan; one example evidence trail; the hero demo audit chain; how to run the optional local live test; how to add a new platform; known limitations; future roadmap.

Most important: build the actual application. Do not stop at architecture. Do not let the LLM mutate or choose anything executable. Do not execute without explicit, authenticated human approval of the exact plan. Do not fabricate evidence. Do not make watermark mandatory. Fail closed.