"""TriageAgent: evidence collection -> LLM investigation -> deterministic verdicts -> report.

The LLM proposes a diagnosis and writes text. Deterministic code decides, and overrides the LLM
on: rerun safety, diagnostic confidence (ceiling), remediation class, remediation confidence,
primary-vs-symptom analysis, transient recovery, and every executable field of the plan.
This module never imports actions/: it produces data (a RemediationPlan) and nothing else.
"""

from collections.abc import Callable
from datetime import datetime

from pydantic import BaseModel, Field

from adapters.base.interfaces import AdapterError, PipelineAdapter
from agent.evidence_pipeline import EvidencePipeline, SanitizeReport
from agent.investigation import InvestigationLoop, InvestigationOutcome
from agent.llm_provider import MOCK_LABEL, LLMProvider
from agent.remediation import write_rationale
from agent.schemas import LLMHypothesis
from core.canonical import canonical_hash
from core.config import Settings
from core.evidence.conventions import CAUSE_CLEARED_CANDIDATE, FIX_ATTESTATION
from core.evidence.freshness import FreshnessContext
from core.evidence.normalizer import NormalizedSignal
from core.models.base import utcnow
from core.models.enums import (
    ActionCapability,
    ActionType,
    AuditEventType,
    ClaimKind,
    ConcurrencyStatus,
    ConfidenceLevel,
    EvidenceCategory,
    HypothesisStatus,
    IncidentState,
    LLMMode,
    ReadCapability,
    RemediationClass,
    ReportStatus,
    TemporalLabel,
)
from core.models.events import PipelineFailureEvent
from core.models.evidence import EvidenceItem
from core.models.pipeline import PipelineRegistration
from core.models.reads import ReadRequest, ReadStatus
from core.models.reasoning import Claim, Hypothesis, RuleEvaluation
from core.models.remediation import RemediationPlan
from core.models.report import InvestigationCycleRecord, SuggestedFix, UniversalTriageReport
from core.reasoning.confidence import ConfidenceResult, compute_diagnostic_confidence
from core.reasoning.failure_analysis import analyze_failures, assess_data_quality, detect_transient_recovered
from core.reasoning.grounding import validate_grounding
from core.reasoning.remediation_confidence import compute_remediation_confidence
from core.remediation.audit import AuditLog
from core.remediation.classification import (
    CAUSE_CLEARED_CATEGORIES,
    ClassificationInput,
    ClassificationResult,
    check_cause_cleared,
    classify_remediation,
)
from core.remediation.plan_builder import build_plan
from core.remediation.selector import RunSnapshot, SelectionResult, select_action
from core.remediation.state_machine import IncidentStateMachine
from core.safety.facts import extract_safety_facts
from core.safety.facts import SafetyFacts
from core.safety.rerun_safety import (
    RerunSafetyInput,
    RerunSafetyResult,
    evaluate_rerun_safety,
    most_conservative,
)
from core.taxonomy.categories import FailureCategory, is_valid_subcategory
from core.taxonomy.preclassifier import PreClassifiedSignal, preclassify
from tools.invoker import ToolInvoker, tool_availability

INITIAL_TOOLS = ("get_run_output", "get_run_history", "get_task_state", "get_pipeline_state")
NO_EVIDENCE = "no-evidence-cited"

# Evidence category -> read capability that can produce it (for "could the cause-cleared test run?").
_CATEGORY_CAPABILITY = {
    EvidenceCategory.RUN_HISTORY: ReadCapability.RUN_HISTORY,
    EvidenceCategory.UPSTREAM: ReadCapability.UPSTREAM_STATUS,
    EvidenceCategory.INFRASTRUCTURE: ReadCapability.INFRASTRUCTURE_EVENTS,
    EvidenceCategory.NETWORK: ReadCapability.INFRASTRUCTURE_EVENTS,
    EvidenceCategory.RESOURCE: ReadCapability.INFRASTRUCTURE_EVENTS,
    EvidenceCategory.STATE: ReadCapability.STATE_TRACKING,
}
_CAPABILITY_TOOL = {
    ReadCapability.RUN_LOGS: "get_run_output", ReadCapability.RUN_HISTORY: "get_run_history",
    ReadCapability.SCHEMA: "compare_schema", ReadCapability.ROW_COUNTS: "get_row_counts",
    ReadCapability.DATA_QUALITY: "get_data_quality_results", ReadCapability.LINEAGE: "get_lineage",
    ReadCapability.STATE_TRACKING: "get_state", ReadCapability.TRANSACTION_HISTORY: "get_transaction_history",
    ReadCapability.CODE_CHANGES: "get_code_changes", ReadCapability.INFRASTRUCTURE_EVENTS: "get_infrastructure_events",
    ReadCapability.CONFIGURATION: "get_configuration", ReadCapability.PERMISSIONS: "get_permissions",
    ReadCapability.UPSTREAM_STATUS: "get_upstream_status", ReadCapability.DOWNSTREAM_STATUS: "get_downstream_status",
}
# DQ failures are not automatically bugs: always look at the DQ results and row counts (Part H).
_SIGNAL_FOLLOW_UP = {
    NormalizedSignal.DQ_GATE_FAILURE: (ReadCapability.DATA_QUALITY, ReadCapability.ROW_COUNTS),
}
_ACTION_CAPABILITY = {
    ActionType.RETRY_FAILED_TASK: ActionCapability.RETRY_FAILED_TASK,
    ActionType.RETRY_FAILED_DAG_RUN: ActionCapability.RETRY_FAILED_DAG_RUN,
}


class TriageContext(BaseModel):
    """Incident history for re-investigation cycles (L10).

    ``start_state`` is RE_INVESTIGATING for every cycle after the first. ``attestations`` are
    human fix attestations (user-provided evidence, MEDIUM reliability). A previously failed action
    may be re-proposed only if cause-cleared evidence is observed after ``evidence_after``.
    """

    incident_id: str | None = None
    investigation_cycle: int = Field(default=1, ge=1)
    start_state: IncidentState = IncidentState.DETECTED
    previously_failed_signatures: frozenset[str] = frozenset()
    new_current_evidence: bool = False
    evidence_after: datetime | None = None
    historical_evidence: list[EvidenceItem] = Field(default_factory=list)
    attestations: list[EvidenceItem] = Field(default_factory=list)


class TriageResult(BaseModel):
    report: UniversalTriageReport
    plan: RemediationPlan | None
    selection: SelectionResult | None
    classification: ClassificationResult
    rerun_safety: RerunSafetyResult
    investigation: InvestigationOutcome
    sanitize: SanitizeReport
    overrides: list[str]


def _claim(claim_id: str, text: str, kind: ClaimKind, ids: list[str],
           evidence: dict[str, EvidenceItem]) -> Claim:
    cited = list(dict.fromkeys(ids)) or ([NO_EVIDENCE] if kind is not ClaimKind.RECOMMENDATION else [])
    categories = sorted({evidence[i].category for i in cited if i in evidence}, key=lambda c: c.value)
    return Claim(claim_id=claim_id, text=text, kind=kind, evidence_ids=cited, evidence_categories=categories)


def _task_evidence(evidence: list[EvidenceItem], task_id: str | None) -> list[EvidenceItem]:
    """Evidence relevant to one task's safety facts: its own logs plus run-level items."""
    def own(item: EvidenceItem) -> bool:
        owner = item.metadata.get("task_id")
        return item.category not in (EvidenceCategory.LOG, EvidenceCategory.STACK_TRACE) or owner in (None, task_id)
    return [e for e in evidence if own(e)]


def _combine_safety(results: dict[str, RerunSafetyResult]) -> RerunSafetyResult:
    """Most conservative result across every primary failed task (the plan clears them all)."""
    if len(results) == 1:
        return next(iter(results.values()))
    outcome = most_conservative([r.outcome for r in results.values()])
    deciding = next(r for r in results.values() if r.outcome is outcome)
    trace = [RuleEvaluation(rule=t.rule, matched=t.matched, outcome=t.outcome, is_cap=t.is_cap,
                            detail=f"[{task}] {t.detail}".strip())
             for task, r in results.items() for t in r.rule_trace]
    conditions = {c.condition_id: c for r in results.values() if r.outcome is outcome for c in r.conditions}
    reason = "; ".join(f"{task}: {r.reason}" for task, r in results.items())
    return deciding.model_copy(update={"outcome": outcome, "rule_trace": trace, "reason": reason,
                                       "conditions": list(conditions.values())})


def _signals(event: PipelineFailureEvent, evidence: list[EvidenceItem]) -> list[PreClassifiedSignal]:
    texts = [event.error_message or ""] + [e.raw_signal for e in evidence if e.raw_signal]
    merged: dict[NormalizedSignal, PreClassifiedSignal] = {}
    for text in texts:
        if not text:
            continue
        for sig in preclassify(text):
            merged.setdefault(sig.normalized_signal, sig)
    recognized = [s for s in merged.values() if s.normalized_signal is not NormalizedSignal.UNRECOGNIZED]
    return recognized or list(merged.values()) or preclassify(event.error_message or "")


class TriageAgent:
    def __init__(
        self,
        adapter: PipelineAdapter,
        provider: LLMProvider,
        settings: Settings,
        audit: AuditLog,
        *,
        action_capabilities: frozenset[ActionCapability] = frozenset(),
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._adapter = adapter
        self._provider = provider
        self._settings = settings
        self._audit = audit
        self._actions = action_capabilities
        self._clock = clock

    # ------------------------------------------------------------------ helpers

    def _record(self, incident_id: str, event_type: AuditEventType, payload: dict, remediation_id: str | None = None) -> None:
        self._audit.record(incident_id=incident_id, actor="SYSTEM", event_type=event_type, payload=payload,
                           remediation_id=remediation_id)

    def _snapshot(self, event: PipelineFailureEvent, limitations: list[str]) -> RunSnapshot | None:
        try:
            return self._adapter.get_run_snapshot(event.pipeline_id, event.execution_id)
        except AdapterError as exc:
            limitations.append(f"run state unreadable: {exc}")
            return None

    @staticmethod
    def _hypotheses(raw: list[LLMHypothesis]) -> list[Hypothesis]:
        out = []
        for rank, h in enumerate(raw, start=1):
            sub = h.subcategory if is_valid_subcategory(h.category, h.subcategory) else None
            out.append(Hypothesis(hypothesis_id=h.hypothesis_id, category=h.category, subcategory=sub,
                                  statement=h.statement, status=HypothesisStatus(h.status),
                                  supporting_evidence_ids=h.supporting_evidence_ids,
                                  contradicting_evidence_ids=h.contradicting_evidence_ids,
                                  missing_evidence=h.missing_evidence, rank=rank))
        return out

    # ------------------------------------------------------------------ main entry

    def triage(
        self,
        event: PipelineFailureEvent,
        registration: PipelineRegistration,
        ctx: TriageContext | None = None,
    ) -> TriageResult:
        ctx = ctx or TriageContext()
        now = self._clock()
        cycle = ctx.investigation_cycle
        incident_id = ctx.incident_id or "inc-" + canonical_hash([event.platform, event.event_id])[:12]
        limitations: list[str] = []
        overrides: list[str] = []
        sm = IncidentStateMachine(incident_id, self._audit, state=ctx.start_state)

        self._record(incident_id, AuditEventType.FAILURE_RECEIVED,
                     {"event_id": event.event_id, "platform": event.platform, "pipeline_id": event.pipeline_id,
                      "execution_id": event.execution_id, "task_id": event.task_id, "cycle": cycle})
        if cycle == 1:
            self._record(incident_id, AuditEventType.INCIDENT_CREATED, {"cycle": cycle})
        if sm.state is not IncidentState.RE_INVESTIGATING:
            sm.transition(IncidentState.INVESTIGATING, reason=f"investigation cycle {cycle}")

        # ---------------------------------------------------------- evidence collection (not counted)
        incident = ReadRequest(pipeline_id=event.pipeline_id, execution_id=event.execution_id,
                               task_id=event.task_id, attempt_number=event.attempt_number,
                               investigation_cycle=cycle)
        invoker = ToolInvoker(self._adapter)
        allowlist = set(invoker.allowlist())
        pipeline = EvidencePipeline()
        freshness = FreshnessContext(pipeline_id=event.pipeline_id, execution_id=event.execution_id,
                                     attempt_number=event.attempt_number, investigation_cycle=cycle, now=now)
        collected: list[EvidenceItem] = []
        capability_status = {name: status.value for name, status in
                             tool_availability(self._adapter.read_capabilities()).items()}
        for tool in INITIAL_TOOLS:
            if tool not in allowlist:
                continue
            result = invoker.invoke(tool, incident)
            capability_status[tool] = result.status.value
            if result.status is ReadStatus.ERROR:
                limitations.append(f"{tool} failed: {result.detail}")
            collected.extend(result.evidence)
        # Human fix attestations are user-provided evidence for this cycle (an attestation, not proof).
        collected.extend(ctx.attestations)
        historical = [e.model_copy(update={"temporal_label": TemporalLabel.HISTORICAL}) for e in ctx.historical_evidence]
        evidence = pipeline.sanitize(EvidencePipeline.label(collected, freshness)) + historical
        self._record(incident_id, AuditEventType.EVIDENCE_COLLECTED,
                     {"count": len(evidence), "evidence_ids": [e.evidence_id for e in evidence]})
        # The reported failure message arrives from outside (webhook / API body): untrusted text.
        error_text = pipeline.scan_text("event.error_message", event.error_message or "")
        self._record(incident_id, AuditEventType.INJECTION_SCAN_COMPLETED,
                     {"suspected_evidence_ids": pipeline.report.injection_evidence_ids,
                      "patterns": pipeline.report.injection_patterns,
                      "secrets_redacted": pipeline.report.secrets_found, "pii_masked": pipeline.report.pii_found})

        # ---------------------------------------------------------- pre-classification + follow-up collection
        # Signals name the evidence that discriminates their candidates (Part E); collect what the
        # platform supports. This is deterministic context collection and does not use the LLM budget.
        signals = _signals(event, evidence)
        collected_tools = {e.provenance.tool for e in evidence}
        follow_up = [_CAPABILITY_TOOL[c] for s in signals for c in s.needs_evidence + list(_SIGNAL_FOLLOW_UP.get(s.normalized_signal, ()))
                     if _CAPABILITY_TOOL.get(c) in allowlist and _CAPABILITY_TOOL[c] not in collected_tools]
        extra: list[EvidenceItem] = []
        for tool in dict.fromkeys(follow_up):
            result = invoker.invoke(tool, incident)
            capability_status[tool] = result.status.value
            if result.status is ReadStatus.ERROR:
                limitations.append(f"{tool} failed: {result.detail}")
            extra.extend(result.evidence)
        if extra:
            evidence = evidence + pipeline.sanitize(EvidencePipeline.label(extra, freshness))
            signals = _signals(event, evidence)

        # ---------------------------------------------------------- LLM investigation
        loop = InvestigationLoop(self._provider, invoker, pipeline)
        outcome = loop.run(incident=incident, evidence=evidence, signals=signals, freshness=freshness,
                           context_extra={"event": {"pipeline_id": event.pipeline_id, "task_id": event.task_id,
                                                    "attempt": event.attempt_number}},
                           untrusted_text={"event.error_message": error_text} if error_text else None)
        evidence = outcome.evidence
        for name in outcome.tool_calls:
            capability_status[name.tool] = name.decision.split(":")[0]
        limitations.extend(outcome.limitations)
        self._record(incident_id, AuditEventType.INVESTIGATION_COMPLETED,
                     {"cycle": cycle, "tool_calls": outcome.calls_used, "rejected_requests": outcome.rejected_requests,
                      "concluded": outcome.conclusion is not None, "llm_mode": self._provider.mode.value})
        sm.transition(IncidentState.DIAGNOSED)
        by_id = {e.evidence_id: e for e in evidence}

        # ---------------------------------------------------------- deterministic failure analysis
        snapshot = self._snapshot(event, limitations)
        analysis = analyze_failures(snapshot)
        # Every primary failure's own log is needed to judge rerun safety for a multi-task plan.
        tries = {ti.task_id: ti.try_number for ti in (snapshot.task_instances if snapshot else [])}
        for task in analysis.primary_tasks if analysis.readable else []:
            if task == event.task_id or not tries.get(task):
                continue
            task_req = incident.model_copy(update={"task_id": task, "attempt_number": tries[task]})
            read = invoker.invoke("get_run_output", task_req) if "get_run_output" in allowlist else None
            if read is None or read.status is not ReadStatus.AVAILABLE:
                limitations.append(f"log of primary failure {task} unreadable")
                continue
            task_freshness = freshness.model_copy(update={"attempt_number": tries[task]})
            evidence = evidence + pipeline.sanitize(EvidencePipeline.label(read.evidence, task_freshness))
        transient = detect_transient_recovered(event.task_id, event.attempt_number, evidence)
        dq = assess_data_quality(evidence)
        conclusion = outcome.conclusion
        log_ids = [e.evidence_id for e in evidence if e.category in (EvidenceCategory.LOG, EvidenceCategory.STACK_TRACE)
                   and e.temporal_label is not TemporalLabel.MISMATCHED]
        state_ids = [e.evidence_id for e in evidence if e.category is EvidenceCategory.STATE
                     and e.temporal_label is TemporalLabel.CURRENT]

        if transient.recovered:
            category, subcategory, known = FailureCategory.TRANSIENT_RECOVERED, "succeeded_on_retry", True
            root_text = (f"Attempt {transient.failed_attempt} of {event.task_id} failed and attempt "
                         f"{transient.succeeded_attempt} succeeded; the failure was transient and has recovered.")
            root_ids = transient.evidence_ids + log_ids
            if conclusion and conclusion.category is not FailureCategory.TRANSIENT_RECOVERED:
                overrides.append(f"LLM category {conclusion.category.value} overridden: later attempt succeeded")
        elif conclusion is not None and conclusion.root_cause_known and conclusion.category is not FailureCategory.OTHER_UNKNOWN:
            category = conclusion.category
            subcategory = conclusion.subcategory if is_valid_subcategory(category, conclusion.subcategory) else None
            known, root_text, root_ids = True, conclusion.root_cause.text, conclusion.root_cause.evidence_ids
        else:
            category, subcategory, known = FailureCategory.OTHER_UNKNOWN, None, False
            root_text, root_ids = "Root cause UNKNOWN: the available evidence is insufficient.", []

        root_claim = _claim("c-root", root_text, ClaimKind.INFERENCE if known else ClaimKind.RECOMMENDATION,
                            root_ids, by_id)
        if analysis.readable and analysis.primary_tasks:
            primary_text = (f"Primary failure: task(s) {', '.join(analysis.primary_tasks)} failed in run "
                            f"{event.execution_id}.")
            primary_ids = state_ids + log_ids
        else:
            primary_text = conclusion.primary_failure.text if conclusion else f"Task {event.task_id} failed."
            primary_ids = (conclusion.primary_failure.evidence_ids if conclusion else []) or log_ids
        primary_claim = _claim("c-primary", primary_text, ClaimKind.FACT, primary_ids, by_id)
        symptom_claims = [_claim(f"c-symptom-{t}", f"Task {t} did not run because an upstream task failed "
                                 f"(downstream symptom, not a cause).", ClaimKind.FACT, state_ids, by_id)
                          for t in analysis.symptom_tasks]
        contributing = [_claim(f"c-contrib-{i}", c.text, ClaimKind.INFERENCE, c.evidence_ids, by_id)
                        for i, c in enumerate(conclusion.contributing_causes if conclusion else [], start=1)]
        if analysis.unexplained_symptoms:
            limitations.append(f"upstream_failed tasks not explained by a primary failure: {analysis.unexplained_symptoms}")
        self._record(incident_id, AuditEventType.ROOT_CAUSE_DETERMINED,
                     {"category": category.value, "subcategory": subcategory, "known": known,
                      "primary_tasks": analysis.primary_tasks, "symptom_tasks": analysis.symptom_tasks})

        grounding = validate_grounding([root_claim, primary_claim, *symptom_claims, *contributing], evidence)
        if not grounding.grounded:
            limitations.append("report has ungrounded claims: " + "; ".join(
                f"{i.claim_id}: {i.problem}" for i in grounding.issues))

        # ---------------------------------------------------------- diagnostic confidence (Part G)
        hypotheses = self._hypotheses(outcome.hypotheses)
        confirmed = next((h for h in hypotheses if h.category is category), None)
        contradicting = [by_id[i] for i in (confirmed.contradicting_evidence_ids if confirmed else []) if i in by_id]
        available = self._adapter.read_capabilities()
        unavailable_names = {c.value for c in ReadCapability} - {c.value for c in available}
        rival_untestable = any(set(h.missing_evidence) & unavailable_names
                               for h in hypotheses if h is not confirmed and h.status is not HypothesisStatus.REJECTED)
        confidence: ConfidenceResult = compute_diagnostic_confidence(
            root_cause_known=known and grounding.grounded,
            supporting=[by_id[i] for i in root_claim.evidence_ids if i in by_id],
            contradicting=contradicting,
            rival_test_capability_unavailable=rival_untestable,
            llm_suggested=conclusion.confidence if conclusion and not transient.recovered else None,
        )
        if conclusion and not transient.recovered and conclusion.confidence is not confidence.deterministic_level:
            overrides.append(f"LLM confidence {conclusion.confidence.value} -> deterministic "
                             f"{confidence.level.value} (LLM may only lower)")

        # ---------------------------------------------------------- rerun safety (Part F)
        # Evaluated for every primary failed task (a DAG-run plan clears them all); most conservative wins.
        policy = registration.policy_for(event.task_id)
        dq_signal = any(s.normalized_signal is NormalizedSignal.DQ_GATE_FAILURE for s in signals)
        safety_tasks: dict[str | None, int | None] = {event.task_id: event.attempt_number}
        if analysis.readable:
            safety_tasks.update({t: tries.get(t) for t in analysis.primary_tasks if t != event.task_id})
        per_task: dict[str, RerunSafetyResult] = {}
        all_facts: dict[str, SafetyFacts] = {}
        for task, attempt in safety_tasks.items():
            task_policy = registration.policy_for(task)
            task_facts = extract_safety_facts(_task_evidence(evidence, task), task_policy,
                                              failed_attempt=attempt, dq_signal=dq_signal)
            all_facts[str(task)] = task_facts
            per_task[str(task)] = evaluate_rerun_safety(RerunSafetyInput(
                policy=task_policy, state=None, target_write=task_facts.target_write,
                concurrency=task_facts.concurrency, failure_stage=task_facts.failure_stage,
                dq_gate=task_facts.dq_gate, retry_supported=bool(self._actions)))
        facts = all_facts[str(event.task_id)]
        rerun = _combine_safety(per_task)
        if conclusion and conclusion.rerun_safety_opinion and conclusion.rerun_safety_opinion is not rerun.outcome:
            overrides.append(f"LLM rerun-safety opinion {conclusion.rerun_safety_opinion.value} ignored; "
                             f"deterministic result {rerun.outcome.value}")
        self._record(incident_id, AuditEventType.RERUN_SAFETY_COMPUTED,
                     {"outcome": rerun.outcome.value,
                      "facts": {t: f.model_dump(mode="json") for t, f in all_facts.items()},
                      "matched_rules": [t.rule for t in rerun.rule_trace if t.matched]})

        # ---------------------------------------------------------- cause cleared + selection + L4
        candidates = [e for e in evidence if e.metadata.get(CAUSE_CLEARED_CANDIDATE)]
        cleared = check_cause_cleared(category, candidates, event.failure_time)
        fix_attested = any(by_id[i].metadata.get(FIX_ATTESTATION) is True for i in cleared.accepted_ids)
        # A failed action may be re-proposed only if cause-cleared evidence post-dates that failure.
        new_current = ctx.new_current_evidence or (ctx.evidence_after is not None and any(
            (by_id[i].timestamp or by_id[i].provenance.collected_at) > ctx.evidence_after
            for i in cleared.accepted_ids))
        raw_selection = select_action(snapshot) if snapshot is not None else None
        same_failed = bool(raw_selection and raw_selection.signature in ctx.previously_failed_signatures)
        selection = (select_action(snapshot, previously_failed_signatures=ctx.previously_failed_signatures,
                                   new_current_evidence=new_current)
                     if snapshot is not None else None)
        needed = {_CATEGORY_CAPABILITY[c] for c in CAUSE_CLEARED_CATEGORIES.get(category, frozenset())
                  if c in _CATEGORY_CAPABILITY}
        cause_untestable = bool(needed) and not (needed & available)
        rem_conf = compute_remediation_confidence(
            diagnostic_confidence=confidence.level, rerun_safety=rerun.outcome,
            cause_cleared_items=[by_id[i] for i in cleared.accepted_ids],
            same_action_previously_failed=same_failed and not new_current,
            cause_cleared_test_capability_unavailable=cause_untestable)
        self._record(incident_id, AuditEventType.REMEDIATION_CONFIDENCE_COMPUTED,
                     {"level": rem_conf.level.value, "cause_cleared_evidence_ids": cleared.accepted_ids})

        # ---------------------------------------------------------- classification (L1) + lowering adjustments
        classification = classify_remediation(ClassificationInput(
            category=category, subcategory=subcategory, root_cause_known=known,
            diagnostic_confidence=confidence.level, rerun_safety=rerun.outcome,
            remediation_confidence=rem_conf.level, cause_cleared_evidence_ids=cleared.accepted_ids,
            transient_recovered=transient.recovered, dq_gate_worked_as_designed=dq.worked_as_designed,
            dq_target_corrupted=dq.target_corrupted, dq_bad_records_quarantined=dq.bad_records_quarantined,
            overlapping_run_active=(facts.concurrency is ConcurrencyStatus.OVERLAP_CONFIRMED)
            if category is FailureCategory.CONCURRENCY else None, fix_attested=fix_attested))

        def lower(to: RemediationClass, rule: str, reason: str) -> None:
            nonlocal classification
            classification = ClassificationResult(remediation_class=to, rule=rule, reason=reason)

        if classification.remediation_class is RemediationClass.AUTOMATABLE:
            if not grounding.grounded:
                lower(RemediationClass.MANUAL_FIX_REQUIRED, "grounding", "report is not fully grounded in evidence")
            elif not self._actions:
                lower(RemediationClass.MANUAL_FIX_REQUIRED, "healing_not_applicable",
                      "platform declares no action capabilities (healing NOT_APPLICABLE)")
            elif selection is None or not selection.selected:
                lower(RemediationClass.BLOCKED, "selection",
                      f"no deterministic plan: {selection.block_reason if selection else 'run state unavailable'}")
            elif _ACTION_CAPABILITY[selection.action_type] not in self._actions:
                lower(RemediationClass.MANUAL_FIX_REQUIRED, "action_capability",
                      f"executor does not support {selection.action_type.value}")

        # ---------------------------------------------------------- plan (rationale-only LLM)
        plan: RemediationPlan | None = None
        if classification.remediation_class is RemediationClass.AUTOMATABLE and selection is not None:
            supporting = [i for i in root_claim.evidence_ids if i in by_id]
            planned = write_rationale(self._provider, selection=selection, evidence=evidence,
                                      supporting_evidence_ids=supporting,
                                      cause_cleared_evidence_ids=cleared.accepted_ids, conditions=rerun.conditions)
            if planned.rejected_reason:
                limitations.append(planned.rejected_reason)
            out = planned.output
            if out is not None and out.recommend_manual:
                lower(RemediationClass.MANUAL_FIX_REQUIRED, "planner_manual",
                      f"planner recommended manual handling: {out.manual_reason or 'no reason given'}")
            else:
                rationale = out.rationale if out else (
                    f"Cause cleared (evidence {', '.join(cleared.accepted_ids)}); rerun safety {rerun.outcome.value}; "
                    f"{selection.action_type.value} recovers the existing failed run.")
                reason = _claim("c-plan", rationale, ClaimKind.INFERENCE,
                                cleared.accepted_ids + supporting + (out.rationale_evidence_ids if out else []), by_id)
                plan = build_plan(
                    remediation_id=f"rem-{incident_id}-{cycle}", incident_id=incident_id, investigation_cycle=cycle,
                    selection=selection, reason=reason, supporting_evidence_ids=supporting,
                    cause_cleared_evidence_ids=cleared.accepted_ids, remediation_confidence=rem_conf.level,
                    remediation_confidence_basis=rem_conf.basis, rerun_safety=rerun.outcome,
                    rerun_safety_rule_trace=rerun.rule_trace, conditions=rerun.conditions,
                    environment=registration.environment, execution_mode=self._settings.healing_execution_mode,
                    now=now, approval_ttl_minutes=self._settings.approval_ttl_minutes,
                    expected_effect=out.expected_effect if out and out.expected_effect else None,
                    condition_text=out.conditions_text if out else None)
                self._record(incident_id, AuditEventType.REMEDIATION_PROPOSED,
                             {"plan_hash": plan.plan_hash, "action_type": plan.action_type.value,
                              "recovery_scope": plan.recovery_scope.value,
                              "task_instances": [t.model_dump() for t in plan.task_instances_to_clear],
                              "risk_level": plan.risk_level.value}, remediation_id=plan.remediation_id)

        final_state = {
            RemediationClass.AUTOMATABLE: IncidentState.PLAN_PROPOSED,
            RemediationClass.NO_ACTION_REQUIRED: IncidentState.NO_ACTION_REQUIRED,
            RemediationClass.MANUAL_FIX_REQUIRED: IncidentState.MANUAL_FIX_REQUIRED,
            RemediationClass.BLOCKED: IncidentState.BLOCKED,
        }[classification.remediation_class]
        sm.transition(final_state, reason=classification.reason,
                      remediation_id=plan.remediation_id if plan else None)

        # ---------------------------------------------------------- report
        if pipeline.report.injection_evidence_ids:
            limitations.append("injection_suspected: instruction-like text found in evidence "
                               f"{pipeline.report.injection_evidence_ids}; treated as data only")
        if self._provider.mode is LLMMode.MOCK:
            limitations.append(f"llm_mode=MOCK: {MOCK_LABEL}; diagnostic accuracy not validated")
        if self._adapter.is_demo:
            limitations.append("DEMO data: evidence comes from FAKE AIRFLOW (DEMO) / mock fixtures")
        if facts.target_write.value == "UNKNOWN":
            limitations.append("target write status could not be established from evidence")
        limitations.extend(f"override: {o}" for o in overrides)

        missing = sorted({m for h in hypotheses for m in h.missing_evidence}
                         | {c.value for s in signals for c in s.needs_evidence if c not in available})
        status = (ReportStatus.INCOMPLETE_UNGROUNDED if not grounding.grounded
                  else ReportStatus.INSUFFICIENT_EVIDENCE if not known else ReportStatus.COMPLETE)
        fix_text = conclusion.suggested_fix if conclusion else "Investigate manually; evidence was insufficient."
        if transient.recovered:
            fix_text = "No action required: a later attempt succeeded. Do not retry again."
        report = UniversalTriageReport(
            incident_id=incident_id, pipeline_id=event.pipeline_id,
            pipeline_name=registration.pipeline_name or event.pipeline_name, platform=event.platform,
            orchestrator=event.orchestrator, compute_engine=event.compute_engine, task_id=event.task_id,
            execution_id=event.execution_id, platform_run_id=event.platform_run_id,
            attempt_number=event.attempt_number, failure_category=category, failure_subcategory=subcategory,
            confidence=confidence.level, confidence_basis=confidence.basis, root_cause=root_claim,
            primary_failure=primary_claim, contributing_causes=contributing, downstream_symptoms=symptom_claims,
            evidence=evidence, hypotheses=hypotheses,
            rejected_hypotheses=[h for h in hypotheses if h.status is HypothesisStatus.REJECTED],
            suggested_fix=SuggestedFix(claim=_claim("c-fix", fix_text, ClaimKind.RECOMMENDATION, [], by_id)),
            remediation_class=classification.remediation_class, remediation_confidence=rem_conf.level,
            remediation_confidence_basis=rem_conf.basis, rerun_safety=rerun.outcome,
            rerun_safety_reason=rerun.reason, rerun_safety_rule_trace=rerun.rule_trace,
            impact=conclusion.impact if conclusion else "",
            affected_assets=[f"{event.pipeline_id}.{t}" for t in analysis.primary_tasks + analysis.symptom_tasks],
            state_mechanism=policy.state_mechanism, available_capabilities=sorted(available, key=lambda c: c.value),
            action_capabilities=sorted(self._actions, key=lambda c: c.value), capability_status=capability_status,
            missing_evidence=missing, limitations=list(dict.fromkeys(limitations)), tool_calls=outcome.tool_calls,
            llm_mode=self._provider.mode, status=status, incident_state=sm.state, created_at=now,
            remediation_plan=plan, approval_status=plan.approval_status if plan else None,
            healing_status=plan.execution_status if plan else None,
            investigation_cycles=[InvestigationCycleRecord(
                cycle=cycle, started_at=now, tool_calls=outcome.calls_used,
                outcome="concluded" if conclusion else "no conclusion")],
        )
        return TriageResult(report=report, plan=plan, selection=selection, classification=classification,
                            rerun_safety=rerun, investigation=outcome, sanitize=pipeline.report, overrides=overrides)
