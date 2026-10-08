"""Scripted mock investigator and planner (llm_mode = MOCK).

The script is deterministic and simple: it reads the trusted structured context, requests a
fixed sequence of allowlisted tools, then concludes from the deterministic pre-classifier's
top candidate. It validates plumbing (schemas, loop limits, grounding, safety gates), not
diagnostic accuracy, and every report produced with it is labeled MOCK.
"""

import json
from typing import Any

from agent.llm_provider import LLMRequest

TOOL_ORDER = ("get_upstream_status", "get_configuration", "get_downstream_status")

SIGNAL_SUBCATEGORY = {
    "SCHEMA_COLUMN_MISMATCH": "column_missing",
    "AUTHORIZATION_FAILURE": "permission_denied",
    "RESOURCE_MEMORY_FAILURE": "memory",
    "NETWORK_CONNECTIVITY_FAILURE": None,
    "TIMEOUT": "timeout_network",
    "MISSING_OBJECT": "missing_object",
    "QUOTA_EXCEEDED": "throttling",
    "DQ_GATE_FAILURE": "rule_violation",
    "UPSTREAM_FAILED": "upstream_failed",
    "DUPLICATE_KEY": "duplicate_keys",
}


def _open_hypotheses(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not signals:
        return [{"hypothesis_id": "h1", "category": "OTHER_UNKNOWN", "subcategory": None,
                 "statement": "[MOCK] unrecognized failure", "supporting_evidence_ids": [],
                 "contradicting_evidence_ids": [], "missing_evidence": [], "status": "OPEN"}]
    top = signals[0]
    return [{"hypothesis_id": f"h{i}", "category": cat, "subcategory": None,
             "statement": f"[MOCK] {top['normalized_signal']} may indicate {cat}", "supporting_evidence_ids": [],
             "contradicting_evidence_ids": [], "missing_evidence": list(top.get("needs_evidence", [])),
             "status": "OPEN"} for i, cat in enumerate(top["candidate_categories"], start=1)]


def _investigate(ctx: dict[str, Any]) -> dict[str, Any]:
    allow = set(ctx.get("allowlist", []))
    called = set(ctx.get("called", []))
    recognized = [s for s in ctx.get("signals", []) if s["normalized_signal"] != "UNRECOGNIZED"]
    if ctx.get("calls_remaining", 0) > 0:
        for tool in TOOL_ORDER:
            if tool in allow and tool not in called:
                return {"action": "call_tool", "reasoning": f"[MOCK] collect {tool}",
                        "hypotheses": _open_hypotheses(recognized),
                        "tool_call": {"tool": tool, "args": {}}, "conclusion": None}

    signals = [s for s in ctx.get("signals", []) if s["normalized_signal"] != "UNRECOGNIZED"]
    evidence = ctx.get("evidence", [])
    if not signals:
        return {"action": "conclude", "reasoning": "[MOCK] no recognizable signal", "hypotheses": [],
                "tool_call": None, "conclusion": {
                    "root_cause_known": False, "category": "OTHER_UNKNOWN", "subcategory": None,
                    "root_cause": {"text": "Root cause could not be determined from available evidence.",
                                   "evidence_ids": []},
                    "primary_failure": {"text": "The task failed with an unrecognized error.",
                                        "evidence_ids": [e["id"] for e in evidence if e["category"] == "LOG"][:1]},
                    "contributing_causes": [], "suggested_fix": "Investigate manually; collect more evidence.",
                    "impact": "", "confidence": "LOW", "rerun_safety_opinion": None, "limitations": []}}

    top = signals[0]
    category = top["candidate_categories"][0]
    signal_ids = [e["id"] for e in evidence if e.get("normalized_signal") == top["normalized_signal"]]
    trace_ids = [e["id"] for e in evidence if e["category"] == "STACK_TRACE"]
    cleared_ids = [e["id"] for e in evidence if e.get("cause_cleared_candidate")]
    support = list(dict.fromkeys(signal_ids + trace_ids + cleared_ids))
    hypotheses = [{"hypothesis_id": "h1", "category": category,
                   "subcategory": SIGNAL_SUBCATEGORY.get(top["normalized_signal"]),
                   "statement": f"[MOCK] {top['normalized_signal']} indicates {category}",
                   "supporting_evidence_ids": support, "contradicting_evidence_ids": [],
                   "missing_evidence": [], "status": "CONFIRMED"}]
    for i, rival in enumerate(top["candidate_categories"][1:], start=2):
        hypotheses.append({"hypothesis_id": f"h{i}", "category": rival, "subcategory": None,
                           "statement": f"[MOCK] rival explanation: {rival}",
                           "supporting_evidence_ids": [], "contradicting_evidence_ids": [],
                           "missing_evidence": list(top.get("needs_evidence", [])), "status": "INCONCLUSIVE"})
    return {"action": "conclude", "reasoning": "[MOCK] concluded from top pre-classifier candidate",
            "hypotheses": hypotheses, "tool_call": None, "conclusion": {
                "root_cause_known": True, "category": category,
                "subcategory": SIGNAL_SUBCATEGORY.get(top["normalized_signal"]),
                "root_cause": {"text": f"[MOCK] {top['raw_signal']}", "evidence_ids": support},
                "primary_failure": {"text": f"[MOCK] task {ctx.get('task_id')} failed: {top['raw_signal']}",
                                    "evidence_ids": signal_ids or support},
                "contributing_causes": [],
                "suggested_fix": f"[MOCK] address {category.lower().replace('_', ' ')} cause, then re-run",
                "impact": "", "confidence": "HIGH", "rerun_safety_opinion": None, "limitations": []}}


def _plan(ctx: dict[str, Any]) -> dict[str, Any]:
    cited = list(dict.fromkeys(ctx.get("cause_cleared_evidence_ids", []) + ctx.get("supporting_evidence_ids", [])))
    return {"rationale": f"[MOCK] The cause appears cleared (evidence {', '.join(cited[:3])}); "
                         f"{ctx.get('action_type')} recovers the existing failed run.",
            "rationale_evidence_ids": cited, "expected_effect": "", "conditions_text": {},
            "recommend_manual": False, "manual_reason": None}


def scripted_triage(request: LLMRequest) -> str:
    if request.role == "planner":
        return json.dumps(_plan(request.context))
    return json.dumps(_investigate(request.context))
