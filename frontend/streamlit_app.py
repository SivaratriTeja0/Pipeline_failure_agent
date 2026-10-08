"""Streamlit UI (spec Part P):  streamlit run frontend/streamlit_app.py

Talks only to the API (TRIAGE_API_URL, default http://localhost:8000) as the signed-in principal
(bearer token, or a demo principal when the API runs the demo auth provider). The UI never decides
anything: Approve/Reject are shown only to permitted principals, and the API enforces it regardless.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from api_client import ApiError, TriageApi  # noqa: E402

PAGES = ["Overview", "Pipelines", "Register Pipeline", "Run Triage", "Incident Details", "Approvals Queue",
         "Evidence Explorer", "Audit Log", "Reports", "Evaluation", "Settings"]
DEMO_PRINCIPALS = ["demo-engineer", "demo-approver-2", "demo-viewer", "demo-admin", "demo-agent"]
API_URL = os.environ.get("TRIAGE_API_URL", "http://localhost:8000")
HERO_FAILURE = {"dag_id": "sales_etl", "dag_run_id": "scheduled__2026-10-08T00:00:00+00:00", "task_id": "load",
                "try_number": 1, "state": "failed", "end_date": "2026-10-09T00:04:10+00:00",
                "exception": "psycopg2.OperationalError: Connection reset by peer"}


# ----------------------------------------------------------------------------- session / client


def client() -> TriageApi:
    return TriageApi(API_URL, token=st.session_state.get("token") or None,
                     demo_principal=st.session_state.get("demo_principal") or None)


def call(fn, *args: Any) -> Any:
    try:
        return fn(*args)
    except ApiError as exc:
        st.error(f"API refused ({exc.status}): {exc.detail}")
    except Exception as exc:  # network errors: show, never crash the page
        st.error(f"API unreachable at {API_URL}: {type(exc).__name__}")
    return None


def banners(health: dict[str, Any]) -> None:
    b = health.get("banners", {})
    if b.get("llm_mode") == "MOCK":
        st.warning("llm_mode=MOCK - scripted mock LLM output; diagnostic accuracy is not validated.")
    if b.get("demo_mode"):
        st.warning("DEMO MODE - demo principals and demo data.")
    if b.get("fake_airflow"):
        st.warning("FAKE AIRFLOW (DEMO) - evidence and actions target an in-process fake Airflow.")
    if b.get("demo_clock"):
        st.warning("DEMO CLOCK - time starts at the demo scenario's 'now' so fixture timestamps line up.")
    if b.get("dry_run"):
        st.info("DRY_RUN - approved plans are recorded as 'would have cleared'; nothing is dispatched.")
    if b.get("halted"):
        st.error("HEALING HALTED by an administrator - every pending plan is blocked.")
    st.caption("State-only verification: a task reaching success does not prove the data is correct.")


def sidebar(health: dict[str, Any]) -> str:
    st.sidebar.title("Pipeline Triage")
    if health.get("banners", {}).get("auth_provider") == "demo":
        st.session_state["demo_principal"] = st.sidebar.selectbox("Demo principal (DEMO MODE)", DEMO_PRINCIPALS)
    else:
        st.session_state["token"] = st.sidebar.text_input("Bearer token", type="password",
                                                          value=st.session_state.get("token", ""))
    params = st.query_params
    default = params.get("page", "Overview")
    page = st.sidebar.radio("Page", PAGES, index=PAGES.index(default) if default in PAGES else 0)
    if params.get("incident"):
        st.session_state.setdefault("incident_id", params.get("incident"))
    return page


# ----------------------------------------------------------------------------- pages


def page_overview(api: TriageApi) -> None:
    st.header("Overview")
    incidents = call(api.get, "/incidents") or []
    states: dict[str, int] = {}
    for incident in incidents:
        states[incident["state"]] = states.get(incident["state"], 0) + 1
    cols = st.columns(max(len(states), 1))
    for col, (state, count) in zip(cols, sorted(states.items())):
        col.metric(state, count)
    st.subheader("Latest reports")
    st.dataframe(call(api.get, "/reports") or [], width="stretch")


def page_pipelines(api: TriageApi) -> None:
    st.header("Pipelines")
    pipelines = call(api.get, "/pipelines") or []
    for p in pipelines:
        with st.expander(f"{p['pipeline_id']} ({p['platform']}) - healing {'ON' if p['healing_enabled'] else 'off'}"):
            st.json(p)
            caps = call(api.get, f"/capabilities/{p['pipeline_id']}")
            if caps:
                st.write(f"Healing: **{caps['healing']}**; actions: {caps['action_capabilities'] or 'none'}")
                st.dataframe([{"tool": k, "status": v} for k, v in caps["tools"].items()])
    if not pipelines:
        st.info("No pipelines registered yet.")


def page_register(api: TriageApi) -> None:
    st.header("Register Pipeline")
    with st.form("register"):
        pipeline_id = st.text_input("Pipeline id", "sales_etl")
        name = st.text_input("Name", "Sales ETL")
        platform = st.selectbox("Platform", ["airflow", "generic"])
        environment = st.text_input("Environment", "production")
        healing = st.checkbox("healing_enabled (requires a HUMAN ADMIN)", value=False)
        actions = st.multiselect("Allowed actions", ["RETRY_FAILED_TASK", "RETRY_FAILED_DAG_RUN"],
                                 default=["RETRY_FAILED_TASK"])
        approvers = st.text_input("Approver ids (comma-separated)", "")
        policies = st.text_area("Task execution policies (JSON: task_id -> policy)", json.dumps({
            "load": {"task_type": "upsert", "write_mode": "merge", "idempotent": True, "state_mechanism": "none",
                     "concurrency_behavior": "forbid_overlap"}}, indent=2), height=180)
        if st.form_submit_button("Register"):
            try:
                body = {"pipeline_id": pipeline_id, "pipeline_name": name, "platform": platform,
                        "environment": environment, "healing_enabled": healing, "allowed_actions": actions,
                        "approver_ids": [a.strip() for a in approvers.split(",") if a.strip()],
                        "task_policies": json.loads(policies or "{}")}
            except ValueError:
                st.error("Task policies must be valid JSON.")
                return
            if call(api.post, "/pipelines/register", body):
                st.success(f"Registered {pipeline_id}")


def page_run_triage(api: TriageApi) -> None:
    st.header("Run Triage")
    pipelines = [p["pipeline_id"] for p in (call(api.get, "/pipelines") or [])]
    if not pipelines:
        st.info("Register a pipeline first.")
        return
    pipeline_id = st.selectbox("Pipeline", pipelines)
    failure = st.text_area("Failure payload (JSON)", json.dumps(HERO_FAILURE, indent=2), height=200)
    manual = st.text_area("Manual evidence (generic platform, JSON list)", "[]", height=100)
    if st.button("Run triage"):
        try:
            body = {"pipeline_id": pipeline_id, "failure": json.loads(failure), "manual_evidence": json.loads(manual)}
        except ValueError:
            st.error("Payloads must be valid JSON.")
            return
        result = call(api.post, "/triage", body)
        if result:
            st.session_state["incident_id"] = result.get("incident_id")
            st.success(f"Incident {result.get('incident_id')} "
                       + (f"(deduplicated: {result['deduplicated']})" if result.get("deduplicated") else ""))


def _incident_picker(api: TriageApi) -> str | None:
    incidents = call(api.get, "/incidents") or []
    ids = [i["incident_id"] for i in incidents]
    if not ids:
        st.info("No incidents yet.")
        return None
    current = st.session_state.get("incident_id")
    choice = st.selectbox("Incident", ids, index=ids.index(current) if current in ids else 0)
    st.session_state["incident_id"] = choice
    return choice


def remediation_panel(api: TriageApi, view: dict[str, Any], may_approve: bool, audit: list[dict[str, Any]]) -> None:
    plan = view["plan"]
    st.subheader("Remediation")
    status = plan["execution_status"]
    if status == "UNCERTAIN":
        st.error("EXECUTION UNCERTAIN - the outcome is unknown; it was NOT resent. A human must decide.")
    if not plan["executed"]:
        st.warning("NOT EXECUTED")
    target = plan.get("target") or {}
    c1, c2, c3 = st.columns(3)
    c1.write(f"**Action:** {plan['action_type']}")
    c2.write(f"**Scope:** {plan['recovery_scope']}")
    c3.write(f"**Risk:** {plan['risk_level']} ({view['approvals_required']} approval(s))")
    st.write(f"**Target:** {target.get('dag_id')} / {target.get('dag_run_id')} / {target.get('task_id') or '*'}")
    st.dataframe(plan["task_instances_to_clear"], width="stretch")
    st.write("**Preconditions:** " + "; ".join(p["description"] for p in plan["preconditions"]))
    st.write(f"**Rollback:** {plan['rollback_description']}")
    expires = datetime.fromisoformat(plan["expires_at"])
    remaining = expires - datetime.now(timezone.utc)
    st.write(f"**Approval:** {plan['approval_status']} - expires {plan['expires_at']} "
             f"({'expired' if remaining.total_seconds() <= 0 else f'{int(remaining.total_seconds() // 60)} min left'})")
    st.write(f"**Execution:** {status} ({plan['execution_mode']})  **Verification:** {plan['verification_status']} "
             f"({plan['verification_depth']})")
    if plan.get("verification_result"):
        st.json(plan["verification_result"])

    acknowledged = [c["condition_id"] for c in plan["conditions"]
                    if st.checkbox(f"{c['condition_id']}: {c['text']}", key=f"ack-{plan['remediation_id']}-{c['condition_id']}")]
    may_act = may_approve and plan["approval_status"] == "PENDING" and status == "NOT_EXECUTED"
    if may_act:
        a, r = st.columns(2)
        if a.button("Approve this exact plan", key=f"approve-{plan['remediation_id']}"):
            body = {"plan_version": plan["plan_version"], "displayed_plan_hash": view["server_plan_hash"],
                    "conditions_acknowledged": acknowledged}
            if call(api.post, f"/remediation/{plan['remediation_id']}/approve", body):
                st.success("Approval recorded.")
        reason = r.text_input("Rejection reason", key=f"reason-{plan['remediation_id']}")
        if r.button("Reject", key=f"reject-{plan['remediation_id']}"):
            if call(api.post, f"/remediation/{plan['remediation_id']}/reject", {"reason": reason}):
                st.success("Rejected.")
    st.write("**Execution timeline**")
    timeline = [e for e in audit if e.get("remediation_id") == plan["remediation_id"]]
    st.dataframe([{"seq": e["seq"], "time": e["timestamp"], "actor": e["actor"], "event": e["event_type"]}
                  for e in timeline], width="stretch")


def page_incident(api: TriageApi) -> None:
    st.header("Incident Details")
    incident_id = _incident_picker(api)
    if not incident_id:
        return
    report = call(api.get, f"/triage/{incident_id}")
    if not report:
        return
    pending = {v["plan"]["remediation_id"]: v["caller_may_approve"] for v in (call(api.get, "/approvals/pending") or [])}
    st.write(f"**Platform:** {report['platform']}  **Pipeline:** {report['pipeline_id']}  "
             f"**Task:** {report['task_id']}  **Execution:** {report['execution_id']}")
    st.write(f"**State:** {report['incident_state']}  **Report status:** {report['status']}  "
             f"**Category:** {report['failure_category']}/{report.get('failure_subcategory') or '-'}")
    trio = st.columns(3)
    trio[0].metric("Root-cause confidence", report["confidence"])
    trio[1].metric("Remediation confidence", report["remediation_confidence"])
    trio[2].metric("Rerun safety", report["rerun_safety"])
    st.subheader(f"Remediation class: {report['remediation_class']}")
    st.write(f"**Root cause:** {report['root_cause']['text']}")
    st.write(f"**Primary failure:** {report['primary_failure']['text']}")
    for symptom in report["downstream_symptoms"]:
        st.write(f"- symptom: {symptom['text']}")
    st.write(f"**State mechanism:** {report['state_mechanism']}")
    st.subheader("Evidence trail (Hypothesis -> Tool -> Evidence -> Decision)")
    st.dataframe([{"hypothesis": t["hypothesis_id"], "tool": t["tool"], "evidence": ", ".join(t["evidence_ids"]),
                   "decision": t["decision"]} for t in report["tool_calls"]], width="stretch")
    st.subheader("Rejected hypotheses")
    st.write(report["rejected_hypotheses"] or "none")
    st.subheader("Suggested fix (not executed)")
    st.write(report["suggested_fix"]["claim"]["text"])
    st.subheader("Rerun safety")
    st.write(report["rerun_safety_reason"])
    st.dataframe(report["rerun_safety_rule_trace"], width="stretch")
    st.write(f"**Impact:** {report.get('impact') or '-'}")
    st.write(f"**Missing evidence:** {', '.join(report['missing_evidence']) or 'none'}")
    st.write("**Limitations:**")
    for limitation in report["limitations"]:
        st.write(f"- {limitation}")

    audit = (call(api.get, f"/incidents/{incident_id}/audit") or {}).get("events", [])
    remediation = call(api.get, f"/incidents/{incident_id}/remediation") or {}
    for view in remediation.get("plans", []):
        remediation_panel(api, view, pending.get(view["plan"]["remediation_id"], False), audit)

    st.subheader("Human review")
    with st.form("feedback"):
        verdict = st.selectbox("Diagnosis was", ["CONFIRMED", "INCORRECT", "PARTIALLY_CORRECT"])
        actual = st.text_input("Actual root cause (optional)")
        note = st.text_area("Note")
        if st.form_submit_button("Submit feedback"):
            if call(api.post, "/feedback", {"incident_id": incident_id, "feedback_status": verdict,
                                            "actual_root_cause": actual or None, "human_note": note or None}):
                st.success("Feedback recorded.")
    if report["incident_state"] == "MANUAL_FIX_REQUIRED":
        fix_note = st.text_area("Describe the fix you applied (an attestation, not proof)")
        if st.button("I applied a fix - re-investigate") and fix_note:
            if call(api.post, f"/incidents/{incident_id}/fix-applied", {"note": fix_note}):
                st.success("Attestation recorded; re-investigation complete.")
    close_note = st.text_input("Manual close note")
    if st.button("Close incident manually") and close_note:
        if call(api.post, f"/incidents/{incident_id}/manual-close", {"note": close_note}):
            st.success("Closed.")


def page_approvals(api: TriageApi) -> None:
    st.header("Approvals Queue")
    pending = call(api.get, "/approvals/pending") or []
    if not pending:
        st.info("Nothing awaiting approval.")
    for view in pending:
        plan = view["plan"]
        st.write(f"**{plan['remediation_id']}** v{plan['plan_version']} - {plan['action_type']} "
                 f"{plan['recovery_scope']} risk {plan['risk_level']} - {view['valid_approvals']}/"
                 f"{view['approvals_required']} approvals - expires {plan['expires_at']} - "
                 f"{'you may approve' if view['caller_may_approve'] else 'you cannot approve'}")
        if st.button("Open", key=f"open-{plan['remediation_id']}"):
            st.session_state["incident_id"] = plan["incident_id"]
            st.info("Select 'Incident Details' in the sidebar.")


def page_evidence(api: TriageApi) -> None:
    st.header("Evidence Explorer")
    incident_id = _incident_picker(api)
    report = call(api.get, f"/triage/{incident_id}") if incident_id else None
    if not report:
        return
    categories = sorted({e["category"] for e in report["evidence"]})
    chosen = st.multiselect("Categories", categories, default=categories)
    rows = [{"id": e["evidence_id"], "category": e["category"], "reliability": e["reliability"],
             "temporal": e["temporal_label"], "attempt": e.get("attempt_number"),
             "adapter": e["provenance"]["adapter"], "capability": e["provenance"]["capability"],
             "tool": e["provenance"]["tool"], "source": e["provenance"]["source"],
             "cycle": e["provenance"]["investigation_cycle"], "description": e["description"]}
            for e in report["evidence"] if e["category"] in chosen]
    st.dataframe(rows, width="stretch")


def page_audit(api: TriageApi) -> None:
    st.header("Audit Log")
    if st.button("Verify the whole chain"):
        result = call(api.get, "/audit/verify")
        if result:
            (st.success if result["valid"] else st.error)(json.dumps(result))
    incident_id = _incident_picker(api)
    events = (call(api.get, f"/incidents/{incident_id}/audit") or {}).get("events", []) if incident_id else []
    st.dataframe([{"seq": e["seq"], "time": e["timestamp"], "actor": e["actor"], "event": e["event_type"],
                   "hash": e["hash"][:12]} for e in events], width="stretch")


def page_reports(api: TriageApi) -> None:
    st.header("Reports")
    reports = call(api.get, "/reports") or []
    st.dataframe(reports, width="stretch")
    if reports:
        st.download_button("Download JSON", json.dumps(reports, indent=2), file_name="reports.json")


def page_evaluation(api: TriageApi) -> None:
    st.header("Evaluation")
    st.warning("With the mock LLM, evaluation scores validate plumbing only (schema, safety, grounding, loop "
               "limits, approval gates), not diagnostic accuracy.")
    results = Path(__file__).resolve().parent.parent / "evaluation" / "results" / "latest.json"
    if results.is_file():
        st.json(json.loads(results.read_text(encoding="utf-8")))
    else:
        st.info("No evaluation results found. The evaluation suite (python -m evaluation.evaluator) is "
                "delivered in Phase 6 and writes evaluation/results/latest.json.")


def page_settings(api: TriageApi) -> None:
    st.header("Settings")
    settings = call(api.get, "/settings")
    if not settings:
        return
    st.write(f"**Kill switches:** HEALING_ENABLED={settings['kill_switches']['HEALING_ENABLED']}, "
             f"halted={settings['kill_switches']['halted']}")
    st.write(f"**Execution mode:** {settings['execution_mode']}  **Auth provider:** {settings['auth_provider']} "
             f"({'ok' if settings['auth_provider_ok'] else 'UNAVAILABLE'})  **Demo mode:** {settings['demo_mode']}")
    st.json(settings["limits"])
    st.caption(settings["verification"]["caveat"])
    reason = st.text_input("Halt reason")
    if st.button("HALT ALL HEALING (ADMIN)") and reason:
        result = call(api.post, "/admin/healing/halt", {"reason": reason})
        if result:
            st.error(f"Healing halted; blocked plans: {result['blocked_plans']}")


RENDERERS = {"Overview": page_overview, "Pipelines": page_pipelines, "Register Pipeline": page_register,
             "Run Triage": page_run_triage, "Incident Details": page_incident, "Approvals Queue": page_approvals,
             "Evidence Explorer": page_evidence, "Audit Log": page_audit, "Reports": page_reports,
             "Evaluation": page_evaluation, "Settings": page_settings}


def main() -> None:
    st.set_page_config(page_title="Pipeline Triage", layout="wide")
    try:
        health = TriageApi(API_URL).health()
    except Exception as exc:
        st.error(f"API unreachable at {API_URL}: {type(exc).__name__}")
        return
    page = sidebar(health)
    banners(health)
    RENDERERS[page](client())


main()
