"""Every Part O endpoint, end to end through the real FastAPI app (SQLite, FAKE AIRFLOW (DEMO))."""

from datetime import timedelta

from tests.api_helpers import LISTED, build_api, plan_hash


# ---------------------------------------------------------------- core


def test_health_needs_no_auth_and_reports_banners():
    api = build_api()
    body = api.get("/health", who=None).json()
    assert body["status"] == "ok" and body["database"] is True
    assert body["banners"] == {"llm_mode": "MOCK", "demo_mode": True, "dry_run": True, "fake_airflow": True,
                               "healing_enabled": True, "execution_mode": "DRY_RUN", "auth_provider": "token",
                               "halted": False, "demo_clock": False,
                               "state_only_verification": True}


def test_register_list_get_pipeline_and_capabilities():
    api = build_api()
    assert api.register().status_code == 201
    assert [p["pipeline_id"] for p in api.get("/pipelines").json()] == ["sales_etl"]
    assert api.get("/pipelines/sales_etl").json()["approver_ids"] == LISTED
    assert api.get("/pipelines/nope").status_code == 404
    caps = api.get("/capabilities/sales_etl").json()
    assert caps["healing"] == "AVAILABLE" and caps["demo"] is True
    assert caps["action_capabilities"] == ["retry_failed_dag_run", "retry_failed_task"]
    assert caps["tools"]["get_schema"] == "UNAVAILABLE" and caps["tools"]["get_run_output"] == "AVAILABLE"
    assert api.post("/pipelines/register", who="human-admin", json={"pipeline_id": "bad id!"}).status_code == 422


def test_generic_pipeline_capabilities_have_no_healing_and_triage_with_manual_evidence():
    api = build_api()
    body = {"pipeline_id": "legacy_job", "platform": "generic", "environment": "production"}
    assert api.post("/pipelines/register", who="human-engineer", json=body).status_code == 201
    caps = api.get("/capabilities/legacy_job").json()
    assert caps["healing"] == "NOT_APPLICABLE" and caps["action_capabilities"] == []
    r = api.post("/triage", json={
        "pipeline_id": "legacy_job",
        "failure": {"execution_id": "2026-10-08", "error_message": "ERROR: permission denied for schema finance",
                    "failure_time": "2026-10-08T23:00:00+00:00"},
        "manual_evidence": [{"category": "LOG", "description": "console", "uploaded_by": "alice",
                             "content": "ERROR: permission denied for schema finance"}]})
    assert r.status_code == 201, r.text
    report = r.json()["report"]
    assert report["platform"] == "generic" and report["remediation_plan"] is None
    assert report["failure_category"] == "SECURITY_AUTHORIZATION"


def test_triage_get_triage_and_reports():
    api = build_api()
    api.register()
    r = api.triage()
    assert r.status_code == 201
    incident_id = r.json()["incident_id"]
    report = api.get(f"/triage/{incident_id}").json()
    assert report["remediation_class"] == "AUTOMATABLE" and report["incident_state"] == "AWAITING_APPROVAL"
    assert report["remediation_plan"]["approval_status"] == "PENDING"
    listing = api.get("/reports").json()
    assert listing[0]["incident_id"] == incident_id and listing[0]["llm_mode"] == "MOCK"
    assert api.get("/reports", params={"pipeline_id": "other"}).json() == []
    assert api.get("/triage/inc-unknown").status_code == 404
    assert len(api.get(f"/incidents/{incident_id}/reports").json()) == 1
    assert api.get("/incidents").json()[0]["state"] == "AWAITING_APPROVAL"


def test_triage_rejects_unregistered_or_mismatched_pipeline():
    api = build_api()
    assert api.triage().status_code == 404
    api.register()
    bad = api.post("/triage", json={"pipeline_id": "sales_etl", "failure": {"dag_id": "other_dag",
                                                                           "dag_run_id": "r1", "task_id": "x"}})
    assert bad.status_code == 422


def test_duplicate_failure_is_deduplicated_into_the_same_incident():
    api = build_api()
    api.register()
    first = api.triage().json()
    again = api.triage().json()
    assert again["deduplicated"] == "DUPLICATE" and again["incident_id"] == first["incident_id"]
    symptom = api.triage(task_id="publish", state="upstream_failed", try_number=0).json()
    assert symptom["deduplicated"] == "SYMPTOM" and symptom["incident_id"] == first["incident_id"]
    assert len(api.get("/incidents").json()) == 1


def test_feedback_is_stored_and_reflected_in_the_report():
    api = build_api()
    incident_id, _ = api.hero_plan()
    r = api.post("/feedback", json={"incident_id": incident_id, "feedback_status": "CONFIRMED",
                                    "actual_root_cause": "warehouse failover", "human_note": "matches the NOC log"})
    assert r.status_code == 201 and r.json()["feedback"][0]["principal_id"] == "alice"
    report = api.get(f"/triage/{incident_id}").json()
    assert report["feedback_status"] == "CONFIRMED" and report["actual_root_cause"] == "warehouse failover"
    assert api.post("/feedback", json={"incident_id": incident_id, "feedback_status": "MAYBE"}).status_code == 422
    assert api.post("/feedback", json={"incident_id": "inc-x", "feedback_status": "CONFIRMED"}).status_code == 404


# ---------------------------------------------------------------- healing


def test_remediation_views_and_approval_executes_in_dry_run():
    api = build_api()
    incident_id, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    assert api.get(f"/remediation/{rid}").json()["server_plan_hash"] == plan_hash(view)
    assert view["not_executed_banner"] is True and view["approvals_required"] == 1
    pending = api.get("/approvals/pending").json()
    assert [p["plan"]["remediation_id"] for p in pending] == [rid] and pending[0]["caller_may_approve"] is True
    assert api.get("/approvals/pending", who="human-viewer").json()[0]["caller_may_approve"] is False

    r = api.post(f"/remediation/{rid}/approve", json=api.approval_body(view))
    assert r.status_code == 200 and r.json()["complete"] and r.json()["execution"] == "scheduled"
    plan = api.get(f"/remediation/{rid}").json()["plan"]
    assert plan["execution_result"]["mode"] == "DRY_RUN" and plan["executed"] is False
    assert api.state.mutating_requests() == []
    verification = api.get(f"/remediation/{rid}/verification").json()
    assert verification["verification_status"] == "NOT_VERIFIED" and "State-only" in verification["caveat"]
    assert api.get("/approvals/pending").json() == []


def test_live_approval_dispatches_once_and_resolves():
    api = build_api(live=True)
    incident_id, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    assert api.post(f"/remediation/{rid}/approve", json=api.approval_body(view)).status_code == 200
    assert api.get(f"/triage/{incident_id}").json()["incident_state"] == "RESOLVED"
    verification = api.get(f"/remediation/{rid}/verification").json()
    assert verification["verification_status"] == "VERIFIED" and verification["executed"] is True
    assert len(api.state.clears()) == 1
    # a second approve of the consumed plan changes nothing
    assert api.post(f"/remediation/{rid}/approve", json=api.approval_body(view)).status_code == 409
    assert len(api.state.clears()) == 1


def test_reject_and_cancel_endpoints():
    api = build_api(live=True)
    incident_id, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    assert api.post(f"/remediation/{rid}/reject", json={"reason": ""}).status_code == 422
    r = api.post(f"/remediation/{rid}/reject", json={"reason": "maintenance window"})
    assert r.status_code == 200 and r.json()["incident_state"] == "REJECTED"
    assert api.post(f"/remediation/{rid}/approve", json=api.approval_body(view)).status_code == 409
    assert api.state.clears() == []

    api2 = build_api(live=True)
    _, view2 = api2.hero_plan()
    rid2 = view2["plan"]["remediation_id"]
    r = api2.post(f"/remediation/{rid2}/cancel", who="human-engineer", json={"reason": "fixing upstream"})
    assert r.status_code == 200 and r.json()["incident_state"] == "CANCELLED"
    assert api2.state.clears() == []


def test_approve_ignores_identity_in_body():
    api = build_api(live=True)
    _, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    body = api.approval_body(view, approved_by="human-admin", decided_by="human-admin", principal_id="human-admin",
                             roles=["ADMIN"])
    r = api.post(f"/remediation/{rid}/approve", who="alice", json=body)
    assert r.status_code == 200 and r.json()["decided_by"] == "alice"
    events = api.get(f"/incidents/{view['plan']['incident_id']}/audit").json()["events"]
    suspicious = [e for e in events if e["event_type"] == "SUSPICIOUS_REQUEST"]
    assert suspicious and suspicious[0]["payload"]["authenticated_principal"] == "alice"
    # and a body identity cannot let a non-approver approve
    api2 = build_api(live=True)
    _, view2 = api2.hero_plan()
    r = api2.post(f"/remediation/{view2['plan']['remediation_id']}/approve", who="human-viewer",
                  json=api2.approval_body(view2, approved_by="alice"))
    assert r.status_code == 403 and api2.state.clears() == []


def test_approve_returns_409_on_stale_hash_or_version():
    api = build_api(live=True)
    _, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    assert api.post(f"/remediation/{rid}/approve", json=api.approval_body(view, displayed_plan_hash="f" * 64)).status_code == 409
    assert api.post(f"/remediation/{rid}/approve", json=api.approval_body(view, plan_version=2)).status_code == 409
    assert api.post(f"/remediation/{rid}/approve", json={"plan_version": 1}).status_code == 422
    assert api.state.clears() == []


def test_approve_enforces_the_ttl():
    api = build_api(live=True)
    _, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    api.clock.advance(timedelta(minutes=61).total_seconds())
    r = api.post(f"/remediation/{rid}/approve", json=api.approval_body(view))
    assert r.status_code == 410
    assert api.get(f"/remediation/{rid}").json()["plan"]["approval_status"] == "EXPIRED"
    assert api.state.clears() == []


def test_fix_applied_and_manual_close_endpoints():
    api = build_api(live=True, scenario="schema_drift")
    api.register()
    incident_id = api.triage("schema_drift").json()["incident_id"]
    assert api.get(f"/triage/{incident_id}").json()["incident_state"] == "MANUAL_FIX_REQUIRED"
    assert api.post(f"/incidents/{incident_id}/fix-applied", json={"note": ""}).status_code == 422
    api.clock.advance(300)
    r = api.post(f"/incidents/{incident_id}/fix-applied", who="human-engineer",
                 json={"note": "restored crm.orders.amount_usd"})
    assert r.status_code == 200 and r.json()["plan_id"] is not None
    view = api.plan(incident_id)
    assert view["plan"]["remediation_confidence"] == "MEDIUM"
    assert api.post(f"/remediation/{view['plan']['remediation_id']}/approve", json=api.approval_body(view)).status_code == 200
    assert api.get(f"/triage/{incident_id}").json()["incident_state"] == "RESOLVED"

    api2 = build_api(scenario="schema_drift")
    api2.register()
    incident2 = api2.triage("schema_drift").json()["incident_id"]
    r = api2.post(f"/incidents/{incident2}/manual-close", who="human-engineer", json={"note": "re-ran by hand"})
    assert r.status_code == 200 and r.json()["incident_state"] == "RESOLVED"


def test_incident_audit_and_chain_verification():
    api = build_api(live=True)
    incident_id, view = api.hero_plan()
    api.post(f"/remediation/{view['plan']['remediation_id']}/approve", json=api.approval_body(view))
    events = api.get(f"/incidents/{incident_id}/audit").json()["events"]
    types = [e["event_type"] for e in events]
    for required in ("FAILURE_RECEIVED", "APPROVAL_GRANTED", "EXECUTION_DISPATCHED", "INCIDENT_RESOLVED"):
        assert required in types
    assert api.get("/audit/verify").json()["valid"] is True
    assert api.get("/incidents/inc-nope/audit").status_code == 404


def test_audit_verify_detects_tampering_in_the_database():
    from sqlalchemy import update

    from database.models import AuditRow

    api = build_api()
    api.hero_plan()
    with api.container.db.session() as s:
        row = s.get(AuditRow, 3)
        s.execute(update(AuditRow).where(AuditRow.seq == 3).values(
            data={**row.data, "payload": {"reason": "rewritten"}}))
    result = api.get("/audit/verify").json()
    assert result["valid"] is False and result["broken_at_seq"] == 3


def test_admin_halt_blocks_pending_plans():
    api = build_api(live=True)
    _, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    r = api.post("/admin/healing/halt", who="human-admin", json={"reason": "freeze"})
    assert r.status_code == 200 and r.json()["blocked_plans"] == [rid]
    assert api.get("/health", who=None).json()["banners"]["halted"] is True
    assert api.post(f"/remediation/{rid}/approve", json=api.approval_body(view)).status_code == 409
    assert api.state.clears() == []


def test_settings_and_me():
    api = build_api()
    settings = api.get("/settings").json()
    assert settings["execution_mode"] == "DRY_RUN" and settings["kill_switches"]["HEALING_ENABLED"] is True
    me = api.get("/me", who="service-approver").json()
    assert me["principal_type"] == "SERVICE" and me["can_approve"] is False


def test_notifications_are_sent_and_never_carry_an_approval_link():
    api = build_api(live=True)
    _, view = api.hero_plan()
    api.post(f"/remediation/{view['plan']['remediation_id']}/approve", json=api.approval_body(view))
    kinds = [n.kind.value for n in api.console.sent]
    assert kinds == ["TRIAGE", "APPROVAL_REQUEST", "EXECUTION_RESULT", "VERIFICATION_RESULT"]
    for n in api.console.sent:
        assert n.link.startswith("https://triage-ui.example.internal/?page=Incident+Details")
        assert "/approve" not in n.text() and "token" not in n.text().lower()
