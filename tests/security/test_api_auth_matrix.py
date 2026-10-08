"""Auth matrix: VIEWER/ENGINEER/APPROVER/ADMIN x HUMAN/SERVICE (+ unauthenticated) on every endpoint
class, and pipeline-approver membership for approve/reject."""

import pytest

from core.models.enums import PrincipalType, Role
from tests.api_helpers import MATRIX, build_api, pid

H, S = PrincipalType.HUMAN, PrincipalType.SERVICE
V, E, A, AD = Role.VIEWER, Role.ENGINEER, Role.APPROVER, Role.ADMIN
NAMES = [pid(t, r) for t, r in MATRIX]


def allowed(rule, ptype, role) -> bool:
    return rule(ptype, role)


RULES = {
    "read": lambda t, r: True,
    "triage": lambda t, r: r in (E, AD),
    "human_engineer": lambda t, r: t is H and r in (E, AD),
    "approve": lambda t, r: t is H and r in (A, AD),     # human-approver is listed; ADMIN needs no listing
    "cancel": lambda t, r: t is H and r in (E, A, AD),
    "halt": lambda t, r: t is H and r is AD,
}


@pytest.fixture(scope="module")
def seeded():
    api = build_api()
    incident_id, view = api.hero_plan()
    return api, incident_id, view


READ_PATHS = ["/me", "/settings", "/pipelines", "/pipelines/sales_etl", "/capabilities/sales_etl", "/reports",
              "/incidents", "/approvals/pending", "/audit/verify"]


@pytest.mark.parametrize("path", READ_PATHS)
def test_read_endpoints_require_authentication_and_allow_every_role(seeded, path):
    api, incident_id, view = seeded
    assert api.get(path, who=None).status_code == 401
    for name in NAMES:
        assert api.get(path, who=name).status_code == 200, (path, name)


def test_incident_scoped_read_endpoints(seeded):
    api, incident_id, view = seeded
    rid = view["plan"]["remediation_id"]
    for path in (f"/triage/{incident_id}", f"/incidents/{incident_id}/remediation", f"/remediation/{rid}",
                 f"/remediation/{rid}/verification", f"/incidents/{incident_id}/audit"):
        assert api.get(path, who=None).status_code == 401
        assert all(api.get(path, who=n).status_code == 200 for n in NAMES), path


def test_bad_token_is_401():
    api = build_api()
    assert api.client.get("/pipelines", headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    assert api.client.get("/pipelines", headers={"X-Demo-Principal": "demo-admin"}).status_code == 401  # token mode


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_triage_matrix(ptype, role):
    api = build_api()
    api.register()
    status = api.triage(who=pid(ptype, role)).status_code
    assert status == (201 if RULES["triage"](ptype, role) else 403)


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_register_matrix_and_enabling_healing_needs_human_admin(ptype, role):
    api = build_api()
    from demo.scenarios.registrations import SALES_ETL

    plain = SALES_ETL.model_copy(update={"healing_enabled": False}).model_dump(mode="json")
    status = api.post("/pipelines/register", who=pid(ptype, role), json=plain).status_code
    assert status == (201 if role in (E, AD) else 403)
    healing = SALES_ETL.model_copy(update={"healing_enabled": True, "pipeline_id": "sales_etl_2"}).model_dump(mode="json")
    status = api.post("/pipelines/register", who=pid(ptype, role), json=healing).status_code
    assert status == (201 if (ptype is H and role is AD) else 403)


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_feedback_matrix(ptype, role, seeded):
    api, incident_id, _ = seeded
    r = api.post("/feedback", who=pid(ptype, role), json={"incident_id": incident_id, "feedback_status": "CONFIRMED"})
    assert r.status_code == (201 if RULES["human_engineer"](ptype, role) else 403)


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_approve_matrix(ptype, role):
    api = build_api(live=True)
    _, view = api.hero_plan()
    r = api.post(f"/remediation/{view['plan']['remediation_id']}/approve", who=pid(ptype, role),
                 json=api.approval_body(view))
    if RULES["approve"](ptype, role):
        assert r.status_code == 200 and len(api.state.clears()) == 1
    else:
        assert r.status_code == 403 and api.state.clears() == []


def test_unlisted_human_approver_cannot_approve_or_reject():
    api = build_api(live=True)
    _, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    assert api.post(f"/remediation/{rid}/approve", who="carol", json=api.approval_body(view)).status_code == 403
    assert api.post(f"/remediation/{rid}/reject", who="carol", json={"reason": "x"}).status_code == 403
    assert api.state.clears() == []


def test_service_principal_listed_as_approver_still_cannot_approve():
    api = build_api(live=True)
    _, view = api.hero_plan()
    rid = view["plan"]["remediation_id"]
    assert "service-approver" in api.get("/pipelines/sales_etl").json()["approver_ids"]
    assert api.post(f"/remediation/{rid}/approve", who="service-approver", json=api.approval_body(view)).status_code == 403
    assert api.state.clears() == []


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_reject_matrix(ptype, role):
    api = build_api()
    _, view = api.hero_plan()
    r = api.post(f"/remediation/{view['plan']['remediation_id']}/reject", who=pid(ptype, role), json={"reason": "no"})
    assert r.status_code == (200 if RULES["approve"](ptype, role) else 403)


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_cancel_matrix(ptype, role):
    api = build_api()
    _, view = api.hero_plan()
    r = api.post(f"/remediation/{view['plan']['remediation_id']}/cancel", who=pid(ptype, role), json={"reason": "no"})
    assert r.status_code == (200 if RULES["cancel"](ptype, role) else 403)


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_fix_applied_and_manual_close_matrix(ptype, role):
    api = build_api(scenario="schema_drift")
    api.register()
    incident_id = api.triage("schema_drift").json()["incident_id"]
    expected_ok = RULES["human_engineer"](ptype, role)
    r = api.post(f"/incidents/{incident_id}/manual-close", who=pid(ptype, role), json={"note": "closing"})
    assert r.status_code == (200 if expected_ok else 403)
    if not expected_ok:
        r = api.post(f"/incidents/{incident_id}/fix-applied", who=pid(ptype, role), json={"note": "fixed"})
        assert r.status_code == 403


@pytest.mark.parametrize("ptype,role", MATRIX)
def test_halt_matrix(ptype, role):
    api = build_api()
    r = api.post("/admin/healing/halt", who=pid(ptype, role), json={"reason": "freeze"})
    assert r.status_code == (200 if RULES["halt"](ptype, role) else 403)


def test_auth_provider_failure_is_503_not_access():
    api = build_api()

    def broken(request):
        from security.auth import AuthProviderUnavailableError
        raise AuthProviderUnavailableError("store down")

    api.container.auth.authenticate = broken
    assert api.get("/pipelines").status_code == 503
    assert api.get("/health", who=None).status_code == 200


def test_demo_auth_provider_header_works_only_in_demo_mode():
    api = build_api(demo_auth=True)
    ok = api.client.get("/me", headers={"X-Demo-Principal": "demo-engineer"})
    assert ok.status_code == 200 and ok.json()["auth_method"] == "demo"
    assert api.client.get("/me", headers={"X-Demo-Principal": "nobody"}).status_code == 401
