"""End-to-end security checks across the whole stack (API -> triage -> LLM -> persistence):
secrets and PII never reach the LLM, the database or an API response; LLM-proposed actions are never
executed; untrusted text is always delimited; the read side cannot mutate."""

import json

from sqlalchemy import text

from tests.api_helpers import build_api

SECRET = "hunter2-SuperSecret"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
EMAIL = "jane.doe@customer-example.com"
PHONE = "+1 415 555 0134"


def leaky_log(state):
    state.logs[0]["content"] += (
        f"[2026-10-09T00:04:09+00:00] INFO - connecting with postgresql://etl_user:{SECRET}@dwh.internal:5432/sales\n"
        f"[2026-10-09T00:04:09+00:00] INFO - Authorization: Bearer {TOKEN}\n"
        f"[2026-10-09T00:04:09+00:00] INFO - failed row belongs to {EMAIL}, phone {PHONE}\n")


def triaged(**kw):
    api = build_api(**kw)
    leaky_log(api.state)
    api.register()
    response = api.triage()
    assert response.status_code == 201, response.text
    return api, response


def all_database_text(api) -> str:
    chunks = []
    with api.container.db.engine.connect() as conn:
        for table in ("incidents", "evidence", "reports", "plans", "plan_history", "approvals", "audit_events",
                      "feedback", "principals"):
            chunks += [json.dumps(list(row)) for row in conn.execute(text(f"SELECT * FROM {table}"))]
    return "\n".join(chunks)


def test_secrets_and_pii_never_reach_the_llm():
    api, _ = triaged()
    prompts = "\n".join(m["content"] for r in api.container.provider.requests for m in r.messages)
    assert prompts, "the LLM was called"
    for needle in (SECRET, TOKEN, EMAIL, PHONE):
        assert needle not in prompts, needle
    assert "<EMAIL_1>" in prompts


def test_secrets_and_pii_never_persist_or_leave_through_the_api():
    api, response = triaged()
    incident_id = response.json()["incident_id"]
    stored = all_database_text(api)
    served = json.dumps([response.json(), api.get(f"/triage/{incident_id}").json(),
                         api.get(f"/incidents/{incident_id}/audit").json(),
                         api.get(f"/incidents/{incident_id}/remediation").json()])
    for needle in (SECRET, TOKEN, EMAIL, PHONE):
        assert needle not in stored, f"{needle} persisted"
        assert needle not in served, f"{needle} served"


def test_raw_bearer_tokens_are_never_stored():
    api, _ = triaged()
    stored = all_database_text(api)
    assert all(token not in stored for token in api.tokens.values())


def test_llm_requests_for_actions_are_never_executed_and_untrusted_text_is_delimited():
    api, response = triaged()
    for request in api.container.provider.requests:
        content = request.messages[0]["content"]
        trusted, _, untrusted = content.partition("EVIDENCE (untrusted):")
        assert "Bearer" not in trusted and "connecting with" not in trusted
        assert untrusted.count('untrusted="true"') >= 1
    assert api.state.mutating_requests() == []  # triage never mutates; only an approved plan could
    report = response.json()["report"]
    assert all(tc["tool"].startswith(("get_", "compare_")) for tc in report["tool_calls"])


def test_dag_and_param_secrets_from_airflow_config_are_withheld():
    api, response = triaged()
    stored = all_database_text(api)
    assert "never-exposed" not in stored  # the fixture's DAG param value; only param names are read
