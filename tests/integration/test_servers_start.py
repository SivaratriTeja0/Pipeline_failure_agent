"""Both servers start: the API under uvicorn and the Streamlit UI, as real processes on free ports.
Every UI page then renders against the running API (Streamlit AppTest), and an approval can be given
through the UI's remediation panel. DEMO MODE / FAKE AIRFLOW (DEMO) / DRY_RUN throughout."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]
UI = REPO / "frontend" / "streamlit_app.py"
HERO = {"dag_id": "sales_etl", "dag_run_id": "scheduled__2026-10-08T00:00:00+00:00", "task_id": "load",
        "try_number": 1, "state": "failed", "end_date": "2026-10-09T00:04:10+00:00",
        "exception": "psycopg2.OperationalError: Connection reset by peer"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url: str, timeout: float = 60) -> httpx.Response:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=2)
            if response.status_code == 200:
                return response
        except httpx.HTTPError as exc:
            last = exc
        time.sleep(0.5)
    raise AssertionError(f"{url} did not come up: {last}")


def demo_env(tmp: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "AIRFLOW_", "HEALING_", "AUTH_",
                                                                     "DEMO_", "WEBHOOK_", "DATABASE_"))}
    env.update({"DATABASE_URL": f"sqlite:///{(tmp / 'servers.db').as_posix()}", "DEMO_MODE": "true",
                "AUTH_PROVIDER": "demo", "HEALING_ENABLED": "true", "PYTHONPATH": str(REPO), **extra})
    return env


@pytest.fixture(scope="module")
def api_server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("api")
    port = free_port()
    log = open(tmp / "api.log", "wb")  # never an unread pipe: a full pipe buffer would block the server
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "api.main:app", "--port", str(port)], cwd=REPO,
                            env=demo_env(tmp), stdout=log, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    try:
        wait_for(f"{url}/health")
        admin = {"X-Demo-Principal": "demo-admin"}
        engineer = {"X-Demo-Principal": "demo-engineer"}
        reg = {"pipeline_id": "sales_etl", "platform": "airflow", "environment": "production", "healing_enabled": True,
               "allowed_actions": ["RETRY_FAILED_TASK", "RETRY_FAILED_DAG_RUN"],
               "approver_ids": ["demo-engineer", "demo-approver-2"],
               "task_policies": {t: {"task_type": "upsert", "write_mode": "merge", "idempotent": True,
                                     "state_mechanism": "none", "concurrency_behavior": "forbid_overlap"}
                                 for t in ("extract", "load", "publish")}}
        assert httpx.post(f"{url}/pipelines/register", json=reg, headers=admin).status_code == 201
        triage = httpx.post(f"{url}/triage", json={"pipeline_id": "sales_etl", "failure": HERO}, headers=engineer,
                            timeout=60)
        assert triage.status_code == 201, triage.text
        yield url, triage.json()["incident_id"]
    finally:
        proc.terminate()
        proc.wait(timeout=20)
        log.close()


def test_api_server_starts_and_serves(api_server):
    url, incident_id = api_server
    health = httpx.get(f"{url}/health").json()
    assert health["status"] == "ok" and health["banners"]["fake_airflow"] is True
    assert httpx.get(f"{url}/pipelines").status_code == 401
    report = httpx.get(f"{url}/triage/{incident_id}", headers={"X-Demo-Principal": "demo-viewer"}).json()
    assert report["remediation_class"] == "AUTOMATABLE" and report["incident_state"] == "AWAITING_APPROVAL"


def test_api_server_refuses_to_start_with_unsafe_configuration(tmp_path):
    env = demo_env(tmp_path, HEALING_EXECUTION_MODE="LIVE")  # demo auth under LIVE
    proc = subprocess.run([sys.executable, "-m", "uvicorn", "api.main:app", "--port", str(free_port())], cwd=REPO,
                          env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0
    assert "ConfigurationError" in proc.stdout + proc.stderr


def test_ui_server_starts(api_server, tmp_path):
    url, _ = api_server
    port = free_port()
    env = demo_env(tmp_path, TRIAGE_API_URL=url)
    proc = subprocess.Popen([sys.executable, "-m", "streamlit", "run", str(UI), "--server.headless", "true",
                             "--server.port", str(port), "--browser.gatherUsageStats", "false"],
                            cwd=REPO, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_for(f"http://127.0.0.1:{port}/_stcore/health").text == "ok"
    finally:
        proc.terminate()
        proc.wait(timeout=20)


# ---------------------------------------------------------------- UI pages (AppTest, in-process, against the API)


def app_for(url: str, page: str, principal: str = "demo-engineer"):
    from streamlit.testing.v1 import AppTest

    os.environ["TRIAGE_API_URL"] = url
    at = AppTest.from_file(str(UI), default_timeout=60)
    at.run()
    at.sidebar.selectbox[0].set_value(principal)
    at.sidebar.radio[0].set_value(page)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


PAGES = ["Overview", "Pipelines", "Register Pipeline", "Run Triage", "Incident Details", "Approvals Queue",
         "Evidence Explorer", "Audit Log", "Reports", "Evaluation", "Settings"]


@pytest.mark.parametrize("page", PAGES)
def test_every_ui_page_renders_with_banners(api_server, page):
    url, _ = api_server
    at = app_for(url, page)
    warnings = " ".join(w.value for w in at.warning)
    assert "llm_mode=MOCK" in warnings and "DEMO MODE" in warnings and "FAKE AIRFLOW (DEMO)" in warnings
    assert any("DRY_RUN" in i.value for i in at.info)
    assert any("State-only verification" in c.value for c in at.caption)
    assert not [e for e in at.error if "API" in e.value], [e.value for e in at.error]


def test_incident_details_shows_trio_class_and_remediation_panel(api_server):
    url, _ = api_server
    at = app_for(url, "Incident Details")
    labels = {m.label: m.value for m in at.metric}
    assert labels == {"Root-cause confidence": "MEDIUM", "Remediation confidence": "MEDIUM", "Rerun safety": "SAFE"}
    headers = " ".join(h.value for h in at.subheader)
    assert "Remediation class: AUTOMATABLE" in headers and "Remediation" in headers
    assert any(w.value == "NOT EXECUTED" for w in at.warning)
    assert any(b.label == "Approve this exact plan" for b in at.button)


def test_approve_button_hidden_for_viewer_and_approval_through_the_ui(api_server):
    url, incident_id = api_server
    viewer = app_for(url, "Incident Details", principal="demo-viewer")
    assert not any(b.label == "Approve this exact plan" for b in viewer.button)

    at = app_for(url, "Incident Details", principal="demo-engineer")
    next(b for b in at.button if b.label == "Approve this exact plan").click()
    at.run()
    assert not at.exception and any("Approval recorded" in s.value for s in at.success)
    plans = httpx.get(f"{url}/incidents/{incident_id}/remediation",
                      headers={"X-Demo-Principal": "demo-viewer"}).json()["plans"]
    plan = plans[0]["plan"]
    assert plan["approved_by"] == ["demo-engineer"]
    assert plan["execution_result"]["mode"] == "DRY_RUN" and plan["executed"] is False
