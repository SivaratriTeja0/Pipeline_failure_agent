"""Documented Airflow ``on_failure_callback`` that reports a failure to POST /webhooks/failure.

Copy this into your DAG repository and attach it yourself (it is never installed automatically):

    from on_failure_callback import report_failure
    default_args = {"on_failure_callback": report_failure}

It needs TRIAGE_WEBHOOK_URL and TRIAGE_WEBHOOK_SECRET (the same value as the API's WEBHOOK_SECRET)
in the Airflow worker environment. The body is signed with HMAC-SHA256; the callback only reports a
failure - it cannot approve, reject or execute anything. Standard library only; no Airflow import.
"""

import hashlib
import hmac
import json
import os
import urllib.request
from typing import Any


def build_payload(context: dict[str, Any]) -> dict[str, Any]:
    ti = context["task_instance"]
    dag_run = context.get("dag_run")
    exception = context.get("exception")
    return {
        "dag_id": ti.dag_id,
        "dag_run_id": getattr(dag_run, "run_id", None) or context.get("run_id"),
        "task_id": ti.task_id,
        "try_number": ti.try_number,
        "map_index": getattr(ti, "map_index", -1),
        "state": "failed",
        "start_date": ti.start_date.isoformat() if ti.start_date else None,
        "end_date": ti.end_date.isoformat() if ti.end_date else None,
        "logical_date": context["logical_date"].isoformat() if context.get("logical_date") else None,
        "exception": str(exception)[:2000] if exception else None,
        "log_url": getattr(ti, "log_url", None),
    }


def signed_request(url: str, secret: str, payload: dict[str, Any]) -> urllib.request.Request:
    body = json.dumps(payload).encode("utf-8")
    signature = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return urllib.request.Request(url, data=body, method="POST",
                                  headers={"Content-Type": "application/json", "X-Triage-Signature": signature})


def report_failure(context: dict[str, Any]) -> None:
    url, secret = os.environ.get("TRIAGE_WEBHOOK_URL"), os.environ.get("TRIAGE_WEBHOOK_SECRET")
    if not url or not secret:
        return  # not configured: never block the DAG on reporting
    try:
        with urllib.request.urlopen(signed_request(url, secret, build_payload(context)), timeout=10):
            pass
    except OSError:
        return  # reporting is best effort; Airflow's own failure handling is unaffected
