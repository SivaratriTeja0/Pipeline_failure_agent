"""Throwaway DAG for the local LIVE test (see README 'First live test'). extract -> load -> publish.
``load`` fails once with a connection reset and succeeds after being cleared."""

from datetime import datetime

from airflow import DAG
from airflow.operators.python import PythonOperator

from live_test_logic import load

with DAG(dag_id="triage_live_test", start_date=datetime(2026, 1, 1), schedule=None, catchup=False,
         default_args={"retries": 0}, tags=["triage-live-test"]) as dag:
    extract = PythonOperator(task_id="extract", python_callable=lambda: "extracted")
    load_task = PythonOperator(task_id="load", python_callable=lambda run_id, **_: load(run_id))
    publish = PythonOperator(task_id="publish", python_callable=lambda: "published")
    extract >> load_task >> publish
