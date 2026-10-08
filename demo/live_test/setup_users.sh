#!/usr/bin/env bash
# Least-privilege users for the agent (run inside the live-test Airflow container).
#   triage_reader : Viewer role         -> AIRFLOW_READ_*  (GET only)
#   triage_writer : TriageClear role    -> AIRFLOW_WRITE_* (clear task instances only)
# Passwords come from the environment of this shell; nothing is hard-coded.
set -euo pipefail
: "${TRIAGE_READER_PASSWORD:?set TRIAGE_READER_PASSWORD}"
: "${TRIAGE_WRITER_PASSWORD:?set TRIAGE_WRITER_PASSWORD}"

airflow roles create TriageClear || true
# Clearing task instances via POST /dags/{dag_id}/clearTaskInstances needs edit on the DAG and its task
# instances, plus reads to resolve them. Verify against your Airflow version's access-control docs.
airflow roles add-perms TriageClear -a can_read -r "DAGs" "DAG Runs" "Task Instances" "Task Logs"
airflow roles add-perms TriageClear -a can_edit -r "DAGs" "Task Instances"

airflow users create --role Viewer --username triage_reader --password "$TRIAGE_READER_PASSWORD" \
  --firstname triage --lastname reader --email triage-reader@example.invalid || true
airflow users create --role TriageClear --username triage_writer --password "$TRIAGE_WRITER_PASSWORD" \
  --firstname triage --lastname writer --email triage-writer@example.invalid || true
echo "created triage_reader (Viewer) and triage_writer (TriageClear)"
