"""Pure task logic for the throwaway live-test DAG (importable without Airflow, so it is unit-tested).

``load`` fails on its first attempt with a connection-reset error and succeeds after the task instance
is cleared: the first attempt leaves a marker file for its run, the retried attempt finds it.
"""

from pathlib import Path

MARKER_DIR = Path("/tmp/triage_live_test")
TRIAGE_MARKER = "[triage] target_write=none_confirmed failure_stage=pre_write"


def load(run_id: str, log=print, marker_dir: Path = MARKER_DIR) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)
    marker = marker_dir / safe
    log(TRIAGE_MARKER)  # the opt-in rerun-safety convention: nothing was written before the failure
    if not marker.exists():
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text("first attempt failed", encoding="utf-8")
        raise ConnectionResetError("server closed the connection unexpectedly: Connection reset by peer")
    return "loaded"
