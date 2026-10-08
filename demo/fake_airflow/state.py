"""In-memory state for FAKE AIRFLOW (DEMO), loaded from a scenario fixture.

Besides the fixture data it simulates a scheduler for the clear endpoint. After a (non-dry-run)
clear, the next ``scheduler_delay`` reads of the run see the instances reset; then
``clear_behavior`` decides what the scheduler does:

  success     cleared instances run and succeed; the run succeeds          ("clear -> success")
  fail_again  the primary failure fails again on a new try; the run fails  ("clear -> fails again")
  running     the instances start and never finish                         (verification timeout)
  stuck       the scheduler never picks the instances up
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FAKE_LABEL = "FAKE AIRFLOW (DEMO)"


class RecordedRequest(BaseModel):
    method: str
    path: str
    query: str
    body: dict[str, Any] | None = None

    @property
    def is_mutating_clear(self) -> bool:
        return self.method == "POST" and self.path.endswith("/clearTaskInstances") and bool(
            self.body and self.body.get("dry_run") is False)


class FakeAirflowState(BaseModel):
    scenario: str
    label: str = FAKE_LABEL
    description: str = ""
    dags: list[dict[str, Any]] = Field(default_factory=list)
    dag_runs: list[dict[str, Any]] = Field(default_factory=list)
    task_instances: list[dict[str, Any]] = Field(default_factory=list)
    logs: list[dict[str, Any]] = Field(default_factory=list)
    down: bool = False
    fail_paths: list[str] = Field(default_factory=list, description="path suffixes answered with 503")
    request_log: list[RecordedRequest] = Field(default_factory=list)
    clear_behavior: str = "success"
    scheduler_delay: int = 1
    post_failure_pool_success: bool = False
    sim_time: str = "2026-10-09T00:45:00+00:00"
    pending: dict[str, Any] | None = None
    sim_clock: Any = Field(default=None, exclude=True, description="optional callable returning 'now'")

    # ------------------------------------------------------------------ lookups

    def dag(self, dag_id: str) -> dict[str, Any] | None:
        return next((d for d in self.dags if d["dag_id"] == dag_id), None)

    def dag_run(self, dag_id: str, dag_run_id: str) -> dict[str, Any] | None:
        return next((r for r in self.dag_runs if r["dag_id"] == dag_id and r["dag_run_id"] == dag_run_id), None)

    def task_instances_for(self, dag_id: str, dag_run_id: str) -> list[dict[str, Any]]:
        return [
            ti for ti in self.task_instances
            if (dag_id == "~" or ti["dag_id"] == dag_id) and (dag_run_id == "~" or ti["dag_run_id"] == dag_run_id)
        ]

    def log(self, dag_id: str, dag_run_id: str, task_id: str, try_number: int, map_index: int) -> str | None:
        for entry in self.logs:
            if (entry["dag_id"], entry["dag_run_id"], entry["task_id"], entry["try_number"],
                    entry.get("map_index", -1)) == (dag_id, dag_run_id, task_id, try_number, map_index):
                return str(entry["content"])
        return None

    def mutating_requests(self) -> list[RecordedRequest]:
        return [r for r in self.request_log if r.method not in ("GET", "HEAD", "OPTIONS")]

    def clears(self) -> list[RecordedRequest]:
        """Clear requests that were not dry runs (i.e. that mutate)."""
        return [r for r in self.request_log if r.is_mutating_clear]

    def ti(self, dag_id: str, dag_run_id: str, task_id: str, map_index: int = -1) -> dict[str, Any] | None:
        return next((t for t in self.task_instances if (t["dag_id"], t["dag_run_id"], t["task_id"],
                     t.get("map_index", -1)) == (dag_id, dag_run_id, task_id, map_index)), None)

    # ------------------------------------------------------------------ simulated scheduler

    def _tick_time(self, offset_seconds: int = -60) -> str:
        """Simulated scheduler time: shortly before the caller's clock when one is attached, so that
        what the scheduler did is already in the past when the agent observes it."""
        if self.sim_clock is not None:
            return (self.sim_clock() + timedelta(seconds=offset_seconds)).isoformat()
        now = datetime.fromisoformat(self.sim_time)
        self.sim_time = (now + timedelta(minutes=5)).isoformat()
        return now.isoformat()

    def apply_clear(self, dag_id: str, dag_run_id: str, keys: list[tuple[str, int]]) -> None:
        run = self.dag_run(dag_id, dag_run_id)
        before = {}
        for task_id, map_index in keys:
            ti = self.ti(dag_id, dag_run_id, task_id, map_index)
            if ti is not None:
                before[f"{task_id}:{map_index}"] = {"state": ti["state"], "try_number": ti["try_number"]}
                ti.update(state=None, end_date=None)
        if run is not None:
            run.update(state="queued", end_date=None)
        self.pending = {"dag_id": dag_id, "dag_run_id": dag_run_id, "before": before, "reads": self.scheduler_delay}

    def advance(self) -> None:
        """Called on every read; applies the pending scheduler outcome after ``scheduler_delay`` reads."""
        if not self.pending:
            return
        if self.pending["reads"] > 0:
            self.pending["reads"] -= 1
            return
        pending, self.pending = self.pending, None
        dag_id, dag_run_id = pending["dag_id"], pending["dag_run_id"]
        run = self.dag_run(dag_id, dag_run_id)
        behavior = self.clear_behavior
        if behavior == "stuck":
            return
        stamp = self._tick_time()
        for key, prior in pending["before"].items():
            task_id, map_index = key.rsplit(":", 1)
            ti = self.ti(dag_id, dag_run_id, task_id, int(map_index))
            if ti is None:
                continue
            if behavior == "success":
                ti.update(state="success", try_number=prior["try_number"] + 1, start_date=stamp, end_date=stamp)
            elif behavior == "running":
                ti.update(state="running", try_number=prior["try_number"] + 1, start_date=stamp)
            elif prior["state"] == "failed":  # fail_again: the primary fails on a new try
                new_try = prior["try_number"] + 1
                ti.update(state="failed", try_number=new_try, start_date=stamp, end_date=stamp)
                old = self.log(dag_id, dag_run_id, task_id, prior["try_number"], int(map_index)) or ""
                self.logs.append({"dag_id": dag_id, "dag_run_id": dag_run_id, "task_id": task_id,
                                  "map_index": int(map_index), "try_number": new_try,
                                  "content": old.replace("attempt 1", f"attempt {new_try}")})
            else:
                ti.update(state="upstream_failed", end_date=stamp)
        if run is not None:
            run.update(state={"success": "success", "running": "running"}.get(behavior, "failed"),
                       end_date=None if behavior == "running" else stamp)
        if behavior == "fail_again" and self.post_failure_pool_success:
            later = self._tick_time(offset_seconds=-30)
            self.task_instances.append({
                "dag_id": "inventory_sync", "dag_run_id": f"scheduled__{later}", "task_id": "sync", "map_index": -1,
                "try_number": 1, "max_tries": 1, "state": "success", "start_date": later, "end_date": later,
                "duration": 60.0, "hostname": "worker-3", "pool": "warehouse_pool", "queue": "default",
                "operator": "PythonOperator"})


def available_scenarios() -> list[str]:
    return sorted(p.stem for p in FIXTURES_DIR.glob("*.json"))


def load_scenario(name: str, *, down: bool = False) -> FakeAirflowState:
    path = FIXTURES_DIR / f"{name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"unknown fake Airflow scenario {name!r}; available: {available_scenarios()}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return FakeAirflowState(**data, down=down)
