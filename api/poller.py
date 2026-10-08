"""Optional failure poller (spec Part N). Enabled with POLLER_ENABLED=true (POLL_INTERVAL_SECONDS).

Periodically lists recently failed executions of each registered pipeline through the platform's
read-only adapter and feeds them to the same intake as the webhook. Incident deduplication makes
repeated sightings of the same failure a no-op. The poller only reads; it never acts.
"""

import threading
from typing import Any

from adapters.base.interfaces import AdapterError
from api.container import AppContainer
from core.incidents.dedup import DedupOutcome
from core.logging_setup import get_logger

_log = get_logger(__name__)


class FailurePoller:
    def __init__(self, container: AppContainer, interval: float = 60.0, limit: int = 5) -> None:
        self._c = container
        self._interval = interval
        self._limit = limit
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll_once(self) -> list[dict[str, Any]]:
        """One sweep. Returns what happened to each failure seen (new incident or deduplicated)."""
        outcomes: list[dict[str, Any]] = []
        for registration in self._c.repo.list_pipelines():
            adapter = self._c.adapters.get(registration.platform)
            orchestrator = self._c.orchestrator(registration.platform)
            if adapter is None or orchestrator is None:
                continue
            try:
                failures = adapter.recent_failures(registration.pipeline_id, self._limit)
            except AdapterError as exc:
                _log.warning("poll_read_failed", extra={"pipeline_id": registration.pipeline_id, "error": str(exc)})
                continue
            for payload in failures:
                try:
                    event = adapter.normalize_failure({**payload, "environment": registration.environment})
                except ValueError:
                    continue
                with self._c.lock:
                    decision = self._c.index.classify(event, self._c.clock())
                    if decision.outcome is not DedupOutcome.NEW:
                        self._c.index.link(decision, event)
                        outcomes.append({"event_id": event.event_id, "deduplicated": decision.outcome.value,
                                         "incident_id": decision.incident_id})
                        continue
                    report = orchestrator.handle_failure(event, registration).report
                    symptoms = {s.claim_id.removeprefix("c-symptom-") for s in report.downstream_symptoms}
                    self._c.index.register(report.incident_id, event, self._c.clock(), symptoms)
                    outcomes.append({"event_id": event.event_id, "incident_id": report.incident_id,
                                     "deduplicated": None})
        return outcomes

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.poll_once()
            except Exception as exc:  # the poller must never take the API down
                _log.error("poll_failed", extra={"error": type(exc).__name__})

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="failure-poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
