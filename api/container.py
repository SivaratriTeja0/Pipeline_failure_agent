"""Application wiring: settings -> database, auth, adapters, executors, LLM, notifier, orchestrators.

Airflow wiring (read side always GET-only; write side only through actions/):
- AIRFLOW_API_BASE_URL set  -> real AirflowReadClient (AIRFLOW_READ_*); the action client is built only
                               when AIRFLOW_WRITE_* credentials exist (without them healing is
                               NOT_APPLICABLE for Airflow pipelines).
- unset and DEMO_MODE=true  -> FAKE AIRFLOW (DEMO) served in-process (scenario FAKE_AIRFLOW_SCENARIO),
                               labeled everywhere.
- unset otherwise           -> Airflow pipelines cannot be triaged (503).
The Generic adapter (manual evidence, investigation only) is always available.
"""

import os
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel

from actions.airflow_actions import AirflowActionConfig, build_airflow_executor
from adapters.airflow.adapter import AirflowAdapter
from adapters.airflow.client import AirflowReadClient, AirflowReadConfig
from adapters.base.interfaces import PipelineAdapter, RemediationExecutor
from adapters.generic.adapter import GenericAdapter
from agent.llm_provider import LLMProvider, build_provider
from agent.mock_llm import scripted_triage
from api.orchestrator import HealingOrchestrator
from core.config import AuthProviderName, Settings, validate_startup
from core.incidents.dedup import IncidentIndex
from core.logging_setup import get_logger
from core.models.base import utcnow
from core.models.enums import LLMMode
from core.remediation.audit import AuditLog
from database.repository import Database, Repository, SqlAuditStore, SqlHealingStore, SqlPrincipalStore
from notifications.notifier import Notifier, build_notifier
from security.auth import AuthProvider, DemoAuthProvider, TokenAuthProvider

_log = get_logger(__name__)

FAKE_AIRFLOW_LABEL = "FAKE AIRFLOW (DEMO)"


class Banners(BaseModel):
    """Persistent UI banners (spec Part P)."""

    llm_mode: LLMMode
    demo_mode: bool
    dry_run: bool
    fake_airflow: bool
    healing_enabled: bool
    execution_mode: str
    auth_provider: str
    halted: bool
    demo_clock: bool = False
    state_only_verification: bool = True


class DemoClock:
    """Labeled demo clock: DEMO_NOW + real elapsed time. Used only with FAKE AIRFLOW (DEMO)."""

    label = "DEMO CLOCK"

    def __init__(self) -> None:
        from demo.scenarios.run_triage import DEMO_NOW

        self._origin = DEMO_NOW
        self._started = utcnow()

    def __call__(self) -> datetime:
        return self._origin + (utcnow() - self._started)


class AppContainer:
    def __init__(
        self,
        settings: Settings,
        env: Mapping[str, str] | None = None,
        *,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
        provider: LLMProvider | None = None,
        airflow_http: httpx.Client | None = None,
        airflow_write_http: httpx.Client | None = None,
        fake_airflow_state: Any = None,
        notifier: Notifier | None = None,
    ) -> None:
        validate_startup(settings)  # fail fast on unsafe configuration (B5)
        e = dict(os.environ if env is None else env)
        uses_fake = airflow_http is None and not e.get("AIRFLOW_API_BASE_URL") and settings.demo_mode
        if uses_fake and clock is utcnow:
            # FAKE AIRFLOW (DEMO) fixtures are dated around DEMO_NOW; run the demo on a clock that starts
            # there and advances in real time, so "after the failure" comparisons behave as in the demo.
            clock = DemoClock()
        self.settings = settings
        self.env = e
        self.clock = clock
        self.lock = threading.RLock()  # serializes state-changing operations within this process
        self.db = Database(settings.database_url)
        self.repo = Repository(self.db)
        self.store = SqlHealingStore(self.db)
        self.audit_store = SqlAuditStore(self.db)
        self.audit = AuditLog(self.audit_store, clock=clock)
        self.principals = SqlPrincipalStore(self.db)
        self.auth: AuthProvider = (DemoAuthProvider(settings) if settings.auth_provider is AuthProviderName.DEMO
                                   else TokenAuthProvider(self.principals))
        self.notifier = notifier or build_notifier(e)
        self.ui_base_url = e.get("UI_BASE_URL") or "http://localhost:8501"
        self.provider = provider or build_provider(settings.anthropic_api_key_present, scripted_triage)
        self.index = IncidentIndex()
        self.fake_airflow = False
        self.fake_airflow_state = fake_airflow_state

        self.adapters: dict[str, PipelineAdapter] = {"generic": GenericAdapter(clock=clock)}
        self.backends: dict[str, RemediationExecutor | None] = {"generic": None}
        airflow = self._airflow(e, airflow_http, airflow_write_http)
        if airflow is not None:
            self.adapters["airflow"], self.backends["airflow"] = airflow

        self.orchestrators = {
            platform: HealingOrchestrator(
                adapter=adapter, provider=self.provider, settings=settings, audit=self.audit, store=self.store,
                auth=self.auth, backend=self.backends[platform], clock=clock, sleep=sleep, notifier=self.notifier,
                report_sink=self.repo.save_report, ui_base_url=self.ui_base_url)
            for platform, adapter in self.adapters.items()
        }

    # ------------------------------------------------------------------ airflow

    def _airflow(self, e: dict[str, str], read_http: httpx.Client | None,
                 write_http: httpx.Client | None) -> tuple[PipelineAdapter, RemediationExecutor | None] | None:
        base_url = e.get("AIRFLOW_API_BASE_URL", "")
        version = e.get("AIRFLOW_API_VERSION") or "v1"
        if read_http is None and not base_url and self.settings.demo_mode:
            from fastapi.testclient import TestClient

            from demo.fake_airflow.app import create_app
            from demo.fake_airflow.state import load_scenario

            state = self.fake_airflow_state or load_scenario(e.get("FAKE_AIRFLOW_SCENARIO") or "hero_transient_network")
            state.sim_clock = self.clock
            self.fake_airflow_state = state
            app = create_app(state)
            read_http = TestClient(app, base_url="http://fake-airflow")
            write_http = TestClient(app, base_url="http://fake-airflow")
            base_url = "http://fake-airflow"
            self.fake_airflow = True
            _log.warning("fake_airflow_in_process", extra={"label": FAKE_AIRFLOW_LABEL})
        if read_http is None and not base_url:
            return None
        if read_http is not None and self.fake_airflow_state is not None:
            self.fake_airflow = True
        read_config = AirflowReadConfig(base_url=base_url or "http://airflow", api_version=version,
                                        username=e.get("AIRFLOW_READ_USERNAME") or None,
                                        password=e.get("AIRFLOW_READ_PASSWORD") or None,
                                        token=e.get("AIRFLOW_READ_TOKEN") or None,
                                        max_log_bytes=self.settings.max_log_bytes)
        adapter = AirflowAdapter(AirflowReadClient(read_config, http=read_http), demo=self.fake_airflow,
                                 max_log_bytes=self.settings.max_evidence_bytes, clock=self.clock)
        write_config = AirflowActionConfig.from_env(e).model_copy(update={"base_url": base_url, "api_version": version})
        backend: RemediationExecutor | None = None
        if write_http is not None or self.settings.airflow_write_credentials_present:
            backend = build_airflow_executor(write_config, http=write_http)
        return adapter, backend

    # ------------------------------------------------------------------ helpers

    def orchestrator(self, platform: str) -> HealingOrchestrator | None:
        return self.orchestrators.get(platform)

    def banners(self) -> Banners:
        return Banners(llm_mode=self.provider.mode, demo_mode=self.settings.demo_mode,
                       dry_run=self.settings.healing_execution_mode.value == "DRY_RUN",
                       fake_airflow=self.fake_airflow, healing_enabled=self.settings.healing_enabled,
                       execution_mode=self.settings.healing_execution_mode.value,
                       auth_provider=self.settings.auth_provider.value, halted=self.store.is_halted(),
                       demo_clock=isinstance(self.clock, DemoClock))

    def rebuild_index(self) -> None:
        """Re-create the in-memory dedup index from persisted incidents after a restart."""
        for record in self.store.list_incidents():
            report = self.repo.latest_report(record.incident_id)
            symptoms = {c.claim_id.removeprefix("c-symptom-") for c in (report.downstream_symptoms if report else [])}
            self.index.register(record.incident_id, record.event, record.event.failure_time or self.clock(), symptoms)
