"""Application settings (spec B5) with fail-fast startup validation.

Defaults are the safe values from Rule 6: healing disabled, DRY_RUN, demo mode.
"""

import os
from collections.abc import Mapping
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ConfigurationError(RuntimeError):
    """Raised when the configuration is unsafe or inconsistent. Startup must abort."""


class ExecutionMode(str, Enum):
    DRY_RUN = "DRY_RUN"
    LIVE = "LIVE"


class AuthProviderName(str, Enum):
    DEMO = "demo"
    TOKEN = "token"


def _bool(raw: str | None, default: bool) -> bool:
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"invalid boolean value: {raw!r}")


def _int(raw: str | None, default: int, name: str) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    demo_mode: bool = True
    auth_provider: AuthProviderName = AuthProviderName.DEMO
    healing_enabled: bool = False
    healing_execution_mode: ExecutionMode = ExecutionMode.DRY_RUN
    max_healing_cycles: int = Field(default=2, ge=1)
    approval_ttl_minutes: int = Field(default=60, ge=1)
    high_risk_approvals: int = Field(default=2, ge=2)
    max_tasks_cleared: int = Field(default=25, ge=1)
    max_actions_per_dag_per_hour: int = Field(default=2, ge=1)
    verify_poll_seconds: int = Field(default=10, ge=1)
    verify_timeout_seconds: int = Field(default=600, ge=1)
    reconcile_attempts: int = Field(default=3, ge=1)
    reconcile_interval_seconds: int = Field(default=5, ge=0)
    airflow_api_base_url: str = ""
    airflow_api_version: str = ""
    airflow_write_credentials_present: bool = False
    anthropic_model: str = ""
    anthropic_api_key_present: bool = False
    webhook_secret_present: bool = False
    database_url: str = "sqlite:///./triage.db"
    max_log_bytes: int = Field(default=200_000, ge=1)
    max_evidence_bytes: int = Field(default=50_000, ge=1)
    max_llm_input_tokens: int = Field(default=50_000, ge=1)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        e = dict(os.environ if env is None else env)
        try:
            auth = AuthProviderName((e.get("AUTH_PROVIDER") or "demo").strip().lower())
            mode = ExecutionMode((e.get("HEALING_EXECUTION_MODE") or "DRY_RUN").strip().upper())
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc
        write_present = bool(
            (e.get("AIRFLOW_WRITE_USERNAME") and e.get("AIRFLOW_WRITE_PASSWORD"))
            or e.get("AIRFLOW_WRITE_TOKEN")
        )
        return cls(
            demo_mode=_bool(e.get("DEMO_MODE"), True),
            auth_provider=auth,
            healing_enabled=_bool(e.get("HEALING_ENABLED"), False),
            healing_execution_mode=mode,
            max_healing_cycles=_int(e.get("MAX_HEALING_CYCLES"), 2, "MAX_HEALING_CYCLES"),
            approval_ttl_minutes=_int(e.get("APPROVAL_TTL_MINUTES"), 60, "APPROVAL_TTL_MINUTES"),
            high_risk_approvals=_int(e.get("HIGH_RISK_APPROVALS"), 2, "HIGH_RISK_APPROVALS"),
            max_tasks_cleared=_int(e.get("MAX_TASKS_CLEARED"), 25, "MAX_TASKS_CLEARED"),
            max_actions_per_dag_per_hour=_int(
                e.get("MAX_ACTIONS_PER_DAG_PER_HOUR"), 2, "MAX_ACTIONS_PER_DAG_PER_HOUR"
            ),
            verify_poll_seconds=_int(e.get("VERIFY_POLL_SECONDS"), 10, "VERIFY_POLL_SECONDS"),
            verify_timeout_seconds=_int(e.get("VERIFY_TIMEOUT_SECONDS"), 600, "VERIFY_TIMEOUT_SECONDS"),
            reconcile_attempts=_int(e.get("RECONCILE_ATTEMPTS"), 3, "RECONCILE_ATTEMPTS"),
            reconcile_interval_seconds=_int(
                e.get("RECONCILE_INTERVAL_SECONDS"), 5, "RECONCILE_INTERVAL_SECONDS"
            ),
            airflow_api_base_url=e.get("AIRFLOW_API_BASE_URL", ""),
            airflow_api_version=e.get("AIRFLOW_API_VERSION", ""),
            airflow_write_credentials_present=write_present,
            anthropic_model=e.get("ANTHROPIC_MODEL", ""),
            anthropic_api_key_present=bool(e.get("ANTHROPIC_API_KEY")),
            webhook_secret_present=bool(e.get("WEBHOOK_SECRET")),
            database_url=e.get("DATABASE_URL") or "sqlite:///./triage.db",
            max_log_bytes=_int(e.get("MAX_LOG_BYTES"), 200_000, "MAX_LOG_BYTES"),
            max_evidence_bytes=_int(e.get("MAX_EVIDENCE_BYTES"), 50_000, "MAX_EVIDENCE_BYTES"),
            max_llm_input_tokens=_int(e.get("MAX_LLM_INPUT_TOKENS"), 50_000, "MAX_LLM_INPUT_TOKENS"),
        )

    @property
    def llm_mode_is_mock(self) -> bool:
        return not self.anthropic_api_key_present


def validate_startup(settings: Settings) -> None:
    """Fail fast on unsafe configuration combinations (spec B5, L5)."""
    if settings.healing_execution_mode is ExecutionMode.LIVE:
        problems: list[str] = []
        if settings.auth_provider is AuthProviderName.DEMO:
            problems.append("AUTH_PROVIDER=demo is refused when HEALING_EXECUTION_MODE=LIVE")
        if not settings.healing_enabled:
            problems.append("LIVE requires HEALING_ENABLED=true")
        if not settings.airflow_write_credentials_present:
            problems.append("LIVE requires AIRFLOW_WRITE_* credentials")
        if settings.demo_mode:
            problems.append("LIVE requires DEMO_MODE=false")
        if problems:
            raise ConfigurationError("; ".join(problems))
