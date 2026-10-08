"""Notifications (spec Part Q). Console by default; Slack and/or email when configured by env vars.

Messages never carry a link or token that approves anything: approval-request notifications link to
the Incident Details page of the authenticated UI, where a logged-in approver must act. Credentials
come only from the environment. A failing channel is logged and never breaks the caller.

    NOTIFY_SLACK_WEBHOOK_URL   Slack incoming-webhook URL
    NOTIFY_SMTP_HOST / NOTIFY_SMTP_PORT / NOTIFY_SMTP_USERNAME / NOTIFY_SMTP_PASSWORD
    NOTIFY_EMAIL_FROM / NOTIFY_EMAIL_TO (comma-separated)
    UI_BASE_URL                base URL of the Streamlit UI used in links (default http://localhost:8501)
"""

import os
import smtplib
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Mapping
from email.message import EmailMessage
from enum import Enum
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from core.logging_setup import get_logger
from core.models.remediation import RemediationPlan
from core.models.report import UniversalTriageReport

_log = get_logger(__name__)


class NotificationKind(str, Enum):
    TRIAGE = "TRIAGE"
    APPROVAL_REQUEST = "APPROVAL_REQUEST"
    EXECUTION_RESULT = "EXECUTION_RESULT"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"
    EXECUTION_UNCERTAIN = "EXECUTION_UNCERTAIN"
    ESCALATION = "ESCALATION"


class Notification(BaseModel):
    kind: NotificationKind
    incident_id: str
    title: str
    fields: dict[str, Any] = Field(default_factory=dict)
    link: str | None = None

    def text(self) -> str:
        body = "\n".join(f"{k}: {v}" for k, v in self.fields.items())
        link = f"\nOpen in the authenticated UI: {self.link}" if self.link else ""
        return f"[{self.kind.value}] {self.title}\n{body}{link}"


class Notifier(ABC):
    @abstractmethod
    def send(self, notification: Notification) -> None:
        """Deliver a notification. Must not raise."""


class ConsoleNotifier(Notifier):
    def __init__(self, keep: int = 200) -> None:
        self.sent: deque[Notification] = deque(maxlen=keep)

    def send(self, notification: Notification) -> None:
        self.sent.append(notification)
        _log.info("notification", extra={"kind": notification.kind.value, "incident_id": notification.incident_id,
                                         "title": notification.title})


class SlackNotifier(Notifier):
    def __init__(self, webhook_url: str, http: httpx.Client | None = None) -> None:
        self._url = webhook_url
        self._http = http or httpx.Client(timeout=10)

    def send(self, notification: Notification) -> None:
        try:
            self._http.post(self._url, json={"text": notification.text()}).raise_for_status()
        except httpx.HTTPError as exc:
            _log.warning("slack_notification_failed", extra={"error": type(exc).__name__})


class EmailNotifier(Notifier):
    def __init__(self, host: str, port: int, sender: str, recipients: list[str],
                 username: str | None = None, password: str | None = None) -> None:
        self._host, self._port, self._sender, self._recipients = host, port, sender, recipients
        self._username, self._password = username, password

    def send(self, notification: Notification) -> None:
        message = EmailMessage()
        message["Subject"] = f"[pipeline-triage] {notification.title}"
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content(notification.text())
        try:
            with smtplib.SMTP(self._host, self._port, timeout=10) as smtp:
                if self._username and self._password:
                    smtp.starttls()
                    smtp.login(self._username, self._password)
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            _log.warning("email_notification_failed", extra={"error": type(exc).__name__})


class FanoutNotifier(Notifier):
    def __init__(self, notifiers: list[Notifier]) -> None:
        self.notifiers = notifiers

    def send(self, notification: Notification) -> None:
        for notifier in self.notifiers:
            try:
                notifier.send(notification)
            except Exception as exc:  # a broken channel never breaks triage or healing
                _log.warning("notification_channel_failed", extra={"error": type(exc).__name__})


def build_notifier(env: Mapping[str, str] | None = None) -> FanoutNotifier:
    e = dict(os.environ if env is None else env)
    channels: list[Notifier] = [ConsoleNotifier()]
    if e.get("NOTIFY_SLACK_WEBHOOK_URL"):
        channels.append(SlackNotifier(e["NOTIFY_SLACK_WEBHOOK_URL"]))
    if e.get("NOTIFY_SMTP_HOST") and e.get("NOTIFY_EMAIL_TO") and e.get("NOTIFY_EMAIL_FROM"):
        channels.append(EmailNotifier(
            e["NOTIFY_SMTP_HOST"], int(e.get("NOTIFY_SMTP_PORT") or 587), e["NOTIFY_EMAIL_FROM"],
            [x.strip() for x in e["NOTIFY_EMAIL_TO"].split(",") if x.strip()],
            e.get("NOTIFY_SMTP_USERNAME") or None, e.get("NOTIFY_SMTP_PASSWORD") or None))
    return FanoutNotifier(channels)


# ----------------------------------------------------------------------------- message builders


def incident_link(ui_base_url: str, incident_id: str) -> str:
    """A link to the Incident Details page. Viewing and acting there require authentication."""
    return f"{ui_base_url.rstrip('/')}/?page=Incident+Details&incident={quote(incident_id)}"


def triage_notification(report: UniversalTriageReport, ui_base_url: str) -> Notification:
    return Notification(
        kind=NotificationKind.TRIAGE, incident_id=report.incident_id,
        title=f"Triage: {report.pipeline_id}.{report.task_id or '-'} {report.failure_category.value}",
        fields={"pipeline": report.pipeline_id, "task": report.task_id, "category": report.failure_category.value,
                "confidence": report.confidence.value, "root_cause": report.root_cause.text,
                "remediation_class": report.remediation_class.value, "rerun_safety": report.rerun_safety.value,
                "report_id": report.incident_id, "llm_mode": report.llm_mode.value},
        link=incident_link(ui_base_url, report.incident_id))


def approval_request_notification(plan: RemediationPlan, required: int, ui_base_url: str) -> Notification:
    return Notification(
        kind=NotificationKind.APPROVAL_REQUEST, incident_id=plan.incident_id,
        title=f"Approval requested: {plan.action_type.value if plan.action_type else '-'} ({plan.risk_level.value} risk)",
        fields={"plan": f"{plan.remediation_id} v{plan.plan_version}",
                "scope": plan.recovery_scope.value if plan.recovery_scope else None,
                "target": f"{plan.target.dag_id}/{plan.target.dag_run_id}" if plan.target else None,
                "task_instances": ", ".join(t.task_id for t in plan.task_instances_to_clear),
                "risk": plan.risk_level.value, "approvals_required": required,
                "expires_at": plan.expires_at.isoformat(), "execution_mode": plan.execution_mode.value,
                "note": "Review and decide in the authenticated UI. This message cannot approve anything."},
        link=incident_link(ui_base_url, plan.incident_id))


def outcome_notification(kind: NotificationKind, incident_id: str, title: str, fields: dict[str, Any],
                         ui_base_url: str) -> Notification:
    return Notification(kind=kind, incident_id=incident_id, title=title, fields=fields,
                        link=incident_link(ui_base_url, incident_id))
