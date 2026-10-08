"""Webhook authentication (spec Part M, N).

POST /webhooks/failure carries ``X-Triage-Signature: sha256=<hex>`` = HMAC-SHA256(WEBHOOK_SECRET, raw body).
- invalid signature                          -> 401, always
- missing signature, DEMO_MODE=false         -> 401
- missing signature, DEMO_MODE=true          -> accepted, and the response says it was unsigned
- no WEBHOOK_SECRET configured, not demo     -> 401 (nothing can be verified)

A webhook can only report a failure. It never approves, rejects or executes anything: any
approval-like text in its body is untrusted data that, at most, ends up as evidence.
"""

import hashlib
import hmac

from pydantic import BaseModel

SIGNATURE_HEADER = "X-Triage-Signature"
_PREFIX = "sha256="


class WebhookVerdict(BaseModel):
    accepted: bool
    signed: bool
    reason: str


def sign(secret: str, body: bytes) -> str:
    """The header value a sender must attach (used by the documented Airflow callback snippet)."""
    return _PREFIX + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_webhook(body: bytes, signature: str | None, secret: str | None, demo_mode: bool) -> WebhookVerdict:
    if signature:
        if not secret:
            return WebhookVerdict(accepted=False, signed=True, reason="no WEBHOOK_SECRET configured to verify against")
        if not signature.startswith(_PREFIX):
            return WebhookVerdict(accepted=False, signed=True, reason="malformed signature")
        if not hmac.compare_digest(sign(secret, body), signature.strip()):
            return WebhookVerdict(accepted=False, signed=True, reason="invalid signature")
        return WebhookVerdict(accepted=True, signed=True, reason="signature valid")
    if demo_mode:
        return WebhookVerdict(accepted=True, signed=False,
                              reason="UNSIGNED request accepted only because DEMO_MODE=true")
    return WebhookVerdict(accepted=False, signed=False, reason="missing signature")
