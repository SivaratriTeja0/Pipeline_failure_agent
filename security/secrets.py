"""Deterministic secret scrubbing (spec Part M). Runs before any LLM call.

Covers private keys, JWTs, bearer/basic auth headers, AWS access keys and secrets,
credentials in connection strings, and key=value assignments for password/token/secret/key.
"""

import re
from collections import Counter

from pydantic import BaseModel, Field


def _redacted(kind: str) -> str:
    return f"<SECRET_REDACTED:{kind}>"


_KV_NAMES = (
    r"password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token"
    r"|refresh[_-]?token|token|private[_-]?key|aws_secret_access_key|secret[_-]?key|sas[_-]?token"
)

# Order matters: most specific first.
_RULES: tuple[tuple[str, re.Pattern[str], str | None], ...] = (
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        None,
    ),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), None),
    (
        "AUTH_HEADER",
        re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*"),
        r"\1 " + _redacted("AUTH_HEADER"),
    ),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), None),
    (
        "CONNECTION_STRING",
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):([^\s@/]+)@"),
        r"\1:" + _redacted("CONNECTION_STRING") + "@",
    ),
    (
        "KEY_VALUE",
        re.compile(
            rf"(?i)\b({_KV_NAMES})(\s*[:=]\s*|\"\s*:\s*\"|'\s*:\s*')(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}}]+)"
        ),
        r"\1\2" + _redacted("KEY_VALUE"),
    ),
)


class ScrubResult(BaseModel):
    text: str
    findings: dict[str, int] = Field(default_factory=dict)

    @property
    def found(self) -> bool:
        return bool(self.findings)


def scrub_secrets(text: str) -> ScrubResult:
    counts: Counter[str] = Counter()
    out = text
    for kind, pattern, replacement in _RULES:
        repl = replacement if replacement is not None else _redacted(kind)
        out, n = pattern.subn(repl, out)
        if n:
            counts[kind] += n
    return ScrubResult(text=out, findings=dict(counts))
