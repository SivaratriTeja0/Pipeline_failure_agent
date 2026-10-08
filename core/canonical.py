"""Canonical JSON serialization and hashing used for plan hashes and the audit chain.

Canonical form: keys sorted, no insignificant whitespace, UTF-8, no NaN/Infinity.
Two semantically identical payloads always produce byte-identical output.
"""

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to canonical JSON. Raises ValueError on non-finite floats."""
    return json.dumps(
        _to_jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_hash(value: Any) -> str:
    """SHA-256 hex digest of the canonical JSON form of ``value``."""
    return sha256_hex(canonical_json(value))
