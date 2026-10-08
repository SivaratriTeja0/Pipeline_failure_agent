"""LLM providers. The LLM only ever returns text; callers parse it into strict schemas.

- ``AnthropicProvider``: Claude via the official ``anthropic`` SDK. Model from ANTHROPIC_MODEL
  (default ``claude-opus-5-5``). Server-side refusal fallbacks are enabled by default
  (``fallbacks="default"``); set ANTHROPIC_FALLBACKS=off to disable them.
- ``MockLLMProvider``: scripted, deterministic, clearly labeled MOCK output. Used whenever no
  API key is configured. Mock scores validate plumbing only, not diagnostic accuracy.
"""

import os
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from typing import Any, Literal

from pydantic import BaseModel, Field

from core.logging_setup import get_logger
from core.models.enums import LLMMode

_log = get_logger(__name__)

DEFAULT_MODEL = "claude-opus-5-5"
MOCK_LABEL = "MOCK LLM (scripted output, not a real model)"

Role = Literal["investigator", "planner"]


class LLMRequest(BaseModel):
    role: Role
    system: str
    messages: list[dict[str, str]]
    # Structured view of the same context. Ignored by real models; used by the scripted mock.
    context: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    text: str
    model: str
    stop_reason: str | None = None


class LLMUnavailableError(RuntimeError):
    """The provider could not produce a response (network, auth, rate limit, refusal)."""


class LLMProvider(ABC):
    mode: LLMMode
    model: str

    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        """Return the model's raw text response, or raise LLMUnavailableError."""


class AnthropicProvider(LLMProvider):
    mode = LLMMode.LIVE

    def __init__(
        self,
        *,
        model: str | None = None,
        client: Any | None = None,
        max_tokens: int = 16000,
        timeout_seconds: float = 120.0,
        fallbacks: bool | None = None,
    ) -> None:
        self.model = model or os.environ.get("ANTHROPIC_MODEL") or DEFAULT_MODEL
        if fallbacks is None:
            fallbacks = os.environ.get("ANTHROPIC_FALLBACKS", "default").strip().lower() != "off"
        self._fallbacks = fallbacks
        self._max_tokens = max_tokens
        if client is None:
            import anthropic

            client = anthropic.Anthropic(timeout=timeout_seconds, max_retries=2)
        self._client = client

    def generate(self, request: LLMRequest) -> LLMResponse:
        import anthropic

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "system": request.system,
            "messages": request.messages,
        }
        try:
            if self._fallbacks:
                response = self._client.beta.messages.create(
                    betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs
                )
            else:
                response = self._client.messages.create(**kwargs)
        except anthropic.AuthenticationError as exc:
            raise LLMUnavailableError("Anthropic authentication failed") from exc
        except anthropic.RateLimitError as exc:
            raise LLMUnavailableError("Anthropic rate limit") from exc
        except anthropic.BadRequestError as exc:
            raise LLMUnavailableError(f"Anthropic rejected the request: {exc.message}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMUnavailableError(f"Anthropic API error {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:  # includes APITimeoutError
            raise LLMUnavailableError("Anthropic unreachable") from exc

        if response.stop_reason == "refusal":
            raise LLMUnavailableError("model declined the request (refusal)")
        if response.stop_reason == "max_tokens":
            raise LLMUnavailableError("model output truncated (max_tokens)")
        text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text")
        return LLMResponse(text=text, model=str(getattr(response, "model", self.model)),
                           stop_reason=response.stop_reason)


Script = Callable[[LLMRequest], str] | Sequence[str]


class MockLLMProvider(LLMProvider):
    """Deterministic scripted provider. A sequence is replayed in order (last entry repeats);
    a callable receives each request and returns text."""

    mode = LLMMode.MOCK

    def __init__(self, script: Script) -> None:
        self.model = "mock"
        self._script = script
        self.requests: list[LLMRequest] = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if callable(self._script):
            text = self._script(request)
        else:
            if not self._script:
                raise LLMUnavailableError("empty mock script")
            index = min(len(self.requests) - 1, len(self._script) - 1)
            text = self._script[index]
        return LLMResponse(text=text, model="mock", stop_reason="end_turn")


def build_provider(api_key_present: bool, mock_script: Script) -> LLMProvider:
    """No API key -> MOCK (clearly labeled). Never hard-codes keys."""
    if api_key_present:
        return AnthropicProvider()
    _log.warning("llm_mode_mock", extra={"label": MOCK_LABEL})
    return MockLLMProvider(mock_script)
