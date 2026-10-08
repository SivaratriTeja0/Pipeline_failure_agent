"""LLM providers: Anthropic (with a stub client, no network) and the labeled mock."""

from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from agent.llm_provider import (
    DEFAULT_MODEL,
    AnthropicProvider,
    LLMRequest,
    LLMUnavailableError,
    MockLLMProvider,
    build_provider,
)
from agent.schemas import InvestigatorTurn, LLMOutputError, PlannerOutput, parse_llm_json
from core.models import LLMMode

REQ = LLMRequest(role="investigator", system="sys", messages=[{"role": "user", "content": "hi"}])


class StubMessages:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


def stub_client(response=None, error=None):
    messages = StubMessages(response, error)
    return SimpleNamespace(messages=messages, beta=SimpleNamespace(messages=messages)), messages


def message(text="{}", stop="end_turn"):
    return SimpleNamespace(content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
                           stop_reason=stop, model="claude-opus-5-5")


def test_anthropic_provider_returns_text_and_uses_fallbacks_by_default(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_FALLBACKS", raising=False)
    client, calls = stub_client(message('{"ok": 1}'))
    provider = AnthropicProvider(client=client)
    out = provider.generate(REQ)
    assert out.text == '{"ok": 1}' and provider.mode is LLMMode.LIVE
    sent = calls.calls[0]
    assert sent["model"] == DEFAULT_MODEL and sent["system"] == "sys"
    assert sent["fallbacks"] == "default" and sent["betas"] == ["server-side-fallback-2026-07-01"]


def test_model_and_fallbacks_from_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    monkeypatch.setenv("ANTHROPIC_FALLBACKS", "off")
    client, calls = stub_client(message())
    AnthropicProvider(client=client).generate(REQ)
    assert calls.calls[0]["model"] == "claude-sonnet-5-5" and "fallbacks" not in calls.calls[0]


@pytest.mark.parametrize("stop", ["refusal", "max_tokens"])
def test_refusal_and_truncation_are_failures(stop):
    client, _ = stub_client(message(stop=stop))
    with pytest.raises(LLMUnavailableError):
        AnthropicProvider(client=client).generate(REQ)


def _status_error(cls, code):
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls("boom", response=httpx2.Response(code, request=request), body=None)


@pytest.mark.parametrize("error", [
    _status_error(anthropic.AuthenticationError, 401),
    _status_error(anthropic.RateLimitError, 429),
    _status_error(anthropic.BadRequestError, 400),
    _status_error(anthropic.InternalServerError, 500),
    anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com")),
])
def test_sdk_errors_become_llm_unavailable(error):
    client, _ = stub_client(error=error)
    with pytest.raises(LLMUnavailableError):
        AnthropicProvider(client=client).generate(REQ)


def test_no_api_key_means_labeled_mock():
    provider = build_provider(api_key_present=False, mock_script=["{}"])
    assert isinstance(provider, MockLLMProvider) and provider.mode is LLMMode.MOCK


def test_mock_replays_script_and_repeats_last():
    mock = MockLLMProvider(["a", "b"])
    assert [mock.generate(REQ).text for _ in range(3)] == ["a", "b", "b"]


def test_parser_accepts_fenced_json_and_rejects_extras():
    turn = parse_llm_json('```json\n{"action": "conclude", "conclusion": null}\n```', InvestigatorTurn)
    assert turn.action == "conclude"
    with pytest.raises(LLMOutputError):
        parse_llm_json('{"rationale": "x", "action_type": "RETRY_FAILED_DAG_RUN"}', PlannerOutput)
    with pytest.raises(LLMOutputError):
        parse_llm_json("I think the answer is...", InvestigatorTurn)
