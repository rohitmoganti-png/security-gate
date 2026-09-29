"""Tests for the AI provider layer (security_gate/ai/llm.py). No network, no cost."""

from types import SimpleNamespace

import anthropic
import pytest

from security_gate.ai import llm


def test_provider_selection_and_default_models(monkeypatch):
    monkeypatch.delenv("SECURITY_GATE_PROVIDER", raising=False)
    monkeypatch.delenv("SECURITY_GATE_MODEL", raising=False)
    assert (llm.provider(), llm.model_name()) == ("openai", "gpt-6-luna")
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "Bedrock")
    assert (llm.provider(), llm.model_name()) == ("bedrock", "global.anthropic.claude-sonnet-4-6")
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "azure")
    with pytest.raises(llm.LLMError, match="unknown SECURITY_GATE_PROVIDER"):
        llm.provider()


@pytest.mark.parametrize(
    ("model", "key"),
    [
        ("global.anthropic.claude-opus-4-6-v1", "claude-opus-4-6"),
        ("us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5"),
        ("global.anthropic.claude-sonnet-4-6", "claude-sonnet-4-6"),
        ("anthropic.claude-opus-5", "claude-opus-5"),
        ("gpt-6-luna", "gpt-6-luna"),
    ],
)
def test_price_key_normalises_bedrock_ids(model, key):
    assert llm.price_key(model) == key


def test_cost_for_bedrock_model():
    assert llm.Reply("", "global.anthropic.claude-sonnet-4-6", 1_000_000, 1_000_000).cost_usd == pytest.approx(18.0)


@pytest.mark.parametrize(
    "text",
    ['{"candidates": []}', '```json\n{"candidates": []}\n```', '```\n{"candidates": []}\n```'],
)
def test_json_fences_are_stripped_deterministically(text):
    assert llm.strip_json_fences(text) == '{"candidates": []}'


def test_bedrock_without_aws_credentials_is_not_configured(monkeypatch):
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "bedrock")
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    assert "no AWS credentials" in llm.not_configured_reason()


def test_bedrock_with_temporary_keys_is_configured(monkeypatch):
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "token")
    assert llm.not_configured_reason() is None


class FakeBedrock:
    """Stands in for anthropic.AnthropicBedrock: records the call, returns a canned message."""

    last_call: dict = {}

    def __init__(self, **kwargs):
        FakeBedrock.init = kwargs
        self.messages = self

    def create(self, **kwargs):
        FakeBedrock.last_call = kwargs
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='```json\n{"candidates": []}\n```')],
            usage=SimpleNamespace(input_tokens=1200, output_tokens=300),
            stop_reason="end_turn",
        )


def test_bedrock_call_shape_and_reply(monkeypatch):
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "bedrock")
    monkeypatch.setenv("SECURITY_GATE_MODEL", "global.anthropic.claude-opus-4-6-v1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setattr(anthropic, "AnthropicBedrock", FakeBedrock)

    reply = llm.complete_json("SYSTEM PROMPT", "USER MESSAGE")
    assert reply.text == '{"candidates": []}'  # fences stripped
    assert (reply.input_tokens, reply.output_tokens) == (1200, 300)
    assert reply.cost_usd == pytest.approx((1200 * 5 + 300 * 25) / 1_000_000)
    assert FakeBedrock.init["aws_region"] == "us-east-1"
    assert FakeBedrock.last_call["system"] == "SYSTEM PROMPT"
    assert FakeBedrock.last_call["messages"] == [{"role": "user", "content": "USER MESSAGE"}]
    assert FakeBedrock.last_call["model"] == "global.anthropic.claude-opus-4-6-v1"


def test_bedrock_refusal_is_an_error(monkeypatch):
    class Refuses(FakeBedrock):
        def create(self, **kwargs):
            return SimpleNamespace(content=[], usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                                   stop_reason="refusal")  # fmt: skip

    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "bedrock")
    monkeypatch.setattr(anthropic, "AnthropicBedrock", Refuses)
    with pytest.raises(llm.LLMError, match="refusal"):
        llm.complete_json("s", "u")


# ---------- LiteLLM provider ----------


class FakeRaw:
    """Stands in for anthropic's raw response: LiteLLM's headers + the parsed message."""

    def __init__(self, headers):
        self.headers = headers

    def parse(self):
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"candidates": []}')],
            usage=SimpleNamespace(input_tokens=1000, output_tokens=200),
            stop_reason="end_turn",
            model="bedrock/global.anthropic.claude-sonnet-4-6",
        )


class FakeAnthropic:
    """Stands in for anthropic.Anthropic pointed at the LiteLLM proxy."""

    headers = {
        "x-litellm-call-id": "call-123",
        "x-litellm-response-cost": "0.0061",
        "x-litellm-model-name": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "x-litellm-attempted-fallbacks": "1",
    }

    def __init__(self, **kwargs):
        FakeAnthropic.init = kwargs
        self.messages = SimpleNamespace(with_raw_response=self)

    def create(self, **kwargs):
        FakeAnthropic.last_call = kwargs
        return FakeRaw(FakeAnthropic.headers)


def test_litellm_is_not_configured_without_its_key(monkeypatch):
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "litellm")
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    assert "LITELLM_API_KEY" in llm.not_configured_reason()
    monkeypatch.setenv("LITELLM_API_KEY", "sk-test")
    assert llm.not_configured_reason() is None


def test_litellm_call_shape_and_reported_cost(monkeypatch):
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "litellm")
    monkeypatch.delenv("SECURITY_GATE_MODEL", raising=False)
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.setenv("LITELLM_API_KEY", "sk-test")
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)

    reply = llm.complete_json("SYSTEM", "USER")
    assert FakeAnthropic.init["base_url"] == "http://127.0.0.1:4000"
    assert FakeAnthropic.init["api_key"] == "sk-test"
    assert FakeAnthropic.last_call["model"] == "security-review"  # the LiteLLM alias
    assert FakeAnthropic.last_call["system"] == "SYSTEM"
    assert reply.call_id == "call-123"
    assert reply.cost_usd == pytest.approx(0.0061)  # LiteLLM's number, not our price table
    assert reply.model == "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"  # the model that answered
    assert reply.fallback_used is True


def test_litellm_without_cost_header_falls_back_to_price_table(monkeypatch):
    monkeypatch.setenv("SECURITY_GATE_PROVIDER", "litellm")
    monkeypatch.setenv("LITELLM_API_KEY", "sk-test")
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    monkeypatch.setattr(FakeAnthropic, "headers", {})
    reply = llm.complete_json("s", "u")
    assert reply.call_id is None
    assert reply.fallback_used is None
    assert reply.model == "bedrock/global.anthropic.claude-sonnet-4-6"  # from the message itself
    assert reply.cost_usd == pytest.approx((1000 * 3 + 200 * 15) / 1_000_000)  # sonnet-4-6 prices
