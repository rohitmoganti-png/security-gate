"""The ONLY place that talks to an AI provider. Two providers, one interface:

  SECURITY_GATE_PROVIDER=openai   (default) OpenAI Responses API with the client's own
                                  OPENAI_API_KEY; store=False
  SECURITY_GATE_PROVIDER=bedrock  Claude on Amazon Bedrock (bedrock-runtime / InvokeModel)
                                  via Anthropic's official SDK, using the standard AWS
                                  credential chain: temporary keys (AWS_ACCESS_KEY_ID /
                                  AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN) today, or a role
                                  assumed via GitHub OIDC later. No code change between the two.
  SECURITY_GATE_PROVIDER=litellm  a LiteLLM proxy (default http://127.0.0.1:4000, started inside the
                                  Security Check machine) that routes to Bedrock with the machine's
                                  role; key LITELLM_API_KEY; model = a LiteLLM alias (security-review).
                                  LiteLLM reports each call's ID and cost, which the report records.

Both: a timeout + a hard output cap so one call can't hang CI or run up a bill, and token
usage returned so every run can print what it cost.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# USD per 1M tokens (input, output).
# OpenAI: checked 2026-09-25 on developers.openai.com/api/docs/pricing.
# Claude: Anthropic list prices used as an ESTIMATE; Bedrock sets its own (check AWS pricing).
PRICES = {
    "gpt-6-luna": (0.10, 0.50),
    "gpt-5-nano": (0.05, 0.40),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5.4-mini": (0.75, 4.50),
    "gpt-6-sol": (2.00, 10.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}
DEFAULT_MODELS = {
    "openai": "gpt-6-luna",
    "bedrock": "global.anthropic.claude-sonnet-4-6",
    "litellm": "security-review",  # alias defined in litellm-config.yaml
}
DEFAULT_LITELLM_URL = "http://127.0.0.1:4000"
MAX_OUTPUT_TOKENS = 16_000  # includes any internal reasoning tokens


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class Reply:
    text: str
    model: str
    input_tokens: int
    output_tokens: int
    call_id: str | None = None  # LiteLLM's call ID (links the report to the LiteLLM log record)
    reported_cost: float | None = None  # cost reported by LiteLLM, used instead of our table
    fallback_used: bool | None = None  # LiteLLM only: did it switch to the fallback model?

    @property
    def cost_usd(self) -> float | None:
        if self.reported_cost is not None:
            return self.reported_cost
        price = PRICES.get(price_key(self.model))
        if price is None:
            return None
        return (self.input_tokens * price[0] + self.output_tokens * price[1]) / 1_000_000


def price_key(model: str) -> str:
    """'global.anthropic.claude-opus-4-6-v1' / 'us.anthropic.claude-haiku-4-5-20251001-v1:0'
    -> 'claude-opus-4-6' / 'claude-haiku-4-5'; OpenAI names pass through unchanged."""
    name = model.split("anthropic.", 1)[-1]
    name = re.sub(r"-\d{8}", "", name)  # date stamp
    name = re.sub(r"-v\d+(:\d+)?$", "", name)  # Bedrock version suffix
    return name


def provider() -> str:
    value = (os.environ.get("SECURITY_GATE_PROVIDER") or "openai").strip().lower()
    if value not in DEFAULT_MODELS:
        raise LLMError(f"unknown SECURITY_GATE_PROVIDER {value!r} (use 'openai', 'bedrock' or 'litellm')")
    return value


def model_name() -> str:
    return os.environ.get("SECURITY_GATE_MODEL") or DEFAULT_MODELS[provider()]


def region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


def api_key() -> str | None:
    return os.environ.get("OPENAI_API_KEY") or None


def litellm_url() -> str:
    return os.environ.get("LITELLM_BASE_URL") or DEFAULT_LITELLM_URL


def not_configured_reason() -> str | None:
    """None if the selected provider has credentials; otherwise why the AI review is skipped."""
    if provider() == "openai":
        return None if api_key() else "no OPENAI_API_KEY configured"
    if provider() == "litellm":
        return None if os.environ.get("LITELLM_API_KEY") else "no LITELLM_API_KEY (LiteLLM not started)"
    try:
        import botocore.session

        if botocore.session.get_session().get_credentials() is None:
            return "no AWS credentials for Bedrock (set AWS keys or a role)"
    except Exception:  # botocore missing or misconfigured
        return "AWS SDK unavailable for Bedrock"
    return None


def complete_json(system: str, user: str, model: str | None = None, timeout: float = 180) -> Reply:
    """One stateless call that must return a JSON object. Raises LLMError on any failure."""
    model = model or model_name()
    if provider() == "bedrock":
        return _bedrock(system, user, model, timeout)
    if provider() == "litellm":
        return _litellm(system, user, model, timeout)
    return _openai(system, user, model, timeout)


def strip_json_fences(text: str) -> str:
    """Claude on Bedrock has no JSON mode: if it wraps the object in ```json fences, unwrap it.
    Deterministic string handling only; the plain-code validator still checks everything."""
    t = text.strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", t, flags=re.DOTALL)
    return match.group(1) if match else t


# ---------- providers ----------


def _bedrock(system: str, user: str, model: str, timeout: float) -> Reply:
    import anthropic  # imported here so Station 8 works even without the package

    try:
        client = anthropic.AnthropicBedrock(aws_region=region(), timeout=timeout, max_retries=2)
        msg = client.messages.create(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
    except anthropic.AuthenticationError as exc:
        raise LLMError("Bedrock rejected the AWS credentials (expired temporary keys?)") from exc
    except anthropic.PermissionDeniedError as exc:
        raise LLMError(f"AWS identity may not call {model!r} on Bedrock (IAM/SCP): {exc}") from exc
    except anthropic.NotFoundError as exc:
        raise LLMError(f"model {model!r} not found in {region()} (check SECURITY_GATE_MODEL)") from exc
    except anthropic.RateLimitError as exc:
        raise LLMError("Bedrock throttled the request (quota)") from exc
    except (anthropic.APITimeoutError, anthropic.APIConnectionError) as exc:
        raise LLMError(f"could not reach Bedrock in {region()}: {exc}") from exc
    except anthropic.APIError as exc:
        raise LLMError(f"Bedrock API error: {exc}") from exc
    except Exception as exc:  # e.g. no credentials / botocore errors
        raise LLMError(f"Bedrock call failed: {type(exc).__name__}: {exc}") from exc

    if msg.stop_reason == "refusal":
        raise LLMError("Claude declined the request (refusal)")
    text = "".join(block.text for block in msg.content if block.type == "text")
    return Reply(strip_json_fences(text), model, msg.usage.input_tokens, msg.usage.output_tokens)


def _litellm(system: str, user: str, model: str, timeout: float) -> Reply:
    """Same Messages API as Bedrock, sent to the LiteLLM proxy (it does retries and the fallback)."""
    import anthropic

    client = anthropic.Anthropic(
        base_url=litellm_url(), api_key=os.environ.get("LITELLM_API_KEY"), timeout=timeout, max_retries=0
    )
    try:
        raw = client.messages.with_raw_response.create(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        msg = raw.parse()
    except anthropic.AuthenticationError as exc:
        raise LLMError("LiteLLM rejected the key (LITELLM_API_KEY)") from exc
    except anthropic.NotFoundError as exc:
        raise LLMError(f"LiteLLM has no model {model!r} (check litellm-config.yaml)") from exc
    except anthropic.RateLimitError as exc:
        raise LLMError("the model was throttled (after LiteLLM's retries and fallback)") from exc
    except (anthropic.APITimeoutError, anthropic.APIConnectionError) as exc:
        raise LLMError(f"could not reach LiteLLM at {litellm_url()}: {exc}") from exc
    except anthropic.APIError as exc:
        raise LLMError(f"LiteLLM/Bedrock error: {exc}") from exc

    if msg.stop_reason == "refusal":
        raise LLMError("Claude declined the request (refusal)")
    text = "".join(block.text for block in msg.content if block.type == "text")
    headers = raw.headers
    cost = None
    for name in ("x-litellm-response-cost", "x-litellm-response-cost-original"):
        try:
            cost = float(headers.get(name, ""))
            break
        except ValueError:
            continue
    fallbacks = headers.get("x-litellm-attempted-fallbacks")
    return Reply(
        strip_json_fences(text),
        headers.get("x-litellm-model-name") or msg.model or model,  # the real model, e.g. after fallback
        msg.usage.input_tokens,
        msg.usage.output_tokens,
        call_id=headers.get("x-litellm-call-id"),
        reported_cost=cost,
        fallback_used=(fallbacks not in ("", "0")) if fallbacks is not None else None,
    )


def _openai(system: str, user: str, model: str, timeout: float) -> Reply:
    import openai  # imported here so Station 8 works even without the package

    client = openai.OpenAI(api_key=api_key(), timeout=timeout, max_retries=2)
    try:
        response = client.responses.create(
            model=model,
            instructions=system,
            input=user,
            text={"format": {"type": "json_object"}},
            max_output_tokens=MAX_OUTPUT_TOKENS,
            store=False,
        )
    except openai.AuthenticationError as exc:
        raise LLMError("OpenAI rejected the API key (check the OPENAI_API_KEY secret)") from exc
    except openai.PermissionDeniedError as exc:
        raise LLMError(f"the API key may not use model {model!r} (check key permissions)") from exc
    except openai.NotFoundError as exc:
        raise LLMError(f"model {model!r} not found (check SECURITY_GATE_MODEL)") from exc
    except openai.RateLimitError as exc:
        raise LLMError("OpenAI rate limit or quota reached (check the project budget)") from exc
    except (openai.APITimeoutError, openai.APIConnectionError) as exc:
        raise LLMError(f"could not reach OpenAI: {exc}") from exc
    except openai.APIError as exc:
        raise LLMError(f"OpenAI API error: {exc}") from exc

    usage = response.usage
    return Reply(
        text=response.output_text or "",
        model=model,
        input_tokens=usage.input_tokens if usage else 0,
        output_tokens=usage.output_tokens if usage else 0,
    )
