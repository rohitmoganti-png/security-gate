"""The ONLY place that talks to the AI provider (OpenAI, the client's own key).

* store=False: ask OpenAI not to keep the conversation as a stored response
* timeout + a hard cap on output tokens so one call can't hang CI or run up a bill
* returns token usage so every run can print what it cost
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# USD per 1M tokens (input, output). Checked 2026-09-25 on developers.openai.com/api/docs/pricing.
PRICES = {
    "gpt-6-luna": (0.10, 0.50),
    "gpt-5-nano": (0.05, 0.40),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5.4-mini": (0.75, 4.50),
    "gpt-6-sol": (2.00, 10.00),
}
DEFAULT_MODEL = "gpt-6-luna"
MAX_OUTPUT_TOKENS = 16_000  # includes the model's internal reasoning tokens


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class Reply:
    text: str
    model: str
    input_tokens: int
    output_tokens: int

    @property
    def cost_usd(self) -> float | None:
        price = PRICES.get(self.model)
        if price is None:
            return None
        return (self.input_tokens * price[0] + self.output_tokens * price[1]) / 1_000_000


def api_key() -> str | None:
    return os.environ.get("OPENAI_API_KEY") or None


def model_name() -> str:
    return os.environ.get("SECURITY_GATE_MODEL") or DEFAULT_MODEL


def complete_json(system: str, user: str, model: str | None = None, timeout: float = 180) -> Reply:
    """One stateless call that must return a JSON object. Raises LLMError on any failure."""
    import openai  # imported here so Station 8 works even without the package

    model = model or model_name()
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
