"""Station 9: the AI Hunter. Proposes candidates; never decides.

Flow: context (redacted) -> prompt -> one AI call -> plain-code validation.
If the reply fails validation, retry ONCE telling the model exactly what was wrong.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from security_gate.ai import llm
from security_gate.ai.candidates import Candidate, parse_candidates
from security_gate.ai.context import Context
from security_gate.ai.prompts import HUNTER_SYSTEM, hunter_user_message

Caller = Callable[[str, str], llm.Reply]  # (system, user) -> Reply; swapped for a fake in tests


@dataclass
class HuntResult:
    candidates: list[Candidate]
    rejected: list[str]
    replies: list[llm.Reply] = field(default_factory=list)

    @property
    def cost_usd(self) -> float | None:
        costs = [r.cost_usd for r in self.replies]
        return None if any(c is None for c in costs) else sum(costs)  # type: ignore[arg-type]

    @property
    def tokens(self) -> tuple[int, int]:
        return sum(r.input_tokens for r in self.replies), sum(r.output_tokens for r in self.replies)


def hunt(context: Context, call: Caller | None = None) -> HuntResult:
    call = call or llm.complete_json
    user, _token = hunter_user_message(context.render())
    reply = call(HUNTER_SYSTEM, user)
    candidates, rejected = parse_candidates(reply.text, context.contents)
    result = HuntResult(candidates, rejected, [reply])

    if _unusable(reply.text, rejected):  # malformed reply: one retry with the exact problems
        fix = user + "\n\nYour previous reply was rejected:\n- " + "\n- ".join(rejected) + (
            "\nReturn ONLY the JSON object, citing only files and lines from the listing."
        )
        retry = call(HUNTER_SYSTEM, fix)
        candidates, rejected = parse_candidates(retry.text, context.contents)
        result = HuntResult(candidates, rejected, [reply, retry])
    return result


def _unusable(text: str, rejected: list[str]) -> bool:
    """Retry only when the whole reply was unusable, not when one candidate was filtered out."""
    return bool(rejected) and rejected[0].startswith(("reply is not valid JSON", "reply must be"))
