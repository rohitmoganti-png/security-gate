"""Station 10: the AI Verifier. Tries to DISPROVE each Hunter candidate, independently.

Independence (ticket ENG-388): every candidate gets its own fresh call. The Verifier sees
only the structured CLAIM plus the redacted source, never the Hunter's instructions,
reasoning or conversation.

Safe fallback: if the Verifier's reply is still invalid after one retry, the candidate becomes
needs_validation, which can never block. A confused AI can't cause a false block.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from security_gate.ai import llm
from security_gate.ai.candidates import Candidate
from security_gate.ai.context import Context
from security_gate.ai.hunter import Caller
from security_gate.ai.prompts import VERIFIER_SYSTEM, verifier_user_message
from security_gate.ai.verdicts import Verdict, VerdictError, parse_verdict


@dataclass
class VerifyResult:
    verdict: Verdict
    replies: list[llm.Reply] = field(default_factory=list)


def claim_of(candidate: Candidate) -> dict:
    """What the Verifier is allowed to see about the Hunter's finding: the claim, nothing else."""
    return {
        "title": candidate.title,
        "category": candidate.category,
        "root_cause": candidate.root_cause,
        "trace": [
            {"kind": s.kind, "path": s.path, "line": s.line, "description": s.description}
            for s in candidate.trace
        ],
        "evidence": candidate.evidence,
    }


def verify(candidate: Candidate, context: Context, call: Caller | None = None) -> VerifyResult:
    call = call or llm.complete_json
    user, _token = verifier_user_message(claim_of(candidate), context.render())
    replies = [call(VERIFIER_SYSTEM, user)]
    try:
        return VerifyResult(parse_verdict(replies[0].text, candidate), replies)
    except VerdictError as first_error:
        retry_msg = f"{user}\n\nYour previous reply was rejected: {first_error}\nReturn ONLY a valid verdict JSON."
        replies.append(call(VERIFIER_SYSTEM, retry_msg))
        try:
            return VerifyResult(parse_verdict(replies[1].text, candidate), replies)
        except VerdictError as second_error:
            fallback = Verdict(
                candidate,
                "needs_validation",
                f"The verifier did not return a valid verdict ({second_error}).",
                blockers="Automated verification failed; a human should review this candidate.",
            )
            return VerifyResult(fallback, replies)
