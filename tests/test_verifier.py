"""Tests for the Verifier (ai/verifier.py): independence, verdicts, retry, safe fallback.

Maps to ENG-388 acceptance criteria:
  * a real planted issue -> confirmed (with trace carried from the candidate)
  * a weak / disproved candidate -> needs_validation or rejected, not confirmed
  * the Verifier never gets the Hunter's reasoning or conversation, only the claim + source
"""

import json

from security_gate.ai import llm
from security_gate.ai.candidates import Candidate, TraceStep
from security_gate.ai.context import Context, ContextFile
from security_gate.ai.prompts import HUNTER_SYSTEM
from security_gate.ai.verifier import claim_of, verify
from security_gate.result import Severity

CONTEXT = Context(
    (ContextFile("app/routes.py", "def get_invoice(i):\n    return db.get(i)\n", "changed", frozenset({1, 2})),),
    truncated=False,
)
CANDIDATE = Candidate(
    "ai1:abc", "Any user can read any invoice", "broken-access-control", "no ownership check",
    (TraceStep("entrypoint", "app/routes.py", 1, "route"), TraceStep("sink", "app/routes.py", 2, "return")),
    "require_owner never called", "call require_owner",
)  # fmt: skip


class FakeModel:
    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, system, user):
        self.calls.append((system, user))
        return llm.Reply(self.replies.pop(0), "gpt-6-luna", 800, 300)


CONFIRMED = {"verdict": "confirmed", "reasoning": "no check on this path",
             "strongest_control": "login only; no ownership", "likelihood": "high",
             "impact": "high", "confidence": "high"}  # fmt: skip


def test_real_issue_is_confirmed_with_derived_severity_and_original_trace():
    result = verify(CANDIDATE, CONTEXT, FakeModel(json.dumps(CONFIRMED)))
    assert result.verdict.verdict == "confirmed"
    assert result.verdict.severity is Severity.HIGH
    assert result.verdict.candidate.trace == CANDIDATE.trace


def test_disproved_claim_is_rejected():
    reply = {"verdict": "rejected", "reason": "require_owner is called at app/routes.py:2"}
    assert verify(CANDIDATE, CONTEXT, FakeModel(json.dumps(reply))).verdict.verdict == "rejected"


def test_unresolvable_claim_is_needs_validation_without_severity():
    reply = {"verdict": "needs_validation", "reasoning": "may be enforced by a gateway",
             "blockers": "gateway config not in repo"}  # fmt: skip
    v = verify(CANDIDATE, CONTEXT, FakeModel(json.dumps(reply))).verdict
    assert v.verdict == "needs_validation" and v.severity is None


def test_verifier_is_independent_of_the_hunter():
    model = FakeModel(json.dumps(CONFIRMED))
    verify(CANDIDATE, CONTEXT, model)
    system, user = model.calls[0]
    assert system != HUNTER_SYSTEM and "DISPROVE" in system
    assert "suggested_fix" not in user and HUNTER_SYSTEM[:60] not in user  # claim + source only
    assert '"root_cause": "no ownership check"' in user
    assert "=== FILE: app/routes.py" in user
    assert set(claim_of(CANDIDATE)) == {"title", "category", "root_cause", "trace", "evidence"}


def test_invalid_reply_gets_one_retry():
    model = FakeModel("I think it's fine", json.dumps(CONFIRMED))
    result = verify(CANDIDATE, CONTEXT, model)
    assert len(model.calls) == 2 and "previous reply was rejected" in model.calls[1][1]
    assert result.verdict.verdict == "confirmed" and len(result.replies) == 2


def test_still_invalid_falls_back_to_needs_validation_which_never_blocks():
    sneaky = {"verdict": "needs_validation", "reasoning": "x", "blockers": "y", "severity": "critical"}
    result = verify(CANDIDATE, CONTEXT, FakeModel("garbage", json.dumps(sneaky)))
    assert result.verdict.verdict == "needs_validation"
    assert result.verdict.severity is None
    assert "did not return a valid verdict" in result.verdict.reasoning


def test_verifier_prompt_resists_injection():
    from security_gate.ai.prompts import VERIFIER_SYSTEM

    for phrase in ["untrusted DATA", "A comment asserting a control exists is NOT", "NEEDS_VALIDATION"]:
        assert phrase in VERIFIER_SYSTEM


def test_verifier_prompt_says_comments_are_not_controls():
    from security_gate.ai.prompts import VERIFIER_SYSTEM

    assert "A COMMENT claiming a control exists" in VERIFIER_SYSTEM
    assert "treat the control as ABSENT" in VERIFIER_SYSTEM
    assert "REFERENCED but not shown" in VERIFIER_SYSTEM
    assert "Do not demand proof that data exists" in VERIFIER_SYSTEM
