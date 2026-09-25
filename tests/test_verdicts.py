"""Tests for the Verifier verdict format + plain-code validator (security_gate/ai/verdicts.py).

Maps to ENG-389 acceptance criteria:
  * well-formed confirmed / needs_validation / rejected each pass
  * a severity on needs_validation is REJECTED by the validator, not just flagged
  * the validator is plain code (no model call anywhere in these tests)
"""

import json

import pytest

from security_gate.ai.candidates import Candidate, TraceStep
from security_gate.ai.verdicts import VerdictError, derive_severity, parse_verdict
from security_gate.result import Severity

CANDIDATE = Candidate(
    fingerprint="ai1:abc",
    title="Any user can read any invoice",
    category="broken-access-control",
    root_cause="no ownership check",
    trace=(TraceStep("entrypoint", "app/routes.py", 25, "route"), TraceStep("sink", "app/routes.py", 32, "return")),
    evidence="require_owner never called",
    suggested_fix="call require_owner",
)

CONFIRMED = {
    "verdict": "confirmed",
    "reasoning": "No control on this path checks ownership; require_owner exists but is never called.",
    "strongest_control": "current_user() only proves the caller is logged in, not that they own the invoice.",
    "likelihood": "high",
    "impact": "high",
    "confidence": "high",
}
NEEDS_VALIDATION = {
    "verdict": "needs_validation",
    "reasoning": "An API gateway could enforce ownership, but its config is not in the repo.",
    "blockers": "Need the gateway routing/authorization config to decide.",
}
REJECTED = {"verdict": "rejected", "reason": "require_owner is called on line 30 before the return."}


def verdict(data):
    return parse_verdict(json.dumps(data), CANDIDATE)


def test_confirmed_passes_and_severity_is_derived_by_code():
    v = verdict(CONFIRMED)
    assert v.verdict == "confirmed"
    assert v.severity is Severity.HIGH  # high likelihood x high impact, from the table
    assert v.candidate.fingerprint == "ai1:abc"  # identity comes from the Hunter's candidate


def test_needs_validation_passes_with_no_severity():
    v = verdict(NEEDS_VALIDATION)
    assert v.verdict == "needs_validation" and v.severity is None
    assert "gateway" in v.blockers


def test_rejected_passes():
    v = verdict(REJECTED)
    assert v.verdict == "rejected" and v.severity is None and "line 30" in v.reasoning


@pytest.mark.parametrize("sneaky", [{"severity": "critical"}, {"likelihood": "high"}, {"impact": "high"}])
def test_needs_validation_can_never_carry_a_severity(sneaky):
    with pytest.raises(VerdictError, match="not allowed"):
        verdict({**NEEDS_VALIDATION, **sneaky})


@pytest.mark.parametrize(
    ("bad", "reason"),
    [
        ({**CONFIRMED, "verdict": "probably"}, "verdict must be one of"),
        ({**CONFIRMED, "severity": "critical"}, "not allowed"),  # the AI can't declare severity
        ({k: v for k, v in CONFIRMED.items() if k != "strongest_control"}, "missing"),
        ({**CONFIRMED, "impact": "catastrophic"}, "impact must be one of"),
        ({**CONFIRMED, "confidence": "low"}, "confidence must be one of"),  # low confidence ≠ confirmed
        ({**CONFIRMED, "reasoning": "  "}, "non-empty"),
        ({**REJECTED, "reason": ""}, "non-empty"),
    ],
)
def test_malformed_verdicts_are_rejected(bad, reason):
    with pytest.raises(VerdictError, match=reason):
        verdict(bad)


@pytest.mark.parametrize("text", ["not json", "[1, 2]"])
def test_non_object_replies_are_rejected(text):
    with pytest.raises(VerdictError):
        parse_verdict(text, CANDIDATE)


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected"),
    [
        ("high", "critical", Severity.CRITICAL),
        ("low", "critical", Severity.HIGH),
        ("medium", "high", Severity.HIGH),
        ("low", "high", Severity.MEDIUM),
        ("high", "low", Severity.MEDIUM),
        ("low", "low", Severity.LOW),
    ],
)
def test_severity_table(likelihood, impact, expected):
    assert derive_severity(likelihood, impact) is expected
