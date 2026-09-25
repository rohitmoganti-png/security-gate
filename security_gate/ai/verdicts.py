"""Station 10 output format (ticket ENG-389): the Verifier's verdict + a PLAIN-CODE validator.

Exactly three verdicts, each with an exact set of fields (no extras allowed):

  confirmed         reasoning, strongest_control, likelihood, impact, confidence
  needs_validation  reasoning, blockers              <- NO likelihood/impact/severity: can never block
  rejected          reason

Severity is DERIVED here from likelihood x impact by a fixed table: the AI can't just
declare "critical". The candidate's identity (file, trace, fingerprint) comes from the
Hunter's validated candidate, never from the Verifier.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from security_gate.ai.candidates import Candidate
from security_gate.result import Severity

LIKELIHOOD = ("low", "medium", "high")
IMPACT = ("low", "medium", "high", "critical")
CONFIDENCE = ("medium", "high")  # "low confidence" is not a confirmation: use needs_validation

_SCHEMAS = {
    "confirmed": {"verdict", "reasoning", "strongest_control", "likelihood", "impact", "confidence"},
    "needs_validation": {"verdict", "reasoning", "blockers"},
    "rejected": {"verdict", "reason"},
}

# rows = impact, columns = likelihood (low, medium, high). Never above what's demonstrated.
_SEVERITY_TABLE = {
    "low": (Severity.LOW, Severity.LOW, Severity.MEDIUM),
    "medium": (Severity.LOW, Severity.MEDIUM, Severity.MEDIUM),
    "high": (Severity.MEDIUM, Severity.HIGH, Severity.HIGH),
    "critical": (Severity.HIGH, Severity.HIGH, Severity.CRITICAL),
}


class VerdictError(ValueError):
    pass


@dataclass(frozen=True)
class Verdict:
    candidate: Candidate
    verdict: str  # "confirmed" | "needs_validation" | "rejected"
    reasoning: str  # for rejected: the reason
    severity: Severity | None = None  # set ONLY for confirmed
    likelihood: str | None = None
    impact: str | None = None
    confidence: str | None = None
    strongest_control: str | None = None
    blockers: str | None = None


def derive_severity(likelihood: str, impact: str) -> Severity:
    return _SEVERITY_TABLE[impact][LIKELIHOOD.index(likelihood)]


def parse_verdict(raw_text: str, candidate: Candidate) -> Verdict:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise VerdictError(f"reply is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise VerdictError("reply must be a JSON object")

    kind = data.get("verdict")
    if kind not in _SCHEMAS:
        raise VerdictError(f"verdict must be one of {list(_SCHEMAS)}, got {kind!r}")
    expected = _SCHEMAS[kind]
    if set(data) != expected:
        missing, extra = expected - set(data), set(data) - expected
        raise VerdictError(
            f"a '{kind}' verdict needs exactly {sorted(expected)} "
            f"(missing: {sorted(missing)}, not allowed: {sorted(extra)})"
        )
    for key in expected - {"verdict"}:
        if not isinstance(data[key], str) or not data[key].strip():
            raise VerdictError(f"{key} must be a non-empty string")

    if kind == "rejected":
        return Verdict(candidate, kind, data["reason"].strip())
    if kind == "needs_validation":
        return Verdict(candidate, kind, data["reasoning"].strip(), blockers=data["blockers"].strip())

    for key, allowed in (("likelihood", LIKELIHOOD), ("impact", IMPACT), ("confidence", CONFIDENCE)):
        if data[key] not in allowed:
            raise VerdictError(f"{key} must be one of {list(allowed)}, got {data[key]!r}")
    return Verdict(
        candidate,
        kind,
        data["reasoning"].strip(),
        severity=derive_severity(data["likelihood"], data["impact"]),
        likelihood=data["likelihood"],
        impact=data["impact"],
        confidence=data["confidence"],
        strongest_control=data["strongest_control"].strip(),
    )
