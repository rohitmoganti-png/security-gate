"""Check 7: AI review = Station 9 (Hunter proposes) + Station 10 (independent Verifier decides).

  confirmed (high/critical)  -> BLOCKING finding (severity derived by code from likelihood x impact)
  confirmed (medium/low)     -> warning finding
  needs_validation           -> note for a human; carries no severity, can never block
  rejected                   -> note with the reason it was disproved
A Hunter candidate on its own never blocks: only what survives the Verifier does.
"""

from __future__ import annotations

import time

from security_gate.ai import llm
from security_gate.ai.context import ContextError, build_context
from security_gate.ai.hunter import Caller, hunt
from security_gate.ai.verifier import verify
from security_gate.changes import ChangeSet
from security_gate.result import CheckResult, Finding
from security_gate.workspace import Workspace

NAME = "AI review"


def run(changes: ChangeSet, workspace: Workspace, call: Caller | None = None) -> CheckResult:
    started = time.monotonic()
    tool = f"hunter+verifier: {llm.model_name()}"
    if call is None and not llm.api_key():
        return CheckResult(NAME, tool, not_applicable="no OPENAI_API_KEY configured (AI review skipped)")
    try:
        context = build_context(changes)
    except ContextError as exc:  # fail closed: never send unscanned code
        return CheckResult(NAME, tool, error=str(exc))
    if not context.files:
        return CheckResult(NAME, tool, not_applicable="no code files changed")

    try:
        hunted = hunt(context, call)  # Station 9
        verified = [verify(c, context, call) for c in hunted.candidates]  # Station 10, one call each
    except llm.LLMError as exc:
        return CheckResult(NAME, tool, error=str(exc))

    findings, notes = [], []
    for result in verified:
        v, c = result.verdict, result.verdict.candidate
        where = f"{c.sink.path}:{c.sink.line}"
        if v.verdict == "confirmed":
            changed = changes.get(c.sink.path)
            trace = " -> ".join(f"{s.path}:{s.line}" for s in c.trace)
            findings.append(
                Finding(
                    rule=f"ai.{c.category}",
                    severity=v.severity,  # type: ignore[arg-type]  (always set for confirmed)
                    path=c.sink.path,
                    line=c.sink.line,
                    message=f"{c.title}. CONFIRMED by independent verifier: {v.reasoning}",
                    evidence=f"trace: {trace} | likelihood {v.likelihood}, impact {v.impact} "
                    f"(confidence {v.confidence}) | fix: {c.suggested_fix} | id: {c.fingerprint}",
                    new=bool(changed and changed.touches(c.sink.line)),
                )
            )
        elif v.verdict == "needs_validation":
            notes.append(f"NEEDS HUMAN REVIEW ({where}): {c.title}. Unresolved: {v.blockers}")
        else:
            notes.append(f"rejected by verifier ({where}): {c.title}. Reason: {v.reasoning}")

    replies = hunted.replies + [r for res in verified for r in res.replies]
    tokens_in = sum(r.input_tokens for r in replies)
    tokens_out = sum(r.output_tokens for r in replies)
    costs = [r.cost_usd for r in replies]
    cost = f"${sum(costs):.4f}" if all(c is not None for c in costs) else "unknown (model not in price table)"
    summary = [
        f"reviewed {len(context.files)} file(s): {', '.join(f.path for f in context.files)}",
        f"hunter proposed {len(hunted.candidates)} candidate(s); verifier: "
        f"{sum(r.verdict.verdict == 'confirmed' for r in verified)} confirmed, "
        f"{sum(r.verdict.verdict == 'needs_validation' for r in verified)} need review, "
        f"{sum(r.verdict.verdict == 'rejected' for r in verified)} rejected",
        f"AI usage: {len(replies)} call(s), {tokens_in} input + {tokens_out} output tokens, estimated cost {cost}",
    ]
    if context.truncated:
        summary.append("context was trimmed to the size cap; some imported files were not shown")
    details = {
        "model": llm.model_name(),
        "calls": len(replies),
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        "cost_usd": round(sum(costs), 6) if all(c is not None for c in costs) else None,
        "files_reviewed": [f.path for f in context.files],
        "candidates": len(hunted.candidates),
        "verdicts": [
            {
                "title": r.verdict.candidate.title,
                "category": r.verdict.candidate.category,
                "location": f"{r.verdict.candidate.sink.path}:{r.verdict.candidate.sink.line}",
                "trace": [f"{s.path}:{s.line}" for s in r.verdict.candidate.trace],
                "verdict": r.verdict.verdict,
                "reasoning": r.verdict.reasoning,
                "likelihood": r.verdict.likelihood,
                "impact": r.verdict.impact,
                "severity": str(r.verdict.severity) if r.verdict.severity else None,
                "blockers": r.verdict.blockers,
                "suggested_fix": r.verdict.candidate.suggested_fix,
                "fingerprint": r.verdict.candidate.fingerprint,
            }
            for r in verified
        ],
        "rejected_by_validator": list(hunted.rejected),
    }
    return CheckResult(NAME, tool, tuple(findings), seconds=time.monotonic() - started,
                       notes=tuple(summary + notes + hunted.rejected), details=details)  # fmt: skip
