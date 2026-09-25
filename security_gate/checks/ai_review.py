"""Check 7: AI review (Station 9, the Hunter), for logic flaws scanners can't see.

Until Station 10 (the independent Verifier) is in place, Hunter candidates are WARNINGS
only: a single AI opinion never blocks a merge (design principle 3).
"""

from __future__ import annotations

import time

from security_gate.ai import llm
from security_gate.ai.context import ContextError, build_context
from security_gate.ai.hunter import Caller, hunt
from security_gate.changes import ChangeSet
from security_gate.result import CheckResult, Finding, Severity
from security_gate.workspace import Workspace

NAME = "AI review"


def run(changes: ChangeSet, workspace: Workspace, call: Caller | None = None) -> CheckResult:
    started = time.monotonic()
    tool = f"hunter: {llm.model_name()}"
    if call is None and not llm.api_key():
        return CheckResult(NAME, tool, not_applicable="no OPENAI_API_KEY configured (AI review skipped)")
    try:
        context = build_context(changes)
    except ContextError as exc:  # fail closed: never send unscanned code
        return CheckResult(NAME, tool, error=str(exc))
    if not context.files:
        return CheckResult(NAME, tool, not_applicable="no code files changed")

    try:
        result = hunt(context, call)
    except llm.LLMError as exc:
        return CheckResult(NAME, tool, error=str(exc))

    findings = []
    for c in result.candidates:
        changed = changes.get(c.sink.path)
        trace = " -> ".join(f"{s.path}:{s.line}" for s in c.trace)
        findings.append(
            Finding(
                rule=f"ai.{c.category}",
                severity=Severity.MEDIUM,  # unverified: Station 10 decides the real severity
                path=c.sink.path,
                line=c.sink.line,
                message=f"{c.title}. {c.root_cause}",
                evidence=f"trace: {trace} | fix: {c.suggested_fix} | id: {c.fingerprint}",
                new=bool(changed and changed.touches(c.sink.line)),
            )
        )

    tokens_in, tokens_out = result.tokens
    cost = f"${result.cost_usd:.4f}" if result.cost_usd is not None else "unknown (model not in price table)"
    notes = [
        f"reviewed {len(context.files)} file(s): {', '.join(f.path for f in context.files)}",
        f"AI usage: {tokens_in} input + {tokens_out} output tokens, estimated cost {cost}",
        "unverified candidates are warnings until the independent Verifier (Station 10) confirms them",
    ]
    if context.truncated:
        notes.append("context was trimmed to the size cap; some imported files were not shown")
    notes += result.rejected  # AI output that failed plain-code validation, and why
    return CheckResult(NAME, tool, tuple(findings), seconds=time.monotonic() - started, notes=tuple(notes))
