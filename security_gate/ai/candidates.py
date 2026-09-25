"""Station 9 output format (ticket ENG-386): a Hunter "candidate" + a PLAIN-CODE validator.

The Hunter (an AI) only ever PROPOSES candidates. Nothing it says is trusted until
this validator checks it with ordinary code, never with another AI call:
  * exact set of fields, correct types, allowed category
  * a trace with at least one entrypoint and one sink
  * every cited file was actually given to the Hunter, every cited line exists
The fingerprint is computed HERE, from the source, so the AI can't forge or reuse it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

CATEGORIES = (
    "broken-access-control",  # e.g. reads another user's data: missing ownership check
    "missing-authentication",  # endpoint reachable without logging in
    "injection",  # SQL / command / template injection
    "business-logic",  # e.g. negative refund amount, skipped payment step
    "sensitive-data-exposure",  # returns secrets / PII it shouldn't
    "other",
)
TRACE_KINDS = ("entrypoint", "propagation", "sink")
_FIELDS = {"title", "category", "root_cause", "trace", "evidence", "suggested_fix"}
_STEP_FIELDS = {"kind", "path", "line", "description"}
_MAX_TEXT = 2000


@dataclass(frozen=True)
class TraceStep:
    kind: str
    path: str
    line: int
    description: str


@dataclass(frozen=True)
class Candidate:
    fingerprint: str
    title: str
    category: str
    root_cause: str
    trace: tuple[TraceStep, ...]
    evidence: str
    suggested_fix: str

    @property
    def sink(self) -> TraceStep:
        return next(s for s in reversed(self.trace) if s.kind == "sink")


class ValidationError(ValueError):
    pass


def parse_candidates(raw_text: str, files: dict[str, str]) -> tuple[list[Candidate], list[str]]:
    """Parse the Hunter's JSON reply. Returns (valid candidates, reasons others were rejected).

    `files` = {path: content} of exactly what the Hunter was shown.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return [], [f"reply is not valid JSON: {exc}"]
    if not isinstance(data, dict) or set(data) != {"candidates"} or not isinstance(data["candidates"], list):
        return [], ['reply must be exactly {"candidates": [...]}']

    valid, rejected = [], []
    for i, item in enumerate(data["candidates"], 1):
        try:
            valid.append(validate(item, files))
        except ValidationError as exc:
            rejected.append(f"candidate {i} rejected: {exc}")
    return valid, rejected


def validate(item: object, files: dict[str, str]) -> Candidate:
    if not isinstance(item, dict):
        raise ValidationError("not an object")
    if set(item) != _FIELDS:
        missing, extra = _FIELDS - set(item), set(item) - _FIELDS
        raise ValidationError(f"wrong fields (missing: {sorted(missing)}, unexpected: {sorted(extra)})")
    for key in _FIELDS - {"trace"}:
        _text(item[key], key)
    if item["category"] not in CATEGORIES:
        raise ValidationError(f"unknown category {item['category']!r}")

    if not isinstance(item["trace"], list) or not item["trace"]:
        raise ValidationError("trace must be a non-empty list")
    steps = tuple(_step(s, files) for s in item["trace"])
    kinds = {s.kind for s in steps}
    if "entrypoint" not in kinds or "sink" not in kinds:
        raise ValidationError("trace needs at least one 'entrypoint' and one 'sink'")

    candidate = Candidate("", item["title"].strip(), item["category"], item["root_cause"].strip(),
                          steps, item["evidence"].strip(), item["suggested_fix"].strip())  # fmt: skip
    return replace(candidate, fingerprint=fingerprint(candidate, files))


def fingerprint(candidate: Candidate, files: dict[str, str]) -> str:
    """Stable ID from the SOURCE, not the AI's wording: category + sink file + sink code line.

    Line numbers are left out, so the ID survives code moving up or down the file.
    """
    sink = candidate.sink
    code = files[sink.path].splitlines()[sink.line - 1]
    normalized = " ".join(code.split())
    digest = hashlib.sha256(f"{candidate.category}|{sink.path}|{normalized}".encode()).hexdigest()
    return f"ai1:{digest[:24]}"


def _step(step: object, files: dict[str, str]) -> TraceStep:
    if not isinstance(step, dict) or set(step) != _STEP_FIELDS:
        raise ValidationError(f"each trace step needs exactly {sorted(_STEP_FIELDS)}")
    if step["kind"] not in TRACE_KINDS:
        raise ValidationError(f"trace kind must be one of {TRACE_KINDS}")
    path = _text(step["path"], "trace.path")
    if path not in files:  # the AI may only cite files we actually showed it
        raise ValidationError(f"cites a file it was not given: {path!r}")
    line = step["line"]
    if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= len(files[path].splitlines()):
        raise ValidationError(f"cites a line that doesn't exist: {path}:{line}")
    return TraceStep(step["kind"], path, line, _text(step["description"], "trace.description"))


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must be a non-empty string")
    if len(value) > _MAX_TEXT:
        raise ValidationError(f"{name} is too long")
    return value
