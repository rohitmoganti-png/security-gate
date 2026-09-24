"""The shared result format every check returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class Status(StrEnum):
    PASS = "PASS"  # ran, found nothing
    WARN = "WARN"  # found something worth a look, but nothing blocking
    FAIL = "FAIL"  # found at least one blocking issue
    NA = "N/A"  # not applicable (e.g. no infra files) - NOT the same as a pass
    ERROR = "ERROR"  # could not run: the gate fails closed


@dataclass(frozen=True)
class Finding:
    rule: str  # scanner rule ID, e.g. "stripe-access-token"
    severity: Severity
    path: str
    line: int
    message: str
    evidence: str = ""  # safe to print: secrets are masked
    new: bool = True  # True if this push wrote the flagged line

    @property
    def blocking(self) -> bool:
        """Blocks only if it's serious AND this push introduced it (old issues never block)."""
        return self.new and self.severity.rank >= Severity.HIGH.rank


@dataclass(frozen=True)
class CheckResult:
    name: str  # "Secrets"
    tool: str  # "gitleaks 8.30.1"
    findings: tuple[Finding, ...] = ()
    error: str = ""  # set when the check could not run
    not_applicable: str = ""  # set when the check doesn't apply to this change
    seconds: float = 0.0
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> Status:
        if self.error:
            return Status.ERROR
        if self.not_applicable:
            return Status.NA
        if any(f.blocking for f in self.findings):
            return Status.FAIL
        return Status.WARN if self.findings else Status.PASS
