"""All Station 8 checks, in the order they run and appear in the log.

Each check is a module with `run(changes, workspace) -> CheckResult`.
Adding a check = write the module + add it to this list.
"""

from security_gate.checks import ai_smells, code, packages, secrets

ALL_CHECKS = [secrets, code, ai_smells, packages]
