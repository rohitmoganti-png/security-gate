"""Find and run the external scanner programs (gitleaks, semgrep, checkov)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class ToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolRun:
    returncode: int
    stdout: str
    stderr: str


def find_tool(name: str) -> str | None:
    """Look in: $SECURITY_GATE_<NAME>, PATH, this Python env's bin/, ./.tools/bin."""
    override = os.environ.get(f"SECURITY_GATE_{name.upper()}")
    if override:
        return override if Path(override).is_file() else None
    if found := shutil.which(name):
        return found
    for folder in (Path(sys.prefix) / "bin", Path.cwd() / ".tools" / "bin"):
        if (folder / name).is_file():
            return str(folder / name)
    return None


def run_tool(cmd: list[str], timeout: float, cwd: Path | None = None) -> ToolRun:
    """Run a scanner: list arguments (no shell), a timeout, and no inherited scanner config."""
    env = {k: v for k, v in os.environ.items() if k != "GITLEAKS_CONFIG"}
    env["SEMGREP_SEND_METRICS"] = "off"
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout, cwd=cwd, env=env
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{Path(cmd[0]).name} timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise ToolError(f"could not start {cmd[0]}: {exc}") from exc
    return ToolRun(r.returncode, r.stdout, r.stderr)
