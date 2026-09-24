"""Shared test helpers: a throwaway git repo."""

import subprocess
from pathlib import Path

import pytest


class TempRepo:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        cmd = ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args]
        return subprocess.run(cmd, cwd=self.path, check=True, capture_output=True, text=True).stdout

    def write(self, rel_path: str, content: str) -> None:
        target = self.path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self, message: str = "commit") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").strip()


@pytest.fixture
def repo(tmp_path: Path) -> TempRepo:
    return TempRepo(tmp_path)
