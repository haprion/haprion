"""One way to run git, shared by everything that has to.

Extracted rather than copied: two callers with their own idea of how git
failures surface is exactly the drift that makes a privileged path behave
differently depending on which entry point reached it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

GIT = "/usr/bin/git"


class GitError(Exception):
    """A git invocation failed. Carries the exit code the caller reports."""

    def __init__(self, message: str, *, exit_code: int = 70):
        super().__init__(message)
        self.exit_code = exit_code


def git(
    repo: Path,
    *args: str,
    stdin: bytes | None = None,
    env: dict[str, str] | None = None,
    allow_failure: bool = False,
) -> bytes:
    completed = subprocess.run(  # noqa: S603 - argv is constructed here, never from input
        [GIT, "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        check=False,
        env=env,
    )
    if completed.returncode != 0 and not allow_failure:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {args[0]} failed: {detail}")
    return completed.stdout
