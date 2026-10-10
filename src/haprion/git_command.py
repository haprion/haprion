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


def git_bounded(repo: Path, *args: str, limit: int) -> bytes | None:
    """git's output if it is at most `limit` bytes, None if it is longer.

    Read as it arrives and stopped past the limit, so a reader that keeps a
    bounded amount never holds more than that in memory either (review
    2026-10-03, K6: a 250 000-line file was read whole to be thrown away).
    """

    with subprocess.Popen(  # noqa: S603 - argv is constructed here, never from input
        [GIT, "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        assert process.stdout is not None and process.stderr is not None  # noqa: S101
        output: bytes = process.stdout.read(limit + 1)
        if len(output) > limit:
            process.kill()
            process.wait()
            return None
        detail = process.stderr.read()
        if process.wait() != 0:
            raise GitError(f"git {args[0]} failed: {detail.decode('utf-8', 'replace').strip()}")
    return output
