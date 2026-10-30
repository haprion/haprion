"""The parts every command's calling half does the same way.

Extracted after measuring, not on principle. Four commands had grown their own
copy of "ask cluster-config where the repository is" and their own idea of what
a usage error exits with, and the copies had already drifted from the shell
commands they replaced in two operator-visible ways:

  * an unknown cluster lost the list of valid ones. cluster-config prints it,
    the shell commands let it through, and the copies captured it and printed a
    shorter sentence of their own instead
  * a usage error exited 1. Every shell command exited 64, and a wrapper script
    that tells a mistyped invocation apart from a failed one reads that number

Both are fixed here, in one place, for all four.
"""

from __future__ import annotations

import io
import subprocess
import sys
from collections.abc import Callable
from contextlib import redirect_stdout
from pathlib import Path
from typing import NoReturn, TextIO

from haprion import exit_codes
from haprion.cli import cluster_config
from haprion.envelope import failure, new_request_id
from haprion.helper_protocol import config_error_code, write_document


class CallerError(Exception):
    """Something the calling half found, before any privileged step ran."""

    def __init__(self, message: str, *, exit_code: int = exit_codes.REFUSED):
        super().__init__(message)
        self.exit_code = exit_code


def field(cluster_id: str, name: str) -> str:
    """One field of a cluster's definition, as `haprion-cluster-config` reports it.

    Asked in this process, of the same code the command runs: the hand-installed
    wrapper that used to stand between them (`cluster-config`, exec'ing the
    release's command) is gone with the packages (B266). Only stdout is caught;
    the command's own diagnosis - including which clusters do exist - goes
    straight to stderr, and nothing is added here. A second sentence would
    either repeat it or, as captured copies once did, replace it with less.
    """

    answer = io.StringIO()
    with redirect_stdout(answer):
        code = cluster_config.main(["-c", cluster_id, "--field", name])
    if code != 0:
        raise SystemExit(code)
    return answer.getvalue().strip()


def config_path(cluster_id: str) -> Path:
    """Where the cluster's configuration repository is, per cluster-config.

    Asked rather than derived from a naming convention: the layout is
    configuration, and a second place that knows it is a second thing to keep in
    step.
    """

    return Path(field(cluster_id, "config_path"))


def usage(text: str) -> NoReturn:
    """Print how the command is called, and exit the way the shell one did.

    On stdout, not stderr: that is where the shell commands' `usage` wrote it,
    and an operator who pipes the output into a pager expects to see it there.
    """

    sys.stdout.write(text if text.endswith("\n") else f"{text}\n")
    raise SystemExit(exit_codes.USAGE)


def without_answer(
    completed: subprocess.CompletedProcess[str],
    *,
    operation: str,
    cluster: str | None,
    json_mode: bool,
    writer: TextIO,
    errors: TextIO,
    fallback: str,
) -> int:
    """A helper that wrote no document: why on stderr and, with `--json`, the one document anyway.

    The helper's own stderr is the reason - no sudo rule, no helper installed,
    an unreadable runtime policy - and it is said once, on stderr. The read
    commands wrote nothing at all to stdout then, so a playbook reading
    `--json` had no document to read, where the apply commands already wrote
    their refusal (review 2026-10-22, 4-2).
    """

    said = completed.stderr.strip() or fallback
    errors.write(f"{said}\n" if said.startswith("ERROR") else f"ERROR: {said}\n")
    if json_mode:
        write_document(
            writer,
            failure(
                operation=operation,
                cluster=cluster,
                request_id=new_request_id(),
                code="dependency_unavailable",
                message=said.removeprefix("ERROR: ")[:2048],
                exit_code=exit_codes.UNAVAILABLE,
            ),
            exit_codes.UNAVAILABLE,
        )
    return exit_codes.UNAVAILABLE


def looked_up(
    resolve: Callable[[str], Path],
    cluster_id: str,
    *,
    operation: str,
    json_mode: bool,
    writer: TextIO | None = None,
) -> Path:
    """`resolve(cluster_id)`, and with `--json` the one document when it stops the command.

    `cluster-config` says why on stderr and the lookup ends the process; with
    `--json` that left stdout empty (review 26-10-30, E7). The exit stays the
    lookup's, the document says the same.
    """

    try:
        return resolve(cluster_id)
    except SystemExit as stopped:
        code = stopped.code if isinstance(stopped.code, int) else exit_codes.USAGE
        exit_code = exit_codes.of_process(code, exit_codes.USAGE)
        if json_mode:
            write_document(
                writer or sys.stdout,
                failure(
                    operation=operation,
                    cluster=cluster_id,
                    request_id=new_request_id(),
                    code=config_error_code(exit_code),
                    message=f"cluster {cluster_id} could not be looked up",
                    exit_code=exit_code,
                ),
                exit_code,
            )
        raise SystemExit(exit_code) from stopped


def through_sudo(
    command: list[str], request: bytes, *, operation: str, cluster: str, json_mode: bool
) -> int:
    """Run a root helper that streams its answer, and still owe `--json` its one document.

    In text mode the helper's output is inherited, which is the streaming. With
    `--json` it is held until the helper has ended: a helper that wrote no
    document - sudo refused it, it was never installed, a signal ended it -
    leaves the document here, as the read commands do (review 26-10-30, E7). A
    return code this table does not have is passed on as one it does.
    """

    if not json_mode:
        completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
            command, input=request, check=False
        )
        return _known_exit(completed.returncode)
    held = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        command, input=request, check=False, capture_output=True
    )
    out = held.stdout.decode("utf-8", errors="replace")
    err = held.stderr.decode("utf-8", errors="replace")
    if out.strip():
        sys.stderr.write(err)
        sys.stdout.write(out)
        sys.stdout.flush()
        return _known_exit(held.returncode)
    _, stopped = exit_codes.foreign(held.returncode, "helper")
    return without_answer(
        subprocess.CompletedProcess(command, held.returncode, "", err),
        operation=operation,
        cluster=cluster,
        json_mode=True,
        writer=sys.stdout,
        errors=sys.stderr,
        fallback=stopped or f"the helper ended with {held.returncode} and wrote no answer",
    )


def _known_exit(returncode: int) -> int:
    """The return code as the exit table has it, and why on stderr when it had none."""

    code, stopped = exit_codes.foreign(returncode, "helper")
    if stopped:
        sys.stderr.write(f"ERROR: {stopped}\n")
    return code
