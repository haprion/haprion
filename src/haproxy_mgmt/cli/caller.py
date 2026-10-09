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
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import NoReturn

from haproxy_mgmt.cli import cluster_config

#
# What a shell command exits with when it was called wrongly, as opposed to when
# it ran and failed. EX_USAGE from sysexits.h.
#
USAGE_EXIT = 64


class CallerError(Exception):
    """Something the calling half found, before any privileged step ran."""

    def __init__(self, message: str, *, exit_code: int = 65):
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
    raise SystemExit(USAGE_EXIT)
