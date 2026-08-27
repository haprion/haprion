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

import subprocess
import sys
from pathlib import Path
from typing import NoReturn

CLUSTER_CONFIG = "/usr/local/lib/haproxy-mgmt/cluster-config"

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


def config_path(cluster_id: str) -> Path:
    """Where the cluster's configuration repository is, per cluster-config.

    Asked rather than derived from a naming convention: the layout is
    configuration, and a second place that knows it is a second thing to keep in
    step.

    Nothing is printed when it fails, deliberately. cluster-config has already
    said what was wrong - including which clusters do exist - straight to the
    terminal, because its stderr is inherited rather than captured. Adding a
    second sentence here would either repeat it or, as the captured copies did,
    replace it with less.
    """

    completed = subprocess.run(  # noqa: S603 - fixed path, fixed arguments
        [CLUSTER_CONFIG, "-c", cluster_id, "--field", "config_path"],
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
    return Path(completed.stdout.strip())


def usage(text: str) -> NoReturn:
    """Print how the command is called, and exit the way the shell one did.

    On stdout, not stderr: that is where the shell commands' `usage` wrote it,
    and an operator who pipes the output into a pager expects to see it there.
    """

    sys.stdout.write(text if text.endswith("\n") else f"{text}\n")
    raise SystemExit(USAGE_EXIT)
