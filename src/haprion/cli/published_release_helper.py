"""The published release stamp of one cluster, for `haprion-config-status`.

The published tree is 750 root:_haprion-pull, so neither an operator nor the
interface's identities can read RELEASE there. The status command still has to
answer "what is published", without a password prompt - otherwise it does not
get run, and the two-tree model stays invisible until something breaks.

No arguments: a sudoers rule matching a cluster name would need a wildcard,
which PRIVILEGE.md forbids. The cluster arrives on stdin, one bounded line.
Read only; the path comes from the cluster file, which validates that it lives
under its root, never from the caller. RELEASE is passed through verbatim - it
is the single source of truth for what is published, and no second
interpretation happens here.

It replaces a hand-installed shell script and the wrapper it called
(B266): the same contract, from the release.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import TextIO

from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config

MAX_LINE = 64
CLUSTER = re.compile(r"[a-z][a-z0-9-]{0,62}")
EXIT_USAGE = 64
EXIT_NOT_ROOT = 68


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = output_stream or sys.stdout
    err = error_stream or sys.stderr
    if require_root and os.geteuid() != 0:
        err.write("ERROR: haprion-published-release-helper must run as root.\n")
        return EXIT_NOT_ROOT
    if argv:
        err.write("ERROR: haprion-published-release-helper takes no arguments.\n")
        return EXIT_USAGE
    #
    # Exactly one line, at most 64 characters: the read cannot swallow an
    # unbounded stream.
    #
    line = (input_stream or sys.stdin).readline(MAX_LINE)
    words = line.split()
    cluster_id = words[0] if words else ""
    if CLUSTER.fullmatch(cluster_id) is None:
        err.write("ERROR: invalid cluster name.\n")
        return EXIT_USAGE
    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(cluster_id)
    except ConfigError as exc:
        err.write(f"ERROR: {exc}\n")
        return exc.exit_code
    release = Path(cluster.publish_path) / "current" / cluster.node_path / "RELEASE"
    if not release.is_file():
        out.write("state=unpublished\n")
        return 0
    out.write(release.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
