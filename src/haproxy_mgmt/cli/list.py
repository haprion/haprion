"""`haproxy-list` - the recent versions of a cluster's configuration.

The whole command runs as the calling user. It reads history and nothing else:
no `sudo`, no root helper, no write anywhere. That is why it was the first of
the remaining shell commands to move - there is no privilege boundary to design,
only output to keep identical.

The table is deliberately the one the shell command printed, column widths and
all. An operator reads it by shape, and a port that "improves" the layout on the
way is a change nobody asked for hidden inside a change nobody should notice.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haproxy_mgmt.cli.caller import CallerError, usage
from haproxy_mgmt.cli.caller import config_path as _config_path
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.repo_health import describe_problem, is_repo_root
from haproxy_mgmt.version_history import recent_versions

USAGE = "Usage:\n  haproxy-list -c <cluster>\n"

#
# The frozen table. `%-9s %-17s %s` in the shell command; the dashed rule under
# the headings is a literal there too, not a computed one.
#
ROW = "{version:<9} {date:<17} {comment}"
RULE = ROW.format(version="-------", date="-" * 16, comment="-" * 40)

type ConfigPath = Callable[[str], Path]


def _parse(argv: list[str]) -> str:
    if len(argv) != 2 or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    return argv[1]


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    config_path: ConfigPath = _config_path,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    cluster_id = _parse(argv)

    try:
        repo = config_path(cluster_id)
        if not is_repo_root(repo):
            writer.write(f"{describe_problem(cluster_id, repo)}\n")
            return 68
        versions = recent_versions(repo)
        #
        # A repository whose branch holds no commit yet. The shell command let
        # git fail here and exited 128 with git's own wording; naming the state
        # is the one deliberate difference in this port, because the repair -
        # publish a first version - is not something git's message points at.
        #
        if not versions:
            raise CallerError(f"cluster '{cluster_id}' has no versions yet.")
    except (CallerError, GitError) as exc:
        writer.write(f"ERROR: {exc}\n")
        return exc.exit_code

    writer.write(f"\nHAProxy configuration history - {cluster_id}\n\n")
    writer.write(ROW.format(version="VERSION", date="DATE", comment="COMMENT") + "\n")
    writer.write(RULE + "\n")
    for entry in versions:
        writer.write(
            ROW.format(version=entry.version, date=entry.date, comment=entry.comment) + "\n"
        )
    writer.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
