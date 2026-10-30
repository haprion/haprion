"""`haprion-list` - the recent versions of a cluster's configuration.

The whole command runs as the calling user. It reads history and nothing else:
no `sudo`, no root helper, no write anywhere. That is why it was the first of
the remaining shell commands to move - there is no privilege boundary to design,
only output to keep identical.

The table is deliberately the one the shell command printed, column widths and
all. An operator reads it by shape, and a port that "improves" the layout on the
way is a change nobody asked for hidden inside a change nobody should notice.

`--json` prints the same reading as an envelope. It reads the repository the
same way the table does rather than going through the root helper, because a
human who can run this command can already read the repository and requiring
`sudo` to get machine-readable output would be privilege for formatting. The
poller, which cannot read the repository, uses `haprion-list-helper`; both build
their result with `haprion.history.history_result`, so the two paths cannot
come to describe the same history differently.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haprion import exit_codes
from haprion.cli.caller import CallerError, looked_up, usage
from haprion.cli.caller import config_path as _config_path
from haprion.cli.caller import field as _field
from haprion.digits import is_digits
from haprion.envelope import Message, envelope
from haprion.git_command import GitError
from haprion.helper_protocol import write_document
from haprion.history import history_result
from haprion.repo_health import describe_problem, is_repo_root
from haprion.status_collect import read_target
from haprion.version_diff import render, version_diff
from haprion.version_history import recent_versions, version_commit

USAGE = (
    "Usage:\n"
    "  haprion-list -c <cluster> [--json]\n"
    "  haprion-list -c <cluster> --diff <version>   what one version changed\n"
)
OPERATION = "list"

#
# The shell command's table, `%-9s %-17s %s`, with one column since 2026-09-29
# (B207): who asked for the version, as the interface's Versions page shows it.
# "-" for a version recorded before anyone was named. The comment stays last,
# where a long one has room.
#
ROW = "{version:<9} {date:<17} {by:<17} {comment}"
RULE = ROW.format(version="-------", date="-" * 16, by="-" * 16, comment="-" * 40)

type ConfigPath = Callable[[str], Path]
type Field = Callable[[str, str], str]


def _parse(argv: list[str]) -> tuple[str, bool, int | None]:
    if len(argv) not in (2, 3, 4) or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    if len(argv) == 4:
        if argv[2] != "--diff" or not is_digits(argv[3]):
            usage(USAGE)
        return argv[1], False, int(argv[3])
    if len(argv) == 3 and argv[2] != "--json":
        usage(USAGE)
    return argv[1], len(argv) == 3, None


def _diff(writer: TextIO, cluster_id: str, version: int, config_path: ConfigPath) -> int:
    """One version's changes, read from the repository as the person running this."""

    try:
        repo = config_path(cluster_id)
        if not is_repo_root(repo):
            raise CallerError(describe_problem(cluster_id, repo), exit_code=exit_codes.UNAVAILABLE)
        commit = version_commit(repo, version)
        if commit is None:
            raise CallerError(
                f"cluster '{cluster_id}' has no version {version}.", exit_code=exit_codes.REFUSED
            )
        found = version_diff(repo, commit)
    except (CallerError, GitError) as exc:
        writer.write(f"ERROR: {exc}\n")
        return exc.exit_code
    writer.write(f"\n{cluster_id} v{version} ({commit[:12]})\n\n")
    writer.write(render(found))
    return 0


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    config_path: ConfigPath = _config_path,
    field: Field = _field,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    cluster_id, json_mode, diff_version = _parse(argv)
    if diff_version is not None:
        return _diff(writer, cluster_id, diff_version, config_path)

    try:
        repo = looked_up(
            config_path, cluster_id, operation=OPERATION, json_mode=json_mode, writer=writer
        )
        if not is_repo_root(repo):
            raise CallerError(describe_problem(cluster_id, repo), exit_code=exit_codes.UNAVAILABLE)
        versions = recent_versions(repo)
        #
        # A repository whose branch holds no commit yet. The shell command let
        # git fail here and exited 128 with git's own wording; naming the state
        # is the one deliberate difference in this port, because the repair -
        # publish a first version - is not something git's message points at.
        #
        if not versions and not json_mode:
            raise CallerError(f"cluster '{cluster_id}' has no versions yet.")
    except (CallerError, GitError) as exc:
        if json_mode:
            return write_document(
                writer,
                envelope(
                    operation=OPERATION,
                    outcome="failed",
                    cluster=cluster_id,
                    result=None,
                    error=Message(code="history_unavailable", message=str(exc)),
                ),
                exc.exit_code,
            )
        #
        # A repository problem is printed as cluster-config's own sentence,
        # without the `ERROR:` prefix the shell command reserved for git
        # failures. Both kept as they were.
        #
        prefix = "" if exc.exit_code == exit_codes.UNAVAILABLE else "ERROR: "
        writer.write(f"{prefix}{exc}\n")
        return exc.exit_code

    if json_mode:
        #
        # An empty history is a result here rather than an error. The table says
        # "no versions yet" because a person needs the repair named; a reader
        # parsing the envelope gets the same fact as an empty list, and treating
        # a new cluster as a failure would make it indistinguishable from a
        # repository that cannot be read at all.
        #
        target = read_target(
            Path(field(cluster_id, "publish_path")), field(cluster_id, "node_path")
        )
        return write_document(
            writer,
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=cluster_id,
                result=history_result(versions, target),
            ),
            0,
        )

    writer.write(f"\nHAProxy configuration history - {cluster_id}\n\n")
    writer.write(ROW.format(version="VERSION", date="DATE", by="BY", comment="COMMENT") + "\n")
    writer.write(RULE + "\n")
    for entry in versions:
        writer.write(
            ROW.format(
                version=entry.version,
                date=entry.date,
                by=entry.requested_by or "-",
                comment=entry.comment,
            )
            + "\n"
        )
    writer.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
