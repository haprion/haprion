"""`haprion-config-status` - "what have I not sent yet, and what is published".

The requirement comes from B10 point 8: the two-tree model must not become
visible only at the moment something breaks. The command has to be usable
without understanding git, and therefore prints no git vocabulary at all - no
"commit", no "HEAD", no "staged".

Everything but one thing runs as the calling user. The exception is the
published release, which lives in a tree only root and the pull identity can
reach; it is read through an exact root helper that takes no arguments, with
NOPASSWD, so a status check never costs a password prompt.

A second root helper says whether a publish would change what the nodes run
(`haprion-regeneration-helper`): the published version made again with the
installed product, compared with what it wrote. It is asked the same way.

The helpers are the only privileged steps, and they are deliberately allowed to fail
without taking the command with it. A status command that refuses to answer
because one of its two questions could not be answered is worse than one that
answers the other and says so - the draft state is exactly what someone needs
when permissions are broken.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes
from haprion.cli.caller import config_path as _config_path
from haprion.cli.caller import usage
from haprion.envelope import new_request_id
from haprion.git_command import GitError
from haprion.regeneration import diff_from_dict
from haprion.release_layout import parse_release_file
from haprion.repo_health import PendingChange, describe_problem, is_repo_root, pending_changes
from haprion.version_diff import render
from haprion.version_history import current_version

RELEASE_HELPER = "/opt/haprion/current/bin/haprion-published-release-helper"
REGENERATION_HELPER = "/opt/haprion/current/bin/haprion-regeneration-helper"
SUDO = "/usr/bin/sudo"

USAGE = "Usage:\n  haprion-config-status -c <cluster> [--diff]\n"

#
# What the manual path owns, and what the interface owns. `managed/` is written
# by the interface and is not published from here, so it is reported separately
# rather than mixed into the list someone is about to publish.
#
MANUAL_PATHS = ("core", "manual")
INTERFACE_PATHS = ("managed",)

UNREADABLE = "could not be read (missing permission or helper)"
UNPUBLISHED = "nothing published yet"

type ConfigPath = Callable[[str], Path]
type ReadPublished = Callable[[str], str | None]
type ReadRegeneration = Callable[[str], Mapping[str, Any] | None]


def _read_published(cluster_id: str) -> str | None:
    """The published RELEASE stamp, or None when it could not be read.

    None covers every way this can fail at once - no sudo rule, no helper, a
    helper that errored - because the answer shown is the same in all of them
    and guessing between them would be a diagnosis this command cannot make.
    Its stderr is discarded for the same reason: `sudo -n` prints its own
    refusal, and that is noise in the middle of a status report.
    """

    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "-n", RELEASE_HELPER],
        input=f"{cluster_id}\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return None if completed.returncode != 0 else completed.stdout


def _read_regeneration(cluster_id: str) -> Mapping[str, Any] | None:
    """The regeneration helper's result, or None when it could not be had.

    Soft in the same way and for the same reason as the stamp above: nothing
    here may take the rest of the report with it.
    """

    request = {
        "schema_version": 1,
        "operation": "regeneration",
        "cluster": cluster_id,
        "request_id": new_request_id(),
        "parameters": {},
    }
    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "-n", REGENERATION_HELPER],
        input=json.dumps(request, separators=(",", ":")),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    result = document.get("result") if isinstance(document, dict) else None
    return result if isinstance(result, dict) and "outcome" in result else None


def _parse(argv: list[str]) -> tuple[str, bool]:
    """The cluster, and whether the regeneration's diff is asked for."""

    rest = argv
    diff = False
    if len(rest) == 3 and rest[2] == "--diff":
        rest, diff = rest[:2], True
    if len(rest) != 2 or rest[0] not in ("-c", "--cluster"):
        usage(USAGE)
    return rest[1], diff


def _regeneration_line(result: Mapping[str, Any] | None) -> str | None:
    """What to say about a regeneration; nothing when a publish would change nothing."""

    if result is None:
        return None
    if result.get("outcome") == "refused":
        return f"  The installed version cannot publish this configuration again: {result.get('message')}\n"
    if result.get("outcome") != "changed":
        return None
    count = int(result.get("files_changed") or 0)
    noun = "file" if count == 1 else "files"
    line = f"  A publish would change what runs: {count} {noun}"
    objects = [
        f"{item['name']} ({', '.join(item['parts'])})" if item.get("parts") else str(item["name"])
        for item in result.get("objects") or []
    ]
    if objects:
        line += f"; objects: {', '.join(objects)}"
    return line + "\n"


def _published_line(stamp: str | None) -> tuple[str, str]:
    """(what to print, the published hash). An empty hash means "not compared".

    The comparison below is skipped whenever the hash is empty, which is what
    keeps an unreadable or unpublished cluster from producing a warning about a
    version mismatch it has no evidence for.
    """

    if stamp is None:
        return UNREADABLE, ""
    fields = parse_release_file(stamp)
    if fields.get("state") == "unpublished":
        return UNPUBLISHED, ""
    version = fields.get("version", "")
    return (version or "unknown"), (fields.get("hash", "") if version else "")


def _listing(writer: TextIO, heading: str, changes: tuple[PendingChange, ...]) -> None:
    writer.write(f"{heading}\n")
    for change in changes:
        writer.write(f"    {change.path:<40} {change.kind}\n")


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    config_path: ConfigPath = _config_path,
    read_published: ReadPublished = _read_published,
    read_regeneration: ReadRegeneration = _read_regeneration,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, show_diff = _parse(argv)

    repo = config_path(cluster_id)

    if not is_repo_root(repo):
        errors.write(f"{describe_problem(cluster_id, repo)}\n")
        return exit_codes.UNAVAILABLE

    try:
        saved = current_version(repo)
        waiting = pending_changes(repo, *MANUAL_PATHS)
        interface_owned = pending_changes(repo, *INTERFACE_PATHS)
    except GitError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    published, published_hash = _published_line(read_published(cluster_id))

    writer.write(f"\nConfiguration - {cluster_id}\n\n")
    writer.write(f"  Published version:  {published}\n")
    writer.write(f"  Last saved:         {saved.version}   {saved.date}   {saved.comment}\n")

    if published_hash and published_hash != saved.commit:
        writer.write(
            "\n  WARNING: the most recently saved version is not the published one.\n"
            f"  The nodes cannot receive version {saved.version} until it is published again.\n"
        )

    regenerated = read_regeneration(cluster_id) if published_hash else None
    line = _regeneration_line(regenerated)
    if line is not None:
        writer.write(f"\n{line}")
        if show_diff and regenerated is not None and regenerated.get("diff"):
            writer.write("\n" + render(diff_from_dict(regenerated["diff"])))

    writer.write("\n")

    if not waiting:
        writer.write("  Nothing unsent. Everything you have changed is published.\n")
    else:
        _listing(writer, "  Unsent - changes that have not become a version yet:", waiting)
        writer.write(f'\n  Publish them with:\n    haprion-publish -c {cluster_id} "<comment>"\n')

    if interface_owned:
        writer.write("\n")
        _listing(
            writer,
            "  Changes owned by the interface, which are not published from here:",
            interface_owned,
        )

    writer.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
