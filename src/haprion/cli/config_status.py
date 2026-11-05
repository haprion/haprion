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
from haprion.cli.caller import looked_up, usage
from haprion.envelope import envelope, failure, new_request_id
from haprion.git_command import GitError
from haprion.helper_protocol import write_document
from haprion.regeneration import diff_from_dict
from haprion.release_layout import parse_release_file
from haprion.repo_health import PendingChange, describe_problem, is_repo_root, pending_changes
from haprion.version_diff import render
from haprion.version_history import current_version

RELEASE_HELPER = "/opt/haprion/current/bin/haprion-published-release-helper"
REGENERATION_HELPER = "/opt/haprion/current/bin/haprion-regeneration-helper"
SUDO = "/usr/bin/sudo"
ANSWERS_AS = "config_status"

USAGE = "Usage:\n  haprion-config-status -c <cluster> [--diff | --json]\n"

#
# What the manual path owns, and what the interface owns. `managed/` is written
# by the interface and is not published from here, so it is reported separately
# rather than mixed into the list someone is about to publish.
#
MANUAL_PATHS = ("core", "manual")
INTERFACE_PATHS = ("managed",)

UNREADABLE = "could not be read (missing permission or helper)"
UNPUBLISHED = "nothing published yet"
UNREADABLE_OUTCOME = "unreadable"

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


def ask_regeneration(cluster_id: str) -> Mapping[str, Any] | None:
    """The regeneration helper's result, or why it could not be had.

    Soft in the same way and for the same reason as the stamp above: nothing
    here may take the rest of the report with it. A helper that answered that
    it could not read gives `{"outcome": "unreadable", "message": ...}`; one
    that did not answer at all (no sudo rule, no helper) gives None.
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
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(document, dict):
        return None
    error = document.get("error")
    if isinstance(error, dict) and error.get("message"):
        return {"outcome": UNREADABLE_OUTCOME, "message": str(error["message"])}
    result = document.get("result")
    if completed.returncode != 0:
        return None
    return result if isinstance(result, dict) and "outcome" in result else None


def _parse(argv: list[str]) -> tuple[str, bool, bool]:
    """The cluster, whether the regeneration's diff is asked for, and whether the answer is JSON.

    The flags come in any order, as they do for every other command.
    """

    cluster: str | None = None
    diff = as_json = False
    index = 0
    while index < len(argv):
        word = argv[index]
        if word in ("-c", "--cluster") and cluster is None and index + 1 < len(argv):
            cluster = argv[index + 1]
            index += 2
        elif word == "--diff" and not diff:
            diff = True
            index += 1
        elif word == "--json" and not as_json:
            as_json = True
            index += 1
        else:
            usage(USAGE)
    if cluster is None or (diff and as_json):
        usage(USAGE)
    return str(cluster), diff, as_json


def _regeneration(result: Mapping[str, Any] | None) -> dict[str, Any]:
    """The regeneration reading as the contract has it."""

    if result is None:
        return {"outcome": "unknown"}
    outcome = result.get("outcome")
    if outcome == UNREADABLE_OUTCOME:
        return {"outcome": "unknown", "message": str(result.get("message"))}
    if outcome == "refused":
        return {"outcome": "refused", "message": str(result.get("message"))}
    if outcome != "changed":
        return {"outcome": "unchanged"}
    return {
        "outcome": "changed",
        "files_changed": int(result.get("files_changed") or 0),
        "objects": [str(item["name"]) for item in result.get("objects") or []],
    }


def _published_state(stamp: str | None) -> dict[str, Any]:
    if stamp is None:
        return {"state": "unreadable", "version": None}
    fields = parse_release_file(stamp)
    if fields.get("state") == "unpublished":
        return {"state": "unpublished", "version": None}
    return {"state": "published", "version": fields.get("version") or None}


def regeneration_line(result: Mapping[str, Any] | None, cluster_id: str) -> str | None:
    """What to say about a regeneration; nothing when a publish would change nothing.

    A reading that is missing is said, not left out: silence reads as "nothing
    differs", which is the one thing it must not be taken for.
    """

    if result is None:
        return f"  Whether a publish would change what runs: {UNREADABLE}\n"
    if result.get("outcome") == UNREADABLE_OUTCOME:
        return f"  Whether a publish would change what runs: could not be read: {result.get('message')}\n"
    if result.get("outcome") == "refused":
        return f"  The installed version cannot publish this configuration again: {result.get('message')}\n"
    if result.get("outcome") != "changed":
        return None
    count = int(result.get("files_changed") or 0)
    noun = "file" if count == 1 else "files"
    line = f"  Publish and deploy to apply the update: {count} {noun} differ{'s' if count == 1 else ''}"
    objects = [
        f"{item['name']} ({', '.join(item['parts'])})" if item.get("parts") else str(item["name"])
        for item in result.get("objects") or []
    ]
    if objects:
        line += f"; objects: {', '.join(objects)}"
    return (
        line
        + f"\n  Publish it with: haprion-publish -c {cluster_id} --regenerate"
        + " (the publish makes its own checks, such as the ports the nodes hold, and may still refuse)"
        + f"\n  Then deploy it with: haprion-deploy -c {cluster_id}\n"
    )


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
    read_regeneration: ReadRegeneration = ask_regeneration,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, show_diff, as_json = _parse(argv)

    def stopped(code: str, message: str, exit_code: int, *, said: str | None = None) -> int:
        errors.write(f"{message if said is None else said}\n")
        if as_json:
            write_document(
                writer,
                failure(
                    operation=ANSWERS_AS,
                    cluster=cluster_id,
                    request_id=new_request_id(),
                    code=code,
                    message=message,
                    exit_code=exit_code,
                ),
                exit_code,
            )
        return exit_code

    repo = looked_up(
        config_path, cluster_id, operation=ANSWERS_AS, json_mode=as_json, writer=writer
    )

    if not is_repo_root(repo):
        return stopped(
            "dependency_unavailable", describe_problem(cluster_id, repo), exit_codes.UNAVAILABLE
        )

    try:
        saved = current_version(repo)
        waiting = pending_changes(repo, *MANUAL_PATHS)
        interface_owned = pending_changes(repo, *INTERFACE_PATHS)
    except GitError as exc:
        return stopped("dependency_unavailable", str(exc), exc.exit_code, said=f"ERROR: {exc}")

    stamp = read_published(cluster_id)
    published, published_hash = _published_line(stamp)

    if as_json:
        regenerated = read_regeneration(cluster_id) if published_hash else None
        return write_document(
            writer,
            envelope(
                operation=ANSWERS_AS,
                outcome="done",
                cluster=cluster_id,
                result={
                    "published": _published_state(stamp),
                    "saved": {
                        "version": str(saved.version),
                        "date": saved.date,
                        "comment": saved.comment,
                    },
                    "saved_is_published": (published_hash == saved.commit)
                    if published_hash
                    else None,
                    "regeneration": _regeneration(regenerated),
                    "unsent": [{"path": c.path, "kind": c.kind} for c in waiting],
                    "interface_owned": [{"path": c.path, "kind": c.kind} for c in interface_owned],
                },
            ),
            exit_codes.OK,
        )

    writer.write(f"\nConfiguration - {cluster_id}\n\n")
    writer.write(f"  Published version:  {published}\n")
    writer.write(f"  Last saved:         {saved.version}   {saved.date}   {saved.comment}\n")

    if published_hash and published_hash != saved.commit:
        writer.write(
            "\n  WARNING: the most recently saved version is not the published one.\n"
            f"  The nodes cannot receive version {saved.version} until it is published again.\n"
        )

    regenerated = read_regeneration(cluster_id) if published_hash else None
    line = regeneration_line(regenerated, cluster_id)
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
