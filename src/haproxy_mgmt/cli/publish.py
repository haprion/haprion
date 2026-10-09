"""`haprion-publish` - save the draft area as a new version and publish it.

The thin half. It runs entirely as the calling user and does only what an
unprivileged caller can honestly do: check the arguments, look up the cluster,
read the draft area, and hand a structured request to the root helper.

Everything that decides what gets published happens on the other side. This half
does not build the artifact, does not validate, does not create the version and
does not write the release - and it is not trusted to have done any of it. The
helper reads the repository again on its own.

What is sent is the draft area's `core/` and `manual/`, chosen exactly the way
the shell path chose them: `git ls-files --cached --others --exclude-standard`,
so `.gitignore` still keeps a stray swap file or `.orig` out of a version.
`managed/` is not sent; it belongs to the application and is carried over from
the current version by the helper. Changes there are reported rather than
silently dropped.

`expected_head` is measured here and checked there. If the repository moves in
between - a concurrent publish, a revert - the helper refuses and no version is
created.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import CallerError, usage
from haproxy_mgmt.cli.caller import config_path as _config_path
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.git_command import git as _git
from haproxy_mgmt.repo_health import describe_problem, is_repo_root
from haproxy_mgmt.repo_snapshot import SNAPSHOT_PREFIXES, PublishError, resolve_head

OPERATION = "publish_version"

HELPER = "/opt/haprion/current/bin/haprion-publish-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haprion-publish -c <cluster> <comment>\n"
    "\n"
    "Examples:\n"
    '  haprion-publish -c internal "Added serverxyz"\n'
    '  haprion-publish -c external "Added public service"\n'
)

type RunHelper = Callable[[bytes], tuple[int, str, str]]
type ConfigPath = Callable[[str], Path]


def _run_helper(request: bytes) -> tuple[int, str, str]:
    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=request,
        capture_output=True,
        check=False,
    )
    return (
        completed.returncode,
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )


def _parse(argv: list[str]) -> tuple[str, str]:
    if len(argv) < 3 or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    comment = " ".join(argv[2:]).strip()
    if not comment:
        usage(USAGE)
    return argv[1], comment


def collect_layers(repo: Path) -> dict[str, str]:
    """The draft area's `core/` and `manual/`, as git would stage them.

    Tracked files plus untracked files that `.gitignore` does not exclude - the
    same set `git add -A -- core manual` produced in the shell path. A tracked
    file that has been deleted is simply absent from the result, and the helper
    turns that absence into a deletion.
    """

    listing = _git(
        repo,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        *(prefix.rstrip("/") for prefix in SNAPSHOT_PREFIXES),
    ).decode()

    files: dict[str, str] = {}
    for relative in listing.split("\0"):
        if not relative:
            continue
        path = repo / relative
        if not path.is_file() or path.is_symlink():
            continue
        try:
            files[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise CallerError(
                f"'{relative}' cannot be read as UTF-8 text: {exc}\n"
                "Configuration is text; remove or fix the file before publishing."
            ) from exc

    if not files:
        raise CallerError(
            f"there is nothing to publish in {repo}: "
            f"{' and '.join(prefix.rstrip('/') for prefix in SNAPSHOT_PREFIXES)} are empty."
        )
    return files


def _report_managed(repo: Path, writer: TextIO) -> None:
    """Say plainly what is not part of this version, instead of dropping it."""

    changed = _git(repo, "status", "--porcelain", "--", "managed").decode().strip()
    if changed:
        writer.write(
            "NOTE: the following changes in managed/ are NOT part of this version:\n"
            f"{changed}\n"
            "managed/ is published by the application; this path publishes core/ and manual/.\n\n"
        )


def _say_what_the_promise_misses(writer: TextIO, result: dict[str, Any]) -> None:
    """The reservations file is not current with the handwritten fragments.

    Said, not refused. Nothing here has read the fragments - `manual/` is read
    and never interpreted - so this cannot know whether they collide with
    anything, and refusing on a suspicion would block a cluster whose
    handwritten half is perfectly correct.

    It is worth saying because the failure it points at is one HAProxy does not
    report. Two frontends on one address both bind it under SO_REUSEPORT and
    the kernel splits new connections between them, so the publish succeeds and
    the node answers correctly for roughly half the traffic. The reservations
    file is what prevents it - and a promise written once and never revisited
    looks exactly like a current one, which is the gap the digests close.

    Each list gets its own sentence. "Nobody wrote this down" and "this changed
    since somebody read it" are different situations, and one merged list would
    leave the operator to work out which of the two they are in.
    """

    review = result.get("fragment_review")
    if not isinstance(review, dict):
        return

    def listed(key: str) -> str | None:
        paths = review.get(key)
        if not isinstance(paths, list) or not paths:
            return None
        return "\n".join(f"    {path}" for path in paths)

    unreviewed, changed, vanished = listed("unreviewed"), listed("changed"), listed("vanished")
    if not (unreviewed or changed or vanished):
        return

    writer.write("Note: manual/reservations.yaml is not current with this cluster's\n")
    writer.write("handwritten configuration.\n\n")
    if unreviewed:
        writer.write(f"Not written down at all:\n{unreviewed}\n\n")
    if changed:
        writer.write(f"Changed since somebody read them:\n{changed}\n\n")
    if vanished:
        writer.write(f"Written down but no longer present:\n{vanished}\n\n")
    writer.write(
        "If any of those bind an address or a hostname, write it down there, then\n"
        "record what you read under `reviewed:`:\n\n"
        "    reviewed:\n"
        "      <path>: <sha256sum of that file>\n\n"
        "Listing a fragment that reserves nothing is how you say you read it.\n"
        "Nothing reads them, so a collision would be found by its traffic.\n\n"
    )


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    run_helper: RunHelper = _run_helper,
    config_path: ConfigPath = _config_path,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    cluster_id, comment = _parse(argv)

    try:
        repo = config_path(cluster_id)
        if not is_repo_root(repo):
            writer.write(f"{describe_problem(cluster_id, repo)}\n")
            return 68
        _, expected_head = resolve_head(repo)
        _report_managed(repo, writer)
        files = collect_layers(repo)
    except (CallerError, GitError, PublishError) as exc:
        writer.write(f"ERROR: {exc}\n")
        return exc.exit_code

    request = json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": str(uuid.uuid4()),
            "parameters": {
                "files": files,
                "expected_head": expected_head,
                "comment": comment,
            },
        }
    ).encode()

    #
    # "Checking", not "Validating". Validation happens on the far side and only
    # when there is something to validate - the shell path printed its line
    # after it knew that, and a progress line that claims work which did not
    # happen is exactly the kind of output nobody can trust under pressure.
    #
    writer.write(f"Checking {cluster_id} ...\n")
    code, out, err = run_helper(request)

    try:
        document = json.loads(out) if out else None
    except json.JSONDecodeError:
        document = None

    if not isinstance(document, dict) or "outcome" not in document:
        #
        # No envelope means the helper died before it could describe what it
        # did. Its own words are the best thing available - inventing a summary
        # here would be guessing.
        #
        writer.write(err or f"ERROR: publishing failed with exit code {code}.\n")
        return code or 70

    if document.get("outcome") != "done":
        error = document.get("error") or {}
        diagnostics = (error.get("details") or {}).get("diagnostics")
        if diagnostics:
            writer.write(f"\n{diagnostics}\n")
        writer.write(f"ERROR: {error.get('message', 'publishing did not run.')}\n")
        return code or 70

    result = document.get("result") or {}
    if not result.get("changed"):
        _say_what_the_promise_misses(writer, result)
        writer.write(f"No changes to publish for cluster '{cluster_id}'.\n")
        return 0

    _say_what_the_promise_misses(writer, result)
    writer.write(
        "HAProxy configuration OK.\n\n"
        f"Cluster '{cluster_id}' is published.\n\n"
        f"  Version:  {result['version']}\n"
        f"  Hash:     {result['hash']}\n"
        f"  Release:  {result['release']}\n\n"
        "No node deployment has run. Bring the nodes into step with:\n\n"
        f"  {result['next_command']}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
