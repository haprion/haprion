"""``haproxy-objects`` - the stored proxy objects, read-only.

Where `haproxy-inventory` says what a node is serving, this says what the
cluster's objects look like as written. The listing names them; `--show <name>`
prints one document exactly as it is stored, so it can be piped, diffed or
copied without going through a browser; `--advanced <name>` prints where each
line of its advanced config goes, as the interface's *Check* does (Fas 17).
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.helper_protocol import write_document
from haproxy_mgmt.proxy_model import ModelError, advanced_placement

OPERATION = "objects"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-objects-helper"
SUDO = "/usr/bin/sudo"
EXIT_UNAVAILABLE = 68
EXIT_NOT_FOUND = 66
EXIT_REFUSED = 65
USAGE = "Usage:\n  haproxy-objects -c <cluster> [--show <name> | --advanced <name> | --json]\n"

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]


def run_objects_helper(
    cluster_id: str, request_id: str, *, unchanged_since: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Ask the root helper for the stored objects of one cluster.

    `unchanged_since` is the fingerprint of a listing the caller holds; the
    helper then answers `unchanged` instead of the listing when it still
    stands. This command never sends it - it always wants the objects.
    """

    request = {
        "schema_version": 1,
        "operation": OPERATION,
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {} if unchanged_since is None else {"unchanged_since": unchanged_since},
    }
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        [SUDO, "-n", HELPER],
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


def _parse(argv: list[str]) -> tuple[str, bool, str | None, bool]:
    """Cluster, `--json`, the object named, and whether its advanced config is asked for."""

    if len(argv) < 2 or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    cluster = argv[1]
    rest = argv[2:]
    if not rest:
        return cluster, False, None, False
    if rest == ["--json"]:
        return cluster, True, None, False
    if len(rest) == 2 and rest[0] in ("--show", "--advanced"):
        return cluster, False, rest[1], rest[0] == "--advanced"
    usage(USAGE)


def _result(document: Mapping[str, Any]) -> Mapping[str, Any]:
    result = document.get("result")
    if document.get("operation") != OPERATION or not isinstance(result, Mapping):
        raise ValueError("the objects helper returned an invalid result")
    return result


def _entries(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    objects = _result(document).get("objects")
    if not isinstance(objects, list):
        raise ValueError("the objects helper returned an invalid object list")
    for entry in objects:
        if not isinstance(entry, Mapping):
            raise ValueError("the objects helper returned an invalid object")
    return list(objects)


def _render(document: Mapping[str, Any], writer: TextIO) -> None:
    entries = _entries(document)
    writer.write(f"Cluster: {document.get('cluster')}\n")
    commit = _result(document).get("commit")
    writer.write(f"Source:  {'nothing committed yet' if commit is None else commit}\n\n")
    if not entries:
        writer.write("No stored objects.\n")
        return

    writer.write("NAME                     TYPE   VIP              SERVES\n")
    for entry in entries:
        hostnames = entry.get("hostnames")
        serves = ", ".join(hostnames) if isinstance(hostnames, list) and hostnames else "-"
        #
        # An unreadable object is listed with what is wrong instead of its
        # shape, because that is the only useful thing to say about it - and
        # leaving it out would hide the one file somebody has to open.
        #
        if not entry.get("readable"):
            writer.write(
                f"{str(entry.get('name', '')):<24} -      CANNOT READ: {entry.get('problem')}\n"
            )
            continue
        #
        # The address the object is served on (B222), or the name the network
        # description lacks. A release older than the field says "-".
        #
        vip = entry.get("vip")
        on = (vip.get("address") or vip.get("name")) if isinstance(vip, Mapping) else None
        writer.write(
            f"{str(entry.get('name', '')):<24} {str(entry.get('protocol', '')):<6} "
            f"{str(on or '-'):<16} {serves}\n"
        )


def _show(document: Mapping[str, Any], name: str, writer: TextIO, errors: TextIO) -> int:
    for entry in _entries(document):
        if entry.get("name") != name:
            continue
        writer.write(str(entry.get("document", "")))
        return 0
    errors.write(f"ERROR: this cluster stores no object named {name}\n")
    return EXIT_NOT_FOUND


def _advanced(document: Mapping[str, Any], name: str, writer: TextIO, errors: TextIO) -> int:
    """Each line of the object's text, what became of it, and where it went.

    Exit 65 when a line is refused, since the object then cannot be published;
    the same refusals `load_proxy` makes, from the same placement.
    """

    for entry in _entries(document):
        if entry.get("name") != name:
            continue
        try:
            placement = advanced_placement(name, str(entry.get("document", "")).encode())
        except ModelError as exc:
            errors.write(f"ERROR: {exc}\n")
            return EXIT_REFUSED
        if placement is None:
            writer.write(f"{name} has no advanced config.\n")
            return 0
        writer.write("LINE  FATE     WHERE                 TEXT\n")
        for line in placement.lines:
            if not line.text:
                continue
            writer.write(f"{line.number:>4}  {line.fate:<8} {line.where or '-':<21} {line.text}\n")
            if line.reason and line.fate != "placed":
                writer.write(f"{'':>15}{line.reason}\n")
        return EXIT_REFUSED if placement.refused else 0
    errors.write(f"ERROR: this cluster stores no object named {name}\n")
    return EXIT_NOT_FOUND


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_objects_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, json_mode, show, advanced = _parse(argv)
    completed = run_helper(cluster_id, new_request_id())

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr.strip() or "ERROR: the objects helper returned no result")
        errors.write("\n")
        return completed.returncode or EXIT_UNAVAILABLE

    if json_mode:
        write_document(writer, document)
        return completed.returncode
    try:
        if show is not None and advanced:
            return completed.returncode or _advanced(document, show, writer, errors)
        if show is not None:
            return completed.returncode or _show(document, show, writer, errors)
        _render(document, writer)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return completed.returncode or EXIT_UNAVAILABLE
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
