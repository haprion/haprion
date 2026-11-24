"""Write one path list across the root boundary (B527, B532).

The worker's `path_list_apply` job sends the list as Settings saved it. This
checks it as the engine reads it (`haprion.path_lists`) and writes it
root-only under /etc/haprion/path-lists, where every publish reads the lists
its objects name. Nothing reaches a node here: a cluster whose version carries
another copy of the list says so in *Needs attention* and takes the change with
its next publish. `remove` deletes the list; whether an object still names it
is the web's check, made before the job is queued.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import exit_codes, path_lists
from haprion.cli import cert_job
from haprion.envelope import envelope
from haprion.helper_protocol import HelperProtocolError, write_document
from haprion.path_lists import PathListError

OPERATION = path_lists.OPERATION
PARAMETERS = frozenset({"name", "revision", "description", "paths", "remove"})


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    directory: Path = path_lists.DIRECTORY,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-path-list-apply-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    parameters = request.parameters
    try:
        name = path_lists.checked_name(parameters.get("name"))
        revision = path_lists.check_revision(parameters.get("revision"))
        remove = parameters.get("remove", False)
        if not isinstance(remove, bool):
            raise PathListError("remove must be true or false")
        item = (
            None
            if remove
            else path_lists.path_list(
                name, parameters.get("paths"), parameters.get("description", ""), revision
            )
        )
    except PathListError as exc:
        return refuse("bad_input", str(exc), exit_codes.REFUSED)

    result: dict[str, object] = {"name": name, "revision": revision}
    try:
        if item is None:
            result["removed"] = path_lists.remove(
                name, directory=directory, require_secure=require_secure
            )
        else:
            notes: list[str] = []
            path_lists.write(
                item, directory=directory, require_secure=require_secure, warnings=notes
            )
            for note in notes:
                errors.write(f"WARNING: {note}\n")
            result["paths"] = len(item.paths)
    except PathListError as exc:
        return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
