"""The `list_files` reading: the lists root keeps, as the poller compares them with the database (B534, PW02).

Run by `haprion-readings-helper` for the poller, as root, with a null cluster.
The answer is, per path list and per blocklist file, its name, its revision and
a digest of what it says - and nothing of a blocklist's secret. The web
compares those with its own rows, so a database restored from an older dump, an
apply that did not finish or a file somebody changed shows on the Settings card
instead of in the next publish. A path list the poller names as having no row
also carries its description and paths, so *Take in* can make the row.

A directory that cannot be read fails the reading; the poller keeps what it
read before. A directory not made yet is an empty answer.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import blocklist_store, exit_codes, path_lists
from haprion.config import DEFAULT_POLICY_PATH
from haprion.envelope import envelope
from haprion.helper_protocol import (
    HelperProtocolError,
    read_scoped_request,
    require_no_arguments,
    write_bad_input,
    write_document,
    write_failure,
)

OPERATION = "list_files"
PARAMETERS: frozenset[str] = frozenset({"known_path_lists"})
MAX_KNOWN = 1000


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    path_list_directory: Path = path_lists.DIRECTORY,
    blocklist_directory: Path = blocklist_store.DEFINITIONS,
) -> int:
    del policy_path, require_secure  # the directories are fixed, not the policy's
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "the list_files reading must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_scoped_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    if request.cluster is not None:
        message = "the lists are the manager's: the cluster must be null"
        errors.write(f"ERROR: {message}\n")
        return write_bad_input(writer, OPERATION, request, message)
    asked = request.parameters.get("known_path_lists", [])
    known = {name for name in asked if isinstance(name, str)} if isinstance(asked, list) else set()
    if not isinstance(asked, list) or len(asked) > MAX_KNOWN or len(known) != len(asked):
        message = f"known_path_lists is a list of at most {MAX_KNOWN} names"
        errors.write(f"ERROR: {message}\n")
        return write_bad_input(writer, OPERATION, request, message)

    try:
        found = {
            "path_lists": path_lists.listing(directory=path_list_directory, known=known),
            "blocklists": blocklist_store.listing(directory=blocklist_directory),
        }
    except (path_lists.PathListError, OSError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=None,
            request_id=request.request_id,
            code="files_unreadable",
            message=str(exc),
            exit_code=exit_codes.IO_ERROR,
        )
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=found,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
