"""The `blocklist_states` reading: what the refresh timer last did with each blocklist (B496, 13; B500).

Run by `haprion-readings-helper` for the poller, as root, with a null
cluster: the lists are the manager's, fetched once and sent to every
cluster. The answer is the timer's state file as it stands - per list when
it was last fetched, last tried and last failed, why, and how many entries
the list it keeps holds - and nothing of the lists themselves. A state file
that cannot be read fails the reading; the poller keeps what it read before.
No state file is an empty answer: the timer has not run, or no list exists.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import blocklist_store, exit_codes
from haprion.blocklist_store import ListState
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

OPERATION = "blocklist_states"
PARAMETERS: frozenset[str] = frozenset()
#
# What a list's error is cut to: the column the poller writes it to holds 500.
#
MAX_ERROR = 500


def _time(value: str | None) -> str | None:
    return None if value is None else value.replace("+00:00", "Z")


def result(states: Mapping[str, ListState]) -> dict[str, Any]:
    """The reading's result: every list in the state file once, by name."""

    return {
        "lists": [
            {
                "name": name,
                "fetched_at": _time(state.fetched_at),
                "attempted_at": _time(state.attempted_at),
                "failed_at": _time(state.failed_at),
                "error": state.error[:MAX_ERROR],
                "entries": state.entries,
                "skipped": state.skipped,
            }
            for name, state in sorted(states.items())
        ]
    }


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    state_directory: Path = blocklist_store.STATE,
) -> int:
    del policy_path, require_secure  # the state file is the timer's, not the policy's
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "the blocklist_states reading must run as root", exit_code=exit_codes.NOT_ROOT
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
        message = "blocklists are the manager's: the cluster must be null"
        errors.write(f"ERROR: {message}\n")
        return write_bad_input(writer, OPERATION, request, message)

    try:
        states = blocklist_store.read_state(directory=state_directory)
    except blocklist_store.StoreError as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=None,
            request_id=request.request_id,
            code="state_unreadable",
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
            result=result(states),
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
