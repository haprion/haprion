"""`haprion-block-ask <client>` - a block client's forced command (B412).

What sshd runs when a block client's key connects to `_haprion-block`: the
client ID is the word its `authorized_keys` line forces, and what the client
asked for is in `SSH_ORIGINAL_COMMAND`:

    block <object> <address>...

The words are checked here, unprivileged, and again by the helper, which is
the boundary. The client's cluster comes from the registry. One line answers
on stdout, for the log of whatever asked - fail2ban's action - and the exit
code is the helper's.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TextIO

from haprion import block_clients, exit_codes
from haprion.block_clients import BlockClientError
from haprion.cli.block_helper import HELPER
from haprion.cli.server_state_helper import SUDO
from haprion.envelope import new_request_id
from haprion.server_state import BLOCK_OPERATION, BLOCK_VERB, MAX_ADDRESSES

type Run = Callable[[str], subprocess.CompletedProcess[str]]


def run_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Through `sudo -n`: there is no terminal to ask a password on."""

    return subprocess.run(  # noqa: S603 - fixed paths, the request on stdin
        [SUDO, "-n", "--", HELPER],
        input=request,
        capture_output=True,
        text=True,
        check=False,
    )


def said(completed: subprocess.CompletedProcess[str]) -> str:
    """The helper's answer in one line: the outcome, or its error's sentence."""

    try:
        document = json.loads(completed.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        document = None
    if not isinstance(document, Mapping):
        lines = (completed.stderr or "").strip().splitlines()
        return lines[-1] if lines else f"no answer (exit {completed.returncode})"
    error = document.get("error")
    if isinstance(error, Mapping) and error.get("message"):
        return f"{document.get('outcome')}: {error.get('message')}"
    warnings = document.get("warnings")
    if isinstance(warnings, list) and warnings:
        notes = "; ".join(
            f"{entry.get('node')}: {entry.get('message')}"
            for entry in warnings
            if isinstance(entry, Mapping)
        )
        return f"{document.get('outcome')}: {notes}"
    return str(document.get("outcome"))


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    clients_file: Path = block_clients.CLIENTS_FILE,
    run: Run = run_helper,
    output_stream: TextIO | None = None,
) -> int:
    writer = output_stream or sys.stdout
    arguments = sys.argv[1:] if argv is None else argv
    words = (os.environ if environ is None else environ).get("SSH_ORIGINAL_COMMAND", "").split()

    def refuse(message: str) -> int:
        writer.write(f"refused: {message}\n")
        return exit_codes.USAGE

    if len(arguments) != 1:
        return refuse("this command is a block client's forced command")
    if len(words) < 3 or words[0] != BLOCK_VERB or len(words) > MAX_ADDRESSES + 2:
        return refuse(f"expected: {BLOCK_VERB} <object> <address>... (at most {MAX_ADDRESSES})")
    try:
        identifier = block_clients.client_id(arguments[0])
        clients = block_clients.read(clients_file)
        entry = clients.get(identifier)
        if entry is None:
            raise BlockClientError("forbidden", f"{identifier} is not a block client")
    except BlockClientError as exc:
        return refuse(str(exc))
    request = json.dumps(
        {
            "schema_version": 1,
            "operation": BLOCK_OPERATION,
            "cluster": entry.cluster,
            "request_id": new_request_id(),
            "parameters": {"client": identifier, "object": words[1], "addresses": words[2:]},
        },
        separators=(",", ":"),
    )
    completed = run(request)
    writer.write(said(completed) + "\n")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
