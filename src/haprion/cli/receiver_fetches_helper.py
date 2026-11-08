"""The `receiver_fetches` reading: when each certificate receiver last fetched (B496, 10; B498).

Run by `haprion-readings-helper` for the poller, as root, with a null
cluster: receivers are the manager's, not a cluster's. The poller names the
moment to read from (`parameters.since`, an ISO 8601 time), and the answer is
the newest fetch per registered receiver since then, or null. A witness that
could not be read is said in `unread` and leaves the other one answered; it is
not a failure of the reading, since the poller keeps what it learnt before.
See `haprion.receiver_fetches`.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import exit_codes, receiver_fetches
from haprion.cert_receiver import HTTPS_PREFIX
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import envelope
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    read_scoped_request,
    require_no_arguments,
    write_bad_input,
    write_document,
    write_failure,
)

OPERATION = receiver_fetches.OPERATION
PARAMETERS: frozenset[str] = frozenset({"since"})


def _since(value: object, now: datetime) -> datetime:
    """The moment asked for, held to the reading's bounds."""

    if value is None:
        return now - receiver_fetches.DEFAULT_LOOKBACK
    if not isinstance(value, str) or len(value) > 40:
        raise HelperProtocolError("parameters.since must be an ISO 8601 time")
    try:
        asked = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HelperProtocolError("parameters.since must be an ISO 8601 time") from exc
    if asked.tzinfo is None:
        raise HelperProtocolError("parameters.since must carry its offset")
    return max(asked.astimezone(UTC), now - receiver_fetches.MAX_LOOKBACK)


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    read: Callable[..., receiver_fetches.Fetches] = receiver_fetches.read,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "the receiver_fetches reading must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_scoped_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    now = datetime.now(UTC)
    try:
        if request.cluster is not None:
            raise HelperProtocolError("receivers are the manager's: the cluster must be null")
        since = _since(request.parameters.get("since"), now)
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_bad_input(writer, OPERATION, request, str(exc))

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=None,
            request_id=request.request_id,
            code=config_error_code(exc.exit_code),
            message=str(exc),
            exit_code=exc.exit_code,
        )

    receivers = dict(runtime.registry.receivers) if runtime.registry is not None else {}
    fetches = read(receivers, since=since, prefix=HTTPS_PREFIX)
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result={
                "since": since.isoformat().replace("+00:00", "Z"),
                **receiver_fetches.result(receivers, fetches),
            },
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
