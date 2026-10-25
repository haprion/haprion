"""What the interface's root tools answer, in the engine's envelope (review 2026-10-22, 4-9).

`haprion-user apply`, `haprion-settings apply`, `haprion-profiles` and
`haprion-export` each built their `--json` envelope by hand, without the
invariants `haprion.envelope` holds, and called every failure `refused`, a
code the contract does not have. A file the tool refuses is `bad_input`, an
installation it cannot use `dependency_unavailable`, a change somebody made
meanwhile `expected_target_changed`; and a run that had already saved some of
its change when it stopped is `partial`, with what it saved (1B-3).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from typing import Any

import psycopg
from haprion import exit_codes
from haprion.envelope import Message, envelope, new_request_id
from haprion.helper_protocol import write_document


class ToolError(Exception):
    """A refusal with the contract's code and the exit it leaves with."""

    def __init__(
        self, message: str, *, code: str = "bad_input", exit_code: int = exit_codes.REFUSED
    ) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def done(operation: str, result: Mapping[str, Any]) -> int:
    return write_document(
        sys.stdout,
        envelope(operation=operation, outcome="done", cluster=None, result=dict(result)),
        exit_codes.OK,
    )


def failed(
    operation: str,
    code: str,
    message: str,
    exit_code: int,
    result: Mapping[str, Any] | None = None,
) -> int:
    """Refused or failed, with what was done before it when there is any."""

    return write_document(
        sys.stdout,
        envelope(
            operation=operation,
            outcome="blocked" if exit_code == exit_codes.BLOCKED else "failed",
            cluster=None,
            request_id=new_request_id(),
            result=None if result is None else dict(result),
            error=Message(code=code, message=message[:2048]),
        ),
        exit_code,
    )


def partial(operation: str, result: Mapping[str, Any], code: str, message: str) -> int:
    """Some of the change was saved and some not: what was, and why the rest was not."""

    return write_document(
        sys.stdout,
        envelope(
            operation=operation,
            outcome="partial",
            cluster=None,
            result=dict(result),
            warnings=(Message(code=code, message=message[:2048]),),
        ),
        exit_codes.PARTIAL,
    )


def refusal(
    args: argparse.Namespace, operation: str | None, code: str, message: str, exit_code: int
) -> int:
    """Said on stderr, and - for a command answering in a contract - as its one document.

    `--json` promises a document on every path (Fas 23 review): a playbook
    reading `stdout | from_json` must get the refusal, not an empty string.
    """

    print(f"ERROR: {message}", file=sys.stderr)
    if operation is not None and getattr(args, "json", False):
        return failed(operation, code, message, exit_code)
    return exit_code


def database_failure(error: psycopg.Error) -> tuple[str, int]:
    """The contract's code and exit for a database error.

    The database's own rules refusing the change - a constraint, or a
    trigger's raise such as the one that keeps the last active admin - are the
    request refused (65). Anything else is the installation's (68): a server
    that does not answer, and a column or a grant an incomplete upgrade left
    out, which said `bad_input` as though the file were wrong (review
    26-10-24, 07-07).
    """

    if isinstance(error, (psycopg.IntegrityError, psycopg.errors.RaiseException)):
        return "bad_input", exit_codes.REFUSED
    return "dependency_unavailable", exit_codes.UNAVAILABLE


def database_refusal(args: argparse.Namespace, operation: str | None, error: psycopg.Error) -> int:
    """A database that could not be used, or one whose own rule refused the change."""

    code, exit_code = database_failure(error)
    return refusal(args, operation, code, f"database: {error}", exit_code)
