"""Every exit code a Haprion command ends with, in one table.

The values follow `sysexits.h` where one fits, and each means the same in
every command. Until 2026-10-23 every module named its own: `EXIT_NOT_ROOT`
was 77 in nineteen helpers and 68 in two, `EXIT_UNAVAILABLE` was 68, 69 or
78, a deploy stopped by split brain ended 65 while one stopped by the lock
ended 75, and the jobs page explained the numbers from a table of its own
(review 2026-10-22, 4-1). `docs/CONTRACT.md` carries this table for callers,
and a test refuses an exit code named or written anywhere else.

The exit code follows the outcome: `OK` is `done`, `PARTIAL` is `partial`,
`BLOCKED` is `blocked`, and every other code is `failed` and says why.
`helper_protocol.write_document` refuses a document whose outcome the exit
code contradicts. A caller that needs more than the outcome branches on the
envelope's error `code`, not on the number.
"""

from __future__ import annotations

OK = 0
#
# Failed, with nothing more for the exit to say than the message does: a
# front end whose helper answered `failed`, a run whose nodes did not take it.
#
FAILED = 1
#
# The caller's mistake: arguments or a request document that are not valid
# (`bad_input`).
#
USAGE = 64
#
# The request was read, and what it asks for was refused: a candidate that
# does not validate, a name already taken. Nothing was changed.
#
REFUSED = 65
#
# What the request names does not exist: a version, an object, a run.
#
NOT_FOUND = 66
#
# Something the command needs could not be read or reached just now: the
# nodes' status, a helper, a repository, a library (`dependency_unavailable`).
#
UNAVAILABLE = 68
#
# Some targets verified and some not.
#
PARTIAL = 69
#
# An unexpected failure in the command itself (`internal_error`).
#
INTERNAL = 70
#
# A file the command had to create, or write, could not be.
#
CANNOT_CREATE = 73
IO_ERROR = 74
#
# Stopped before anything was changed: a lock, a safety condition, a target
# that moved, or every item refused.
#
BLOCKED = 75
#
# A root helper run as another account.
#
NOT_ROOT = 77
#
# The installation lacks what the command needs: an identity, a registry, a
# section of the runtime policy.
#
CONFIG = 78
#
# A command that ran out of its time, as `timeout(1)` reports it.
#
TIMED_OUT = 124

MEANINGS = {
    OK: "Finished.",
    FAILED: "Failed; the message says why.",
    USAGE: "The request itself was not valid.",
    REFUSED: "Refused before anything was changed.",
    NOT_FOUND: "What the request named does not exist.",
    UNAVAILABLE: "Something the command needs could not be read or reached.",
    PARTIAL: "Finished on some targets only.",
    INTERNAL: "The command failed unexpectedly.",
    CANNOT_CREATE: "A file could not be created.",
    IO_ERROR: "A file could not be written.",
    BLOCKED: "Stopped before anything was changed: a lock, a safety check or a moved target.",
    NOT_ROOT: "The command must run as root.",
    CONFIG: "The installation lacks something the command needs.",
    TIMED_OUT: "The command ran out of time.",
}


def outcome(code: int) -> str:
    """The outcome an exit code stands for: `done`, `partial`, `blocked` or `failed`."""

    if code == OK:
        return "done"
    if code == PARTIAL:
        return "partial"
    if code == BLOCKED:
        return "blocked"
    return "failed"


def for_outcome(document_outcome: object) -> int:
    """The exit code for a document's outcome, with `FAILED` for every failure.

    For a command that passes another's document on and has no reason of its
    own to give - the socket front ends - and for one that has decided the
    outcome before the reason.
    """

    return {"done": OK, "partial": PARTIAL, "blocked": BLOCKED}.get(str(document_outcome), FAILED)


def of_process(returncode: int, fallback: int) -> int:
    """A child's return code when it is one of these, and `fallback` when not.

    A helper killed by a signal comes back negative through `sudo -n`, and 126
    or 127 when it could not be run at all; neither is an exit this table
    explains, and passing one on made a document no check would write (review
    26-10-24, 06-05).
    """

    return returncode if returncode in MEANINGS else fallback


def foreign(returncode: int, helper: str) -> tuple[int, str | None]:
    """A helper's return code as this table has it, and what to say when it had none.

    `of_process` with `INTERNAL`, and the sentence a front owes its reader when
    the helper gave no exit of its own: killed by a signal, or ended with a
    code no Haprion command gives, it may have acted before it went (review
    26-10-24, 13-05). None when the code is one of these.
    """

    if returncode in MEANINGS:
        return returncode, None
    if returncode < 0:
        said = f"the {helper} was stopped by signal {-returncode} before it answered"
    else:
        said = f"the {helper} ended with {returncode}, which is no Haprion exit"
    return of_process(returncode, INTERNAL), f"{said}; it may have acted"


def check(document_outcome: object, code: int) -> int:
    """`code`, when it agrees with the outcome a document states; ValueError when not.

    The same kind of check `envelope.envelope` makes of its own invariants: a
    document that says `blocked` and an exit that says `failed` is two answers
    to one question, and the caller cannot tell which to believe.
    """

    if code not in MEANINGS:
        raise ValueError(f"exit code {code} is not in haprion.exit_codes")
    if document_outcome != outcome(code):
        raise ValueError(f"exit code {code} contradicts the outcome {document_outcome!r}")
    return code
