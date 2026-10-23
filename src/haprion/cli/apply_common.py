"""What every ``apply`` from the terminal shares (Fas 23, B293).

One refusal type with the exit code it leaves with, one envelope for `--json`,
one way to send a request to the publish helper and read its answer, and one
diff. `haprion-objects apply` and `haprion-network apply` read differently and
publish the same way; a second copy of this would be a second answer to "what
did the helper say".
"""

from __future__ import annotations

import difflib
import json
import re
import subprocess
from collections.abc import Callable, Mapping
from typing import Any

from haprion import exit_codes
from haprion.envelope import Message, outcome_for_exit
from haprion.envelope import envelope as make_envelope

CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_MESSAGE = 2048

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]
type RunPublish = Callable[[str], subprocess.CompletedProcess[str]]


class Refused(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        exit_code: int = exit_codes.REFUSED,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        #
        # The helper's own details, passed on: HAProxy's words on a candidate
        # it refused are the only way to find the line (Fas 18, the install
        # test: `apply` said only that the candidate was invalid).
        #
        self.details = dict(details) if details else None

    def report(self) -> str:
        """The refusal as the terminal shows it, with HAProxy's words when there are any."""

        diagnostics = (self.details or {}).get("diagnostics")
        text = f"ERROR: {self}\n"
        if not isinstance(diagnostics, str) or not diagnostics.strip():
            return text
        return text + f"\n{diagnostics.rstrip()}\n"


class PartlyDone(Refused):
    """Refused after some of the change was published, so not a refusal of it all.

    `haprion-objects apply` publishes in versions of at most 64 objects; when a
    later one is refused, the earlier ones stand. They were named only in the
    message, with `result` null (review 2026-10-22, 4-2); the result carries
    them now, under an outcome that says the run is `partial`.
    """

    def __init__(self, refused: Refused, done: list[dict[str, Any]]) -> None:
        super().__init__(refused.code, str(refused), exit_codes.PARTIAL, refused.details)
        self.done = done


def envelope(operation: str, cluster: str, result: Any, error: Refused | None) -> dict[str, Any]:
    """The command's one document: `done` with its result, or the refusal it stopped at.

    Built by `haprion.envelope`, as every helper's is; the outcome of a refusal
    is its exit code's (a lock or a moved head is `blocked`), and a code that
    is not one is `internal_error` (review 2026-10-22, 4-9: this built its own
    dictionary, called every such code `refused`, and every stop `failed`).
    """

    if error is None:
        return make_envelope(operation=operation, outcome="done", cluster=cluster, result=result)
    if isinstance(error, PartlyDone):
        return make_envelope(
            operation=operation,
            outcome="partial",
            cluster=cluster,
            result=result,
            warnings=(Message(code=error.code, message=str(error)[:MAX_MESSAGE]),),
        )
    return make_envelope(
        operation=operation,
        outcome=outcome_for_exit(error.exit_code),
        cluster=cluster,
        result=None,
        error=Message(
            code=error.code if CODE.fullmatch(error.code) else "internal_error",
            message=(str(error) or error.code)[:MAX_MESSAGE],
            details=error.details,
        ),
    )


def answer_of(completed: subprocess.CompletedProcess[str], operation: str) -> Mapping[str, Any]:
    """A helper's result, or its own refusal in its own words and exit code."""

    try:
        answer = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise Refused(
            "dependency_unavailable",
            completed.stderr.strip() or f"the {operation} helper returned no result",
            completed.returncode or exit_codes.UNAVAILABLE,
        ) from exc
    if not isinstance(answer, Mapping) or answer.get("operation") != operation:
        raise Refused(
            "dependency_unavailable",
            f"the {operation} helper returned an invalid result",
            completed.returncode or exit_codes.UNAVAILABLE,
        )
    error = answer.get("error")
    if isinstance(error, Mapping):
        details = error.get("details")
        raise Refused(
            str(error.get("code") or "refused"),
            str(error.get("message") or "refused"),
            completed.returncode or exit_codes.REFUSED,
            details if isinstance(details, Mapping) else None,
        )
    result = answer.get("result")
    if not isinstance(result, Mapping):
        raise Refused(
            "dependency_unavailable",
            f"the {operation} helper returned no result",
            completed.returncode or exit_codes.UNAVAILABLE,
        )
    return result


def diff(name: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"{name} (stored)",
            tofile=f"{name} (file)",
        )
    )
