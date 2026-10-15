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

from haprion.envelope import new_request_id

EXIT_REFUSED = 65
EXIT_NOT_FOUND = 66
EXIT_UNAVAILABLE = 68
CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_MESSAGE = 2048

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]
type RunPublish = Callable[[str], subprocess.CompletedProcess[str]]


class Refused(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        exit_code: int = EXIT_REFUSED,
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


def envelope(
    operation: str, cluster: str, outcome: str, result: Any, error: Refused | None
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": error is None,
        "outcome": outcome,
        "operation": operation,
        "cluster": cluster,
        "request_id": new_request_id(),
        "result": result,
        "warnings": [],
        "error": None
        if error is None
        else {
            "code": error.code if CODE.fullmatch(error.code) else "refused",
            "message": (str(error) or error.code)[:MAX_MESSAGE],
            **({"details": error.details} if error.details else {}),
        },
    }


def answer_of(completed: subprocess.CompletedProcess[str], operation: str) -> Mapping[str, Any]:
    """A helper's result, or its own refusal in its own words and exit code."""

    try:
        answer = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise Refused(
            "unavailable",
            completed.stderr.strip() or f"the {operation} helper returned no result",
            completed.returncode or EXIT_UNAVAILABLE,
        ) from exc
    if not isinstance(answer, Mapping) or answer.get("operation") != operation:
        raise Refused(
            "unavailable",
            f"the {operation} helper returned an invalid result",
            completed.returncode or EXIT_UNAVAILABLE,
        )
    error = answer.get("error")
    if isinstance(error, Mapping):
        details = error.get("details")
        raise Refused(
            str(error.get("code") or "refused"),
            str(error.get("message") or "refused"),
            completed.returncode or EXIT_REFUSED,
            details if isinstance(details, Mapping) else None,
        )
    result = answer.get("result")
    if not isinstance(result, Mapping):
        raise Refused(
            "unavailable",
            f"the {operation} helper returned no result",
            completed.returncode or EXIT_UNAVAILABLE,
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
