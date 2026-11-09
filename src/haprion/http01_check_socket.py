"""How the web asks whether HTTP-01 would reach this manager for a name (B496, B499).

Over `/run/haprion/http01-check.sock` to `haprion-http01-check-helper`, which
runs as root: it writes a test file in the webroot, fetches it over the name
and removes it again. A service that cannot be asked is said as such, not as
an answer about the name.
"""

from __future__ import annotations

import json
import uuid

from haprion import helper_socket
from haprion.http01_check import ANSWERS, Check, CheckError

SOCKET_PATH = "/run/haprion/http01-check.sock"
#
# Over the helper unit's RuntimeMaxSec, which bounds the check's own 25 s:
# the helper has removed its test file before the web says it did not answer.
#
TIMEOUT_SECONDS = 45.0


def ask(name: str, *, path: str = SOCKET_PATH) -> Check:
    """The helper's answer for the name, or CheckError with its sentence."""

    request = {
        "schema_version": 1,
        "operation": "http01_check",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": {"name": name},
    }
    try:
        raw = helper_socket.ask(
            request, path=path, timeout=TIMEOUT_SECONDS, what="the HTTP-01 check helper"
        )
    except helper_socket.HelperUnavailable as error:
        #
        # Busy, silent or absent alike: a check changes nothing that stays,
        # so there is nothing to tell apart, as there is for the NDES server.
        #
        raise CheckError("unavailable", str(error)) from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise CheckError(
            "unavailable", "the HTTP-01 check helper answered with something that is not JSON"
        ) from error
    if not isinstance(document, dict) or document.get("outcome") != "done":
        refusal = document.get("error") if isinstance(document, dict) else None
        code = refusal.get("code") if isinstance(refusal, dict) else None
        message = refusal.get("message") if isinstance(refusal, dict) else None
        raise CheckError(
            str(code or "unavailable"), str(message or "the HTTP-01 check helper did not say")
        )
    result = document.get("result")
    try:
        if not isinstance(result, dict) or result.get("answer") not in ANSWERS:
            raise TypeError
        return Check(**result)
    except TypeError as error:
        raise CheckError(
            "unavailable", "the HTTP-01 check helper's answer was incomplete"
        ) from error
