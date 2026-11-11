"""How the web asks *Test* and *Check address* of the blocklists (B496 nr 13, B500).

Over `/run/haprion/blocklist-check.sock` to `haprion-blocklist-check-helper`,
which runs as root. A service that cannot be asked is said as such, not as an
answer about the list or the address.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from typing import Any

from haprion import helper_socket
from haprion.blocklist_check import AddressCheck, CheckError, Tested

SOCKET_PATH = "/run/haprion/blocklist-check.sock"
#
# Over the helper unit's RuntimeMaxSec, which bounds the fetch's own 30 s.
#
TIMEOUT_SECONDS = 50.0
WHAT = "the blocklist check helper"


def _ask(parameters: dict[str, object], path: str) -> dict[str, Any]:
    request = {
        "schema_version": 1,
        "operation": "blocklist_check",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": parameters,
    }
    try:
        raw = helper_socket.ask(request, path=path, timeout=TIMEOUT_SECONDS, what=WHAT)
    except helper_socket.HelperUnavailable as error:
        raise CheckError("unavailable", str(error)) from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise CheckError(
            "unavailable", f"{WHAT} answered with something that is not JSON"
        ) from error
    if not isinstance(document, dict) or document.get("outcome") != "done":
        refusal = document.get("error") if isinstance(document, dict) else None
        code = refusal.get("code") if isinstance(refusal, dict) else None
        message = refusal.get("message") if isinstance(refusal, dict) else None
        raise CheckError(str(code or "unavailable"), str(message or f"{WHAT} did not say"))
    result = document.get("result")
    if not isinstance(result, dict):
        raise CheckError("unavailable", f"{WHAT}'s answer was incomplete")
    return result


def test(
    *,
    name: str,
    url: str,
    every_hours: int,
    authorization: str,
    username: str = "",
    excepts: Sequence[str] = (),
    secret: str = "",
    keep_secret: bool = False,
    path: str = SOCKET_PATH,
) -> Tested:
    """Fetch the list as the form holds it, keeping nothing; CheckError with its sentence otherwise."""

    fields: dict[str, object] = {
        "name": name,
        "url": url,
        "every_hours": every_hours,
        "authorization": authorization,
        "username": username,
        "excepts": list(excepts),
    }
    if keep_secret:
        fields["keep_secret"] = True
    elif secret:
        fields["secret"] = secret
    result = _ask({"list": fields}, path)
    try:
        return Tested.from_dict(result)
    except (KeyError, TypeError, ValueError) as error:
        raise CheckError("unavailable", f"{WHAT}'s answer was incomplete") from error


def check_address(address: str, *, path: str = SOCKET_PATH) -> AddressCheck:
    """Which kept lists hold the address; CheckError with its sentence otherwise."""

    result = _ask({"address": address}, path)
    try:
        return AddressCheck.from_dict(result)
    except (KeyError, TypeError, ValueError) as error:
        raise CheckError("unavailable", f"{WHAT}'s answer was incomplete") from error
