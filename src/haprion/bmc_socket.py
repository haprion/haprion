"""How the web asks about a BMC receiver (B526, B536, B538).

Over `/run/haprion/bmc.sock` to `haprion-bmc-helper`, which runs as root: it
opens the account the web sealed, asks the BMC what it serves, and writes the
BMC into the registry once the administrator has confirmed it. The web has
no network of its own, so every question to a BMC goes this way. A service that
cannot be asked is said as such, not as an answer about the BMC.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from haprion import helper_socket

SOCKET_PATH = "/run/haprion/bmc.sock"
#
# Over the helper unit's RuntimeMaxSec (90 s), which bounds the sign-in and the
# questions: the helper has ended, whatever it did, before the web says it did
# not answer.
#
TIMEOUT_SECONDS = 100.0


class BmcAskError(Exception):
    """A refusal or a service that could not be asked, with the code it came under.

    `unavailable`: the helper could not be asked and changed nothing.
    `unanswered`: it was asked and fell silent, so root may have made the change.
    Any other code is the helper's own (`bmc_login_refused`, `expected_target_changed`, ...).
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def ask(
    action: str,
    receiver_id: str,
    *,
    path: str = SOCKET_PATH,
    port: int | None = None,
    certificate: str | None = None,
    fingerprint_sha256: str | None = None,
    key_id: str | None = None,
    ciphertext: bytes | None = None,
) -> dict[str, Any]:
    """The helper's result for one action on one BMC, or BmcAskError.

    `certificate` is the one a save or an assign chooses; "" chooses none.
    """

    parameters: dict[str, Any] = {"action": action, "id": receiver_id}
    if certificate is not None:
        parameters["certificate"] = certificate
    if port is not None:
        parameters["port"] = port
    if fingerprint_sha256 is not None:
        parameters["fingerprint_sha256"] = fingerprint_sha256
    if key_id is not None:
        parameters["key_id"] = key_id
    if ciphertext is not None:
        parameters["ciphertext_base64"] = base64.b64encode(ciphertext).decode("ascii")
    request = {
        "schema_version": 1,
        "operation": "bmc",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": parameters,
    }
    try:
        raw = helper_socket.ask(request, path=path, timeout=TIMEOUT_SECONDS, what="the BMC helper")
    except helper_socket.HelperBusy as error:
        raise BmcAskError("unavailable", str(error)) from error
    except helper_socket.HelperSilent as error:
        #
        # Asked, then quiet: root may have saved or removed the target. Told
        # apart from a service that could not be asked at all.
        #
        raise BmcAskError("unanswered", str(error)) from error
    except helper_socket.HelperUnavailable as error:
        raise BmcAskError("unavailable", str(error)) from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise BmcAskError(
            "unavailable", "the BMC helper answered with something that is not JSON"
        ) from error
    if not isinstance(document, dict) or document.get("outcome") != "done":
        refusal = document.get("error") if isinstance(document, dict) else None
        code = refusal.get("code") if isinstance(refusal, dict) else None
        message = refusal.get("message") if isinstance(refusal, dict) else None
        raise BmcAskError(str(code or "unavailable"), str(message or "the BMC helper did not say"))
    result = document.get("result")
    if not isinstance(result, dict) or result.get("id") != receiver_id:
        raise BmcAskError("unavailable", "the BMC helper's answer was incomplete")
    return result
