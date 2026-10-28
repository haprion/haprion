"""How the web asks about the NDES servers this manager enrolls with (B383, B385).

Over `/run/haprion/ndes-server.sock` to `haprion-ndes-server-helper`, which runs
as root: it lists the servers in the runtime policy, fetches a server's CA for
the administrator to compare, and writes a server in once its CA is confirmed.
A service that cannot be asked is said as such, not as an answer about the
server.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from haprion import helper_socket
from haprion.ndes_servers import NdesServerError

SOCKET_PATH = "/run/haprion/ndes-server.sock"
#
# GetCACert is bounded at 20 s in the helper; the rest is local.
#
TIMEOUT_SECONDS = 45.0


def ask(action: str, *, path: str = SOCKET_PATH, **parameters: str | list[str]) -> dict[str, Any]:
    """The helper's result for one action, or NdesServerError with its sentence."""

    request = {
        "schema_version": 1,
        "operation": "ndes_server",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": {"action": action, **parameters},
    }
    try:
        raw = helper_socket.ask(
            request, path=path, timeout=TIMEOUT_SECONDS, what="the NDES server service"
        )
    except helper_socket.HelperUnavailable as error:
        raise NdesServerError("unavailable", str(error)) from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise NdesServerError(
            "unavailable", "the NDES server service answered with something that is not JSON"
        ) from error
    result = document.get("result") if isinstance(document, dict) else None
    if not isinstance(document, dict) or document.get("outcome") != "done":
        refusal = document.get("error") if isinstance(document, dict) else None
        code = refusal.get("code") if isinstance(refusal, dict) else None
        message = refusal.get("message") if isinstance(refusal, dict) else None
        raise NdesServerError(
            str(code or "unavailable"), str(message or "the NDES server service did not say")
        )
    if not isinstance(result, dict):
        raise NdesServerError("unavailable", "the NDES server service's answer was incomplete")
    return result
