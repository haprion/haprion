"""How the web asks for a block to be placed, in the same call (B416).

Over `/run/haprion/block.sock` to `haprion-block-api-helper`, which runs as
root and places the block with the code the ssh path uses. A service that
cannot be asked is said as such (`HelperUnavailable`), and one that was asked
and then went quiet as `HelperSilent`: the second may have placed the block,
and the caller must not call it a failure.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from typing import Any

from haprion import helper_socket
from haprion.helper_socket import HelperBusy, HelperSilent, HelperUnavailable

__all__ = ["SOCKET_PATH", "HelperBusy", "HelperSilent", "HelperUnavailable", "ask"]

SOCKET_PATH = "/run/haprion/block.sock"
#
# Each node is asked once, in parallel, and given thirty seconds
# (`server_state.CALL_TIMEOUT_SECONDS`); the rest is reading the repository.
# Bounded so a node that never answers becomes a sentence for the caller.
#
TIMEOUT_SECONDS = 45.0


def ask(
    cluster: str,
    object_name: str,
    addresses: Sequence[str],
    *,
    actor: str,
    request_id: str | None = None,
    path: str = SOCKET_PATH,
) -> dict[str, Any]:
    """The helper's envelope for one block, as a document.

    Raises `HelperUnavailable` or `HelperSilent`; an answer that is not a
    document is `HelperSilent` too, since the helper ran.
    """

    request = {
        "schema_version": 1,
        "operation": "dynamic_block",
        "cluster": cluster,
        "request_id": request_id or str(uuid.uuid4()),
        "parameters": {"object": object_name, "addresses": list(addresses), "actor": actor},
    }
    raw = helper_socket.ask(request, path=path, timeout=TIMEOUT_SECONDS, what="the block service")
    try:
        document = json.loads(raw)
    except ValueError:
        document = None
    if not isinstance(document, dict):
        raise HelperSilent("The block service answered with something that is not a document.")
    return document
