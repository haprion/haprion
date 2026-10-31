"""The payloads of jobs both a page and the API queue, built in one place.

The worker and the root helpers must not be able to tell a job the API queued
from the one a page queued, so the payload is made by the same code. What
each caller adds is only what it was given: the page a form's text, the API a
JSON body.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from haprion.digits import is_digits
from haprion.server_state import MAX_SERVERS

#
# The longest server line kept, and what a page posts at most. One past the
# bound, so the helper's own limit refuses a request over it rather than this
# quietly sending part of one.
#
SERVER_LINE = 300


def chosen_servers(entries: Iterable[object]) -> list[str]:
    """The servers a request names, once each, in the order given, and one past `MAX_SERVERS`."""

    return list(dict.fromkeys(str(entry)[:SERVER_LINE] for entry in entries))[: MAX_SERVERS + 1]


def server_state(name: str, servers: list[str], state: str) -> dict[str, Any]:
    """Drain, maintenance or ready for `servers` of the object `name`."""

    return {"object": name, "servers": servers, "state": state}


def deploy(*, allow_vip_unknown: bool, expected_version: str | int | None) -> dict[str, Any]:
    """Deploy the published configuration, bound to the version the caller saw when it is given.

    Text that is not a number goes on as it came, so `operations.prepare`
    refuses it the way it refuses any other bad value.
    """

    payload: dict[str, Any] = {"allow_vip_unknown": allow_vip_unknown}
    if expected_version is not None and expected_version != "":
        payload["expected_version"] = (
            int(expected_version)
            if isinstance(expected_version, str) and is_digits(expected_version)
            else expected_version
        )
    return payload
