"""How the web asks the manager's resolver for a dns server's address (B253).

The generator takes a `dnsdist_config.Lookup`, and where it runs in the web -
the editor and the preview - this is the one it is given: each name goes over
`/run/haprion/resolve.sock` to `haprion-resolve-helper`, which looks it up
the way the publish will. The web itself reaches nothing beyond localhost.

A service that cannot be asked is said as such, not as a name that does not
resolve: the first is the installation, the second the object.
"""

from __future__ import annotations

import json
import uuid

from haprion import dnsdist_config, helper_socket

SOCKET_PATH = "/run/haprion/resolve.sock"
#
# A lookup waits on the resolver's own timeouts, a few seconds per attempt.
# Bounded so a resolver that never answers becomes a sentence.
#
TIMEOUT_SECONDS = 15.0
#
# What the helper takes at once (its MAX_NAMES); the rest of a very large
# object is not looked up rather than refused.
#
MAX_ASKED = 20


def lookup(host: str, *, path: str = SOCKET_PATH) -> str:
    """`dnsdist_config.lookup`'s answer for one name, asked of the resolve service."""

    request = {
        "schema_version": 1,
        "operation": "resolve",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": {"names": [host]},
    }
    try:
        raw = helper_socket.ask(
            request, path=path, timeout=TIMEOUT_SECONDS, what="the name lookup service"
        )
    except helper_socket.HelperUnavailable as error:
        raise dnsdist_config.Unresolved(f"{host} could not be looked up here: {error}") from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise dnsdist_config.Unresolved(
            f"{host} could not be looked up here: the lookup service answered with "
            "something that is not JSON"
        ) from error
    result = document.get("result") if isinstance(document, dict) else None
    names = result.get("names") if isinstance(result, dict) else None
    found = next(
        (
            entry
            for entry in (names if isinstance(names, list) else ())
            if isinstance(entry, dict) and entry.get("name") == host
        ),
        None,
    )
    if found is None:
        refusal = document.get("error") if isinstance(document, dict) else None
        message = refusal.get("message") if isinstance(refusal, dict) else None
        raise dnsdist_config.Unresolved(
            f"{host} could not be looked up here: {message or 'the lookup service did not say'}"
        )
    address = found.get("address")
    if isinstance(address, str) and dnsdist_config.is_address(address):
        return address
    raise dnsdist_config.Unresolved(str(found.get("problem") or f"{host} did not resolve"))


def unresolved(hosts: list[str], *, path: str = SOCKET_PATH) -> list[str] | None:
    """The pool members' names the manager cannot resolve (finding 72), asked in one request.

    None when the service could not be asked: that is the installation, and
    the editor then says nothing about the names rather than something wrong.
    """

    if not hosts:
        return []
    request = {
        "schema_version": 1,
        "operation": "resolve",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": {"names": hosts[:MAX_ASKED], "any": True},
    }
    try:
        raw = helper_socket.ask(
            request, path=path, timeout=TIMEOUT_SECONDS, what="the name lookup service"
        )
        document = json.loads(raw)
    except (helper_socket.HelperUnavailable, ValueError):
        return None
    result = document.get("result") if isinstance(document, dict) else None
    names = result.get("names") if isinstance(result, dict) else None
    if not isinstance(names, list):
        return None
    return [
        str(entry["name"])
        for entry in names
        if isinstance(entry, dict)
        and isinstance(entry.get("name"), str)
        and entry.get("address") is None
    ]
