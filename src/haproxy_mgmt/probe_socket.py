"""How an unprivileged service asks for a probe without being able to sudo.

The probe helper needs root, for one reason: the probe identity's private key is
root-owned, because no application identity may hold a key that reaches a node.
The web service needs to ask for a probe. And the web service is built so that
it *cannot* gain privilege at all - `NoNewPrivileges=yes`, an empty capability
bounding set, `RestrictSUIDSGID=yes` - which means `sudo` there does not fail
because a rule is missing. It fails before it reads sudoers, and it will keep
failing however the rule is written.

So the privilege does not travel with the caller. It sits still, in a
socket-activated unit that runs as root and speaks the same stdin/stdout helper
protocol every other helper speaks. The web service opens a unix socket, writes
one request, and reads one answer. It gains nothing by connecting: what is on
the other end takes no arguments and does exactly one thing.

A refusal here has to say which of the two it was. "The probe did not run"
because nothing is listening is an installation that is missing a unit; "the
probe did not run" because this account may not connect is a permission on the
socket. A reader who is shown neither will look for the fault in the pool.
"""

from __future__ import annotations

from typing import Any

from haproxy_mgmt import helper_socket

#
# `/run` is tmpfs and cleared at boot on purpose - a socket must not outlive the
# process that answers on it. `/etc/tmpfiles.d/haprion.conf` recreates the
# directory, and systemd creates the socket inside it.
#
SOCKET_PATH = "/run/haprion/probe.sock"

#
# Generous, because the far side asks both nodes and each may sit through its
# own timeout for as many as twenty targets. It exists so a service that never
# answers becomes a sentence rather than a request that hangs.
#
TIMEOUT_SECONDS = 60.0


class ProbeUnavailable(Exception):
    """The probe could not be asked for, with a sentence saying why.

    Separate from a probe that ran and found nothing reachable. The two arrive
    at the same place in the interface and must never read the same.
    """


def build_request(
    cluster_id: str,
    request_id: str,
    targets: list[dict[str, Any]],
    *,
    source: str = "",
    timeout_ms: int = 2000,
) -> dict[str, Any]:
    """The one construction of a probe request.

    Both callers - the command a person runs and the service behind the form -
    build the same document here. Two constructions of one request are two
    things to keep in step, and each looks correct on its own until they differ.
    """

    return {
        "schema_version": 1,
        "operation": "probe",
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {"targets": targets, "source": source, "timeout_ms": timeout_ms},
    }


def ask(
    request: dict[str, Any],
    *,
    path: str = SOCKET_PATH,
    timeout: float = TIMEOUT_SECONDS,
) -> str:
    """Send one request to the probe service and return what it answered.

    The mechanics are `helper_socket`'s, shared with the receiver helper's
    client (B163); what is this module's is the socket, the bound and the
    name a refusal carries.
    """

    try:
        return helper_socket.ask(request, path=path, timeout=timeout, what="the probe service")
    except helper_socket.HelperUnavailable as error:
        raise ProbeUnavailable(str(error)) from error
