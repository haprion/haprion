"""One request to a root helper that answers on a unix socket, and one answer back.

Two helpers are reached this way rather than through sudo, for two different
reasons that end in the same place. The web service asks for a probe and
*cannot* gain privilege at all (`probe_socket`). The worker asks for a receiver
to be registered, and can - but the helper it would start inherits the
worker's mount namespace, and `useradd` needs `/etc` writable, which no
`ReadWritePaths` line should give a job runner (B163). So in both cases the
privilege sits still, in a socket-activated unit that runs as root and speaks
the same stdin/stdout helper protocol every other helper speaks, and the
request travels to it.

A refusal here has to say which of three it was. "It did not run" because
nothing is listening is an installation that is missing a unit; because this
account may not connect, a permission on the socket; because the far side went
quiet, a service that hung. A reader shown none of them will look for the
fault in the request.
"""

from __future__ import annotations

import json
import socket
from typing import Any


class HelperUnavailable(Exception):
    """The helper could not be asked, with a sentence saying why.

    Separate from a helper that ran and refused: that answer arrives as an
    envelope, and the two must never read the same.
    """


class HelperSilent(HelperUnavailable):
    """The helper was asked and then went quiet, or dropped the connection.

    Not "it did not run": the request reached a root service that carries on
    without this client, so the operation may be half done or finished. A
    caller must not write that as a failure - the worker's word for an answer
    that never came is `unknown` (review 2026-09-25, finding 1).
    """


class HelperBusy(HelperSilent):
    """The connection was dropped at once, before any answer: another holds the socket.

    A socket unit with `MaxConnections` resets a connection past its limit
    straight away (measured 2026-09-26, systemd 259). Still a HelperSilent, so
    a caller that cannot tell this from a helper that died keeps treating it
    as one; only a read-only question may take it to mean "ask again later".
    """


def ask(
    request: dict[str, Any],
    *,
    path: str,
    timeout: float,
    what: str,
) -> str:
    """Send one request to the service on `path` and return what it answered.

    The write side is shut down after the request because the helper reads its
    stdin to end of file - the same protocol it follows when a person pipes a
    request into it. Without the half-close both sides wait for the other.
    `what` names the service in the sentences a refusal carries, in lower
    case; it is capitalised where a sentence starts with it.
    """

    lead = what[:1].upper() + what[1:]
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        try:
            connection.connect(path)
        except FileNotFoundError as error:
            raise HelperUnavailable(
                f"{lead} is not installed here. It answers on a socket this service could not find."
            ) from error
        except ConnectionRefusedError as error:
            raise HelperUnavailable(f"{lead} is not running here.") from error
        except PermissionError as error:
            raise HelperUnavailable(f"This service is not allowed to reach {what}.") from error
        except OSError as error:
            raise HelperUnavailable(f"{lead} could not be reached: {error}.") from error

        chunks: list[bytes] = []
        try:
            connection.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8"))
            connection.shutdown(socket.SHUT_WR)
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except TimeoutError as error:
            raise HelperSilent(f"{lead} did not answer in time.") from error
        except (ConnectionResetError, BrokenPipeError) as error:
            if chunks:
                raise HelperSilent(f"{lead} stopped answering: {error}.") from error
            raise HelperBusy(f"{lead} dropped the connection before answering.") from error
        except OSError as error:
            raise HelperSilent(f"{lead} stopped answering: {error}.") from error
    finally:
        connection.close()

    return b"".join(chunks).decode("utf-8", "replace")
