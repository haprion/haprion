"""What a handwritten configuration has already claimed.

`manual/reservations.yaml` is written by a person, in the layer the application
may never touch, and it says which hostnames and which ports the handwritten
half of the configuration is already using. The generator refuses an object
that claims one.

It exists because the failure it prevents is silent in the worst possible way.
Two frontends binding one port pass `haproxy -c` and then kill the process at
startup - measured on 3.4.4 on this machine, and written down as B47 - so the
publish reports success and the node stops serving. A hostname claimed twice is
quieter still: whichever frontend HAProxy reaches first answers, and which one
that is depends on filenames.

The file is a promise a person makes, not a fact the system derives. Deriving
it would mean parsing handwritten HAProxy configuration, which is the thing
this project has decided not to do - `manual/` is read, never interpreted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml

from haproxy_mgmt.config import ConfigError, _mapping, _only_keys
from haproxy_mgmt.proxy_model import HOSTNAME

#
# Bounded like every other document that reaches a parser here.
#
MAX_RESERVATIONS_BYTES = 64 * 1024


class ReservationError(ConfigError):
    """The reservations file cannot be understood."""


@dataclass(frozen=True, slots=True)
class Reservations:
    """Names and ports the generated layer may not use.

    Empty is the normal state and the one both clusters are in today: the file
    exists, holds `{}`, and reserves nothing.
    """

    hostnames: frozenset[str] = frozenset()
    tcp_ports: frozenset[int] = frozenset()


#
# The state both clusters are in today, and the one a caller that has nothing
# to say passes. A module-level value rather than a call in a default argument,
# which is built once and shared - it is frozen, so sharing it is safe.
#
NOTHING_RESERVED = Reservations()


def load_reservations(document: bytes, location: str = "manual/reservations.yaml") -> Reservations:
    """Read the file, or say exactly what is wrong with it.

    The shared validation helpers raise `ConfigError`, and a module that
    promises its own error type has to keep that promise - the same wrapping
    `load_proxy` does, for the same reason: a caller should need to know one
    name.
    """

    try:
        return _load(document, location)
    except ReservationError:
        raise
    except ConfigError as exc:
        raise ReservationError(str(exc)) from exc


def _load(document: bytes, location: str) -> Reservations:
    if len(document) > MAX_RESERVATIONS_BYTES:
        raise ReservationError(f"{location} exceeds the size limit")
    try:
        loaded = yaml.safe_load(document.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ReservationError(f"{location} is not valid YAML: {exc}") from exc
    if loaded is None:
        return Reservations()

    data = _mapping(loaded, location)
    _only_keys(data, {"hostnames", "tcp_ports"}, location)
    return Reservations(
        hostnames=frozenset(_hostnames(data.get("hostnames"), f"{location}.hostnames")),
        tcp_ports=frozenset(_ports(data.get("tcp_ports"), f"{location}.tcp_ports")),
    )


def _hostnames(value: Any, location: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReservationError(f"{location} must be a list of hostnames")
    names = []
    for entry in value:
        #
        # Lowercased on the way in, because a Host header is compared that way
        # and a reservation written in mixed case would otherwise reserve
        # nothing while looking like it reserved something.
        #
        if not isinstance(entry, str) or not HOSTNAME.match(entry.lower()):
            raise ReservationError(f"{location} contains something that is not a hostname")
        names.append(entry.lower())
    return names


def _ports(value: Any, location: str) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReservationError(f"{location} must be a list of port numbers")
    ports = []
    for entry in value:
        if not isinstance(entry, int) or isinstance(entry, bool) or not 1 <= entry <= 65535:
            raise ReservationError(f"{location} contains something that is not a port number")
        ports.append(entry)
    return ports
