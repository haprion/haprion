"""What a handwritten configuration has already claimed.

`manual/reservations.yaml` is written by a person, in the layer the application
may never touch, and it says which hostnames and which ports the handwritten
half of the configuration is already using. The generator refuses an object
that claims one.

It exists because the failure it prevents is silent in the worst possible way.
Two frontends binding one port both come up - HAProxy binds with SO_REUSEPORT,
measured on 3.4.4 on this machine - and the kernel then hands each new
connection to one of them at random, so the publish reports success and the
node answers correctly for about half the traffic. A crash would be noticed.
A hostname claimed twice is quieter still: whichever frontend HAProxy reaches
first answers, and which one that is depends on filenames.

The file is a promise a person makes, not a fact the system derives. Deriving
it would mean parsing handwritten HAProxy configuration, which is the thing
this project has decided not to do - `manual/` is read, never interpreted.

A port is claimed either on one address or on all of them, and the file says
which in the same notation HAProxy's own `bind` line uses: `443` and `:443`
reserve the port on every address the cluster has, `192.0.2.10:443` reserves
it on that one. The distinction is not decoration. A cluster with several VIPs
is exactly the arrangement this file exists for - something complex written by
hand *beside* the generated objects - and a reservation that could only be
made cluster-wide would block every managed object on every other address too,
which is a promise nobody can afford to make.

The bare form is the wider one on purpose. `bind :8404` binds every address the
host carries, including whichever VIP a node happens to hold, so a handwritten
line without an address really has taken the port everywhere. Reading a bare
number as cluster-wide is therefore what that line means, not a convenience.

A promise also has to be current. What a person wrote down describes the
handwritten fragments as they read them, and nothing about the file says so:
an old reservation and a complete one look alike, and a new listener can be
added to a fragment without the promise moving. `reviewed:` closes that gap by
naming each handwritten fragment together with the SHA-256 of the bytes that
were read. When a fragment changes, its digest stops matching and the operator
is asked to look again.

It proves currency and that somebody looked, not that the promise is
semantically complete - that would need the parser this project has decided
not to write. Listing a fragment whose reservations are empty is the explicit
way to say "I read this and it claims nothing", which is why the confirmation
is per file and not a single digest over all of them: one digest could say
that something changed, but never which file to go and read.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml

from haproxy_mgmt import safe_yaml
from haproxy_mgmt.config import ConfigError, _address, _mapping, _only_keys
from haproxy_mgmt.proxy_model import HOSTNAME

#
# Where the promise lives, named once. Two modules read this file, and a
# path spelled out in each of them is the kind of duplication that stays
# correct until one of them moves.
#
RESERVATIONS_PATH = "manual/reservations.yaml"

#
# Bounded like every other document that reaches a parser here.
#
MAX_RESERVATIONS_BYTES = 64 * 1024

#
# Where a handwritten listener can be defined. Both bands, not only `manual/`:
# the collision that made this necessary came from `core/conf.d/0010-stats.cfg`,
# and a rule that watched one of the two handwritten layers would have missed
# the incident it was written for.
#
# `haproxy.cfg` and `maps/` are deliberately outside it. `core/haproxy.cfg`
# exists in every cluster, so counting it would make the observation fire on
# every publish - and an observation that always fires is one nobody reads.
#
# It is also the answer to which files a confirmation covers. A digest over an
# arbitrary selection would move the problem rather than solve it, so the set
# is named once, here, and both the promise and the check read it from here.
#
FRAGMENT_DIRECTORIES = ("core/conf.d/", "manual/conf.d/")

#
# Lowercase hex, the form `hashlib` produces and `sha256sum` prints.
#
DIGEST = re.compile(r"[0-9a-f]{64}")


def fragment_digest(content: bytes) -> str:
    """What a confirmation records about one handwritten fragment.

    Over the exact bytes the version carries, so the answer is about what was
    published rather than about a work tree somebody has since edited. Not a
    security boundary - the fragment and the promise sit in the same repository
    and anyone who can change one can change the other - so a plain content
    digest is what the question needs: did this file move since a person read
    it.
    """

    return hashlib.sha256(content).hexdigest()


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
    """Ports claimed on every address, from an entry written without one."""

    tcp_listeners: frozenset[tuple[str, int]] = frozenset()
    """Ports claimed on one address, as `(address, port)`."""

    reviewed: frozenset[tuple[str, str]] = frozenset()
    """Fragments a person has confirmed reading, as `(path, sha256)`.

    A pair set rather than a mapping so the whole value stays hashable like
    every other field here. The same path cannot appear twice - YAML would
    not allow it and `_reviewed` refuses it anyway - so a lookup is exact.
    """

    def claims(self, address: str, port: int) -> bool:
        """Whether the handwritten layer has this address and port."""

        return port in self.tcp_ports or (address, port) in self.tcp_listeners

    def reviewed_digest(self, path: str) -> str | None:
        """What was confirmed about this fragment, if anything was."""

        for reviewed_path, digest in self.reviewed:
            if reviewed_path == path:
                return digest
        return None


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
        loaded = safe_yaml.load(document.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ReservationError(f"{location} is not valid YAML: {exc}") from exc
    if loaded is None:
        return Reservations()

    data = _mapping(loaded, location)
    _only_keys(data, {"hostnames", "tcp_ports", "reviewed"}, location)
    ports, listeners = _claims(data.get("tcp_ports"), f"{location}.tcp_ports")
    return Reservations(
        hostnames=frozenset(_hostnames(data.get("hostnames"), f"{location}.hostnames")),
        tcp_ports=frozenset(ports),
        tcp_listeners=frozenset(listeners),
        reviewed=frozenset(_reviewed(data.get("reviewed"), f"{location}.reviewed")),
    )


def _reviewed(value: Any, location: str) -> list[tuple[str, str]]:
    """`path: sha256` for each handwritten fragment somebody has read.

    Paths are refused outside `FRAGMENT_DIRECTORIES`, because a confirmation
    about a file the check never looks at is a line that silences nothing while
    reading as though it did. A digest that is not a SHA-256 is refused for the
    same reason: it can never match, so it would be a permanent complaint about
    a file that may be perfectly fine.
    """

    if value is None:
        return []
    reviewed = []
    for path, digest in _mapping(value, location).items():
        if not isinstance(path, str) or not path.startswith(FRAGMENT_DIRECTORIES):
            listed = " or ".join(FRAGMENT_DIRECTORIES)
            raise ReservationError(
                f"{location} names {path!r}, which is not a fragment under {listed}"
            )
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest.strip().lower()):
            raise ReservationError(f"{location}.{path} must be the SHA-256 of that file, in hex")
        reviewed.append((path, digest.strip().lower()))
    return reviewed


def _claims(value: Any, location: str) -> tuple[list[int], list[tuple[str, int]]]:
    """Split the list into what is claimed everywhere and what on one address.

    One key rather than two, because a person writing the file is answering a
    single question - which listeners are already taken - and splitting that
    across two lists would let the two disagree about the same port.
    """

    if value is None:
        return [], []
    if not isinstance(value, list):
        raise ReservationError(f"{location} must be a list of ports or address:port entries")

    ports: list[int] = []
    listeners: list[tuple[str, int]] = []
    for entry in value:
        if isinstance(entry, bool):
            #
            # Before the int check: bool is an int in Python, and `yes` in YAML
            # is a bool, so `- yes` would otherwise reserve port 1.
            #
            raise ReservationError(f"{location} contains something that is not a port")
        if isinstance(entry, int):
            ports.append(_port(entry, location))
            continue
        if not isinstance(entry, str):
            raise ReservationError(f"{location} contains something that is not a port")
        address, port = _split(entry.strip(), location)
        if address is None:
            ports.append(port)
        else:
            listeners.append((address, port))
    return ports, listeners


def _split(entry: str, location: str) -> tuple[str | None, int]:
    """`443`, `:443` and `192.0.2.10:443`, in HAProxy's own bind notation.

    An IPv6 address has to be bracketed, exactly as a bind line requires. The
    brackets are what makes `::1:443` readable at all - without them the last
    colon is not distinguishable from part of the address, and guessing which
    it is would silently reserve the wrong thing.
    """

    if entry.startswith("["):
        closing = entry.find("]")
        if closing == -1 or not entry[closing + 1 :].startswith(":"):
            raise ReservationError(
                f"{location} contains {entry!r}, which is not an [address]:port entry"
            )
        return _address(entry[1:closing], location), _text_port(entry[closing + 2 :], location)

    head, separator, tail = entry.rpartition(":")
    if not separator:
        return None, _text_port(entry, location)
    if not head:
        #
        # `:443` is a bind line without an address, which takes the port on
        # every address the host has. The same reading as a bare number.
        #
        return None, _text_port(tail, location)
    if ":" in head:
        raise ReservationError(
            f"{location} contains {entry!r}; an IPv6 address must be written as [address]:port"
        )
    return _address(head, location), _text_port(tail, location)


def _text_port(value: str, location: str) -> int:
    if not value.isdigit():
        raise ReservationError(f"{location} contains {value!r}, which is not a port number")
    return _port(int(value), location)


def _port(value: int, location: str) -> int:
    if not 1 <= value <= 65535:
        raise ReservationError(f"{location} contains {value}, which is not a port number")
    return value


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


@dataclass(frozen=True, slots=True)
class FragmentReview:
    """What the promise fails to say about the handwritten fragments.

    Three questions rather than one flag, because the operator does something
    different about each. Empty in all three is the quiet, correct state.
    """

    unreviewed: tuple[str, ...] = ()
    """Fragments present that nobody has confirmed reading."""

    changed: tuple[str, ...] = ()
    """Fragments confirmed once and edited since."""

    vanished: tuple[str, ...] = ()
    """Confirmations about fragments that are no longer in the version.

    Worth saying, though it claims nothing dangerous on its own: it means the
    reservations file still describes a file that is gone, and whatever that
    file reserved may have been dropped or moved without the promise following.
    """

    def __bool__(self) -> bool:
        return bool(self.unreviewed or self.changed or self.vanished)


#
# The quiet answer, built once and shared. Frozen, so sharing it is safe - the
# same reason `NOTHING_RESERVED` is a module-level value rather than a call in
# a default argument.
#
NOTHING_TO_REVIEW = FragmentReview()


def review_fragments(files: Mapping[str, bytes], reservations: Reservations) -> FragmentReview:
    """Whether the promise is current with the fragments it describes.

    Not a parser, and it must not become one: `manual/` is read and never
    interpreted, so this asks only which fragments exist and whether the person
    who wrote the promise had read these exact bytes. Two frontends on one
    address bind it under SO_REUSEPORT and split the traffic at random, and the
    reservation file is the only thing standing between that and a publish that
    reports success.

    What replaced the earlier rule is why B86 was not enough. That one went
    quiet the moment anything at all was reserved, so a promise written once and
    never revisited looked exactly like a complete one, and a listener added to
    a fragment afterwards was invisible. Comparing digests moves the question
    from "has anybody said anything" to "did they say it about this version of
    this file", which is the part a person can actually answer.

    It still cannot say the promise is *complete*. Only reading the fragments
    could, and reading them is the thing this project has decided not to do.
    """

    present = {path: data for path, data in files.items() if path.startswith(FRAGMENT_DIRECTORIES)}
    unreviewed = []
    changed = []
    for path, data in present.items():
        confirmed = reservations.reviewed_digest(path)
        if confirmed is None:
            unreviewed.append(path)
        elif confirmed != fragment_digest(data):
            changed.append(path)
    vanished = [path for path, _ in reservations.reviewed if path not in present]
    return FragmentReview(
        unreviewed=tuple(sorted(unreviewed)),
        changed=tuple(sorted(changed)),
        vanished=tuple(sorted(vanished)),
    )
