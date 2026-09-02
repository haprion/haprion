"""The stable name every generated object carries.

HAProxy 3.4 can keep statistics counters in shared memory, and after a reload
the new process re-attaches counters to objects by GUID and type. An object
without a GUID does not take part: its counters start from zero. Since every
deploy is a reload, that would make an ordinary configuration change look like
a traffic outage in the interface, and make before-and-after impossible to
compare at exactly the moment somebody wants to.

So every frontend, listener, backend and server the generator writes gets a
GUID, derived from what the object *is* rather than from where it happened to
land in a file. The same object keeps the same GUID across publications, and
reordering a list of servers moves no counters.

What HAProxy accepts, read from the 3.4.4 documentation on this machine rather
than from memory: at most 127 characters, alphanumerics plus `.`, `:`, `-` and
`_`, case-sensitive, and unique across every object type in the whole
configuration. Listeners are the exception in form - a bind line takes
`guid-prefix` and HAProxy appends `-<index>` per listener itself - so a prefix
has to leave room for that suffix.

The derivation is versioned on purpose. Changing it is cheap today and
expensive once `shm-stats-file` is enabled, because every object whose GUID
changes has its counters reset once. A version constant makes that an explicit
decision with a name, instead of a refactor nobody noticed.
"""

from __future__ import annotations

import hashlib
import re

from haproxy_mgmt.proxy_model import Proxy, Server

#
# The character set HAProxy documents for a GUID. Ours are a strict subset -
# lowercase names and hex digests - but the check exists so that a future
# widening of the model cannot quietly generate a name HAProxy refuses at
# startup, which would be a failed validation rather than a readable error.
#
GUID = re.compile(r"^[A-Za-z0-9.:_-]{1,127}$")

MAX_GUID = 127

#
# How many listeners one bind line could plausibly hold, reserved out of the
# prefix budget. HAProxy appends `-<index>` to a `guid-prefix`, and a prefix
# that only just fits would produce a listener GUID that does not.
#
LISTENER_SUFFIX_BUDGET = len("-999")

#
# The identity of the derivation itself, mixed into every digest. Bump it only
# as a decision somebody wrote down: every GUID changes, every golden file is
# rewritten, and with shared-memory stats enabled every counter resets once.
#
SCHEME = "haproxy-mgmt/guid/v1"

#
# Kept in the visible part of the GUID as well as in the digest. In the digest
# it is what keeps a backend and its frontend apart even when nothing else
# distinguishes them; in the visible part it is what lets a human reading
# `show stat` see what kind of object a counter belongs to.
#
FRONTEND = "fe"
LISTENER = "li"
BACKEND = "be"
#
# The identity space a redirect route's derived name is hashed in. Its own,
# so a name here can never collide with a backend GUID.
#
REDIRECT = "redirect"
SERVER = "srv"

#
# 64 bits of digest. The whole configuration is a few hundred objects, so this
# is far past the point where a collision is a real risk, and it keeps the GUID
# short enough to read in a terminal next to the object's own name.
#
DIGEST_LENGTH = 16


def _digest(kind: str, *identity: str) -> str:
    """The stable part, hashed from the object's identity.

    The parts are joined with a newline, which none of them can contain: proxy
    and backend names are a restricted character set, and a host or port that
    reached this point has been through the model. Without a separator that
    cannot appear inside a part, two different objects could produce the same
    joined string.
    """

    material = "\n".join((SCHEME, kind, *identity)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:DIGEST_LENGTH]


def _guid(kind: str, proxy: str, *identity: str) -> str:
    return f"{kind}:{proxy}.{_digest(kind, proxy, *identity)}"


def frontend_guid(proxy: str) -> str:
    """The frontend that serves one proxy object."""

    return _guid(FRONTEND, proxy)


def listener_guid_prefix(proxy: str) -> str:
    """The bind line's prefix, which HAProxy turns into one GUID per listener.

    Returned as a prefix rather than as a GUID because that is the keyword:
    `guid-prefix` on the bind line, and HAProxy appends `-0`, `-1` and so on.
    The generated value therefore has to stay short enough that the suffix
    still fits, which `check_guid` verifies for the widest index this reserves
    room for.
    """

    return _guid(LISTENER, proxy)


def redirect_name(path: str, match: str, location: str) -> str:
    """A stable name for the backend a redirect route becomes.

    Derived from what the route is and does, not from where it sits in the
    list, so adding a route above one moves neither its name nor its GUID. Its
    counters therefore survive an edit that has nothing to do with it - the
    same reason `server_guid` is taken from an address instead of a position.

    Short: the name is joined into a backend name that already carries a prefix
    and the object's name, and HAProxy bounds the whole thing.
    """

    return _digest(REDIRECT, path, match, location)[:8]


def backend_guid(proxy: str, backend: str) -> str:
    return _guid(BACKEND, proxy, backend)


def server_guid(proxy: str, backend: str, server: Server) -> str:
    """One pool member, identified by where it points.

    Address and port rather than position in the list. Reordering the servers
    in the object then moves no counters, and changing a server's address
    correctly starts a new set: it is a different machine, and carrying the old
    machine's traffic history onto it would be a lie in a graph.
    """

    return _guid(SERVER, proxy, backend, server.host, str(server.port))


def guid_is_usable(value: str) -> bool:
    """Whether HAProxy would accept this as a GUID at all."""

    return bool(GUID.match(value))


def guid_prefix_is_usable(value: str) -> bool:
    """Whether a bind line's prefix still fits once HAProxy adds its suffix."""

    return guid_is_usable(value) and len(value) + LISTENER_SUFFIX_BUDGET <= MAX_GUID


def guids_for(proxy: Proxy) -> dict[str, str]:
    """Every GUID one proxy object contributes, keyed by what it names.

    The key is the object's place in the model - `frontend`, `listen`,
    `backend:web`, `server:web:198.51.100.10:8080` - and exists so that the
    generator and its tests can talk about "the GUID of this thing" without
    rebuilding the identity by hand in two places. The mapping is also what
    makes uniqueness testable: a duplicate GUID inside one object would collapse
    to fewer values than there are keys.
    """

    guids = {
        "frontend": frontend_guid(proxy.name),
        "listen": listener_guid_prefix(proxy.name),
    }
    for name, backend in proxy.backends.items():
        guids[f"backend:{name}"] = backend_guid(proxy.name, name)
        for server in backend.servers:
            guids[f"server:{name}:{server.host}:{server.port}"] = server_guid(
                proxy.name, name, server
            )
    return guids
