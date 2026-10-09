"""What a proxy object is, before it is HAProxy configuration.

This is the generator's input: one object per file, written by the application
and read here. It deliberately speaks the vocabulary of somebody who runs
proxies - site, hostnames, routes, backend pools, health checks - and not the
vocabulary of HAProxy. Nothing in this module mentions a frontend, an acl or a
`use_backend`, because translating between the two is the generator's job and
the whole reason the application exists.

Read from bytes rather than from a path, and that is not an accident of
plumbing. The generator's input is the committed tree, the same bytes
`git archive` produces, exactly as `release_layout` takes its tree. A generator
that could fall back to a working tree would let an uncommitted change appear in
generated configuration, which is the same mistake `inventory` refuses to make.

Everything is refused rather than defaulted where a default would be a guess. An
unknown field is an error: a key nobody expected is either a typo that silently
does nothing, or a feature this version does not have and the writer thinks it
does. Both are worse than being told.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any

import yaml

from haproxy_mgmt import advanced as advanced_config
from haproxy_mgmt import geo, safe_yaml
from haproxy_mgmt.config import (
    ABUSE_WINDOW,
    DEFAULT_ABUSE_WINDOW,
    TLS_POLICY_NAMES,
    ConfigError,
    _mapping,
    _only_keys,
    _required_string,
)
from haproxy_mgmt.tls_policy import DEFAULT_BACKEND_POLICY

#
# Bounded for the same reason every other document this system reads is: a file
# that reaches the parser is a file somebody could have made enormous.
#
MAX_MODEL_BYTES = 256 * 1024

#
# The object's identity. It is the filename, part of every generated name, and
# the seed of every GUID, so it has to be stable, lowercase and free of anything
# that means something to a path or to HAProxy.
#
# Underscore is in, since 2026-09-03 (B72). It is what people already call these
# things, and it means nothing to a path or to HAProxy - proved against a real
# 3.4 rather than read out of the documentation. The characters kept out are the
# ones that do mean something: a dot collides with the numbering scheme and with
# file extensions, a slash is a path, whitespace and `#` end a token in HAProxy's
# own parser, and a capital makes two names that differ only in case land on one
# file on a case-insensitive filesystem.
#
# Widening is safe in the one direction that matters: every name that was valid
# before is valid still, so nothing that exists has to be renamed or migrated.
#
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
#
# The start of every name the generator gives a section of its own (`generate.
# PREFIX`, held equal by a test). A pool is named by itself in HAProxy since
# B250, so a pool called `mgd-metrics` would meet the exporter's frontend.
#
GENERATED_PREFIX = "mgd-"
#
# The same rule as a sentence, so a refusal can say what would be accepted.
# A message that only says a name is unusable leaves the person to guess which
# character was the problem - and the two most common ones, a dot and an
# uppercase letter, look entirely innocent.
#
NAME_RULE = (
    "lowercase letters, digits, hyphens and underscores, "
    "starting with a letter, at most 40 characters"
)


def name_refusal(name: str) -> str:
    """Why this particular name was refused, in the person's own characters.

    "not a usable object name" leaves somebody to work out which character was
    the problem, and the two that catch people out - a dot and a capital - look
    entirely innocent in a hostname they copied the name from. Named here so
    every place that refuses a name says the same thing.
    """

    if not name:
        return "it is empty"

    offending = sorted({character for character in name if not ALLOWED.match(character)})
    #
    # Capitals are named as a class rather than listed. A name copied from a
    # hostname can carry several, and "'F', 'P', 'T' are not allowed" reads as
    # three separate problems instead of one rule about case.
    #
    written = [character for character in offending if not character.isupper()]
    reasons = []
    if written:
        listed = ", ".join(f"'{character}'" for character in written)
        reasons.append(
            f"{listed} is not allowed" if len(written) == 1 else f"{listed} are not allowed"
        )
    if len(written) != len(offending):
        reasons.append("capital letters are not allowed")
    if reasons:
        return " and ".join(reasons)

    if not name[0].isalpha():
        return "it must start with a letter"
    if len(name) > 40:
        return "it is longer than 40 characters"
    return NAME_RULE


ALLOWED = re.compile(r"[a-z0-9_-]")

#
# A hostname as it appears in a Host header. Not a full RFC validation - that
# would reject things HAProxy happily serves - but enough that a value which is
# obviously something else, such as a URL or an address with a port, is caught
# where the writer can still fix it.
#
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)

#
# A path prefix as a route matches on. Absolute, no query, no wildcards: the
# matching rules are about segments, and a pattern language here would make the
# frozen semantics ambiguous before the first golden file exists.
#
ROUTE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")

#
# `dns` is served by dnsdist rather than HAProxy (Fas 19, B249): community
# HAProxy 3.4 listens on UDP only in `log-forward` sections, measured in its
# own manual on this machine. The object is otherwise a tcp object's shape - a
# port and one pool - and the generator writes it into a layer of its own.
#
# `syslog` is served by the kernel's IPVS through keepalived (Fas 19b, B256):
# UDP only, forwarded with the sender's own address (NAT, one packet at a
# time), so the receivers see who sent each message. A port and one pool,
# like dns, in a layer of its own - `managed/keepalived/ipvs.conf`.
#
PROTOCOLS = ("http", "https", "tcp", "dns", "syslog")
#
# The objects HAProxy does not serve, and which therefore get no HAProxy
# configuration of their own.
#
OUTSIDE_HAPROXY = ("dns", "syslog")
#
# The objects that name their own port rather than sharing the cluster's.
#
OWN_PORT = ("tcp", "dns", "syslog")
#
# The objects whose traffic leaves with the sender's address rather than one of
# the cluster's (B256): no source address, every node checks from its own, and
# the node holding the VIP - the one the traffic passes - answers for them
# wherever a page shows one node's view (review 26-10-08, F4).
#
SENDERS_ADDRESS = ("syslog",)
#
# The balancing algorithms an object may choose, read from HAProxy 3.4.4's own
# documentation on this machine. HAProxy has more - `hash`, `hdr()`,
# `url_param()`, `rdp-cookie` - and they are left out on purpose: each takes an
# expression as an argument, and a field where somebody writes an expression is
# the raw HAProxy syntax this project has decided not to have.
#
#   roundrobin  in turn, by weight. The fair default for HTTP.
#   static-rr   the same without on-the-fly weight changes; no server limit.
#   leastconn   fewest connections first. For long-lived sessions, not short
#               HTTP ones - HAProxy's own documentation says so.
#   first       fill one server before using the next, so idle ones can be
#               powered off. Only meaningful together with a connection limit.
#   source      hash the client address, so one client keeps one server. The
#               stickiness you get without asking the browser to hold a cookie.
#   uri         hash the path, so one URL keeps one server. What a cache in the
#               backend wants.
#   random      pick at random. Behaves well when several proxies balance over
#               the same pool and would otherwise agree on the same "next" one.
#
#   hdr         hash one request header's value, named by `balance_key`. What
#               a multi-tenant backend wants when the tenant is in a header.
#   url_param   hash one query parameter's value, named by `balance_key`. The
#               usual way to keep one logged-in user on one server without
#               involving a cookie.
#
# `hash <expression>` is the one HAProxy offers that is left out, and it is
# left out for a reason rather than an oversight: its argument is an arbitrary
# HAProxy expression, which is the raw configuration syntax this project has
# decided not to have. `rdp-cookie` waits for TCP support, since it is
# meaningless in an HTTP backend, and `sticky` is for log backends.
#
BALANCE = (
    "roundrobin",
    "static-rr",
    "leastconn",
    "first",
    "source",
    "uri",
    "random",
    "hdr",
    "url_param",
)

#
# A server's weight (B263), HAProxy's range less nought: 0 takes the server out
# of balancing while it still takes persistent connections, which is a drain,
# and a drain is something done to a server for a while rather than a setting
# that outlives the reason for it. HAProxy's default is 1.
#
MIN_WEIGHT = 1
MAX_WEIGHT = 256

#
# The algorithms that hash something the request carries by name, and therefore
# need to be told which name.
#
BALANCE_NEEDS_KEY = ("hdr", "url_param")

#
# The algorithms that hash something only an HTTP request carries. HAProxy does
# not refuse these in tcp mode - `hdr` and `uri` fall back to roundrobin with a
# warning, and `url_param` is the only one it rejects outright. Measured on
# 3.4.4 on this machine.
#
BALANCE_HTTP_ONLY = ("hdr", "uri", "url_param")

#
# How a dns pool chooses a server: dnsdist's own policies, read from the 2.1
# source (`getBuiltInPolicies`). Four of its seven; `wrandom` and `whashed`
# need a weight per server and `orderedWrandUntag` tags, neither of which an
# object has. `roundrobin` is the one name HAProxy shares.
#
#   roundrobin        in turn. Even, and the default.
#   leastOutstanding  fewest unanswered queries, then the fastest. dnsdist's
#                     own default; measured to put 5955 of 6000 queries on the
#                     quicker of two servers (26-10-06).
#   firstAvailable    the first server in the list that is up: active/passive,
#                     which is what `backup` means elsewhere.
#   chashed           one name keeps one server, and few names move when a
#                     server comes or goes - what a caching resolver wants.
#
DNS_ONLY_BALANCE = ("leastOutstanding", "firstAvailable", "chashed")
DNS_BALANCE = ("roundrobin", *DNS_ONLY_BALANCE)

#
# How a syslog pool chooses a receiver: three of IPVS's schedulers, under the
# names the other protocols already use (B256). Each message is scheduled on
# its own (`ops`), so there is no connection to count, and the schedulers
# that count them (`lc`, `wlc`, `sed`, `nq`, `lblc`, `lblcr`, `twos`, `ovf`)
# would decide nothing.
#
#   roundrobin      `rr`: message by message, in turn. Measured in the lab
#                   (26-10-07): 3514/3513 of 7027 from one sender.
#   source          `mh`, Maglev hashing of the sender's address: one sender
#                   keeps one receiver, and when a receiver goes only its own
#                   senders move - which `sh` does not promise.
#   firstAvailable  `fo`: the first receiver in the list that is up, as a
#                   dns pool's of the same name. Active/passive.
#
SYSLOG_BALANCE = ("roundrobin", "source", "firstAvailable")

#
# A query parameter name. Deliberately narrower than what a URL may carry: this
# value is written into a configuration line, and a name needing escaping there
# is a name worth refusing where somebody can still change it.
#
PARAMETER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

#
# A cookie name, as a cookie name is allowed to look. Narrow for the same
# reason everything else here is: it is written into a configuration line and
# read back by a browser, and the intersection of what both accept is smaller
# than either.
#
COOKIE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

#
# An HTTP field name, as RFC 9110 defines a token.
#
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

#
# What a header value may never hold. CR, LF and NUL are how a value stops
# being a value and becomes a second header, and refusing them is the whole of
# response-splitting defence at this layer. The single quote is here because
# the generator writes values in single quotes: HAProxy expands `$NAME` inside
# double quotes but not inside single ones, measured on 3.4.4 on this machine,
# so single quoting is what lets a value contain a dollar sign at all - and a
# single quote in the value would end the string early.
#
FORBIDDEN_IN_VALUE = ("\r", "\n", "\0", "'")

#
# The headers the cluster decides and an object may not touch. They are written
# by the frontend from what the connection actually was; an object that set one
# would be overwriting a measured fact with a guess.
#
RESERVED_HEADERS = ("x-forwarded-for", "x-forwarded-proto", "x-forwarded-host")

MAX_HEADER_VALUE = 200

#
# What a maintenance page may say. The value is written into a double-quoted
# configuration line, so a quote or a backslash would end that line somewhere
# other than where it looks like it ends. `$` is allowed and escaped where the
# line is written: HAProxy 3.4.4 on this machine expands `$HOME` inside double
# quotes, but reads `\$` as a literal dollar, so a price or a shell name in a
# sentence costs nothing. The single quote is the field that stays: a message
# is a sentence for visitors, and "we'll be back" is how one is written.
#
MESSAGE = re.compile(r"^[A-Za-z0-9 %#.,:;!?()'/@+$-]{1,200}$")

#
# The one thing a message may ask to have filled in: the site's own name. It is
# substituted where the configuration is generated, not where the request is
# answered, so a visitor reads a name this object actually claims. HAProxy can
# do the second - `lf-string` with `%[req.hdr(host)]` - and that would print
# back whatever header the client sent, which is a different and worse thing.
# `%` is otherwise literal in a HAProxy `string`, measured on 3.4.4 on this
# machine, so the token is ours alone to read.
#
URL_PLACEHOLDER = "%URL%"

#
# Anything else between percent signs is refused rather than passed through. A
# message that reads `%SITE%` to its author and prints `%SITE%` to a visitor is
# the silent kind of wrong this model exists to prevent.
#
PLACEHOLDER = re.compile(r"%[A-Za-z_]+%")
#
# What a health check speaks. The variants an ADC lists separately - TCP,
# TCP-ECV, HTTP, HTTP-ECV, HTTPS, HTTPS-ECV - are combinations of three
# independent choices here rather than six names: which protocol, whether it
# runs over TLS, and whether it looks at the answer. The same reasoning as the
# path modes: a combination of fields that each say what they do beats a
# vocabulary somebody has to look up.
#
HEALTH_TYPES = ("disabled", "tcp", "http", "dns", "udp")

#
# A udp check is keepalived's `UDP_CHECK`, for a syslog pool: a datagram to
# the receiver's port, and an ICMP "port unreachable" back means it is down.
# Measured in the lab (26-10-07): a stopped receiver out after one try, back
# within about six seconds.
#
# keepalived has no `rise`: one passing check puts a receiver back. `fall` is
# written as its `retry`, the checks after the first failing one.
#

#
# A dns check asks a real question and waits for an answer. The name and type
# are dnsdist's defaults (2.1); `a.root-servers.net.` is answered by any
# resolver that recurses, and an authoritative server is asked for its own
# zone instead. dnsdist counts its interval in whole seconds - `std::stoul`
# in its 2.1 source, so half a second would be read as none - and its own
# defaults for the rest are what the lab measured (26-10-06): a dead server
# out within a quarter of a second at a second's interval.
#
DNS_QUERY_TYPES = ("A", "AAAA", "SOA", "NS", "MX", "TXT")
DNS_NAME = re.compile(
    r"^(?=.{1,254}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*"
    r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$"
)
DEFAULT_QUERY_NAME = "a.root-servers.net."
DEFAULT_QUERY_TYPE = "A"
DEFAULT_DNS_INTERVAL = "1s"
DEFAULT_DNS_RISE = 1
DEFAULT_DNS_FALL = 1

#
# How often, and how many answers in a row it takes to change a server's mind.
# HAProxy's own defaults, written out rather than inherited, so the generated
# file says what it does.
#
DEFAULT_INTERVAL = "2s"
DEFAULT_RISE = 2
DEFAULT_FALL = 3
#
# `fastinter` and `downinter`. Not HAProxy's default, which is `inter`: ours,
# for every pool. A server changing state, or down, is checked this often, so a
# dead one is out in about `inter` plus `fall` seconds and a returning one is in
# within `rise` seconds. That matters most behind a `source` keepalived holds:
# the node without it sees every server down, and after a failover waits for
# `rise` passing checks spaced by these (measured 2026-09-25: 14-32 s of 503 at
# `inter` 5-25 s). The check's timeout stays `inter` - the 3.4.4 manual, under
# `inter` - so a short value asks sooner without asking less patiently.
#
DEFAULT_FAST_INTERVAL = "1s"
DEFAULT_DOWN_INTERVAL = "1s"

#
# The status range a check accepts when nobody said. Also HAProxy's own
# behaviour made explicit: without it, anything below 500 counts as healthy -
# including a 302 to a login page, which is exactly the answer a broken
# application gives.
#
DEFAULT_EXPECT_STATUS = "200-399"

DURATION = re.compile(r"^[1-9][0-9]{0,4}(ms|s|m)$")

#
# The most connections one server is handed at a time. Above it, requests wait
# in the pool's queue rather than being refused, which is the whole point: a
# backend that is slow under load stays slow instead of falling over, and the
# wait is bounded by `timeout queue`.
#
MAX_CONNECTIONS = (1, 65535)
STATUS_RANGE = re.compile(r"^[1-5][0-9]{2}(-[1-5][0-9]{2})?$")

#
# What a check may send and look for. Narrow on purpose: the value is written
# into a configuration line, and whitespace, quotes or backslashes there change
# where the line ends rather than what the check looks for.
#
PROBE = re.compile(r"^[A-Za-z0-9._:/+=@-]{1,64}$")
MATCH_MODES = ("exact", "prefix")
VERIFY_MODES = ("system", "none")

#
# How old a handshake to a pool may be. `tls_policy` holds what each one means;
# the order here is the order they are offered in, strongest first.
#
BACKEND_POLICY_NAMES = ("modern", "intermediate", "legacy")


#
# Every key a proxy document may carry, split by the shape it belongs to. This
# is one table rather than three lists in three places on purpose, and it is
# what keeps `mode tcp` honest.
#
# HAProxy refuses none of this. Measured on 3.4.4 on this machine: in `mode
# tcp` a `cookie` line is ignored with a warning, `http-request` rules are
# ignored, `option forwardfor` is ignored, and `balance hdr` and `balance uri`
# *fall back to round robin* - and `haproxy -c` exits 0 through all of it. So a
# site that asked for session persistence would be published successfully,
# validated successfully, and quietly balanced at random. This is the only
# place it can be caught.
#
# A hand-kept list of forbidden fields would go stale the moment somebody adds
# an HTTP field and forgets the entry, and the cost of forgetting would be
# silence. Deriving both the allowlist and the refusal from this table changes
# what forgetting costs: a key that is in neither group is in no allowlist
# either, so the object is refused outright, for every shape, in whatever test
# its author writes first.
#
COMMON_KEYS = frozenset(
    {"schema", "name", "listen", "backends", "allow_from", "deny_from", "rate_limit", "advanced"}
)

HTTP_ONLY_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "hostnames": "there is no Host header on a raw connection, and the port identifies it",
        "routes": "a raw connection carries no path",
        "maintenance": "there is no way to answer a raw connection with a page",
        "unavailable": "there is no way to answer a raw connection with a message",
        "headers": "a raw connection carries no headers",
        "deny_rules": "a raw connection carries no path, method or headers to refuse on",
        "max_request_body": "a raw connection has no request body",
        "waf": "the WAF engine inspects HTTP requests, and a raw connection is not one",
    }
)

#
# What a dns object cannot carry, on top of everything HTTP_ONLY_KEYS refuses.
# Each is a HAProxy feature: dnsdist serves the object, and a setting no line
# of its configuration would carry is refused rather than published as a
# promise nothing keeps.
#
DNS_REFUSED_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "advanced": "advanced config is HAProxy text, and dnsdist serves this object",
        "rate_limit": "the request limit is HAProxy's, and dnsdist serves this object",
        "deny_from": "refusals by address are HAProxy's; list who may ask in allow_from",
    }
)

#
# What a syslog object cannot carry, on top of everything HTTP_ONLY_KEYS
# refuses. IPVS forwards packets and decides nothing about them: there is no
# list of who may send, and no HAProxy to carry the rest (B256).
#
SYSLOG_REFUSED_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "allow_from": "IPVS forwards every packet that reaches the address and has no list of "
        "senders; protect the address in front of it",
        "deny_from": "IPVS forwards every packet that reaches the address and refuses no sender",
        "advanced": "advanced config is HAProxy text, and the kernel's IPVS serves this object",
        "rate_limit": "the request limit is HAProxy's, and the kernel's IPVS serves this object",
    }
)

TCP_ONLY_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "backend": "a pool is named by the route that reaches it",
    }
)

PROXY_KEYS = COMMON_KEYS | frozenset(HTTP_ONLY_KEYS) | frozenset(TCP_ONLY_KEYS)


class ModelError(ConfigError):
    """A proxy object cannot be understood.

    A `ConfigError`, so it carries exit code 65 - "the input is wrong" - and is
    reported the same way as every other refusal on the publishing path.
    """


@dataclass(frozen=True, slots=True)
class Server:
    """One pool member.

    `backup` is the classic active/passive pair: a member that takes no traffic
    at all while any non-backup member is up, and everything the moment none
    is. It is a property of the member rather than of the pool, because which
    machine is the standby is exactly what a reader needs to see on the line
    that names it.
    """

    host: str
    port: int
    backup: bool = False
    address: str | None = None
    """A dns server's name looked up when the object was saved (B261): what dnsdist forwards to."""
    weight: int | None = None
    """Its share of the pool's traffic against the others' (B263); None is HAProxy's default, 1."""


@dataclass(frozen=True, slots=True)
class Health:
    """How a backend member is decided to be usable.

    `disabled` is spelled out rather than being the absence of the section. A
    pool with no health checking is a decision somebody made, and it should read
    like one in a diff.

    `host` exists because of a failure mode that looks like something else
    entirely: a backend doing name-based virtual hosting answers a check with
    no Host header with a 404 or a redirect, the pool goes down, and the
    interface reports a dead server that is in fact perfectly healthy.
    """

    type: str
    #
    # Three answers, not two. `None` follows the pool - a TLS pool is checked
    # over TLS, a plain one in plain - which is HAProxy's own behaviour and
    # what an object that says nothing has always meant. `True` is a check that
    # speaks TLS whatever the pool does; `False` is one that does not, which a
    # TLS pool with a plaintext management port needs and could not say before.
    #
    tls: bool | None = None
    port: int | None = None
    path: str | None = None
    host: str | None = None
    expect_status: str | None = None
    expect_body: str | None = None
    send: str | None = None
    expect: str | None = None
    query_name: str | None = None
    query_type: str | None = None
    interval: str = DEFAULT_INTERVAL
    #
    # HAProxy's `fastinter` and `downinter`: the interval while a server is on
    # its way up or down, and while it is down. Absent is the generator's
    # choice - see `generate._server_check` - not HAProxy's `inter`.
    #
    fast_interval: str | None = None
    down_interval: str | None = None
    rise: int = DEFAULT_RISE
    fall: int = DEFAULT_FALL


def duration_ms(value: str) -> int:
    """A duration the model has already accepted, as milliseconds.

    For comparing two of them, which is the only reason this exists: a written
    duration is otherwise carried through to HAProxy exactly as it was written.
    """

    if value.endswith("ms"):
        return int(value[:-2])
    if value.endswith("m"):
        return int(value[:-1]) * 60_000
    return int(value[:-1]) * 1_000


@dataclass(frozen=True, slots=True)
class BackendTls:
    verify: str
    """Whether the pool's certificate has to be trusted.

    **Verifying requires that every server is named, not addressed.** The name
    is sent to the pool as SNI and is what the certificate is checked against,
    and there is no honest way to derive one from an address. A pool named by
    address is therefore refused rather than verified against something nobody
    chose.

    That is not a preference about how to write configuration. Measured on
    HAProxy 3.4.4 on 2026-09-04: `ssl verify required ca-file @system-ca`
    without `sni` fails the handshake on every request - the site answers 503 -
    against a pool whose certificate `openssl s_client` accepts with
    `Verify return code: 0`. The health check meanwhile stays green, because a
    check does not verify what traffic verifies. A site that is down while
    every reading says it is up is the failure this project exists to prevent,
    so the name is required at the point the object is written.
    """

    policy: str = DEFAULT_BACKEND_POLICY
    """Which TLS versions and ciphers this pool may be reached over.

    Separate from `verify`, because they answer different questions: `verify`
    is whether the pool's certificate has to be trusted, this is how old the
    handshake may be. A device can need a lax answer to one and not the other.

    `intermediate` unless the object says otherwise, which is a floor where
    there was none - a pool used to negotiate down to whatever OpenSSL on the
    node happened to allow. `legacy` reaches TLS 1.1 and exists only here, on
    the side where the far end is a device somebody can name.
    """


@dataclass(frozen=True, slots=True)
class Backend:
    name: str
    balance: str
    servers: tuple[Server, ...]
    health: Health
    tls: BackendTls | None = None
    cookie: str | None = None
    max_connections: int | None = None
    """How many connections one server takes at once. None means no limit.

    A limit protects the application behind it: a pool of servers that each
    take what they can serve keeps answering under a load that would otherwise
    make all of them slow at once. What does not fit waits in the pool's queue.
    """

    slow_start: str | None = None
    """How long a server that just came back ramps up to full load.

    A server that has been down usually comes back cold - empty caches, no
    connection pools, a JIT that has forgotten everything - and handing it its
    full share immediately is a good way to knock it over again. HAProxy only
    applies this to a server that was previously seen as failed, so it costs
    nothing at startup.
    """
    """The name of the cookie that keeps one visitor on one member.

    Session persistence, and deliberately not a balancing algorithm.
    `balance source` is the version that needs no cookie and breaks the moment
    a group of visitors shares an address - an office behind NAT, a mobile
    network - because they then share a server too. A cookie follows the
    session rather than the address.
    """
    balance_key: str | None = None
    """Which header or query parameter `hdr` and `url_param` hash.

    Required by those two and refused by every other algorithm, rather than
    ignored. A key set next to `roundrobin` means somebody believed the pool
    was sticky when it was not, and finding that out from a support call is
    worse than finding it out from the editor.
    """

    @property
    def written_by_hand(self) -> bool:
        """Whether the object's advanced config writes this pool (B224).

        A pool the model has read has servers unless it was `servers: []`, which
        is what `pool_written_by_hand` asks of the stored document.
        """

        return not self.servers


def pool_written_by_hand(pool: Any) -> bool:
    """Whether a pool in a stored document is the advanced config's to write (B224).

    The one rule, for every reader that has the document rather than the model:
    the dialog, the form and `advanced_placement`. `Backend.written_by_hand` is
    the same answer once the model has read it.
    """

    return isinstance(pool, Mapping) and pool.get("servers") == []


@dataclass(frozen=True, slots=True)
class Redirect:
    """A route that answers rather than forwards.

    Generated as a backend of its own rather than as a rule in the frontend,
    for the reason the unknown-name answer is: `http-request` rules run before
    `use_backend`, so a redirect written there would be evaluated before the
    routing decision and a short redirect path would shadow a longer route that
    should have won. As a backend it takes part in the same longest-prefix
    order as everything else, and the semantics frozen in `route_match` need no
    exception.

    `location` replaces the whole target rather than keeping the path. One
    behaviour, said plainly; preserving the path is an additive field the day
    somebody needs it.
    """

    location: str
    status: int = 301


@dataclass(frozen=True, slots=True)
class Route:
    """One matching rule and where it sends what it matched.

    `strip_prefix` and `add_prefix` are two optional fields rather than one mode
    with four values. The four modes the plan names - preserve, strip, add,
    strip+add - are then the four combinations, and each one reads as what it
    does to the path instead of as a word to look up.
    """

    path: str
    match: str
    backend: str | None = None
    """The pool this route sends to. None where the route redirects instead."""

    redirect: Redirect | None = None
    """An answer instead of a destination. Exactly one of the two is set."""

    strip_prefix: str | None = None
    add_prefix: str | None = None

    @property
    def segments(self) -> int:
        """How specific this route is, counted the way the plan freezes it.

        Segments rather than characters: `/a/b` beats `/abcdef`, because a
        deeper path is a more specific statement about the request than a longer
        one. Decided here and written into file order by the generator, so
        nothing at runtime depends on how a list happened to be sorted.
        """

        return len([part for part in self.path.split("/") if part])


#
# The answers a redirect may give. Permanent and temporary, and the two that
# promise the method survives - a browser is free to turn a redirected POST
# into a GET on 301 and 302, and may not on 307 and 308. Written out as a
# choice because "redirect" without a code is four different behaviours.
#
REDIRECT_STATUS = (301, 302, 303, 307, 308)

#
# The longest promise HSTS may make. Two years is what the preload lists ask
# for, and more than that is a commitment nobody can honour by editing
# configuration - the browser stops asking.
#
MAX_HSTS_AGE = 63072000


@dataclass(frozen=True, slots=True)
class Hsts:
    """A promise to the browser that this name is https from now on.

    Off unless asked for, and it is the one setting in the model that cannot
    be taken back by changing configuration: for `max_age` seconds the browser
    refuses plain http on its own, whatever the server now says.
    `include_subdomains` extends that to names this object may not even own,
    which is why it is a separate, deliberate word rather than part of a
    preset.
    """

    max_age: int
    include_subdomains: bool = False


@dataclass(frozen=True, slots=True)
class HeaderActions:
    """What one direction of the traffic has done to its headers.

    `assign` replaces whatever was there, `append` adds another field with the
    same name, and `remove` takes every one away. Three separate lists rather
    than one list of operations, because the YAML then reads as three questions
    with answers instead of a program.
    """

    assign: tuple[tuple[str, str], ...] = ()
    append: tuple[tuple[str, str], ...] = ()
    remove: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.assign or self.append or self.remove)


@dataclass(frozen=True, slots=True)
class Headers:
    """Header edits, in each direction. Absent means the traffic is untouched."""

    request: HeaderActions = HeaderActions()
    response: HeaderActions = HeaderActions()

    def __bool__(self) -> bool:
        return bool(self.request or self.response)


@dataclass(frozen=True, slots=True)
class Maintenance:
    """This object is out of service on purpose, and says so.

    Taking a site down by deleting its object loses everything the object
    knows - its routes, its pools, its checks - and the way back is to write it
    again from memory. This is the other way: the object stays exactly as it
    is, and every request for its names is answered with a page instead of
    being routed.

    The message is required rather than defaulted. A maintenance mode with
    nothing to say produces the naked 503 that B49 objected to in the first
    place, only now on purpose; the whole difference between the two is that
    somebody wrote down what is happening and when it ends.
    """

    message: str


@dataclass(frozen=True, slots=True)
class Unavailable:
    """What a visitor is told when no server in the pool can answer.

    The one page a site cannot serve for itself: 502 and 503 arise precisely
    when nothing behind the proxy is answering, so an error page hosted by the
    application is unreachable exactly when it is needed. Left out, HAProxy
    serves its own grey text, which says nothing about which site this was or
    who to tell.

    A line of text rather than a file. A real HTML page would have to be
    carried to every node, versioned with the release and reviewed like
    configuration, and none of that is worth it for a sentence.
    """

    message: str


@dataclass(frozen=True, slots=True)
class RateLimit:
    """How much one source address may ask of this object, over a window.

    The cluster's abuse protection moved down to one object (B216): the same
    counter, the same 429 and the same reading of a trusted proxy's forwarded
    address, but with a table of the object's own, so a limit here says
    nothing about any other site on the address.

    One threshold, and which one depends on the shape. An http object counts
    requests; a tcp object has no requests and counts new connections, which
    is the only question a raw stream can be asked before it is forwarded.
    Exactly one of the two is set.

    Counted per node and forgotten on reload, like the cluster's: HAProxy
    keeps the table in the process, and nothing here synchronises it.
    """

    window: str
    max_requests: int | None = None
    max_new_connections: int | None = None


@dataclass(frozen=True, slots=True)
class HeaderCondition:
    """One header an access rule asks about, and how its value must read."""

    name: str
    match: str
    """`equals`, `prefix` or `contains` - never a pattern (B227)."""

    value: str


@dataclass(frozen=True, slots=True)
class AccessRule:
    """A refusal on what a request asks for (Fas 21, B216 point 3, B227).

    Every condition the rule names must hold; an object's rules are tried in
    order and any one of them is enough. A rule names at least one condition,
    because a rule with none would refuse everything the object serves.

    `log` lets the request through and records the rule's name on its traffic
    record, so that what a rule would refuse can be seen before it refuses it;
    `deny` answers 403 and records the same.
    """

    name: str
    mode: str
    path: str | None = None
    path_match: str = "prefix"
    methods: tuple[str, ...] = ()
    header: HeaderCondition | None = None
    sources: tuple[str, ...] = ()
    source_negate: bool = False
    """The rule holds for visitors *outside* `sources` - "all but these"."""


@dataclass(frozen=True, slots=True)
class DenyFrom:
    """Who gets no answer, by address - the counterpart of `allow_from`.

    `log` exists for http objects only: a tcp object has no traffic record
    for the match to appear on, so there it would be a rule nothing shows.
    """

    mode: str
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Waf:
    """The WAF engine on this object (Fas 21 del B, B232).

    Coraza with the OWASP Core Rule Set inspects every request; what the engine
    finds is decided on in HAProxy. `log` lets the request through and marks
    its traffic record `crs:log`, `block` answers 403 and marks it `crs:deny`.
    A new object starts in `log`, so false alarms show before anything is
    refused. `on_engine_error` is what happens when the engine does not answer:
    `allow` lets the request through, `deny` answers 503. `paranoia` is the CRS
    blocking paranoia level; `exceptions` are how a false alarm is taken away
    (B234), each as narrow as the finding allows.

    The engine reads a body only as far as HAProxy's buffer holds it, so in
    `block` a request whose body did not fit is refused (413, `waf-body:deny`)
    rather than passed with its end unread - padding before an attack would
    otherwise carry it through (review 2026-10-04 F1, B243). `large_bodies`
    are the paths where such a body is expected - an upload, a large JSON call
    - and is let through with what fitted inspected; each covers itself and
    what lies under it. In `log` the body is only marked `waf-body:log`.
    """

    mode: str = "log"
    on_engine_error: str = "allow"
    paranoia: int = 1
    exceptions: tuple[WafException, ...] = ()
    large_bodies: tuple[str, ...] = ()

    @property
    def inspecting(self) -> bool:
        """Whether the engine sees the object's requests: `off` keeps settings, not inspection."""
        return self.mode != "off"


@dataclass(frozen=True, slots=True)
class WafException:
    """One CRS rule let through on this object (B234, chosen 26-10-03).

    `field` narrows it to one part of the request as the rule set names it -
    `ARGS:q`, `REQUEST_HEADERS:User-Agent` - and empty means the whole request.
    `paths` narrows it to exact request paths, compared as the engine sees them
    after decoding and normalising; empty means every path. `by` and `at` say
    who made it and when, for the WAF page's list.
    """

    rule: int
    field: str = ""
    paths: tuple[str, ...] = ()
    by: str = ""
    at: str = ""


@dataclass(frozen=True, slots=True)
class Advanced:
    """The object's advanced config: the text as stored, and where each line goes.

    Placed when the object is read, so the generator, the CLI and the
    interface all write and show the same thing - and an object whose text
    has a refused line is refused like any other object that cannot be
    understood, by the one reader every path goes through.
    """

    text: str
    placement: advanced_config.Placement


@dataclass(frozen=True, slots=True)
class Listen:
    """Where this object is reached, and how.

    `vip` names one of the cluster's addresses rather than being an address.
    An address is an environment value and belongs in the cluster
    configuration; the object says which of them it sits on, and the same
    object therefore means the same thing in a rehearsal cluster and in
    production. Left out, it means the cluster's default VIP, which is the
    normal case and the only case until somebody adds a second one.
    """

    protocol: str
    vip: str | None = None
    port: int | None = None
    """The port a tcp object is served on. None for http and https.

    A tcp object names its own port because there is no shared one to name it
    for: http and https have a cluster-wide port each and every object on an
    address shares it, while a raw tcp service is a port and nothing else.
    """

    source: str | None = None
    certificate: str | None = None
    tls_policy: str | None = None
    """Which TLS versions this object's listener accepts, overriding its VIP's.

    None means the VIP decides, which is the normal case. Named here because
    HAProxy chooses a filtered certificate-list line by SNI. The same
    certificate may therefore occur on several lines with different terms, so
    a site with a requirement of its own needs neither a separate certificate
    nor a VIP. See `_crt_list` and `_tls_sni_guard` in the generator.
    """
    redirect_http: bool = False
    hsts: Hsts | None = None


@dataclass(frozen=True, slots=True)
class Proxy:
    name: str
    hostnames: tuple[str, ...]
    """The names this object answers for. Empty for tcp, which has no names.

    There is no Host header on a raw tcp connection, so a hostname on a tcp
    object would be a label nothing consults - and a label that looks like
    routing is worse than no label.
    """

    listen: Listen
    routes: tuple[Route, ...]
    """Where each path goes. Empty for tcp, which has no paths."""

    backend: str | None = None
    """The single pool a tcp object forwards to. None for http and https."""

    backends: Mapping[str, Backend] = MappingProxyType({})
    allow_from: tuple[str, ...] = ()
    """Who may reach this object at all. Empty means everyone.

    An entry is either the name of a group the cluster defines, or a literal
    address or range. The named form is the better one where it fits - the
    object says "the office" and which addresses that is stays in the cluster
    configuration, so the same object means the same thing in a rehearsal
    cluster and in production - but a range that belongs to one site and
    nothing else has no business being named cluster-wide, and writing it here
    is then the honest answer rather than a workaround.

    This is a different question from the trusted proxy list. That one decides
    whose forwarded headers are believed; this one decides who gets an answer.
    """

    maintenance: Maintenance | None = None
    """Set while the site is deliberately out of service. None means serving."""

    unavailable: Unavailable | None = None
    """What to say when the pool cannot answer. None means HAProxy's own text."""

    headers: Headers = Headers()
    """What this object adds to, replaces in, or removes from the traffic."""

    rate_limit: RateLimit | None = None
    """How much one source may ask of this object. None means no limit."""

    advanced: Advanced | None = None
    """HAProxy text pasted onto the object (Fas 17, B223). None means none."""

    deny_from: DenyFrom | None = None
    """Who is refused by address. None means nobody is (Fas 21)."""

    deny_rules: tuple[AccessRule, ...] = ()
    """Refusals on path, method, header and source, in order (Fas 21)."""

    waf: Waf | None = None
    """The WAF engine's settings. None, or `mode: off`, means the engine does not see this object."""

    @property
    def inspected(self) -> Waf | None:
        """The settings the engine applies, or None where it does not see the object."""
        return self.waf if self.waf is not None and self.waf.inspecting else None

    max_request_body: int | None = None
    """The largest declared request body in bytes. None means no limit (Fas 21).

    Held against the declared length only: HAProxy cannot count a chunked body
    past its buffer (measured in 3.4.6, 2026-10-02), so such a request is let
    through and marked on its traffic record instead (B227, choice C).
    """


def _string(value: Mapping[str, Any], key: str, location: str, allowed: tuple[str, ...]) -> str:
    result = _required_string(value, key, location)
    if result not in allowed:
        raise ModelError(f"{location}.{key} must be one of: {', '.join(allowed)}")
    return result


def _boolean(value: Mapping[str, Any], key: str, location: str, *, default: bool) -> bool:
    result = value.get(key, default)
    if not isinstance(result, bool):
        raise ModelError(f"{location}.{key} must be true or false")
    return result


def _optional_prefix(value: Mapping[str, Any], key: str, location: str) -> str | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str) or not ROUTE_PATH.match(raw) or raw == "/":
        raise ModelError(f"{location}.{key} must be an absolute path below /")
    return raw.rstrip("/") or None


def _is_address(host: str) -> bool:
    """Whether this names a machine by address rather than by name."""

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _server(value: Any, location: str) -> Server:
    data = _mapping(value, location)
    _only_keys(data, {"host", "port", "backup", "address", "weight"}, location)
    host = _required_string(data, "host", location)
    port = data.get("port")
    #
    # A bool is an int in Python, and `port: true` would otherwise be port 1.
    # The same check the worker's payload validation makes, for the same reason.
    #
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ModelError(f"{location}.port must be a port number")
    address = data.get("address")
    if address is not None:
        #
        # The address a name had when the object was saved (B261). Beside a
        # name only: an address beside an address is two answers to one
        # question, and nothing would say which one dnsdist uses.
        #
        if not isinstance(address, str) or not _is_address(address):
            raise ModelError(f"{location}.address must be an IP address")
        if _is_address(host):
            raise ModelError(f"{location}.address belongs beside a name, not an address")
        address = str(ipaddress.ip_address(address.strip("[]")))
    weight = data.get("weight")
    if weight is not None and (
        not isinstance(weight, int)
        or isinstance(weight, bool)
        or not MIN_WEIGHT <= weight <= MAX_WEIGHT
    ):
        raise ModelError(
            f"{location}.weight must be a whole number from {MIN_WEIGHT} to {MAX_WEIGHT}"
        )
    return Server(
        host=host,
        port=port,
        backup=_boolean(data, "backup", location, default=False),
        address=address,
        weight=weight,
    )


_HTTP_ONLY = ("path", "host", "expect_status", "expect_body")
_TCP_ONLY = ("send", "expect")
_DNS_ONLY = ("query_name", "query_type")
_TIMING = ("tls", "port", "interval", "fast_interval", "down_interval", "rise", "fall")


def _health(value: Any, location: str) -> Health:
    data = _mapping(value, location)
    _only_keys(data, {"type", *_HTTP_ONLY, *_TCP_ONLY, *_DNS_ONLY, *_TIMING}, location)
    kind = _string(data, "type", location, HEALTH_TYPES)

    if kind == "disabled":
        unusable = sorted(set(data) - {"type"})
        if unusable:
            raise ModelError(
                f"{location} is disabled, so it cannot also be configured: {', '.join(unusable)}"
            )
        return Health(type=kind)

    if kind == "dns":
        return _dns_health(data, location)
    if kind == "udp":
        return _udp_health(data, location)
    for key in (*(_TCP_ONLY if kind == "http" else _HTTP_ONLY), *_DNS_ONLY):
        if data.get(key) is not None:
            raise ModelError(f"{location}.{key} means nothing for a {kind} health check")

    interval = data.get("interval", DEFAULT_INTERVAL)
    if not isinstance(interval, str) or not DURATION.match(interval):
        raise ModelError(f"{location}.interval must be a duration such as 5s or 500ms")
    fast_interval = _duration(data, "fast_interval", location)
    down_interval = _duration(data, "down_interval", location)

    #
    # Absent is not false. Written out, `false` is somebody asking for a
    # plaintext check on a pool that is reached over TLS - a different request
    # from having no opinion, and the one HAProxy needs `no-check-ssl` for.
    #
    tls = data.get("tls")
    if tls is not None and not isinstance(tls, bool):
        raise ModelError(f"{location}.tls must be true or false")
    #
    # A separate port for the check, because a health endpoint is not always on
    # the port that serves traffic - plenty of systems answer on their own
    # management port instead. Absent means the server's own port, which is the
    # usual case and needs no words.
    #
    port = data.get("port")
    if port is not None and (
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
    ):
        raise ModelError(f"{location}.port must be a port number")
    rise = _count(data, "rise", location, DEFAULT_RISE)
    fall = _count(data, "fall", location, DEFAULT_FALL)

    if kind == "http":
        path = data.get("path")
        if not isinstance(path, str) or not ROUTE_PATH.match(path):
            raise ModelError(f"{location}.path must be an absolute path for an http health check")
        host = data.get("host")
        if host is not None and (not isinstance(host, str) or not HOSTNAME.match(host)):
            raise ModelError(f"{location}.host must be a hostname")
        status = data.get("expect_status", DEFAULT_EXPECT_STATUS)
        if not isinstance(status, str) or not STATUS_RANGE.match(status):
            raise ModelError(f"{location}.expect_status must be a status or range, such as 200-299")
        return Health(
            type=kind,
            path=path,
            host=host,
            expect_status=status,
            expect_body=_probe(data, "expect_body", location),
            tls=tls,
            port=port,
            interval=interval,
            fast_interval=fast_interval,
            down_interval=down_interval,
            rise=rise,
            fall=fall,
        )

    send = _probe(data, "send", location)
    expect = _probe(data, "expect", location)
    if (send is None) != (expect is None):
        #
        # Sending without looking at the answer proves only that the port is
        # open, which a plain connection already proved; looking without
        # sending waits for a greeting that most protocols never volunteer.
        #
        raise ModelError(f"{location}.send and {location}.expect belong together")
    return Health(
        type=kind,
        send=send,
        expect=expect,
        tls=tls,
        port=port,
        interval=interval,
        fast_interval=fast_interval,
        down_interval=down_interval,
        rise=rise,
        fall=fall,
    )


def _dns_health(data: Mapping[str, Any], location: str) -> Health:
    """A real question to each server, in what dnsdist can be told.

    No separate port, no TLS and no fast or down interval: dnsdist asks the
    server on the address it forwards to, over plain DNS, at one interval. A
    field it cannot be given is refused rather than dropped, so the object never
    reads as something the node does not do.
    """

    for key in (*_HTTP_ONLY, *_TCP_ONLY, "tls", "port", "fast_interval", "down_interval"):
        if data.get(key) is not None:
            raise ModelError(f"{location}.{key} means nothing for a dns health check")
    interval = data.get("interval", DEFAULT_DNS_INTERVAL)
    if (
        not isinstance(interval, str)
        or not DURATION.match(interval)
        or duration_ms(interval) % 1000
        or duration_ms(interval) > 60_000
    ):
        raise ModelError(
            f"{location}.interval must be whole seconds from 1s to 1m; dnsdist counts no finer"
        )
    query_name = data.get("query_name", DEFAULT_QUERY_NAME)
    if not isinstance(query_name, str) or not DNS_NAME.match(query_name):
        raise ModelError(f"{location}.query_name must be a DNS name, such as example.com.")
    return Health(
        type="dns",
        query_name=query_name if query_name.endswith(".") else f"{query_name}.",
        query_type=(
            _string(data, "query_type", location, DNS_QUERY_TYPES)
            if "query_type" in data
            else DEFAULT_QUERY_TYPE
        ),
        interval=interval,
        rise=_count(data, "rise", location, DEFAULT_DNS_RISE),
        fall=_count(data, "fall", location, DEFAULT_DNS_FALL),
    )


def _udp_health(data: Mapping[str, Any], location: str) -> Health:
    """A datagram to each receiver, as keepalived's `UDP_CHECK` sends it.

    On the receiver's own port and nothing else to say: no payload, no answer
    to wait for (a syslog receiver sends none), and no rise - see
    `HEALTH_TYPES`.
    """

    for key in (*_HTTP_ONLY, *_TCP_ONLY, *_DNS_ONLY, "tls", "port"):
        if data.get(key) is not None:
            raise ModelError(f"{location}.{key} means nothing for a udp health check")
    for key in ("fast_interval", "down_interval", "rise"):
        if data.get(key) is not None:
            raise ModelError(
                f"{location}.{key} is HAProxy's, and keepalived checks this pool; it puts a "
                f"receiver back after one passing check"
            )
    interval = data.get("interval", DEFAULT_INTERVAL)
    if not isinstance(interval, str) or not DURATION.match(interval):
        raise ModelError(f"{location}.interval must be a duration such as 5s or 500ms")
    return Health(
        type="udp",
        interval=interval,
        fall=_count(data, "fall", location, DEFAULT_FALL),
    )


def _duration(data: Mapping[str, Any], key: str, location: str) -> str | None:
    value = data.get(key)
    if value is not None and (not isinstance(value, str) or not DURATION.match(value)):
        raise ModelError(f"{location}.{key} must be a duration such as 2s or 500ms")
    return value


def _count(data: Mapping[str, Any], key: str, location: str, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 10:
        raise ModelError(f"{location}.{key} must be a small number of checks")
    return value


def _probe(data: Mapping[str, Any], key: str, location: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not PROBE.match(value):
        raise ModelError(
            f"{location}.{key} must be a short value without spaces, quotes or backslashes"
        )
    return value


def _balance_key(data: Mapping[str, Any], balance: str, location: str) -> str | None:
    key = data.get("balance_key")
    if balance not in BALANCE_NEEDS_KEY:
        if key is not None:
            raise ModelError(
                f"{location}.balance_key means nothing for balance: {balance}; "
                f"it names what hdr or url_param hashes"
            )
        return None
    if not isinstance(key, str):
        raise ModelError(f"{location}.balance_key is required for balance: {balance}")
    pattern = HEADER_NAME if balance == "hdr" else PARAMETER
    if not pattern.match(key):
        what = "an HTTP header name" if balance == "hdr" else "a query parameter name"
        raise ModelError(f"{location}.balance_key must be {what}")
    return key


def _backend(name: str, value: Any, location: str) -> Backend:
    data = _mapping(value, location)
    if pool_written_by_hand(data):
        #
        # A pool written by hand in the object's advanced config (B224): empty
        # here, and nothing else either - balance, checks, cookie and the rest
        # of what makes a pool are then the text's, and a value here beside
        # them would be one nobody reads. Whether the object may do this at
        # all is decided where the whole object is known.
        #
        if set(data) != {"servers"}:
            raise ModelError(
                f"{location} is written in advanced config, so it may say nothing but "
                f"servers: []; found {', '.join(sorted(set(data) - {'servers'}))}"
            )
        return Backend(name=name, balance="", servers=(), health=Health(type="disabled"))
    _only_keys(
        data,
        {
            "balance",
            "balance_key",
            "cookie",
            "servers",
            "health",
            "tls",
            "max_connections",
            "slow_start",
        },
        location,
    )
    #
    # Both vocabularies are read here and each is held to its protocol where
    # the whole object is known: a pool does not know what it is behind.
    #
    balance = _string(data, "balance", location, (*BALANCE, *DNS_ONLY_BALANCE))
    balance_key = _balance_key(data, balance, location)

    servers = data.get("servers")
    if not isinstance(servers, list) or not servers:
        raise ModelError(f"{location}.servers must list at least one server")
    members = tuple(
        _server(item, f"{location}.servers[{index}]") for index, item in enumerate(servers)
    )
    #
    # Two members at the same address and port are almost certainly a copied
    # line rather than an intent, and HAProxy would happily balance between
    # them and report a pool that looks twice as healthy as it is.
    #
    addresses = [(member.host, member.port) for member in members]
    if len(set(addresses)) != len(addresses):
        raise ModelError(f"{location}.servers lists the same host and port twice")
    #
    # `first` fills one server before the next and ignores weights entirely
    # (HAProxy 3.4.6's documentation): a weight there would be a number that
    # changes nothing while reading as if it did.
    #
    if balance == "first" and any(member.weight is not None for member in members):
        raise ModelError(
            f"{location}: balance first ignores weights; remove them or choose another"
        )

    tls = data.get("tls")
    backend_tls = None
    if tls is not None:
        tls_data = _mapping(tls, f"{location}.tls")
        _only_keys(tls_data, {"verify", "policy"}, f"{location}.tls")
        backend_tls = BackendTls(
            verify=_string(tls_data, "verify", f"{location}.tls", VERIFY_MODES),
            #
            # Absent is the default rather than an error, so every object
            # written before this field existed still loads and still means what
            # it meant.
            #
            policy=(
                _string(tls_data, "policy", f"{location}.tls", BACKEND_POLICY_NAMES)
                if "policy" in tls_data
                else DEFAULT_BACKEND_POLICY
            ),
        )

    if backend_tls is not None and backend_tls.verify != "none":
        #
        # Verification needs a name to send, and it needs it twice over.
        # Measured on 3.4.4: `ssl verify required` against a server named only
        # by address fails the handshake before any answer arrives - the pool
        # 503s on every request - while the health check stays green, because a
        # check does not verify what traffic verifies. That combination is the
        # worst one this project knows: a site that is down while every reading
        # says it is up.
        #
        # So the name is required rather than defaulted. There is no honest
        # default: an address cannot be turned into the name a certificate was
        # issued for, and guessing one would verify against something nobody
        # chose.
        #
        addressed = sorted({member.host for member in members if _is_address(member.host)})
        if addressed:
            raise ModelError(
                f"{location}.tls.verify is {backend_tls.verify}, so every server must be named "
                f"by hostname rather than by address - verification sends the name to the pool "
                f"and checks the certificate against it. Named by address: "
                f"{', '.join(addressed)}"
            )

    health = _health(data.get("health", {"type": "disabled"}), f"{location}.health")
    #
    # A check over TLS on a pool that is not itself reached over TLS used to be
    # refused here. HAProxy 3.4.4 does refuse the configuration that was written
    # for it - "verify is enabled by default but no CA file specified" - and the
    # refusal was there rather than pick a verification policy on somebody's
    # behalf, quietly picking the insecure one at that.
    #
    # Measured again 2026-09-05, and the missing piece was one word: `verify
    # none` alone on the server line, without `ssl`, leaves the pool plain and
    # lets the check speak TLS. `L7OK 200` against a local TLS server. So the
    # generator writes it, and the choice is no longer silent - it is a word in
    # the diff somebody reads before publishing, and the form says in a sentence
    # that this check does not judge the certificate.
    #
    # It cannot judge it either way. Verification needs a name to check the
    # certificate against, HAProxy's own check sends no SNI, and `check-sni`
    # was measured to fail outright against a pool the same configuration
    # serves. An object that asked for a verified check would be asking for
    # something that does not work.
    #

    cookie = data.get("cookie")
    if cookie is not None and (not isinstance(cookie, str) or not COOKIE.match(cookie)):
        raise ModelError(f"{location}.cookie must be a usable cookie name")

    max_connections = data.get("max_connections")
    if max_connections is not None and (
        not isinstance(max_connections, int)
        or isinstance(max_connections, bool)
        or not MAX_CONNECTIONS[0] <= max_connections <= MAX_CONNECTIONS[1]
    ):
        raise ModelError(
            f"{location}.max_connections must be between "
            f"{MAX_CONNECTIONS[0]} and {MAX_CONNECTIONS[1]} connections per server"
        )

    slow_start = data.get("slow_start")
    if slow_start is not None:
        if not isinstance(slow_start, str) or not DURATION.match(slow_start):
            raise ModelError(f"{location}.slow_start must be a duration such as 30s")
        #
        # Read from HAProxy 3.4.4's own documentation on this machine: the ramp
        # is applied at each health check, and it never applies at startup -
        # only to a server that was previously seen as failed. Without checks
        # there is no such transition and no step to apply, so the field would
        # be a setting that quietly does nothing.
        #
        if health.type == "disabled":
            raise ModelError(
                f"{location}.slow_start needs a health check: it is applied when a server "
                f"that was seen as failed comes back, and without checks that never happens"
            )
        if duration_ms(slow_start) <= duration_ms(health.interval):
            raise ModelError(
                f"{location}.slow_start must be longer than the check interval "
                f"({health.interval}); the ramp moves one step per check"
            )

    return Backend(
        name=name,
        balance=balance,
        balance_key=balance_key,
        cookie=cookie,
        servers=members,
        health=health,
        tls=backend_tls,
        max_connections=max_connections,
        slow_start=slow_start,
    )


def _route(value: Any, location: str, backends: set[str]) -> Route:
    data = _mapping(value, location)
    _only_keys(
        data, {"path", "match", "backend", "redirect", "strip_prefix", "add_prefix"}, location
    )

    path = _required_string(data, "path", location)
    if not ROUTE_PATH.match(path):
        raise ModelError(f"{location}.path must be an absolute path")
    path = path.rstrip("/") or "/"

    match = data.get("match", "prefix")
    if match not in MATCH_MODES:
        raise ModelError(f"{location}.match must be one of: {', '.join(MATCH_MODES)}")

    redirect = _redirect(data.get("redirect"), f"{location}.redirect")
    backend = data.get("backend")
    if (backend is None) == (redirect is None):
        raise ModelError(f"{location} must set exactly one of backend or redirect")
    if backend is not None:
        backend = _required_string(data, "backend", location)
        if backend not in backends:
            raise ModelError(f"{location}.backend names no backend in this object: {backend}")

    strip = _optional_prefix(data, "strip_prefix", location)
    if strip is not None and not path.startswith(strip):
        raise ModelError(f"{location}.strip_prefix must be a prefix of the route's own path")
    #
    # A rewrite describes what the pool behind the route is handed. A redirect
    # hands nothing to a pool, so a rewrite beside one is an instruction with
    # nowhere to land - and silently ignoring it is how somebody spends an
    # afternoon wondering why the path never changed.
    #
    if redirect is not None and (strip is not None or data.get("add_prefix") is not None):
        raise ModelError(f"{location} rewrites the path of a route that redirects instead")

    return Route(
        path=path,
        match=str(match),
        backend=backend,
        redirect=redirect,
        strip_prefix=strip,
        add_prefix=_optional_prefix(data, "add_prefix", location),
    )


def _redirect(value: Any, location: str) -> Redirect | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"location", "status"}, location)
    target = data.get("location")
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        raise ModelError(f"{location}.location must be an absolute http or https URL")
    if any(character in target for character in FORBIDDEN_IN_VALUE) or " " in target:
        raise ModelError(f"{location}.location may not contain spaces, quotes or line breaks")
    status = data.get("status", REDIRECT_STATUS[0])
    if status not in REDIRECT_STATUS:
        raise ModelError(
            f"{location}.status must be one of: {', '.join(str(code) for code in REDIRECT_STATUS)}"
        )
    return Redirect(location=target, status=int(status))


def dump_document(fields: Mapping[str, Any]) -> str:
    """Write a proxy object out as the YAML it is stored as.

    The counterpart of `load_proxy`, and here rather than in whichever caller
    happens to need it: an object written by the interface and an object
    written by hand have to be the same document, and two serialisers would
    eventually disagree about quoting or key order in a way that shows up as a
    confusing diff rather than as an error.

    Key order is preserved rather than sorted, because the order is the reading
    order - what the site is, then where it listens, then where traffic goes.
    """

    document = dict(fields)
    if isinstance(document.get("advanced"), str):
        document["advanced"] = advanced_config.normalise(document["advanced"])
    return yaml.dump(document, Dumper=_Dumper, sort_keys=False, default_flow_style=False)


class _Dumper(yaml.SafeDumper):
    """The safe dumper, writing text of several lines as a block.

    For the advanced config, which is the only such text an object has: as a
    quoted string it is one line of `\\n`s that no diff can be read in. PyYAML
    still falls back to quoting when a line ends in blanks, which is why the
    text is normalised first.
    """


def _text(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    if "\n" in value:
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", value)


_Dumper.add_representer(str, _text)


def load_proxy(name: str, document: bytes) -> Proxy:
    """Read one proxy object, or say exactly what is wrong with it.

    `name` is the object's identity - the filename without its suffix - and the
    document must agree with it. Two sources for one identity is how a rename
    ends up producing configuration under the old name.

    The shared validation helpers are reused rather than reimplemented, so a
    malformed mapping is described here the same way it is everywhere else in
    the engine - but they raise `ConfigError`, and a module that promises its
    own error type has to keep that promise. Every refusal leaves this function
    as a `ModelError`, and callers therefore need to know one name.
    """

    try:
        return _load_proxy(name, document)
    except ModelError:
        raise
    except ConfigError as exc:
        raise ModelError(str(exc)) from exc


def read_document(name: str, document: bytes) -> dict[str, Any]:
    """The stored object as a plain mapping, without interpreting it.

    `load_proxy` is what answers whether an object is usable. This answers the
    narrower question an editor asks first - what does the file actually say -
    and it exists here rather than in the caller so that nothing outside the
    engine has to own a second YAML reader. A caller that parsed the document
    itself would be free to disagree with the engine about size, encoding and
    what counts as a mapping, in exactly the cases where the disagreement is
    invisible until a publish.

    The defaults the model fills in are deliberately absent from the result. An
    editor that read them back would offer to write down values nobody typed,
    and the object would grow every time it was opened.
    """

    if len(document) > MAX_MODEL_BYTES:
        raise ModelError(f"{name}: the proxy object exceeds the size limit")
    try:
        loaded = safe_yaml.load(document.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ModelError(f"{name}: the proxy object is not valid YAML: {exc}") from exc
    try:
        return _mapping(loaded, name)
    except ConfigError as exc:
        raise ModelError(str(exc)) from exc


def _load_proxy(name: str, document: bytes) -> Proxy:
    data = read_document(name, document)
    _only_keys(data, PROXY_KEYS, name)

    if data.get("schema") != 1:
        raise ModelError(f"{name}.schema must be 1")
    if _required_string(data, "name", name) != name:
        raise ModelError(f"{name}.name must match the file it is written in")
    if not NAME.match(name):
        raise ModelError(
            f"{name} is not a usable object name - {name_refusal(name)}; use {NAME_RULE}"
        )

    listen = _listen(data.get("listen"), f"{name}.listen")

    backends_raw = _mapping(data.get("backends"), f"{name}.backends")
    if not backends_raw:
        raise ModelError(f"{name}.backends must define at least one backend")
    backends = {
        key: _backend(key, value, f"{name}.backends.{key}") for key, value in backends_raw.items()
    }
    for key in backends:
        if not NAME.match(key):
            raise ModelError(f"{name}.backends.{key} is not a usable backend name")
        if key.startswith(GENERATED_PREFIX):
            raise ModelError(
                f"{name}.backends.{key} begins with {GENERATED_PREFIX}, which is the generator's"
            )

    hostnames: tuple[str, ...]
    routes: tuple[Route, ...]
    if listen.protocol in OWN_PORT:
        _refuse_keys(data, HTTP_ONLY_KEYS, name, f"a {listen.protocol} object")
        hostnames = ()
        routes = ()
        backend = _tcp_backend(data, backends, name)
        used = {backend}
        if listen.protocol == "dns":
            _refuse_keys(data, DNS_REFUSED_KEYS, name, "a dns object")
            _refuse_non_dns_pools(backends, name)
            _refuse_countries(data, name)
        elif listen.protocol == "syslog":
            _refuse_keys(data, SYSLOG_REFUSED_KEYS, name, "a syslog object")
            _refuse_non_syslog_pools(backends, backends_raw, name)
        else:
            _refuse_http_only_pools(backends, name)
        if listen.protocol != "dns":
            _refuse_saved_addresses(backends, name, listen.protocol)
    else:
        _refuse_keys(data, TCP_ONLY_KEYS, name, "an http or https object")
        _refuse_dns_only_pools(backends, name)
        _refuse_saved_addresses(backends, name, listen.protocol)
        hostnames = _hostnames(data.get("hostnames"), name)
        backend = None
        routes_raw = data.get("routes")
        if not isinstance(routes_raw, list) or not routes_raw:
            raise ModelError(f"{name}.routes must list at least one route")
        routes = tuple(
            _route(item, f"{name}.routes[{index}]", set(backends))
            for index, item in enumerate(routes_raw)
        )
        paths = [(item.path, item.match) for item in routes]
        if len(set(paths)) != len(paths):
            raise ModelError(f"{name}.routes matches the same path twice")
        used = {item.backend for item in routes if item.backend is not None}

    #
    # Every pool has to be reachable. A backend nothing routes to is either a
    # leftover from an edit or a route somebody forgot to add, and generating
    # configuration for it would hide both.
    #
    unused = sorted(set(backends) - used)
    if unused:
        raise ModelError(f"{name}.backends defines backends no route uses: {', '.join(unused)}")

    allow_from = _allow_from(data.get("allow_from", []), name)
    maintenance = _maintenance(data.get("maintenance"), f"{name}.maintenance")
    unavailable = _unavailable(data.get("unavailable"), f"{name}.unavailable")
    headers = _headers(data.get("headers"), f"{name}.headers")
    rate_limit = _rate_limit(data.get("rate_limit"), f"{name}.rate_limit", listen.protocol)
    deny_from = _deny_from(data.get("deny_from"), f"{name}.deny_from", listen.protocol)
    deny_rules = _deny_rules(data.get("deny_rules"), f"{name}.deny_rules")
    max_request_body = _body_size(data.get("max_request_body"), f"{name}.max_request_body")
    waf = _waf(data.get("waf"), f"{name}.waf")
    handwritten = sorted(key for key, backend in backends.items() if backend.written_by_hand)
    advanced = _advanced(
        data.get("advanced"),
        name,
        listen.protocol,
        rate_limit=rate_limit is not None,
        handwritten=bool(handwritten),
    )
    if handwritten:
        _refuse_unwritten_pool(name, handwritten[0], len(backends), advanced)

    return Proxy(
        name=name,
        hostnames=tuple(hostnames),
        listen=listen,
        routes=routes,
        backends=backends,
        allow_from=tuple(allow_from),
        maintenance=maintenance,
        unavailable=unavailable,
        headers=headers,
        backend=backend,
        rate_limit=rate_limit,
        advanced=advanced,
        deny_from=deny_from,
        deny_rules=deny_rules,
        max_request_body=max_request_body,
        waf=waf,
    )


#
# Below this, a code point in the text is a control character: a terminal
# escape or a NUL that would land in a file HAProxy reads and in pages the
# interface draws. A tab is a separator in HAProxy's grammar and is kept.
#
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _advanced(
    value: Any, name: str, protocol: str, *, rate_limit: bool, handwritten: bool
) -> Advanced | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelError(f"{name}.advanced must be text")
    if _CONTROL.search(value):
        raise ModelError(f"{name}.advanced contains a control character")
    text = advanced_config.normalise(value)
    if not text:
        raise ModelError(f"{name}.advanced is empty; leave it out instead")
    placement = advanced_config.place(
        text, name=name, protocol=protocol, rate_limit=rate_limit, handwritten=handwritten
    )
    refused = placement.refused
    if refused:
        #
        # Three lines named, and the count. Enough to find them in the text,
        # and a refusal that quoted a whole pasted block back would be longer
        # than the block.
        #
        named = "; ".join(f"line {line.number}: {line.reason}" for line in refused[:3])
        more = f" (and {len(refused) - 3} more)" if len(refused) > 3 else ""
        raise ModelError(f"{name}.advanced has lines that cannot be written - {named}{more}")
    return Advanced(text=text, placement=placement)


def advanced_placement(name: str, document: bytes) -> advanced_config.Placement | None:
    """Where each line of an object's advanced config goes, refused lines included.

    What `haproxy-objects --advanced` prints and the interface's *Check* shows,
    from one function so the two cannot disagree. It reads only what the
    placement depends on - the shape, whether the form has a rate limit, and
    whether the pool is written by hand - so a text with refused lines can
    still be shown line by line, which `load_proxy` would refuse whole.
    None when the object has no text.
    """

    data = read_document(name, document)
    value = data.get("advanced")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelError(f"{name}.advanced must be text")
    listen = data.get("listen")
    protocol = listen.get("protocol") if isinstance(listen, Mapping) else None
    backends = data.get("backends")
    handwritten = isinstance(backends, Mapping) and any(
        pool_written_by_hand(pool) for pool in backends.values()
    )
    return advanced_config.place(
        advanced_config.normalise(value),
        name=name,
        protocol=str(protocol or ""),
        rate_limit=data.get("rate_limit") is not None,
        handwritten=handwritten,
    )


def _refuse_unwritten_pool(name: str, pool: str, pools: int, advanced: Advanced | None) -> None:
    """A pool left empty for the text must be one pool, and the text must fill it (B224).

    One pool, because an http object's rows land in every pool it has: two pools
    written by hand would be the same servers twice, a choice nobody made. And
    filled, because an empty pool answers every request with a 503 - which is
    what `servers: []` would otherwise publish without a word.
    """

    if pools != 1:
        raise ModelError(
            f"{name}.backends.{pool} is written in advanced config, which only an object "
            f"with one pool can do"
        )
    if advanced is None:
        raise ModelError(
            f"{name}.backends.{pool}.servers is empty and the object has no advanced config "
            f"to write the pool"
        )
    if not any(
        advanced_config.words(line.text)[0] in ("server", "server-template")
        for line in advanced.placement.backend
    ):
        raise ModelError(
            f"{name}.backends.{pool} is written in advanced config, but the text has no server line"
        )


def _maintenance(value: Any, location: str) -> Maintenance | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"message"}, location)
    return Maintenance(message=_message(data, location))


def _message(data: Mapping[str, Any], location: str) -> str:
    message = data.get("message")
    if not isinstance(message, str) or not MESSAGE.match(message):
        raise ModelError(
            f"{location}.message must be a line of readable text, "
            f"up to 200 characters, without double quotes or backslashes"
        )
    unknown = sorted({found for found in PLACEHOLDER.findall(message) if found != URL_PLACEHOLDER})
    if unknown:
        raise ModelError(
            f"{location}.message uses something this version does not fill in: "
            f"{', '.join(unknown)}. The only one is {URL_PLACEHOLDER}"
        )
    return message


def _refuse_keys(data: Mapping[str, Any], keys: Mapping[str, str], name: str, shape: str) -> None:
    """The keys the other shape owns, refused with the reason they mean nothing.

    Driven by `HTTP_ONLY_KEYS` and `TCP_ONLY_KEYS` rather than by a list
    written out here, so that adding a field to the document means classifying
    it once and nowhere else - see the table for what forgetting costs.
    """

    for key, why in keys.items():
        if key in data:
            raise ModelError(f"{name}.{key} means nothing for {shape}: {why}")


def _refuse_http_only_pools(backends: Mapping[str, Backend], name: str) -> None:
    """The pool settings a tcp object cannot have, refused rather than written.

    The document's own keys are handled by `_refuse_keys`; these live one level
    down, inside a backend, where the same key is legitimate for an http object
    and meaningless here. `certificate`, `redirect_http` and `hsts` need no
    check at all: `_listen` already refuses all three for anything but https,
    and a second guard that can never fire is a line the next reader has to
    prove is dead.
    """

    _refuse_dns_only_pools(backends, name)
    for key, pool in backends.items():
        where = f"{name}.backends.{key}"
        if pool.cookie is not None:
            raise ModelError(
                f"{where}.cookie means nothing for a tcp object: HAProxy ignores it in tcp mode "
                f"with a warning, and the pool is then balanced without persistence"
            )
        if pool.balance in BALANCE_HTTP_ONLY:
            raise ModelError(
                f"{where}.balance: {pool.balance} hashes something only an HTTP request has; "
                f"HAProxy falls back to roundrobin in tcp mode without failing"
            )


def _refuse_dns_only_pools(backends: Mapping[str, Backend], name: str) -> None:
    """dnsdist's and keepalived's vocabulary on a pool HAProxy serves, refused by name."""

    for key, pool in backends.items():
        where = f"{name}.backends.{key}"
        if pool.balance in DNS_ONLY_BALANCE:
            raise ModelError(
                f"{where}.balance: {pool.balance} is a dns policy; this object is served by HAProxy"
            )
        if pool.health.type == "dns":
            raise ModelError(f"{where}.health: a dns check is for dns objects")
        if pool.health.type == "udp":
            raise ModelError(f"{where}.health: a udp check is for syslog objects")


#
# What a syslog pool's tcp check may say: keepalived's `TCP_CHECK` connects to
# a port and nothing more. Held against the written keys, because the parsed
# check has HAProxy's defaults filled in and cannot tell `rise: 2` written from
# `rise` left out.
#
_SYSLOG_TCP_CHECK = frozenset({"type", "port", "interval", "fall"})


def _refuse_non_syslog_pools(
    backends: Mapping[str, Backend], written: Mapping[str, Any], name: str
) -> None:
    """What a syslog pool cannot have, because keepalived has no line to carry it (B256).

    `backup` and weights above all: IPVS has neither a standby receiver nor,
    under `rr`, a use for a weight. `firstAvailable` is how a syslog pool says
    active/passive, as a dns pool does. A receiver is an address: IPVS takes
    nothing else, and the name a person meant would be a lookup on the node.
    """

    for key, pool in backends.items():
        where = f"{name}.backends.{key}"
        if pool.balance not in SYSLOG_BALANCE:
            raise ModelError(
                f"{where}.balance must be one of {', '.join(SYSLOG_BALANCE)} for a syslog object"
            )
        for field_name, value in (
            ("balance_key", pool.balance_key),
            ("cookie", pool.cookie),
            ("tls", pool.tls),
            ("max_connections", pool.max_connections),
            ("slow_start", pool.slow_start),
        ):
            if value is not None:
                raise ModelError(f"{where}.{field_name} means nothing for a syslog object")
        if any(server.backup for server in pool.servers):
            raise ModelError(
                f"{where}: IPVS has no backup receiver; use balance: firstAvailable, which "
                f"sends every message to the first receiver that is up"
            )
        if any(server.weight is not None for server in pool.servers):
            raise ModelError(f"{where}: a syslog pool's receivers have no weight")
        if pool.health.type not in ("udp", "tcp", "disabled"):
            raise ModelError(f"{where}.health must be a udp or tcp check, or disabled")
        if pool.health.type == "tcp":
            health = written.get(key, {}).get("health", {})
            extra = sorted(set(health) - _SYSLOG_TCP_CHECK)
            if extra:
                raise ModelError(
                    f"{where}.health: keepalived's tcp check connects to a port and nothing "
                    f"more, so it cannot carry {', '.join(extra)}"
                )
        named = sorted({server.host for server in pool.servers if not _is_address(server.host)})
        if named:
            raise ModelError(f"{where}.servers must be addresses for IPVS: {', '.join(named)}")


def _refuse_saved_addresses(backends: Mapping[str, Backend], name: str, protocol: str) -> None:
    """A server's saved `address` is a dns object's (B261); HAProxy resolves its own names."""

    for key, pool in backends.items():
        if any(server.address is not None for server in pool.servers):
            raise ModelError(
                f"{name}.backends.{key}.servers: address is saved for a dns object's servers "
                f"only, not for a {protocol} object"
            )


def _refuse_non_dns_pools(backends: Mapping[str, Backend], name: str) -> None:
    """What a dns pool cannot have, because dnsdist has no line to carry it.

    `backup` above all: dnsdist has no standby member, and a pool that read as
    active/passive while every server took queries would be the silent kind of
    wrong. `firstAvailable` is how a dns pool says active/passive.
    """

    for key, pool in backends.items():
        where = f"{name}.backends.{key}"
        if pool.balance not in DNS_BALANCE:
            raise ModelError(
                f"{where}.balance must be one of {', '.join(DNS_BALANCE)} for a dns object"
            )
        for field_name, value in (
            ("balance_key", pool.balance_key),
            ("cookie", pool.cookie),
            ("tls", pool.tls),
            ("max_connections", pool.max_connections),
            ("slow_start", pool.slow_start),
        ):
            if value is not None:
                raise ModelError(f"{where}.{field_name} means nothing for a dns object")
        if any(server.backup for server in pool.servers):
            raise ModelError(
                f"{where}: dnsdist has no backup server; use balance: firstAvailable, which "
                f"sends every query to the first server that is up"
            )
        if any(server.weight is not None for server in pool.servers):
            raise ModelError(f"{where}: a dns pool's servers have no weight")
        if pool.health.type not in ("dns", "disabled"):
            raise ModelError(f"{where}.health must be a dns check, or disabled")
        #
        # A server may be named (B252, 26-10-06): dnsdist takes addresses only,
        # so the name is looked up when the object is saved and the address
        # stored beside it (`dnsdist_config.with_addresses`, B261); publishing
        # looks nothing up. The status says when the name no longer resolves to
        # what was published. A name is held to the hostname pattern: it is
        # written into the file as a comment beside the address.
        #
        unnamed = sorted(
            {
                server.host
                for server in pool.servers
                if not _is_address(server.host) and not HOSTNAME.match(server.host)
            }
        )
        if unnamed:
            raise ModelError(
                f"{where}.servers must be addresses or host names: {', '.join(unnamed)}"
            )


def _refuse_countries(data: Mapping[str, Any], name: str) -> None:
    """Countries, which reach the nodes as HAProxy map files dnsdist does not read.

    An empty `allow_from` means everybody, as on every other object (decided
    26-10-06): a resolver that answers the internet is a choice its owner
    protects in front of it, not one the object refuses.
    """

    entries = data.get("allow_from")
    if not isinstance(entries, list):
        return
    for entry in entries:
        if isinstance(entry, str) and geo.is_country(entry.lower()):
            raise ModelError(
                f"{name}.allow_from: countries are not available on a dns object ({entry})"
            )


def _hostnames(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ModelError(f"{name}.hostnames must list at least one hostname")
    for hostname in value:
        if not isinstance(hostname, str) or not HOSTNAME.match(hostname):
            raise ModelError(f"{name}.hostnames contains something that is not a hostname")
    if len(set(value)) != len(value):
        raise ModelError(f"{name}.hostnames lists the same hostname twice")
    return tuple(value)


def _tcp_backend(data: Mapping[str, Any], backends: Mapping[str, Backend], name: str) -> str:
    """The single pool a tcp object forwards to.

    Named at the top of the object rather than through a route, because a route
    is a path condition and a raw connection carries no path. One pool: a tcp
    frontend has nothing to decide with, so a second one could never be
    reached.
    """

    backend = _required_string(data, "backend", name)
    if backend not in backends:
        raise ModelError(f"{name}.backend names no backend in this object: {backend}")
    return backend


def _headers(value: Any, location: str) -> Headers:
    if value is None:
        return Headers()
    data = _mapping(value, location)
    _only_keys(data, {"request", "response"}, location)
    return Headers(
        request=_header_actions(data.get("request"), f"{location}.request"),
        response=_header_actions(data.get("response"), f"{location}.response"),
    )


def _header_actions(value: Any, location: str) -> HeaderActions:
    if value is None:
        return HeaderActions()
    data = _mapping(value, location)
    _only_keys(data, {"set", "add", "delete"}, location)

    assign = _header_pairs(data.get("set"), f"{location}.set")
    append = _header_pairs(data.get("add"), f"{location}.add")
    remove = _header_names(data.get("delete"), f"{location}.delete")

    #
    # One header named by two actions is an instruction that contradicts
    # itself: whichever wins is decided by the order this module happens to
    # write, which is exactly the kind of answer nobody should have to look up.
    #
    seen: dict[str, str] = {}
    for action, names in (
        ("set", [name for name, _ in assign]),
        ("add", [name for name, _ in append]),
        ("delete", list(remove)),
    ):
        for name in names:
            lowered = name.lower()
            if lowered in seen:
                raise ModelError(f"{location} names {name} under both {seen[lowered]} and {action}")
            seen[lowered] = action
    return HeaderActions(assign=assign, append=append, remove=remove)


def _header_pairs(value: Any, location: str) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    data = _mapping(value, location)
    pairs = []
    for name in sorted(data):
        _header_name(name, location)
        content = data[name]
        #
        # YAML reads `yes`, `no`, `on` and `off` as booleans, so a header value
        # that looks like a word arrives here as True. Said plainly, because
        # "must be text" about something that is plainly text reads as a bug in
        # the parser rather than as missing quotes.
        #
        if isinstance(content, bool):
            raise ModelError(
                f"{location}.{name} was read as a true/false value; quote it to make it text"
            )
        if not isinstance(content, (str, int)):
            raise ModelError(f"{location}.{name} must be text")
        text = str(content)
        if not text or len(text) > MAX_HEADER_VALUE:
            raise ModelError(
                f"{location}.{name} must be between 1 and {MAX_HEADER_VALUE} characters"
            )
        if any(character in text for character in FORBIDDEN_IN_VALUE):
            raise ModelError(
                f"{location}.{name} may not contain line breaks, NUL or a single quote"
            )
        pairs.append((name, text))
    return tuple(pairs)


def _header_names(value: Any, location: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ModelError(f"{location} must be a list of header names")
    for name in value:
        _header_name(name, location)
    return tuple(sorted(value))


def _header_name(name: Any, location: str) -> None:
    if not isinstance(name, str) or not HEADER_NAME.match(name):
        raise ModelError(f"{location} contains something that is not a header name: {name!r}")
    if name.lower() in RESERVED_HEADERS:
        raise ModelError(
            f"{location} may not touch {name}: the cluster writes it from what the "
            f"connection actually was"
        )


#
# The most a limit may name. Not a HAProxy ceiling - the counter is an integer
# - but a figure past which the number is a typing mistake rather than a limit
# anybody means: a million requests per source per second is no limit at all.
#
MAX_RATE = 1_000_000


def _rate_limit(value: Any, location: str, protocol: str) -> RateLimit | None:
    if value is None:
        return None
    data = _mapping(value, location)
    #
    # The threshold that means nothing for this shape is refused, not ignored,
    # for the reason `HTTP_ONLY_KEYS` gives: a tcp object that asked for a
    # request limit would otherwise be published with no limit at all.
    #
    wanted = "max_new_connections" if protocol == "tcp" else "max_requests"
    other = "max_requests" if protocol == "tcp" else "max_new_connections"
    if other in data:
        shape = (
            "a tcp object has no requests"
            if protocol == "tcp"
            else ("an http or https object counts requests, not connections")
        )
        raise ModelError(f"{location}.{other} does not apply: {shape}; use {wanted}")
    _only_keys(data, {"window", wanted}, location)
    window = data.get("window", DEFAULT_ABUSE_WINDOW)
    if not isinstance(window, str) or not ABUSE_WINDOW.fullmatch(window):
        raise ModelError(f"{location}.window must be a duration such as 10s or 1m")
    limit = data.get(wanted)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RATE:
        raise ModelError(f"{location}.{wanted} must be a count from 1 to {MAX_RATE}")
    if protocol == "tcp":
        return RateLimit(window=window, max_new_connections=limit)
    return RateLimit(window=window, max_requests=limit)


def _unavailable(value: Any, location: str) -> Unavailable | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"message"}, location)
    return Unavailable(message=_message(data, location))


def is_range(entry: str) -> bool:
    """Whether an `allow_from` entry is a literal address or range.

    Decided by trying to parse it, not by looking for a slash: a bare address is
    a range of one, and a name can never parse as either.
    """

    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    return True


def _allow_from(value: Any, name: str) -> tuple[str, ...]:
    return _sources(value, f"{name}.allow_from", "allow")


def _sources(value: Any, location: str, verb: str) -> tuple[str, ...]:
    """Group names and literal ranges, as `allow_from`, `deny_from` and a rule's
    `source` all take them - one reading, so the three cannot drift apart."""

    if not isinstance(value, list):
        raise ModelError(f"{location} must list group names, addresses or ranges")

    entries: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise ModelError(f"{location} contains something that is not a name or range")
        if geo.is_country(entry.lower()):
            #
            # A country (B228). Upper case as the database spells it, so
            # `country:se` and `country:SE` are one entry and one file.
            #
            country = geo.code(entry.lower()).upper()
            if not geo.COUNTRY.match(country):
                raise ModelError(
                    f"{location} contains {entry!r}; a country is two letters, such as country:SE"
                )
            entries.append(f"{geo.PREFIX}{country}")
            continue
        if is_range(entry):
            network = ipaddress.ip_network(entry, strict=False)
            if network.prefixlen == 0:
                #
                # A range that means everywhere is an allowlist that allows
                # everything, which is worse than none: it reads as a
                # restriction and enforces nothing. Refusing everywhere is
                # no better - it is turning the site off by another name.
                #
                raise ModelError(f"{location} may not {verb} an entire address family")
            entries.append(str(network))
            continue
        if not NAME.match(entry):
            raise ModelError(
                f"{location} contains {entry!r}, which is neither a group name nor an "
                f"address or range"
            )
        entries.append(entry)

    if len(set(entries)) != len(entries):
        raise ModelError(f"{location} names the same group or range twice")
    return tuple(entries)


ACCESS_MODES = ("log", "deny")
HEADER_MATCHES = ("equals", "prefix", "contains")
HTTP_METHODS = ("CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE")
#
# Names the generator writes on a traffic record itself. A rule called the same
# would be indistinguishable from them on the WAF page.
#
RESERVED_RULE_NAMES = (
    "deny-from",
    "body-limit",
    "body-unbounded",
    "crs",
    "waf-engine",
    "path-dots",
)
#
# A rule list long enough to be a mistake rather than a policy, and short
# enough that the shared frontend stays readable. Raised when someone needs it.
#
MAX_DENY_RULES = 50
BODY_SIZE = re.compile(r"^([1-9][0-9]{0,9})([kmg]?)$")
BODY_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
#
# A kilobyte at the least - below it a form with a name in it is refused - and
# a hundred gigabytes at the most, past which the figure is a typing mistake.
#
MIN_BODY = 1024
MAX_BODY = 100 * 1024**3


def _mode(data: Mapping[str, Any], location: str) -> str:
    mode = data.get("mode", "log")
    if mode not in ACCESS_MODES:
        raise ModelError(f"{location}.mode must be one of: {', '.join(ACCESS_MODES)}")
    return str(mode)


def _deny_from(value: Any, location: str, protocol: str) -> DenyFrom | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"mode", "sources"}, location)
    #
    # A new refusal starts by only looking (B227), so `log` is what an absent
    # mode means - except on tcp, where nothing would show what it saw, and
    # the honest default is to ask for `deny` rather than to pretend.
    #
    if protocol == "tcp":
        if data.get("mode") != "deny":
            raise ModelError(
                f"{location}.mode must be deny on a tcp object: a raw connection has no "
                f"traffic record for a logged match to appear on"
            )
        mode = "deny"
    else:
        mode = _mode(data, location)
    sources = _sources(data.get("sources"), f"{location}.sources", "refuse")
    if not sources:
        raise ModelError(f"{location}.sources must name at least one group or range")
    return DenyFrom(mode=mode, sources=sources)


def _deny_rules(value: Any, location: str) -> tuple[AccessRule, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ModelError(f"{location} must be a list of rules")
    if len(value) > MAX_DENY_RULES:
        raise ModelError(f"{location} may hold at most {MAX_DENY_RULES} rules")
    rules = tuple(_deny_rule(item, f"{location}[{index}]") for index, item in enumerate(value))
    names = [rule.name for rule in rules]
    if len(set(names)) != len(names):
        raise ModelError(f"{location} names the same rule twice")
    return rules


def _deny_rule(value: Any, location: str) -> AccessRule:
    data = _mapping(value, location)
    _only_keys(
        data,
        {"name", "mode", "path", "match", "methods", "header", "source", "source_negate"},
        location,
    )
    name = _required_string(data, "name", location)
    if not NAME.match(name):
        raise ModelError(
            f"{location}.name must start with a letter and hold lowercase letters, digits, "
            f"- and _, at most 40"
        )
    if name in RESERVED_RULE_NAMES:
        raise ModelError(f"{location}.name {name} is written by the generator itself")
    mode = _mode(data, location)

    path = data.get("path")
    match = data.get("match", "prefix")
    if path is not None:
        if not isinstance(path, str) or not ROUTE_PATH.match(path):
            raise ModelError(f"{location}.path must be an absolute path")
        #
        # The rule reads the request's path decoded and with its slashes merged
        # (review 2026-10-04 F2), so a path written any other way could never
        # match - and a rule that silently matches nothing refuses nothing.
        #
        segments = path.split("/")[1:]
        if "%" in path or "//" in path or any(part in (".", "..") for part in segments):
            raise ModelError(
                f"{location}.path must be written as it reads decoded: no %, //, . or .. "
                f"(requests are matched after decoding)"
            )
        path = path.rstrip("/") or "/"
        if match not in MATCH_MODES:
            raise ModelError(f"{location}.match must be one of: {', '.join(MATCH_MODES)}")
    elif "match" in data:
        raise ModelError(f"{location}.match says how a path matches, and the rule names none")

    methods_raw = data.get("methods", [])
    if not isinstance(methods_raw, list) or any(
        method not in HTTP_METHODS for method in methods_raw
    ):
        raise ModelError(f"{location}.methods must list methods from: {', '.join(HTTP_METHODS)}")
    if len(set(methods_raw)) != len(methods_raw):
        raise ModelError(f"{location}.methods names the same method twice")

    header = _header_condition(data.get("header"), f"{location}.header")
    sources = _sources(data["source"], f"{location}.source", "refuse") if "source" in data else ()

    negate = data.get("source_negate", False)
    if not isinstance(negate, bool):
        raise ModelError(f"{location}.source_negate must be true or false")
    if negate and not sources:
        raise ModelError(f"{location}.source_negate needs the sources it excepts")

    if path is None and not methods_raw and header is None and not sources:
        raise ModelError(
            f"{location} names no condition: a rule without one would refuse everything "
            f"the object serves"
        )
    return AccessRule(
        name=name,
        mode=mode,
        path=path,
        path_match=str(match),
        methods=tuple(sorted(methods_raw)),
        header=header,
        sources=sources,
        source_negate=negate,
    )


def _header_condition(value: Any, location: str) -> HeaderCondition | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"name", *HEADER_MATCHES}, location)
    name = data.get("name")
    if not isinstance(name, str) or not HEADER_NAME.match(name):
        raise ModelError(f"{location}.name must be a header name")
    given = [match for match in HEADER_MATCHES if match in data]
    if len(given) != 1:
        raise ModelError(f"{location} must say exactly one of: {', '.join(HEADER_MATCHES)}")
    match = given[0]
    content = data[match]
    if isinstance(content, bool):
        raise ModelError(
            f"{location}.{match} was read as a true/false value; quote it to make it text"
        )
    if not isinstance(content, (str, int)):
        raise ModelError(f"{location}.{match} must be text")
    text = str(content)
    if not text or len(text) > MAX_HEADER_VALUE:
        raise ModelError(f"{location}.{match} must be between 1 and {MAX_HEADER_VALUE} characters")
    if any(character in text for character in FORBIDDEN_IN_VALUE):
        raise ModelError(f"{location}.{match} may not contain line breaks, NUL or a single quote")
    return HeaderCondition(name=name, match=match, value=text)


def _body_size(value: Any, location: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ModelError(f"{location} must be a size such as 512k, 10m or 1g")
    found = BODY_SIZE.fullmatch(str(value))
    if found is None:
        raise ModelError(f"{location} must be a size such as 512k, 10m or 1g")
    size = int(found.group(1)) * BODY_UNITS[found.group(2)]
    if not MIN_BODY <= size <= MAX_BODY:
        raise ModelError(f"{location} must be between 1k and 100g")
    return size


#
# `off` keeps the settings and the exceptions while the engine looks at nothing
# (26-10-03): turning the engine off for a while is not deleting the work of
# telling false alarms from attacks, and a form that could only drop the whole
# block would do exactly that.
#
WAF_MODES = ("log", "block", "off")
WAF_ENGINE_ERRORS = ("allow", "deny")
#
# The CRS rule ranges an object may turn off: the attack rules the engine
# reports (91xxxx-95xxxx), and the scoring and protocol rules around them.
# Below 900000 are Coraza's own and the installation's; turning those off is
# not a false alarm being taken away.
#
WAF_RULE_IDS = range(900000, 1000000)
#
# The rule files that decide and report rather than detect: 949 refuses a
# request whose score crossed the threshold, 959 the same for responses, 980
# reports. Letting one of them through is not taking a false alarm away; it is
# turning the engine off where it applies.
#
WAF_DECIDING_RULES = (949, 959, 980)
MAX_WAF_EXCEPTIONS = 200
MAX_WAF_EXCEPTION_PATHS = 20
#
# The parts of a request an exception can name, as the rule set's own log
# names them: a collection and a key (`ARGS:q`, `ARGS:json.q`,
# `REQUEST_HEADERS:User-Agent`), or a collection that has no keys. The key is
# the requester's own text; only these characters go into the engine's
# configuration, where `;`, `,`, quotes and spaces would change what the
# directive says (measured 26-10-03).
#
WAF_KEYED_FIELDS = (
    "ARGS",
    "ARGS_GET",
    "ARGS_POST",
    "ARGS_NAMES",
    "REQUEST_HEADERS",
    "REQUEST_COOKIES",
    "REQUEST_COOKIES_NAMES",
    "FILES",
    "FILES_NAMES",
)
WAF_KEYLESS_FIELDS = (
    "REQUEST_FILENAME",
    "REQUEST_BASENAME",
    "REQUEST_URI",
    "REQUEST_URI_RAW",
    "REQUEST_LINE",
    "REQUEST_BODY",
    "QUERY_STRING",
)
WAF_FIELD_KEY = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,128}$")
#
# A path is compared after the engine decodes it and normalises it, so it is
# written in that form: decoded (no `%`), with no empty, `.` or `..` segment.
# Quotes, spaces and backslashes would end the directive's argument.
#
WAF_PATH = re.compile(r"^/[A-Za-z0-9._~!$&()*+=:@,/-]{0,1023}$")
WAF_EXCEPTION_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def waf_field(value: str) -> bool:
    """Whether `value` is a part of a request an exception may name."""
    collection, separator, key = value.partition(":")
    if not separator:
        return collection in WAF_KEYLESS_FIELDS
    return collection in WAF_KEYED_FIELDS and WAF_FIELD_KEY.fullmatch(key) is not None


def _waf_path(value: Any, location: str) -> str:
    if not isinstance(value, str) or WAF_PATH.fullmatch(value) is None:
        raise ModelError(
            f"{location} must be a request path such as /search, without quotes, spaces or %"
        )
    segments = value.split("/")[1:]
    if any(segment in ("", ".", "..") for segment in segments[:-1]) or segments[-1] in (".", ".."):
        raise ModelError(f"{location} must be a normalised path, without //, /./ or /../")
    return value


def _waf_exception(value: Any, location: str) -> WafException:
    data = _mapping(value, location)
    _only_keys(data, {"rule", "field", "paths", "by", "at"}, location)
    rule = data.get("rule")
    if isinstance(rule, bool) or not isinstance(rule, int) or rule not in WAF_RULE_IDS:
        raise ModelError(f"{location}.rule must be a CRS rule ID, 900000 to 999999")
    if rule // 1000 in WAF_DECIDING_RULES:
        raise ModelError(
            f"{location}.rule {rule} decides or reports rather than detects; "
            "letting it through would turn the engine off"
        )
    field = data.get("field", "")
    if not isinstance(field, str) or (field and not waf_field(field)):
        raise ModelError(
            f"{location}.field must name a part of the request such as ARGS:q or "
            "REQUEST_HEADERS:User-Agent"
        )
    paths = data.get("paths", [])
    if not isinstance(paths, list) or len(paths) > MAX_WAF_EXCEPTION_PATHS:
        raise ModelError(f"{location}.paths must list at most {MAX_WAF_EXCEPTION_PATHS} paths")
    checked = tuple(_waf_path(path, f"{location}.paths") for path in paths)
    if len(set(checked)) != len(checked):
        raise ModelError(f"{location}.paths names the same path twice")
    by = data.get("by", "")
    if not isinstance(by, str) or len(by) > 64 or any(ord(c) < 32 or ord(c) == 127 for c in by):
        raise ModelError(f"{location}.by must be an account name of at most 64 characters")
    at = data.get("at", "")
    #
    # YAML reads an unquoted time as a time, and that is how a person writes
    # it; in UTC and to the second it is the same value as the quoted form.
    #
    if isinstance(at, datetime) and at.utcoffset() == timedelta(0) and at.microsecond == 0:
        at = at.strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(at, str) or (at and WAF_EXCEPTION_TIME.fullmatch(at) is None):
        raise ModelError(f"{location}.at must be a UTC time such as 2026-10-03T09:10:00Z")
    return WafException(rule=rule, field=field, paths=tuple(sorted(checked)), by=by, at=at)


def _waf(value: Any, location: str) -> Waf | None:
    if value is None:
        return None
    data = _mapping(value, location)
    if "exclude_rules" in data:
        raise ModelError(
            f"{location}.exclude_rules was replaced by exceptions, "
            "each with a rule and optionally a field and paths"
        )
    _only_keys(
        data, {"mode", "on_engine_error", "paranoia", "exceptions", "large_bodies"}, location
    )
    mode = data.get("mode", "log")
    #
    # YAML reads an unquoted `off` as false, and `mode: off` is how a person
    # writes it. Only false: `true` names no mode.
    #
    if mode is False:
        mode = "off"
    if mode not in WAF_MODES:
        raise ModelError(f"{location}.mode must be one of: {', '.join(WAF_MODES)}")
    on_error = data.get("on_engine_error", "allow")
    if on_error not in WAF_ENGINE_ERRORS:
        raise ModelError(
            f"{location}.on_engine_error must be one of: {', '.join(WAF_ENGINE_ERRORS)}"
        )
    paranoia = data.get("paranoia", 1)
    if isinstance(paranoia, bool) or paranoia not in (1, 2, 3, 4):
        raise ModelError(f"{location}.paranoia must be 1, 2, 3 or 4")
    listed = data.get("exceptions", [])
    if not isinstance(listed, list) or len(listed) > MAX_WAF_EXCEPTIONS:
        raise ModelError(f"{location}.exceptions must list at most {MAX_WAF_EXCEPTIONS} exceptions")
    exceptions = tuple(
        _waf_exception(item, f"{location}.exceptions[{index}]") for index, item in enumerate(listed)
    )
    scopes = [(e.rule, e.field, e.paths) for e in exceptions]
    if len(set(scopes)) != len(scopes):
        raise ModelError(
            f"{location}.exceptions lets the same rule through on the same scope twice"
        )
    large = data.get("large_bodies", [])
    if not isinstance(large, list) or len(large) > MAX_WAF_EXCEPTION_PATHS:
        raise ModelError(
            f"{location}.large_bodies must list at most {MAX_WAF_EXCEPTION_PATHS} paths"
        )
    bodies = tuple(_waf_path(path, f"{location}.large_bodies").rstrip("/") or "/" for path in large)
    if len(set(bodies)) != len(bodies):
        raise ModelError(f"{location}.large_bodies names the same path twice")
    return Waf(
        mode=str(mode),
        on_engine_error=str(on_error),
        paranoia=int(paranoia),
        exceptions=exceptions,
        large_bodies=tuple(sorted(bodies)),
    )


def _listen(value: Any, location: str) -> Listen:
    data = _mapping(value, location)
    _only_keys(
        data,
        {"protocol", "vip", "port", "source", "certificate", "redirect_http", "hsts", "tls"},
        location,
    )
    protocol = _string(data, "protocol", location, PROTOCOLS)
    vip = data.get("vip")
    if vip is not None and (not isinstance(vip, str) or not NAME.match(vip)):
        raise ModelError(f"{location}.vip must name one of the cluster's VIPs")
    #
    # The address this object leaves from, when it should not be the one the
    # VIP pairs with. Named rather than written, like every other address.
    #
    source = data.get("source")
    if source is not None and (not isinstance(source, str) or not NAME.match(source)):
        raise ModelError(f"{location}.source must name one of the cluster's source addresses")
    certificate = data.get("certificate")
    redirect = _boolean(data, "redirect_http", location, default=False)

    if protocol == "https":
        if not isinstance(certificate, str) or not certificate:
            raise ModelError(f"{location}.certificate is required for https")
    elif certificate is not None:
        raise ModelError(f"{location}.certificate is only meaningful for https")

    #
    # The listener's own terms, when the VIP's are not what this site needs.
    # Refused on anything but https for the reason the certificate is: there is
    # no handshake on the other protocols to hold to anything.
    #
    listen_tls = data.get("tls")
    if listen_tls is not None:
        if protocol != "https":
            raise ModelError(f"{location}.tls is only meaningful for https")
        if not isinstance(listen_tls, str) or listen_tls not in TLS_POLICY_NAMES:
            raise ModelError(f"{location}.tls must be one of: {', '.join(TLS_POLICY_NAMES)}")

    #
    # Redirecting to https from a listener that has no https is a promise the
    # object cannot keep, and it would generate a redirect loop rather than an
    # error somebody could read.
    #
    if redirect and protocol != "https":
        raise ModelError(f"{location}.redirect_http requires protocol: https")

    hsts = _hsts(data.get("hsts"), f"{location}.hsts")
    if hsts is not None and protocol != "https":
        raise ModelError(f"{location}.hsts requires protocol: https")

    port = data.get("port")
    if protocol in OWN_PORT:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ModelError(
                f"{location}.port is required for {protocol} and must be a port number"
            )
    elif port is not None:
        raise ModelError(
            f"{location}.port is only meaningful for tcp, dns and syslog; http and https are "
            f"served on the cluster's own ports"
        )

    #
    # A syslog object forwards each message with the sender's own address -
    # that is why it is IPVS and not HAProxy (B256) - so there is no address
    # it leaves from to choose.
    #
    if protocol == "syslog" and source is not None:
        raise ModelError(
            f"{location}.source means nothing for syslog: messages reach the receivers with "
            f"the sender's own address"
        )

    return Listen(
        protocol=protocol,
        vip=vip,
        port=port,
        source=source,
        certificate=certificate,
        tls_policy=listen_tls,
        redirect_http=redirect,
        hsts=hsts,
    )


def _hsts(value: Any, location: str) -> Hsts | None:
    if value is None:
        return None
    data = _mapping(value, location)
    _only_keys(data, {"max_age", "include_subdomains"}, location)
    max_age = data.get("max_age")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 0 < max_age <= MAX_HSTS_AGE:
        raise ModelError(f"{location}.max_age must be a number of seconds up to {MAX_HSTS_AGE}")
    return Hsts(
        max_age=max_age,
        include_subdomains=_boolean(data, "include_subdomains", location, default=False),
    )
