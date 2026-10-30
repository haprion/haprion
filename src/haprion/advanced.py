"""Advanced config: HAProxy text pasted onto one object, and where each line goes.

The interface owns the object and the text is a layer on top of it (B205,
B215, B223, B224). The text is written as somebody would write a proxy - lines
under a `frontend`, a `backend` of their own, a few lines with no section at
all - and the engine decides where each line lands, because the sections the
object actually consists of are the generator's and their names are not the
author's to know:

* the object's rows - lines outside any section and lines under the text's own
  `frontend`/`listen` - go to every pool of an http object, or to a tcp
  object's own frontend when HAProxy takes the keyword there and to its pool
  when it does not. Always after the generated lines, so the cluster's brake
  and the object's rate limit run first and the text can read their counters;
* a `backend`, `cache`, `http-errors`, `userlist` or `ring` of the text's own
  is written as it stands, under a name that must begin with the object's,
  once every line of it is one that section type takes and this module lets
  through;
* everything else is refused, and so is a line whose meaning would depend on
  something the text cannot see.

Every line is held to a list of what it may be, never to a list of what it may
not: the proxy keyword matrix below for the object's rows and an added
backend, and `SECTION_KEYWORDS` for the other sections. A word that is on
neither is refused. The text runs on every node as root at load, `haproxy -c`
included, so a keyword that names a file the node opens - a ring's
`backing-file` creates and truncates one - would otherwise be a way from the
interface to any file on the node (code review 2026-10-30, E1).

What this module promises is narrower than "the text works": only that each
line lands where it says, and that a line which would have been ignored, or
would quietly have changed another object or the cluster, is refused rather
than written. `haproxy -c` on the candidate is still the last word on syntax.

One rule runs through all of it (B218): a valid line can mean something else
by where it is put, and HAProxy says nothing about that. Measured on 3.4.6 on
the manager (2026-10-01): two `timeout server` lines in one section are
accepted without a warning and the later one wins; a keyword a section does
not take is a warning at most (`capture` in a backend), and `http-request` in
a tcp frontend is a warning without a line number. The generated config is
validated with `-c` alone, where warnings pass - so this module, and not the
validation, is where those cases are caught.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from haprion.digits import is_digits

#
# Every section keyword HAProxy 3.4 knows (configuration.txt chapters 3-12,
# and the binary's own strings). A line starting with one of these opens a
# section whatever its indentation - HAProxy does not read indentation.
#
SECTIONS = frozenset(
    {
        "global",
        "defaults",
        "frontend",
        "listen",
        "backend",
        "peers",
        "resolvers",
        "mailers",
        "userlist",
        "program",
        "http-errors",
        "ring",
        "cache",
        "fcgi-app",
        "log-forward",
        "log-profile",
        "crt-store",
        "traces",
        "acme",
        "healthcheck",
    }
)

#
# Sections whose lines are the object's own rows: the header is read as "what
# follows belongs to this object" and is not written.
#
OBJECT_SECTIONS = frozenset({"frontend", "listen"})

#
# Sections the text may add, under a name of the object's. The rest are the
# cluster's or the process's (B223).
#
EXTRA_SECTIONS = frozenset({"backend", "cache", "http-errors", "userlist", "ring"})

#
# What each of those sections other than a backend may hold (code review
# 2026-10-30, E1), from configuration.txt 6.2.1, 12.2, 12.4 and 12.5 of
# HAProxy 3.4 - a test holds every keyword against the installed manual. A
# backend is held to the proxy keyword matrix instead. Per keyword:
#
# * cache: all five, sizes and ages in memory;
# * http-errors: `errorfile`, its file held to the packaged error pages as
#   everywhere else;
# * userlist: `user` and `group`, both names and password hashes;
# * ring: everything but `backing-file`, which creates the named file, renames
#   an existing one to `.bak` and maps the ring into it - as root, during
#   `haproxy -c` too - so any path on the node would be overwritten. A ring's
#   `server` is a server line like any other, held to the same parameters.
#
SECTION_KEYWORDS: dict[str, frozenset[tuple[str, ...]]] = {
    "cache": frozenset(
        {
            ("total-max-size",),
            ("max-object-size",),
            ("max-age",),
            ("process-vary",),
            ("max-secondary-entries",),
        }
    ),
    "http-errors": frozenset({("errorfile",)}),
    "userlist": frozenset({("user",), ("group",)}),
    "ring": frozenset(
        {
            ("description",),
            ("format",),
            ("maxlen",),
            ("size",),
            ("timeout", "connect"),
            ("timeout", "server"),
            ("server",),
        }
    ),
}
BACKING_FILE = "a ring's backing file is created and overwritten on the node as root"
SECTION_REFUSED: dict[tuple[str, ...], str] = {("ring", "backing-file"): BACKING_FILE}

SECTION_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

#
# How much memory the text's sections may ask for (code review 2026-10-30
# again, R3). `haproxy -c` allocates none of it, so the check before a
# publish passes whatever is written; at the reload HAProxy maps a cache's
# whole size at once - a 1024 MB cache was 1.16 GB resident a second after
# start - and the old and the new process live side by side while it
# reloads. The same text runs on every node, so a size that does not fit
# takes every node down together. Tables and rings fill as traffic comes,
# but fill they do. Sized for a small site:
#
# * a cache: 64 MB, an object in it half of that, and 256 MB for all the
#   caches of a cluster together (the generator adds them up);
# * a ring: 16 MB;
# * a stick table: 100k entries, with string and binary keys of 256 bytes at
#   most - some 30 MB full.
#
MEGABYTE = 1024 * 1024
CACHE_MAX_MB = 64
CACHE_OBJECT_MAX = CACHE_MAX_MB * MEGABYTE // 2
CLUSTER_CACHE_MAX_MB = 256
RING_MAX = 16 * MEGABYTE
TABLE_MAX_ENTRIES = 100 * 1024
TABLE_MAX_KEY = 256
MEMORY = "HAProxy reserves this on every node at the reload, and `haproxy -c` does not"
_PLAIN = re.compile(r"[0-9]{1,12}")
_SIZED = re.compile(r"(?P<number>[0-9]{1,12})(?P<unit>[kKmMgG]?)")
_UNITS = {"": 1, "k": 1024, "m": MEGABYTE, "g": 1024 * MEGABYTE}


def size_of(value: str, *, units: bool) -> int | None:
    """A size as HAProxy reads it - with a k, m or g suffix where it takes one - or None."""

    match = (_SIZED if units else _PLAIN).fullmatch(value)
    if match is None:
        return None
    if not units:
        return int(value)
    return int(match["number"]) * _UNITS[match["unit"].lower()]


#
# Per section and keyword: the most it may be, whether it takes a suffix, and
# what the number counts.
#
_LIMITS: dict[tuple[str, str], tuple[int, bool, str]] = {
    ("cache", "total-max-size"): (CACHE_MAX_MB, False, "MB"),
    ("cache", "max-object-size"): (CACHE_OBJECT_MAX, False, "bytes"),
    ("ring", "size"): (RING_MAX, True, "bytes"),
    ("stick-table", "size"): (TABLE_MAX_ENTRIES, True, "entries"),
    ("stick-table", "len"): (TABLE_MAX_KEY, False, "bytes"),
}


def _limit_problem(kind: str, keyword: str, value: str) -> str:
    limit = _LIMITS.get((kind, keyword))
    if limit is None:
        return ""
    most, units, counted = limit
    size = size_of(value, units=units)
    if size is None:
        return f"write {keyword} as a plain number" + (" with k, m or g" if units else "")
    if size > most:
        return f"{keyword} is at most {most} {counted} here: {MEMORY}"
    return ""


def cache_megabytes(section: Section) -> int:
    """What an added cache section asks for, in MB, for the cluster's sum."""

    for line in section.lines:
        tokens = words(line.text)
        if tokens[:1] == ["total-max-size"] and len(tokens) > 1:
            return size_of(tokens[1], units=False) or 0
    return 0


#
# HAProxy 3.4's proxy keyword matrix, configuration.txt section 4.1, as it is
# printed: keyword, then defaults, frontend, listen and backend. Kept as the
# manual's own rows so a test can hold this against the installed manual line
# for line - a hand-kept list of keywords is the kind that drifts.
#
# The manual leaves some directives out of the matrix on purpose ("one more way
# to discourage anyone to use it"); a keyword that is not here is refused.
#
MATRIX = """\
acl                                       X (!)      X         X         X
backlog                                   X          X         X         -
balance                                   X          -         X         X
be-unpublished                            -          -         X         X
bind                                      -          X         X         -
capture cookie                            -          X         X         -
capture request header                    -          X         X         -
capture response header                   -          X         X         -
clitcpka-cnt                              X          X         X         -
clitcpka-idle                             X          X         X         -
clitcpka-intvl                            X          X         X         -
compression                               X          X         X         X
cookie                                    X          -         X         X
crt                                       -          X         X         -
declare capture                           -          X         X         -
default-server                            X          -         X         X
default_backend                           X          X         X         -
description                               -          X         X         X
disabled                                  X          X         X         X
dispatch                    (deprecated)  -          -         X         X
email-alert from                          X          X         X         X
email-alert level                         X          X         X         X
email-alert mailers                       X          X         X         X
email-alert myhostname                    X          X         X         X
email-alert to                            X          X         X         X
enabled                                   X          X         X         X
errorfile                                 X          X         X         X
errorfiles                                X          X         X         X
errorloc                                  X          X         X         X
errorloc302                               X          X         X         X
errorloc303                               X          X         X         X
error-log-format                          X          X         X         -
external-check command                    X          -         X         X
external-check path                       X          -         X         X
force-persist                             -          -         X         X
force-be-switch                           -          X         X         -
filter                                    -          X         X         X
fullconn                                  X          -         X         X
guid                                      -          X         X         X
hash-balance-factor                       X          -         X         X
hash-preserve-affinity                    X          -         X         X
hash-type                                 X          -         X         X
http-after-response                       X (!)      X         X         X
http-check comment                        X          -         X         X
http-check connect                        X          -         X         X
http-check disable-on-404                 X          -         X         X
http-check expect                         X          -         X         X
http-check send                           X          -         X         X
http-check send-state                     X          -         X         X
http-check set-var                        X          -         X         X
http-check unset-var                      X          -         X         X
http-error                                X          X         X         X
http-request                              X (!)      X         X         X
http-response                             X (!)      X         X         X
http-reuse                                X          -         X         X
http-send-name-header                     X          -         X         X
id                                        -          X         X         X
ignore-persist                            -          -         X         X
load-server-state-from-file               X          -         X         X
log                                  (*)  X          X         X         X
log-format                                X          X         X         -
log-format-sd                             X          X         X         -
log-tag                                   X          X         X         X
log-steps                                 X          X         X         -
max-keep-alive-queue                      X          -         X         X
max-session-srv-conns                     X          X         X         -
maxconn                                   X          X         X         -
mode                                      X          X         X         X
monitor fail                              -          X         X         -
monitor-uri                               X          X         X         -
option abortonclose                  (*)  X          X         X         X
option allbackups                    (*)  X          -         X         X
option checkcache                    (*)  X          -         X         X
option clitcpka                      (*)  X          X         X         -
option contstats                     (*)  X          X         X         -
option disable-h2-upgrade            (*)  X          X         X         -
option dontlog-normal                (*)  X          X         X         -
option dontlognull                   (*)  X          X         X         -
option external-check                     X          -         X         X
option forwardfor                         X          X         X         X
option forwarded                     (*)  X          -         X         X
option h1-case-adjust-bogus-client   (*)  X          X         X         -
option h1-case-adjust-bogus-server   (*)  X          -         X         X
option http-buffer-request           (*)  X          X         X         X
option http-drop-request-trailers    (*)  X          -         -         X
option http-drop-response-trailers   (*)  X          -         X         -
option http-ignore-probes            (*)  X          X         X         -
option http-keep-alive               (*)  X          X         X         X
option http-no-delay                 (*)  X          X         X         X
option http-pretend-keepalive        (*)  X          -         X         X
option http-restrict-req-hdr-names        X          X         X         X
option http-server-close             (*)  X          X         X         X
option http-use-proxy-header         (*)  X          X         X         -
option httpchk                            X          -         X         X
option httpclose                     (*)  X          X         X         X
option httplog                            X          X         X         -
option httpslog                           X          X         X         -
option idle-close-on-response        (*)  X          X         X         -
option independent-streams           (*)  X          X         X         X
option ldap-check                         X          -         X         X
option log-health-checks             (*)  X          -         X         X
option log-separate-errors           (*)  X          X         X         -
option logasap                       (*)  X          X         X         -
option mysql-check                        X          -         X         X
option nolinger                      (*)  X          X         X         X
option originalto                         X          X         X         X
option persist                       (*)  X          -         X         X
option pgsql-check                        X          -         X         X
option prefer-last-server            (*)  X          -         X         X
option redispatch                    (*)  X          -         X         X
option redis-check                        X          -         X         X
option smtpchk                            X          -         X         X
option socket-stats                  (*)  X          X         X         -
option splice-auto                   (*)  X          X         X         X
option splice-request                (*)  X          X         X         X
option splice-response               (*)  X          X         X         X
option spop-check                         X          -         X         X
option srvtcpka                      (*)  X          -         X         X
option ssl-hello-chk                      X          -         X         X
option tcp-check                          X          -         X         X
option tcp-smart-accept              (*)  X          X         X         -
option tcp-smart-connect             (*)  X          -         X         X
option tcpka                              X          X         X         X
option tcplog                             X          X         X         -
option transparent      (deprecated) (*)  X          -         X         X
option use-small-buffers             (*)  X          -         X         X
persist rdp-cookie                        X          -         X         X
quic-initial                              X (!)      X         X         -
rate-limit sessions                       X          X         X         -
redirect                                  -          X         X         X
retries                                   X          -         X         X
retry-on                                  X          -         X         X
server                                    -          -         X         X
server-state-file-name                    X          -         X         X
server-template                           -          -         X         X
source                                    X          -         X         X
srvtcpka-cnt                              X          -         X         X
srvtcpka-idle                             X          -         X         X
srvtcpka-intvl                            X          -         X         X
stats admin                               -          X         X         X
stats auth                                X          X         X         X
stats enable                              X          X         X         X
stats hide-version                        X          X         X         X
stats http-request                        -          X         X         X
stats realm                               X          X         X         X
stats refresh                             X          X         X         X
stats scope                               X          X         X         X
stats show-desc                           X          X         X         X
stats show-legends                        X          X         X         X
stats show-node                           X          X         X         X
stats show-version                        X          X         X         X
stats uri                                 X          X         X         X
stick match                               -          -         X         X
stick on                                  -          -         X         X
stick store-request                       -          -         X         X
stick store-response                      -          -         X         X
stick-table                               -          X         X         X
tcp-check comment                         X          -         X         X
tcp-check connect                         X          -         X         X
tcp-check expect                          X          -         X         X
tcp-check send                            X          -         X         X
tcp-check send-lf                         X          -         X         X
tcp-check send-binary                     X          -         X         X
tcp-check send-binary-lf                  X          -         X         X
tcp-check set-var                         X          -         X         X
tcp-check unset-var                       X          -         X         X
tcp-request connection                    X (!)      X         X         -
tcp-request content                       X (!)      X         X         X
tcp-request inspect-delay                 X (!)      X         X         X
tcp-request session                       X (!)      X         X         -
tcp-response content                      X (!)      -         X         X
tcp-response inspect-delay                X (!)      -         X         X
timeout check                             X          -         X         X
timeout client                            X          X         X         -
timeout client-fin                        X          X         X         -
timeout client-hs                         X          X         X         -
timeout connect                           X          -         X         X
timeout http-keep-alive                   X          X         X         X
timeout http-request                      X          X         X         X
timeout queue                             X          -         X         X
timeout server                            X          -         X         X
timeout server-fin                        X          -         X         X
timeout tarpit                            X          X         X         X
timeout tunnel                            X          -         X         X
transparent                 (deprecated)  X          -         X         X
unique-id-format                          X          X         X         X
unique-id-header                          X          X         X         -
use_backend                               -          X         X         -
use-fcgi-app                              -          -         X         X
use-server                                -          -         X         X
"""

_MATRIX_ROW = re.compile(
    r"^(?P<keyword>[a-z0-9_-]+(?: [a-z0-9_-]+)*)"
    r"\s+(?:\(deprecated\)\s+)?(?P<inverted>\(\*\)\s+)?"
    r"(?P<defaults>[X-])(?: \(!\))?\s+(?P<frontend>[X-])\s+(?P<listen>[X-])\s+(?P<backend>[X-])\s*$"
)


@dataclass(frozen=True, slots=True)
class Keyword:
    words: tuple[str, ...]
    frontend: bool
    backend: bool
    invertible: bool


def parse_matrix(rows: Iterable[str]) -> dict[tuple[str, ...], Keyword]:
    """The matrix rows as keywords, for this module and for the test against the manual."""

    keywords: dict[tuple[str, ...], Keyword] = {}
    for row in rows:
        match = _MATRIX_ROW.fullmatch(row)
        if match is None:
            continue
        words = tuple(match["keyword"].split())
        keywords[words] = Keyword(
            words=words,
            frontend=match["frontend"] == "X",
            backend=match["backend"] == "X",
            invertible=match["inverted"] is not None,
        )
    return keywords


KEYWORDS = parse_matrix(MATRIX.splitlines())
_LONGEST = max(len(words) for words in KEYWORDS)

#
# Always the interface's (B215 class 1, B223 point 6). `source` because the
# address a pool is reached from is what a firewall further in is written
# against, and the object's is set by the interface; `guid` because the
# generator writes every section's; the routing because the frontend is
# shared; `bind` because an address is the cluster's. `dispatch` and
# `transparent` are deprecated ways of naming where a connection goes or comes
# from, which is the same question as `source`.
#
STATE_FILE = (
    "a server state file is one the node reads as root; state across a reload is the cluster's"
)
EXTERNAL_CHECK = "an external check runs a program on the node"
REFUSED = {
    ("bind",): "the address an object listens on is set in the form",
    ("use_backend",): "routing is the interface's: the frontend is shared",
    ("default_backend",): "routing is the interface's: the frontend is shared",
    ("source",): "the address a pool is reached from is set by the interface",
    ("guid",): "the generator gives every section its identity",
    ("dispatch",): "a deprecated way of naming the destination; routing is the interface's",
    ("transparent",): "a deprecated form of source, which the interface sets",
    ("option", "transparent"): "a deprecated form of source, which the interface sets",
    #
    # Keywords that name a file or a program on the node (E1). A server state
    # file is read as root at load from any path it is given, and state across
    # a reload is the cluster's (`shm-stats-file` in `core/`); an external
    # check runs a program; `crt` names a certificate and its key, which the
    # form chooses.
    #
    ("server-state-file-name",): STATE_FILE,
    ("load-server-state-from-file",): STATE_FILE,
    ("external-check", "command"): EXTERNAL_CHECK,
    ("external-check", "path"): EXTERNAL_CHECK,
    ("option", "external-check"): EXTERNAL_CHECK,
    ("crt",): "a certificate and its key are files on the node; the form chooses them",
}

#
# The keywords that make up a pool (B215 class 2). The form's when the pool is
# filled in there, and the text's when the object has chosen a pool written by
# hand (B223 point 5, B224). Without the choice they are skipped, not refused:
# the line is fine, it is just not this text's to say.
#
POOL = frozenset(
    {
        ("server",),
        ("server-template",),
        ("default-server",),
        ("balance",),
        ("hash-type",),
        ("hash-balance-factor",),
        ("hash-preserve-affinity",),
        ("cookie",),
        ("option", "httpchk"),
        ("option", "tcp-check"),
        ("option", "ssl-hello-chk"),
        ("option", "ldap-check"),
        ("option", "mysql-check"),
        ("option", "pgsql-check"),
        ("option", "redis-check"),
        ("option", "smtpchk"),
        ("option", "spop-check"),
        ("option", "external-check"),
        ("external-check", "command"),
        ("external-check", "path"),
        ("timeout", "check"),
        ("timeout", "connect"),
        ("timeout", "server"),
        ("timeout", "tunnel"),
        ("timeout", "queue"),
    }
)
POOL_PREFIXES = (("http-check",), ("tcp-check",))

#
# Keywords a tcp object cannot use. Measured on 3.4.6 (2026-10-01): in `mode
# tcp` some of these are ignored with a warning that names no line, and the rest
# - `http-error`, `capture`, `compression`, `errorfile`, `http-reuse`,
# `unique-id-header`, the HTTP timeouts - are accepted without a word and do
# nothing. Either way the text would promise something the object does not do.
#
TCP_REFUSED_PREFIXES = (
    ("http-request",),
    ("http-response",),
    ("http-after-response",),
    ("http-error",),
    ("http-reuse",),
    ("http-send-name-header",),
    ("redirect",),
    ("capture",),
    ("declare", "capture"),
    ("cookie",),
    ("compression",),
    ("stats",),
    ("monitor-uri",),
    ("monitor",),
    ("unique-id-header",),
    ("errorfile",),
    ("errorfiles",),
    ("errorloc",),
    ("errorloc302",),
    ("errorloc303",),
    ("use-fcgi-app",),
    ("timeout", "http-request"),
    ("timeout", "http-keep-alive"),
    ("option", "forwardfor"),
    ("option", "forwarded"),
    ("option", "originalto"),
    ("option", "httplog"),
    ("option", "httpslog"),
    ("option", "httpclose"),
    ("option", "http-buffer-request"),
    ("option", "http-drop-request-trailers"),
    ("option", "http-drop-response-trailers"),
    ("option", "http-ignore-probes"),
    ("option", "http-keep-alive"),
    ("option", "http-no-delay"),
    ("option", "http-pretend-keepalive"),
    ("option", "http-restrict-req-hdr-names"),
    ("option", "http-server-close"),
    ("option", "http-use-proxy-header"),
    ("option", "disable-h2-upgrade"),
    ("option", "h1-case-adjust-bogus-client"),
    ("option", "h1-case-adjust-bogus-server"),
)
TCP_REFUSED_FILTERS = frozenset({"compression", "cache", "fcgi-app"})

#
# The stick counter slots (B223 point 3). The cluster's brake tracks the first
# in the shared frontend and the object's rate limit the second; a stream tracks
# each slot once, and a second `track-sc0` is ignored without a word - read in
# the 3.4.6 manual, and `haproxy -c` accepts it.
#
CLUSTER_SLOT = 0
RATE_SLOT = 1
#
# Dynamic blocking counts on the fourth slot and marks on the fifth (B271),
# which is why a cluster with it needs `tune.stick-counters 5`.
#
BLOCK_SLOTS = (3, 4)
TRACK = re.compile(r"^track-sc([0-9]+)$")
COUNTER_ACTION = re.compile(r"^sc-[a-z0-9-]+\(([^)]*)\)$")
STICK_RULES = frozenset({"on", "match", "store-request", "store-response"})

#
# What a line may write to by name: a table, a ring or a cache this same text
# adds, and nothing else (code review 2026-10-30 again, R2, R5, B3). A name
# that merely begins with the object's is not enough - `shop` and `shop-api`
# are two objects, and a pool may be called anything - so the text's own
# sections are read first and a name is held to them exactly. A table is a
# backend the text adds; HAProxy names a table after its section.
#
Own = Mapping[str, frozenset[str]]
NOT_OWN_TABLE = "{table} is not a table this text adds; a line writes only to its own"
NOT_OWN_RING = "{ring} is not a ring this text adds; a line writes only to its own"
#
# The sample fetches and converters that change a table rather than read it:
# they create the entry when it is missing, so `src,table_inc_gpc0(<table>)`
# put a visitor into another object's dynamic blocking. The table is the last
# argument, at the position given by the form of the name.
#
_TABLE_WRITER = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<function>(?P<kind>sc[0-9]*|src|table)_"
    r"(?:(?:inc|clr)_gpc(?P<array>[01]?)|updt_conn_cnt))(?:\((?P<arguments>[^)]*)\))?"
)
_DEBUG = re.compile(r"(?<![A-Za-z0-9_.-])debug\((?P<arguments>[^)]*)\)")

#
# Fates a line can have, as the dialog and the CLI say them.
#
PLACED = "placed"
SKIPPED = "skipped"
REFUSED_FATE = "refused"
IGNORED = "ignored"

#
# Where an object row lands.
#
FRONTEND = "frontend"
BACKEND = "backend"

#
# The comment in front of every block the generator writes from the text. It
# says which lines of which object follow, so the generated file maps itself
# back to the text without anything carried beside it: `haproxy -c` names a
# file and a line, and `text_line_of` turns that into the object and the line
# somebody pasted. Read on a node too, by whoever opens conf.d.
#
BLOCK_COMMENT = "# advanced config of {name}: lines {lines}"
_BLOCK = re.compile(r"^\s*# advanced config of (?P<name>\S+): lines (?P<lines>\d+(?: \d+)*)\s*$")

MAX_LINE = 4096


@dataclass(frozen=True, slots=True)
class Line:
    """One line of the text and what became of it."""

    number: int
    text: str
    fate: str
    where: str = ""
    reason: str = ""


@dataclass(frozen=True, slots=True)
class Section:
    """A section the text adds, written as it stands under its own name."""

    kind: str
    name: str
    header: Line
    lines: tuple[Line, ...]


@dataclass(frozen=True, slots=True)
class Placement:
    lines: tuple[Line, ...]
    frontend: tuple[Line, ...] = ()
    """A tcp object's frontend rows. Always empty for http, whose frontend is shared."""

    backend: tuple[Line, ...] = ()
    """Rows for every pool of the object - for a tcp object, its one pool."""

    sections: tuple[Section, ...] = ()
    servers: tuple[tuple[str, str], ...] = field(default=())
    """`(name, host:port)` of each `server` line in a pool written by hand."""

    @property
    def refused(self) -> tuple[Line, ...]:
        return tuple(line for line in self.lines if line.fate == REFUSED_FATE)


class TextError(ValueError):
    """The text cannot be read as lines at all."""


def normalise(text: str) -> str:
    """The text as it is stored: Unix line ends, no trailing blanks, one final newline.

    Trailing blanks are the one change, and they carry nothing in HAProxy's
    grammar. They are dropped because YAML cannot keep a block of text with them
    as a block - PyYAML falls back to one quoted line full of `\\n` - and the
    text is read in diffs.
    """

    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}


def words(line: str) -> list[str]:
    """A line split as HAProxy splits it (configuration.txt 2.2).

    Quotes group, a backslash escapes outside single quotes, and an unquoted
    `#` ends the line. `\\n`, `\\r`, `\\t` and `\\xNN` are the characters they
    stand for, as HAProxy reads them: taken as a backslash and a letter, the
    word `\\x67lobal` was `x67lobal` here and the section `global` on the node,
    and every refusal below could be spelled past (code review 2026-10-22,
    5-1). Only the words are needed - which keyword this is, and whether a
    parameter such as `source` or `track-sc0` occurs - so variables are left as
    written.
    """

    result: list[str] = []
    current: list[str] = []
    started = False
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote == "'":
            if char == "'":
                quote = ""
            else:
                current.append(char)
        elif char == "\\" and index + 1 < len(line):
            index += 1
            escaped = line[index]
            if escaped == "x":
                digits = line[index + 1 : index + 3]
                if len(digits) != 2 or any(digit not in string.hexdigits for digit in digits):
                    raise TextError("\\x takes two hexadecimal digits")
                current.append(chr(int(digits, 16)))
                index += 2
            else:
                current.append(_ESCAPES.get(escaped, escaped))
            started = True
        elif quote == '"':
            if char == '"':
                quote = ""
            else:
                current.append(char)
        elif char in "'\"":
            quote = char
            started = True
        elif char == "#":
            break
        elif char in " \t":
            if started:
                result.append("".join(current))
                current, started = [], False
        else:
            current.append(char)
            started = True
        index += 1
    if quote:
        raise TextError("a quote is not closed")
    if started:
        result.append("".join(current))
    return result


def keyword_of(tokens: Sequence[str]) -> tuple[tuple[str, ...] | None, Keyword | None]:
    """The matrix keyword a line starts with, longest match first.

    `no` and `default` in front of an option HAProxy marks as invertible are
    part of the line and not of the keyword.
    """

    rest = list(tokens)
    inverted = False
    if rest and rest[0] in ("no", "default") and len(rest) > 1:
        rest = rest[1:]
        inverted = True
    for length in range(min(_LONGEST, len(rest)), 0, -1):
        found = KEYWORDS.get(tuple(rest[:length]))
        if found is not None:
            if inverted and not found.invertible:
                return None, None
            return found.words, found
    return None, None


def _starts(words_: tuple[str, ...], prefixes: Iterable[tuple[str, ...]]) -> bool:
    return any(words_[: len(prefix)] == prefix for prefix in prefixes)


def _counter_problem(
    tokens: Sequence[str],
    keyword: tuple[str, ...],
    own: Own,
    rate_limit: bool,
    *,
    own_table: bool,
    dynamic_block: bool = False,
) -> str:
    """Why this rule's stick counter cannot be the text's, or "".

    Read in the action's place only - the word after the rule keyword, as in
    `http-request track-sc2` or `tcp-request content sc-inc-gpc0(1)` - so a
    header value that happens to say `track-sc0` is a value and not a counter.

    `own_table` is a section of the text's own, where a counter without `table`
    is that section's table. On the object's rows it would be the pool's table,
    which is the rate limit's, so a table must be named there.
    """

    index = len(keyword)
    if len(tokens) <= index:
        return ""
    action = tokens[index]
    rest = list(tokens[index + 1 :])
    track = TRACK.fullmatch(action)
    if track:
        slot = int(track[1])
        table = rest[rest.index("table") + 1] if "table" in rest[:-1] else None
        if slot == CLUSTER_SLOT:
            return "sc0 is the cluster's abuse brake; the text counts on sc2"
        if slot == RATE_SLOT and rate_limit:
            return "sc1 is this object's rate limit; the text counts on sc2"
        if slot in BLOCK_SLOTS and dynamic_block:
            return f"sc{slot} is this object's dynamic blocking; the text counts on sc2"
        if table is None and not own_table:
            return (
                "a counter here needs `table <name>` of a backend the text adds: "
                "the pool's own table is the rate limit's"
            )
        if table is not None and table not in own["backend"]:
            return NOT_OWN_TABLE.format(table=table)
        return ""
    counter = COUNTER_ACTION.fullmatch(action)
    if counter:
        problem = _changed_slot_problem(
            counter[1].split(",")[-1], rate_limit=rate_limit, dynamic_block=dynamic_block
        )
        if problem:
            return problem
    #
    # And the fetches that change the counter they read: `sc0_inc_gpc0`, or
    # `sc_clr_gpc(<idx>,<slot>)`, anywhere on the line.
    #
    for word in tokens:
        for match in _TABLE_WRITER.finditer(word):
            if match["kind"] == "sc":
                arguments = (match["arguments"] or "").split(",")
                at = 1 if match["array"] == "" else 0
                slot = arguments[at] if len(arguments) > at else ""
            elif match["kind"].startswith("sc"):
                slot = match["kind"].removeprefix("sc")
            else:
                continue
            problem = _changed_slot_problem(
                slot, rate_limit=rate_limit, dynamic_block=dynamic_block
            )
            if problem:
                return problem
    return ""


#
# A slot as HAProxy reads one where a line changes a counter: an optional
# sign, then digits - `sc-inc-gpc0(+0)` and `sc_inc_gpc0(-0)` are slot 0 to it
# (measured on 3.4.7, code review 2026-10-30 again, R4). Anything else is
# refused rather than guessed at.
#
_SLOT = re.compile(r"[+-]?[0-9]{1,6}")


def _changed_slot_problem(written: str, *, rate_limit: bool, dynamic_block: bool) -> str:
    """Why a line may not change the counter in this slot, or ""."""

    written = written.strip()
    if not _SLOT.fullmatch(written):
        return f"write the counter's slot as a number, not {written!r}"
    slot = int(written)
    if slot == CLUSTER_SLOT:
        return "sc0 is the cluster's abuse brake; the text may read it but not change it"
    if slot == RATE_SLOT and rate_limit:
        return "sc1 is this object's rate limit; the text may read it but not change it"
    if slot in BLOCK_SLOTS and dynamic_block:
        return f"sc{slot} is this object's dynamic blocking; the text may read it but not change it"
    return ""


def _stick_problem(tokens: Sequence[str], keyword: tuple[str, ...], own: Own) -> str:
    if keyword[:1] != ("stick",) or len(keyword) < 2 or keyword[1] not in STICK_RULES:
        return ""
    if "table" not in tokens[:-1]:
        return (
            "a stick rule here needs `table <name>` of a backend the text adds: "
            "the pool's own table is the rate limit's"
        )
    table = tokens[tokens.index("table") + 1]
    if table not in own["backend"]:
        return NOT_OWN_TABLE.format(table=table)
    return ""


def _written_problem(tokens: Sequence[str], own: Own, *, own_table: bool) -> str:
    """Why a fetch or converter on this line writes to a table or ring not the text's, or ""."""

    for word in tokens:
        for match in _TABLE_WRITER.finditer(word):
            arguments = [part.strip() for part in (match["arguments"] or "").split(",")]
            at = (match["kind"] == "sc") + (match["array"] == "")
            table = arguments[at] if len(arguments) > at and arguments[at] else None
            if table is None:
                if match["kind"] in ("src", "table") and not own_table:
                    return (
                        f"{match['function']} here needs a table of a backend the text adds: "
                        "the pool's own table is the rate limit's"
                    )
                continue
            if any(char in table for char in "'\"\\"):
                return "write a table's name plainly, without quotes or backslashes"
            if table not in own["backend"]:
                return NOT_OWN_TABLE.format(table=table)
        for match in _DEBUG.finditer(word):
            arguments = match["arguments"].split(",")
            if len(arguments) > 1:
                ring = arguments[1].strip()
                if ring not in own["ring"]:
                    return NOT_OWN_RING.format(ring=ring)
    return ""


#
# A stick table's parameters, with how many words each takes, from the
# synopsis in configuration.txt 11.1 (a test holds it there). `len` follows a
# `string` or `binary` type. Read parameter by parameter like a server line,
# so `write-to` - which copies every update a peer sends into the named table
# and creates the entry there (R2) - is seen whatever comes before it.
#
STICK_TABLE_PARAMETERS = {
    "type": 1,
    "len": 1,
    "size": 1,
    "expire": 1,
    "nopurge": 0,
    "recv-only": 0,
    "write-to": 1,
    "srvkey": 1,
    "store": 1,
    "brates-factor": 1,
    "peers": 1,
}


def _stick_table_problem(tokens: Sequence[str], keyword: tuple[str, ...], own: Own) -> str:
    if keyword != ("stick-table",):
        return ""
    index = 1
    while index < len(tokens):
        parameter = tokens[index]
        width = STICK_TABLE_PARAMETERS.get(parameter)
        if width is None:
            return f"{parameter} is not a stick-table parameter in HAProxy 3.4"
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        if parameter == "write-to" and value not in own["backend"]:
            return NOT_OWN_TABLE.format(table=value)
        problem = _limit_problem("stick-table", parameter, value)
        if problem:
            return problem
        index += 1 + width
    return ""


def _waf_problem(tokens: Sequence[str], keyword: tuple[str, ...]) -> str:
    """The WAF engine's names, which only the generated lines may use (B232).

    Its SPOE engine, and the `txn.coraza.*` variables its verdict is read
    from: a line that set, cleared or sent them could make the engine's answer
    say something it did not.
    """

    if keyword == ("filter",) and tokens[1:2] == ["spoe"] and "coraza" in tokens:
        return "the coraza SPOE engine is the WAF engine's, set on the object's form"
    if any("txn.coraza." in word or word == "coraza-req" for word in tokens):
        return "the txn.coraza variables are the WAF engine's answer, set by the generator"
    return ""


#
# A server's parameters, with how many words each takes: HAProxy 3.4.7's own
# list as `haproxy -dKcfg` prints it after `server <name> <addr>`, where `+1`
# is one word of value. A test holds it against the installed binary. A
# server line is read parameter by parameter, so a value is never mistaken for
# a parameter or the other way round, and a word that is not one of these is
# refused (E1).
#
# Left out, and so refused: `source` and `usesrc` (the interface's), `guid`
# (the generator's), `crt` (a certificate and its key, files on the node),
# `crl-file` (a file the node reads as root) and `namespace` (a network
# namespace is a file under /var/run/netns, and with it the address the pool
# is reached from). `ca-file` is held to the trust store and the cluster's
# authorities below; `addr`, `agent-addr` and `socks4` to network addresses.
#
SERVER_LIST = """\
addr +1
agent-addr +1
agent-check
agent-inter +1
agent-port +1
agent-send +1
allow-0rtt
alpn +1
backup
ca-file +1
cc +1
check
check-alpn +1
check-pool-conn-name +1
check-proto +1
check-reuse-pool
check-send-proxy
check-sni +1
check-sni-auto
check-ssl
check-via-socks4
ciphers +1
ciphersuites +1
client-sigalgs +1
cookie +1
curves +1
disabled
downinter +1
enabled
error-limit +1
fall +1
fastinter +1
force-sslv3
force-tlsv10
force-tlsv11
force-tlsv12
force-tlsv13
hash-key +1
healthcheck +1
id +1
idle-ping +1
init-addr +1
init-state +1
inter +1
ktls +1
log-bufsize +1
log-proto +1
max-reuse +1
maxconn +1
maxqueue +1
minconn +1
no-agent-check
no-backup
no-check
no-check-reuse-pool
no-check-send-proxy
no-check-sni-auto
no-check-ssl
no-renegotiate
no-send-proxy
no-send-proxy-v2
no-send-proxy-v2-ssl
no-send-proxy-v2-ssl-cn
no-sni-auto
no-ssl
no-ssl-reuse
no-sslv3
no-tfo
no-tls-tickets
no-tlsv10
no-tlsv11
no-tlsv12
no-tlsv13
non-stick
npn +1
observe +1
on-error +1
on-marked-down +1
on-marked-up +1
pool-conn-name +1
pool-low-conn +1
pool-max-conn +1
pool-purge-delay +1
port +1
proto +1
proxy-v2-options +1
quic-cc-algo +1
redir +1
renegotiate
resolve-net +1
resolve-opts +1
resolve-prefer +1
resolvers +1
rise +1
send-proxy
send-proxy-v2
send-proxy-v2-ssl
send-proxy-v2-ssl-cn
shard +1
sigalgs +1
slowstart +1
sni +1
sni-auto
socks4 +1
ssl
ssl-max-ver +1
ssl-min-ver +1
ssl-reuse
stick
strict-maxconn
tcp-md5sig +1
tcp-ut +1
tfo
tls-tickets
track +1
verify +1
verifyhost +1
weight +1
ws +1
"""


def parse_server_list(rows: Iterable[str]) -> dict[str, int]:
    """`haproxy -dK`'s server rows as parameter and width, for this module and its test."""

    parameters: dict[str, int] = {}
    for row in rows:
        words_ = row.split()
        if words_:
            parameters[words_[0]] = 1 if words_[1:] == ["+1"] else 0
    return parameters


SERVER_PARAMETERS = parse_server_list(SERVER_LIST.splitlines())
#
# Written `set-proxy-v2-tlv-fmt(<id>) <fmt>`: the keyword carries its TLV type
# in the same word, and the format follows.
#
_TLV_PARAMETER = re.compile(r"^set-proxy-v2-tlv-fmt\([^)]*\)$")
SERVER_REFUSED = {
    "source": "the address a pool is reached from is set by the interface",
    "usesrc": "the address a pool is reached from is set by the interface",
    "guid": "the generator gives every server its identity",
    "crt": "a certificate and its key are files on the node; the form chooses them",
    "crl-file": "a revocation list is a file the node reads as root",
    "namespace": "a network namespace is a file on the node, and sets where the pool is reached from",
}
#
# A network address, with the prefixes that keep it one: no `/path`, `unix@`,
# `abns@`, `fd@` or `sockpair@`, which are sockets on the node rather than
# somewhere on the network. A server is reached over TCP; a log target may
# also be UDP.
#
_HOST = r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._:-]*)(?::[+-]?[0-9]{1,5})?"
SERVER_ADDRESS = re.compile(rf"^(?:(?:ipv4|ipv6|tcp|tcp4|tcp6)@)?{_HOST}$")
LOG_ADDRESS = re.compile(rf"^(?:(?:ipv4|ipv6|tcp|tcp4|tcp6|udp|udp4|udp6)@)?{_HOST}$")
#
# Where the trust a server is verified against may come from: the operating
# system's store by HAProxy's own name for it, or one of the cluster's
# authorities, which the generator names the same way (B276). Both are public
# certificates.
#
SYSTEM_CA = "@system-ca"
AUTHORITIES = "/etc/haproxy/certs/ca/"
NOT_AN_ADDRESS = "a server is reached at a network address, not a socket or file on the node"


#
# A file the text may name is held to the form the generator itself writes,
# not read as a path: a directory, then one name of plain characters. With no
# `/` after the directory and no leading dot, neither `..` nor any other way
# out of it can be spelled, however the line is read. That matters because
# HAProxy reads a converter's arguments twice - once as words, then again as
# arguments, where `'` and `"` are taken away a second time - so `\'..\'` was
# a name here and `..` to HAProxy, and a map read any file on the node as
# root (code review 2026-10-30 again, R1). The class has no quote and no
# backslash, so the second reading cannot change a name it lets through.
#
FILE_NAME = r"[A-Za-z0-9_-][A-Za-z0-9._-]*"


def _file_in(directory: str, name: str = FILE_NAME) -> re.Pattern[str]:
    return re.compile(rf"{re.escape(directory)}{name}")


AUTHORITY_FILE = _file_in(AUTHORITIES)


def _server_problem(tokens: Sequence[str], keyword: tuple[str, ...]) -> str:
    """Why a `server`, `server-template` or `default-server` line cannot be the text's, or ""."""

    if keyword == ("server",):
        address_at = 2
    elif keyword == ("server-template",):
        address_at = 3
    elif keyword == ("default-server",):
        address_at = 0
    else:
        return ""
    if address_at:
        if len(tokens) <= address_at:
            return ""
        if not SERVER_ADDRESS.fullmatch(tokens[address_at]):
            return NOT_AN_ADDRESS
    index = address_at + 1
    while index < len(tokens):
        parameter = tokens[index]
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        if parameter in SERVER_REFUSED:
            return SERVER_REFUSED[parameter]
        if _TLV_PARAMETER.fullmatch(parameter):
            width = 1
        elif parameter in SERVER_PARAMETERS:
            width = SERVER_PARAMETERS[parameter]
        else:
            return f"{parameter} is not a server parameter in HAProxy 3.4"
        if parameter == "ca-file" and value != SYSTEM_CA and not AUTHORITY_FILE.fullmatch(value):
            return (
                f"a server is verified against {SYSTEM_CA} or one of the cluster's "
                f"authorities under {AUTHORITIES}"
            )
        if parameter in ("addr", "agent-addr", "socks4") and not SERVER_ADDRESS.fullmatch(value):
            return NOT_AN_ADDRESS
        index += 1 + width
    return ""


#
# The files a line may make HAProxy serve: the error pages the haproxy package
# installs, and nothing else. HAProxy reads such a file as root when it loads
# the configuration and hands it to whoever asks, and the candidate's sandbox
# checks the line against a placeholder - so `return ... file` naming another
# object's certificate served its key (code review 2026-10-22, 5-2).
#
ERROR_PAGES = "/etc/haproxy/errors/"
ERROR_PAGE = _file_in(ERROR_PAGES, r"[0-9]{3}\.http")
#
# Where a file follows: `errorfile <code> <file>` as a keyword, and the
# payload words of `return` and `http-error`.
#
_FILE_WORDS = frozenset({"file", "lf-file", "errorfile"})
_FILE_KEYWORDS = frozenset(
    {("http-request",), ("http-response",), ("http-after-response",), ("http-error",)}
)


def _file_problem(tokens: Sequence[str], keyword: tuple[str, ...] | None) -> str:
    named: list[str] = []
    if tokens and tokens[0] == "errorfile":
        named.extend(tokens[2:3])
    elif keyword is not None and keyword[:1] in _FILE_KEYWORDS:
        named.extend(
            tokens[index + 1] for index, word in enumerate(tokens[:-1]) if word in _FILE_WORDS
        )
    for path in named:
        if not ERROR_PAGE.fullmatch(path):
            return f"a file the text names must be one of the error pages under {ERROR_PAGES}"
    return ""


#
# Where a log line may go: the cluster's own log setting, a ring the text adds,
# or a syslog server on the network. A path, `unix@`, `fd@`, `stdout` and the
# like are sockets and descriptors on the node; `backend@` sends through a log
# backend, which is not a form this module checks.
#
LOG_STREAMS = frozenset({"stdout", "stderr"})


def _log_problem(tokens: Sequence[str], keyword: tuple[str, ...], own: Own) -> str:
    if keyword != ("log",):
        return ""
    at = tokens.index("log") + 1
    if at >= len(tokens) or tokens[0] in ("no", "default"):
        return ""
    target = tokens[at]
    if target == "global":
        return ""
    if target.startswith("ring@"):
        ring = target.removeprefix("ring@")
        return "" if ring in own["ring"] else NOT_OWN_RING.format(ring=ring)
    if target in LOG_STREAMS or not LOG_ADDRESS.fullmatch(target):
        return "a log goes to global, a ring of the text's or a syslog server's network address"
    return ""


#
# The filters the text may add (`haproxy -dKflt` on 3.4.7, held against it by
# a test). Left out: `spoe` and `opentracing`, which read a configuration file
# on the node as root (the WAF engine's own SPOE is the form's), and
# `fcgi-app`, whose section is refused.
#
FILTERS = frozenset(
    {"bwlim-in", "bwlim-out", "cache", "comp-req", "comp-res", "compression", "trace"}
)


def _filter_problem(tokens: Sequence[str], keyword: tuple[str, ...]) -> str:
    if keyword != ("filter",) or len(tokens) < 2 or tokens[1] in FILTERS:
        return ""
    if tokens[1] in ("spoe", "opentracing"):
        return f"the {tokens[1]} filter reads its configuration from a file on the node"
    return f"{tokens[1]} is not a filter the text may add"


#
# Lists read from a file: an ACL's `-f <file>` and the `map*` converters'
# first argument. HAProxy reads them as root when it loads, so they are held
# to the cluster's lists, which the release carries to every node (B228).
# The actions that change a list at run time - `set-map`, `del-map`,
# `add-acl`, `del-acl` - are refused whatever they name: a list is shared by
# every line that reads it, other objects' included. `jwt_verify` and its
# kin read a key or certificate file when they name one.
#
MAPS = "/etc/haproxy/maps/"
MAP_FILE = _file_in(MAPS)
_MAP_CONVERTER = re.compile(r"(?<![A-Za-z0-9_.-])map(?:_[a-z0-9_]+)?\(([^,)]*)")
_LIST_ACTION = re.compile(r"^(?:set-map|del-map|add-acl|del-acl)\(")
_JWT_FILE = re.compile(r"(?<![A-Za-z0-9_.-])jwt_(?:verify|verify_cert|decrypt_cert)\(([^)]*)\)")


def _list_problem(tokens: Sequence[str]) -> str:
    named: list[str] = []
    for index, word in enumerate(tokens):
        if word == "-f":
            named.append(tokens[index + 1] if index + 1 < len(tokens) else "")
        if _LIST_ACTION.match(word):
            return (
                "a list is shared by every line that reads it; the text may read one, not change it"
            )
        named.extend(match[1] for match in _MAP_CONVERTER.finditer(word))
        if any("/" in match[1] for match in _JWT_FILE.finditer(word)):
            return "a key or certificate file is one the node reads as root"
    for path in named:
        if not MAP_FILE.fullmatch(path):
            return f"a list the text reads must be one of the cluster's under {MAPS}"
    return ""


def expands_variable(line: str) -> bool:
    """Whether HAProxy would put an environment variable's value into this line.

    It does inside double quotes only (configuration.txt 2.3, and measured on
    3.4.7: `"${PWD}/x"` is expanded, `${PWD}/x` and `$PWD/x` are not). Every
    check here reads the words as written, and a variable's value is the
    node's - `"${HOME}"` is a path no check would see - so such a line is
    refused rather than read.
    """

    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote == "'":
            if char == "'":
                quote = ""
        elif char == "\\":
            index += 1
        elif char == '"':
            quote = "" if quote else '"'
        elif not quote and char == "'":
            quote = "'"
        elif not quote and char == "#":
            return False
        elif quote and char == "$":
            following = line[index + 1 : index + 2]
            if following == "{" or following == "_" or following.isalpha():
                return True
        index += 1
    return False


def _line_problem(
    tokens: Sequence[str], keyword: tuple[str, ...], own: Own, *, own_table: bool
) -> str:
    """What every proxy line is held to, on the object's rows and in an added backend."""

    return (
        _server_problem(tokens, keyword)
        or _waf_problem(tokens, keyword)
        or _filter_problem(tokens, keyword)
        or _file_problem(tokens, keyword)
        or _log_problem(tokens, keyword, own)
        or _list_problem(tokens)
        or _written_problem(tokens, own, own_table=own_table)
        or _stick_table_problem(tokens, keyword, own)
    )


def _section_problem(kind: str, tokens: Sequence[str]) -> str:
    """Why a line of an added cache, http-errors, userlist or ring cannot be written, or ""."""

    allowed = SECTION_KEYWORDS[kind]
    for length in (2, 1):
        words_ = tuple(tokens[:length])
        if len(words_) != length:
            continue
        if (kind, *words_) in SECTION_REFUSED:
            return SECTION_REFUSED[(kind, *words_)]
        if words_ in allowed:
            return (
                _server_problem(tokens, words_)
                or _file_problem(tokens, None)
                or (_limit_problem(kind, tokens[0], tokens[1]) if len(tokens) > 1 else "")
            )
    return f"not a keyword HAProxy 3.4 takes in a {kind} section"


def _server_fact(tokens: Sequence[str]) -> tuple[str, str] | None:
    if len(tokens) < 3 or tokens[0] != "server":
        return None
    address = tokens[2]
    host, _, port = address.rpartition(":")
    if not host or not is_digits(port):
        return None
    return tokens[1], f"{host.strip('[]')}:{port}"


def _header_problem(kind: str, tokens: Sequence[str], name: str) -> str:
    """Why the header of a section the text adds cannot be written, or ""."""

    section_name = tokens[1] if len(tokens) > 1 else ""
    if len(tokens) != 2 or not SECTION_NAME.fullmatch(section_name):
        return f"a {kind} section needs one name"
    if not section_name.startswith(f"{name}-"):
        return (
            f"a section the text adds must be named {name}-…; it is not renamed, "
            "since other files may refer to it by name"
        )
    return ""


def _readable(line: str) -> list[str] | None:
    """The words of a line `place` reads at all, or None for one it ignores or refuses whole."""

    if not line or line.startswith(("#", ".")) or len(line) > MAX_LINE:
        return None
    try:
        tokens = words(line)
    except TextError:
        return None
    if not tokens or expands_variable(line):
        return None
    return tokens


def _own_sections(raw: Sequence[str], name: str) -> Own:
    """The sections the text adds, by kind: what its lines may write to by name."""

    found: dict[str, set[str]] = {kind: set() for kind in EXTRA_SECTIONS}
    for original in raw:
        tokens = _readable(original.strip())
        if tokens and tokens[0] in EXTRA_SECTIONS and not _header_problem(tokens[0], tokens, name):
            found[tokens[0]].add(tokens[1])
    return {kind: frozenset(names) for kind, names in found.items()}


def place(
    text: str,
    *,
    name: str,
    protocol: str,
    rate_limit: bool,
    handwritten: bool,
    dynamic_block: bool = False,
) -> Placement:
    """Decide, line by line, where the text goes and what is refused.

    `rate_limit` is whether the form has the object's limit on (it owns sc1
    then), `dynamic_block` whether its dynamic blocking is (sc3 and sc4), and
    `handwritten` whether the object's one pool is written here
    (B224). The answer covers every line, so the dialog and the CLI can show
    the whole text with what became of each.
    """

    raw = text.replace("\r\n", "\n").split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    own = _own_sections(raw, name)

    lines: list[Line] = []
    frontend: list[Line] = []
    backend: list[Line] = []
    sections: list[Section] = []
    servers: list[tuple[str, str]] = []
    seen_sections: set[str] = set()

    # Where the text currently is: the object's rows, an added section, or a
    # refused one whose lines are refused with it.
    current: tuple[str, str] | None = None
    section_header: Line | None = None
    section_lines: list[Line] = []

    def close() -> None:
        nonlocal section_header, section_lines
        if current is not None and current[0] == "extra" and section_header is not None:
            kind, _, section_name = current[1].partition(" ")
            sections.append(Section(kind, section_name, section_header, tuple(section_lines)))
        section_header, section_lines = None, []

    for number, original in enumerate(raw, start=1):
        line = original.strip()

        def record(
            fate: str, where: str = "", reason: str = "", *, row: str = line, at: int = number
        ) -> Line:
            entry = Line(at, row, fate, where, reason)
            lines.append(entry)
            return entry

        if not line or line.startswith("#"):
            record(IGNORED, reason="comment" if line else "")
            continue
        if len(line) > MAX_LINE:
            record(REFUSED_FATE, reason=f"longer than {MAX_LINE} characters")
            continue
        if line.startswith("."):
            record(
                REFUSED_FATE,
                reason="conditional blocks and directives are the process's, not one object's",
            )
            continue
        try:
            tokens = words(line)
        except TextError as exc:
            record(REFUSED_FATE, reason=str(exc))
            continue
        if not tokens:
            record(IGNORED, reason="comment")
            continue
        if expands_variable(line):
            record(
                REFUSED_FATE,
                reason="an environment variable is the node's, and what it holds is not checked here",
            )
            continue

        first = tokens[0]
        if first in SECTIONS:
            close()
            if first in OBJECT_SECTIONS:
                current = ("object", "")
                record(IGNORED, reason="the object's own rows follow")
                continue
            if first not in EXTRA_SECTIONS:
                current = ("refused", first)
                record(REFUSED_FATE, reason=f"a {first} section is the cluster's or the process's")
                continue
            section_name = tokens[1] if len(tokens) > 1 else ""
            problem = _header_problem(first, tokens, name)
            if not problem and section_name in seen_sections:
                problem = f"the text names {section_name} twice"
            if problem:
                current = ("refused", first)
                record(REFUSED_FATE, reason=problem)
                continue
            seen_sections.add(section_name)
            current = ("extra", f"{first} {section_name}")
            section_header = record(
                PLACED, f"{first} {section_name}", row=f"{first} {section_name}"
            )
            continue

        if current is not None and current[0] == "refused":
            record(REFUSED_FATE, reason=f"inside a refused {current[1]} section")
            continue

        if current is not None and current[0] == "extra":
            kind, _, section_name = current[1].partition(" ")
            where = f"{kind} {section_name}"
            #
            # A cache, http-errors, userlist or ring takes none of the proxy
            # keywords, so it is held to its own list instead of the matrix:
            # a line of it is written only when that list has it.
            #
            if kind != "backend":
                problem = _section_problem(kind, tokens)
                if problem:
                    record(REFUSED_FATE, where, problem)
                else:
                    section_lines.append(record(PLACED, where))
                continue
            keyword, found = keyword_of(tokens)
            problem = ""
            if found is None or keyword is None:
                problem = "not a proxy keyword in HAProxy 3.4's keyword matrix"
            elif not found.backend:
                problem = "HAProxy does not take this in a backend"
            elif keyword in REFUSED:
                problem = (
                    "the generator writes this backend's source and identity"
                    if keyword in (("source",), ("guid",))
                    else REFUSED[keyword]
                )
            else:
                problem = _line_problem(tokens, keyword, own, own_table=True) or _counter_problem(
                    tokens,
                    keyword,
                    own,
                    rate_limit,
                    own_table=True,
                    dynamic_block=dynamic_block,
                )
            if problem:
                record(REFUSED_FATE, where, problem)
            else:
                section_lines.append(record(PLACED, where))
            continue

        # The object's rows.
        keyword, found = keyword_of(tokens)
        if found is None or keyword is None:
            record(REFUSED_FATE, reason="not a proxy keyword in HAProxy 3.4's keyword matrix")
            continue
        if keyword in REFUSED:
            record(REFUSED_FATE, reason=REFUSED[keyword])
            continue
        if keyword == ("mode",):
            record(SKIPPED, reason="the protocol is set in the form")
            continue
        if keyword == ("stick-table",):
            record(
                REFUSED_FATE,
                reason=f"a section holds one table and the pool's is the rate limit's; "
                f"put the table in a backend {name}-… of its own",
            )
            continue
        if protocol == "tcp" and (
            _starts(keyword, TCP_REFUSED_PREFIXES)
            or (keyword == ("filter",) and len(tokens) > 1 and tokens[1] in TCP_REFUSED_FILTERS)
        ):
            record(REFUSED_FATE, reason="HTTP only: a tcp object has no requests")
            continue
        problem = (
            _line_problem(tokens, keyword, own, own_table=False)
            or _counter_problem(
                tokens, keyword, own, rate_limit, own_table=False, dynamic_block=dynamic_block
            )
            or _stick_problem(tokens, keyword, own)
        )
        if problem:
            record(REFUSED_FATE, reason=problem)
            continue

        if keyword in POOL or _starts(keyword, POOL_PREFIXES):
            if not handwritten:
                record(SKIPPED, reason="the pool is the form's")
                continue
            backend.append(record(PLACED, "pool"))
            fact = _server_fact(tokens)
            if fact is not None:
                servers.append(fact)
            continue

        if protocol == "tcp":
            if found.frontend:
                frontend.append(record(PLACED, FRONTEND))
            elif found.backend:
                backend.append(record(PLACED, "pool"))
            else:
                record(
                    REFUSED_FATE, reason="HAProxy takes this in neither a frontend nor a backend"
                )
            continue
        if not found.backend:
            record(
                REFUSED_FATE, reason="frontend only, and the frontend is shared with other objects"
            )
            continue
        backend.append(record(PLACED, "every pool"))

    close()
    return Placement(
        lines=tuple(lines),
        frontend=tuple(frontend),
        backend=tuple(backend),
        sections=tuple(sections),
        servers=tuple(servers),
    )


def block(name: str, rows: Sequence[Line], indent: str = "    ") -> list[str]:
    """Rows as the generator writes them, behind the comment that maps them back."""

    if not rows:
        return []
    numbers = " ".join(str(row.number) for row in rows)
    return [f"{indent}{BLOCK_COMMENT.format(name=name, lines=numbers)}"] + [
        f"{indent}{row.text}" for row in rows
    ]


def section_block(name: str, section: Section, generated: Sequence[str]) -> list[str]:
    """An added section: the comment, its header, its lines, then what the generator adds."""

    numbers = " ".join(str(row.number) for row in (section.header, *section.lines))
    return [
        "",
        BLOCK_COMMENT.format(name=name, lines=numbers),
        section.header.text,
        *(f"    {row.text}" for row in section.lines),
        *generated,
    ]


def text_lines(content: str) -> dict[int, tuple[str, int]]:
    """Which lines of a generated file came from which object's text, and from which line.

    The inverse of `block`: file line (1-based) to `(object, text line)`.
    """

    mapping: dict[int, tuple[str, int]] = {}
    file_lines = content.split("\n")
    index = 0
    while index < len(file_lines):
        match = _BLOCK.fullmatch(file_lines[index])
        if match is None:
            index += 1
            continue
        numbers = [int(value) for value in match["lines"].split()]
        for offset, number in enumerate(numbers, start=1):
            mapping[index + 1 + offset] = (match["name"], number)
        index += 1 + len(numbers)
    return mapping


_PARSING = re.compile(r"parsing \[(?P<path>[^\]:]+):(?P<line>\d+)\]")


def text_line_of(diagnostic: str, files: Mapping[str, str]) -> tuple[str, int] | None:
    """The object and text line a `haproxy -c` message points at, if it points at one.

    `files` are the generated files by name; the message names a path whose
    last part is one of them.
    """

    match = _PARSING.search(diagnostic)
    if match is None:
        return None
    content = files.get(match["path"].rsplit("/", 1)[-1])
    if content is None:
        return None
    return text_lines(content).get(int(match["line"]))


def annotate(diagnostics: str, files: Mapping[str, str]) -> tuple[str, list[str]]:
    """The diagnostics with each line that points into a text said in its terms.

    Returns the annotated text and the warnings that point into a text. A
    publish refuses on those: a warning there is HAProxy saying a pasted line
    will be ignored, and `-c` would otherwise let it through.
    """

    out: list[str] = []
    warnings: list[str] = []
    for message in diagnostics.split("\n"):
        found = text_line_of(message, files)
        if found is None:
            out.append(message)
            continue
        annotated = f"{message} (advanced config of {found[0]}, line {found[1]})"
        out.append(annotated)
        if "[WARNING]" in message:
            warnings.append(annotated)
    return "\n".join(out), warnings
