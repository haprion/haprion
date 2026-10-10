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
  is written as it stands, under a name that must begin with the object's;
* everything else is refused, and so is a line whose meaning would depend on
  something the text cannot see.

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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

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

SECTION_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

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
        match = _MATRIX_ROW.match(row)
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
REFUSED = {
    ("bind",): "the address an object listens on is set in the form",
    ("use_backend",): "routing is the interface's: the frontend is shared",
    ("default_backend",): "routing is the interface's: the frontend is shared",
    ("source",): "the address a pool is reached from is set by the interface",
    ("guid",): "the generator gives every section its identity",
    ("dispatch",): "a deprecated way of naming the destination; routing is the interface's",
    ("transparent",): "a deprecated form of source, which the interface sets",
    ("option", "transparent"): "a deprecated form of source, which the interface sets",
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
TRACK = re.compile(r"^track-sc(\d+)$")
COUNTER_ACTION = re.compile(r"^sc-[a-z0-9-]+\(([^)]*)\)$")
STICK_RULES = frozenset({"on", "match", "store-request", "store-response"})

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


def words(line: str) -> list[str]:
    """A line split as HAProxy splits it (configuration.txt 2.2).

    Quotes group, a backslash escapes outside single quotes, and an unquoted
    `#` ends the line. Only the words are needed - which keyword this is, and
    whether a parameter such as `source` or `track-sc0` occurs - so variables
    are left as written.
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
            current.append(line[index])
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
    name: str,
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
    track = TRACK.match(action)
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
        if table is not None and not table.startswith(f"{name}-"):
            return f"the table must be one this text adds, named {name}-…"
        return ""
    counter = COUNTER_ACTION.match(action)
    if counter:
        last = counter[1].split(",")[-1].strip()
        slot_written = int(last) if last.isdigit() else None
        if slot_written == CLUSTER_SLOT:
            return "sc0 is the cluster's abuse brake; the text may read it but not change it"
        if slot_written == RATE_SLOT and rate_limit:
            return "sc1 is this object's rate limit; the text may read it but not change it"
        if slot_written in BLOCK_SLOTS and dynamic_block:
            return (
                f"sc{slot_written} is this object's dynamic blocking; "
                f"the text may read it but not change it"
            )
    return ""


def _stick_problem(tokens: Sequence[str], keyword: tuple[str, ...], name: str) -> str:
    if keyword[:1] != ("stick",) or len(keyword) < 2 or keyword[1] not in STICK_RULES:
        return ""
    if "table" not in tokens[:-1]:
        return (
            "a stick rule here needs `table <name>` of a backend the text adds: "
            "the pool's own table is the rate limit's"
        )
    table = tokens[tokens.index("table") + 1]
    if not table.startswith(f"{name}-"):
        return f"the table must be one this text adds, named {name}-…"
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


def _server_problem(tokens: Sequence[str], keyword: tuple[str, ...]) -> str:
    if keyword not in (("server",), ("server-template",), ("default-server",)):
        return ""
    for token in tokens[1:]:
        if token in ("source", "usesrc"):
            return "the address a pool is reached from is set by the interface"
        if token in ("guid",):
            return "the generator gives every server its identity"
    return ""


def _server_fact(tokens: Sequence[str]) -> tuple[str, str] | None:
    if len(tokens) < 3 or tokens[0] != "server":
        return None
    address = tokens[2]
    host, _, port = address.rpartition(":")
    if not host or not port.isdigit():
        return None
    return tokens[1], f"{host.strip('[]')}:{port}"


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
            problem = ""
            if len(tokens) != 2 or not SECTION_NAME.match(section_name):
                problem = f"a {first} section needs one name"
            elif not section_name.startswith(f"{name}-"):
                problem = (
                    f"a section the text adds must be named {name}-…; it is not renamed, "
                    "since other files may refer to it by name"
                )
            elif section_name in seen_sections:
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
            if kind != "backend":
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
                problem = (
                    _server_problem(tokens, keyword)
                    or _waf_problem(tokens, keyword)
                    or _counter_problem(
                        tokens,
                        keyword,
                        name,
                        rate_limit,
                        own_table=True,
                        dynamic_block=dynamic_block,
                    )
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
            _server_problem(tokens, keyword)
            or _waf_problem(tokens, keyword)
            or _counter_problem(
                tokens, keyword, name, rate_limit, own_table=False, dynamic_block=dynamic_block
            )
            or _stick_problem(tokens, keyword, name)
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
        match = _BLOCK.match(file_lines[index])
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
