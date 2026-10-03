"""Turn a filled-in form into a proxy object, and that object into configuration.

This is the page where somebody can see what the generator does before any of
it is published. Nothing here writes anything: it builds the YAML document an
object would be stored as, runs it through the engine's own parser, and shows
both that document and the HAProxy configuration it produces.

The form does not build a `Proxy` directly. It writes the same YAML the
application will one day store under `managed/proxies/`, and hands it to
`load_proxy` - the parser the command line uses. A form that constructed the
object itself would be a second interpretation of the schema, and the two would
drift in the direction nobody notices: the interface would accept something the
engine refuses, or refuse something it accepts, and the difference would show up
during a publish rather than here.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from haproxy_mgmt import geo
from haproxy_mgmt.advanced import normalise as normalise_advanced
from haproxy_mgmt.config import AbuseProtection, Cluster, Node, UnknownHost, Vip
from haproxy_mgmt.generate import GeneratorError, countries_named, generate
from haproxy_mgmt.proxy_model import (
    BALANCE,
    MAX_DENY_RULES,
    STATUS_RANGE,
    ModelError,
    Proxy,
    dump_document,
    load_proxy,
    pool_written_by_hand,
    read_document,
)
from haproxy_mgmt.tls_policy import DEFAULT_BACKEND_POLICY

#
# A documented example cluster. No page renders against it any more.
#
# It existed because the application identities cannot read the engine's
# configuration, so the preview page had no real VIP names, certificate IDs or
# network names to offer. The editor solved that from the other end - it reads
# the poller's cache and generates against the cluster's actual addresses - and
# the preview page was removed once it did (B73).
#
# What is left is a test fixture, and it is kept because it is a good one: it
# lets the form's whole path, filled-in fields to stored document to generated
# configuration, be exercised without standing up a cluster. Named here rather
# than in the tests because `choices` and `preview` below are its only callers
# and they read as production code otherwise.
#
# Every value below is from the repository's fictional set.
#
PREVIEW_CLUSTER = Cluster(
    cluster_id="alpha",
    display_name="Preview",
    vip="192.0.2.20",
    address_prefix=None,
    address_interface=None,
    vips={
        "internal": Vip(name="internal", address="192.0.2.20", source="192.0.2.25"),
        "dmz": Vip(name="dmz", address="198.51.100.20", source="198.51.100.25"),
    },
    default_vip="internal",
    resolvers="cluster-dns",
    sources={"outbound": "192.0.2.35"},
    networks={"office": ("198.51.100.0/24",), "vpn": ("203.0.113.0/24",)},
    unknown_host=UnknownHost(status=404),
    abuse_protection=AbuseProtection(window="10s", max_requests=100, max_errors=20),
    config_path=Path("/preview"),
    publish_path=Path("/preview"),
    node_path="preview",
    validation_certs=Path("/preview"),
    default_certificate="example.com",
    certificate_ids=("example.com", "example.net", "wildcard-example-com"),
    trusted_proxy_cidrs=(),
    nodes=(Node(name="node-a", mgmt_host="node-a.example.com"),),
)

#
# What each of the example certificates answers for. A publish reads this from
# the certificates themselves; the page has no certificate directory, so the
# example cluster carries its own coverage - and picking a certificate that
# does not answer for the hostname is then refused here in the engine's words,
# exactly as it would be at publish time (B66).
#
# The wildcard is the one worth having in an example. `*.example.com` answers
# for `shop.example.com` and not for `a.b.example.com`, which is the mistake
# that looks right until a browser refuses.
#
PREVIEW_CERTIFICATE_SANS = {
    "example.com": ("example.com", "www.example.com"),
    "example.net": ("example.net", "www.example.net"),
    "wildcard-example-com": ("*.example.com", "example.com"),
}

#
# What the form starts with. A single site on the cluster's default address,
# one backend, one server - the shape most objects have, so the first thing
# somebody sees is the common case rather than an empty page.
#
DEFAULTS = {
    "name": "app",
    #
    # Left empty so the placeholder shows. It names two hostnames, which is how
    # somebody learns the field takes more than one - and a prefilled value is
    # a value that can be saved by not being looked at.
    #
    "hostnames": "",
    "protocol": "https",
    "tcp_port": "",
    "vip": "",
    "source": "",
    "certificate": "",
    "redirect_http": True,
    "hsts": False,
    "hsts_max_age": "31536000",
    "hsts_subdomains": False,
    "backend": "web",
    "balance": "roundrobin",
    "balance_key": "",
    "cookie": "",
    "servers": "198.51.100.10:8080",
    #
    # No check until somebody asks for one. The field is optional and the model
    # agrees - `disabled` is its own default - and a form that arrived with a
    # check already chosen was deciding on the reader's behalf, in the one place
    # where a wrong choice is invisible until a server is wrongly marked down.
    #
    "health_type": "disabled",
    "health_path": "/",
    "health_host": "",
    "health_port": "",
    "health_expect_status": "",
    "health_expect_body": "",
    "health_send": "",
    "health_expect": "",
    "health_interval": "",
    "health_fast_interval": "",
    "health_down_interval": "",
    "health_rise": "",
    "health_fall": "",
    "backend_tls": "",
    "backend_tls_policy": "",
    "listen_tls_policy": "",
    "max_connections": "",
    "slow_start": "",
    "allow_from": (),
    "allow_ranges": "",
    "rate_limit": "",
    "rate_window": "",
    "deny_from": (),
    "deny_ranges": "",
    "deny_mode": "log",
    "max_request_body": "",
    "rule_index": [],
    "rule_name": [],
    "rule_mode": [],
    "rule_path": [],
    "rule_match": [],
    "rule_header": [],
    "rule_header_match": [],
    "rule_header_value": [],
    "rule_source": [],
    "rule_methods": [],
    "rule_negate": [],
    "maintenance": False,
    "maintenance_message": "",
    "unavailable_message": "",
    "request_headers": "",
    "response_headers": "",
    "redirect_path": "",
    "redirect_match": "prefix",
    "redirect_location": "",
    "redirect_status": "301",
    #
    # Carried, not shown (Fas 17, B223, B224): the object's advanced config is
    # edited in its own dialog, and the form only has to hand it back unchanged.
    # So does a pool the text writes - the form has no fields for it then.
    #
    "advanced": "",
    "handwritten_pool": False,
    #
    # The WAF engine (Fas 21, B234): mode, what happens when the engine does not
    # answer, and how strict. Exceptions are made on the WAF page and carried
    # here unchanged, as JSON, so a save from this form keeps them.
    #
    "waf_mode": "off",
    "waf_engine_error": "allow",
    "waf_paranoia": "1",
    "waf_exceptions": "",
}


#
# What the check's Type box offers, and the whole of it. `Type` and a separate
# TLS box were two questions about one thing - the backend above says `Plain HTTP`
# or `HTTPS` in one box, and the check has no business needing two.
#
# The document keeps the two fields it always had: HAProxy has a check *type*
# and a check *protocol*, and they are not the same axis. Joining them is the
# form's job, and these two functions are where it happens.
#
CHECK_TYPES = (
    ("disabled", "disabled"),
    ("http", "http"),
    ("https", "https"),
    ("tcp", "tcp"),
    ("tcp-tls", "tcp, TLS handshake"),
)


def check_kind(chosen: str) -> str:
    """The document's `health.type` for what the box says."""

    if chosen in ("https", "http"):
        return "http"
    if chosen in ("tcp-tls", "tcp"):
        return "tcp"
    return "disabled"


def check_tls(chosen: str, backend_tls: str) -> bool | None:
    """The document's `health.tls`, written only where it differs from the backend.

    `None` means the document says nothing, which is HAProxy following the backend
    - and it is deliberately what a plain check on a plain backend and a TLS check
    on a TLS backend both produce. An object that already says nothing keeps
    saying nothing when it is loaded and saved, so the generated file does not
    gain a line for a change nobody made.

    `tcp, TLS handshake` is the exception and always written. `option
    ssl-hello-chk` is a check the backend's own TLS does not imply - inheritance
    opens a TLS connection, this asks whether the handshake itself succeeds -
    so it is a request, not a consequence.
    """

    backend_is_tls = bool(backend_tls)
    if chosen == "tcp-tls":
        return True
    if chosen in ("https",):
        return None if backend_is_tls else True
    if chosen in ("http", "tcp"):
        return False if backend_is_tls else None
    return None


def check_type_of(health: Mapping[str, Any], backend_tls: str) -> str:
    """What the box says for a document that has already been written.

    The value shown is what the check will actually do, which is why the backend
    is read here too: a document that says nothing about a check's protocol on
    a backend reached over TLS describes a TLS check, and a box reading `http`
    would be the form telling somebody something untrue.
    """

    kind = str(health.get("type", "") or "")
    if kind not in ("http", "tcp"):
        return kind
    written = health.get("tls")
    if kind == "tcp":
        return "tcp-tls" if written is True else "tcp"
    if written is True:
        return "https"
    if written is False:
        return "http"
    return "https" if backend_tls else "http"


def suggested_cookie(name: str) -> str:
    """The session cookie name offered for an object that has none yet.

    Prefixed so it is recognisable as this system's in a browser's cookie list,
    and next to the object's own name so two sites do not overwrite each
    other's. Cookie names are case-sensitive, so the suggestion picks one
    casing and stays with it.
    """

    return f"hap_{name}" if name else "hap_site"


@dataclass(frozen=True, slots=True)
class Preview:
    """What the page shows: the object, the configuration, or what is wrong.

    `problem` is a single readable sentence rather than a list, because every
    refusal the engine raises names one thing and says what it should be. Two
    of them at once would mean the first was not answered.
    """

    document: str = ""
    files: dict[str, str] = field(default_factory=dict)
    problem: str | None = None
    #
    # Whether the refusal is about this object or about how it sits beside its
    # neighbours. The model refuses documents that are not objects; the
    # generator refuses objects that clash with the ones already there. Only
    # the first kind means the person has not finished writing something, and
    # only the first kind should stop them from saving what they have.
    #
    about_the_object: bool = False
    #
    # Whether the object was generated beside the cluster's others, so that a
    # clash with a neighbour would have been found. False when the cluster's
    # network description is missing or stale: the object is then known only to be valid on
    # its own, and the page must not say more (26-10-03).
    #
    beside_others: bool = False

    @property
    def problem_field(self) -> str:
        """The field a refusal names, when it names one.

        Every refusal the engine raises begins with the path of the thing it is
        about - `app.listen.certificate`, `shop.backends.web.servers` - so the
        page can show that as the subject rather than leaving the reader to
        find it inside a sentence.
        """

        if self.problem is None:
            return ""
        head = self.problem.split(" ", 1)[0]
        return head if "." in head and head[0].isalnum() else ""

    @property
    def problem_text(self) -> str:
        """What is wrong with it, with the field taken off the front."""

        if self.problem is None:
            return ""
        if not self.problem_field:
            return self.problem
        return self.problem[len(self.problem_field) :].lstrip()


def _servers(raw: str) -> list[dict[str, object]]:
    """One `host:port` per line, `backup` after it for a standby member.

    Parsed here rather than in the model because this is the only place the
    shorthand exists: the stored object spells host, port and backup out, and a
    reader of that file should not have to know a form convention to understand
    it.

    `backup` is the model's whole remaining server field, so a backend written here
    can say everything a backend may say. It was the last thing that made an
    otherwise ordinary object impossible to open.
    """

    servers: list[dict[str, object]] = []
    for line in raw.splitlines():
        entry = line.strip()
        if not entry:
            continue
        #
        # Only the exact word counts as the marker. Anything else is part of a
        # line that is not an address, and saying so names the real mistake -
        # a line reading "not a server" is not a server carrying an unknown
        # flag.
        #
        address, backup = entry, False
        head, _, tail = entry.rpartition(" ")
        if tail.lower() == "backup" and head.strip():
            address, backup = head.strip(), True
        host, separator, port = address.rpartition(":")
        if not separator or not port.isdigit():
            raise ValueError(f"{entry!r} is not a host and port, such as 198.51.100.10:8080")
        server: dict[str, object] = {"host": host, "port": int(port)}
        if backup:
            server["backup"] = True
        servers.append(server)
    if not servers:
        raise ValueError("a backend needs at least one server")
    #
    # Every member a standby is a backend with nothing serving it. HAProxy would
    # accept it; the person writing it meant something else.
    #
    if all(server.get("backup") for server in servers):
        raise ValueError("every server is a backup, so nothing would take traffic")
    return servers


def build_document(form: dict[str, object]) -> str:
    """The YAML the object would be stored as.

    Built as data and dumped, never assembled as text: a hostname or a cookie
    name typed into a form is not trusted to be YAML-safe, and quoting it by
    hand is how an input ends up meaning something structural.
    """

    def text(key: str) -> str:
        return str(form.get(key, "") or "").strip()

    def flag(key: str) -> bool:
        return bool(form.get(key))

    protocol = text("protocol")
    listen: dict[str, object] = {"protocol": protocol}
    if protocol == "tcp":
        port = text("tcp_port")
        if not port.isdigit():
            raise ValueError("a tcp object must name the port it is served on")
        listen["port"] = int(port)
    if text("vip"):
        listen["vip"] = text("vip")
    if text("source"):
        listen["source"] = text("source")
    if protocol == "https":
        if text("certificate"):
            listen["certificate"] = text("certificate")
        #
        # Only when the site asked for terms of its own. An empty field means
        # the VIP decides, and a key written for every object would move every
        # site off its VIP's policy the moment somebody opened its page.
        #
        if text("listen_tls_policy"):
            listen["tls"] = text("listen_tls_policy")
        if flag("redirect_http"):
            listen["redirect_http"] = True
        if flag("hsts"):
            max_age = text("hsts_max_age")
            if not max_age.isdigit():
                raise ValueError("the HSTS lifetime must be a number of seconds")
            listen["hsts"] = {
                "max_age": int(max_age),
                "include_subdomains": flag("hsts_subdomains"),
            }

    #
    # One box on the form, two fields in the document. `check_kind` and
    # `check_tls` are the whole of the translation; everything below reads the
    # document's own type so a `https` check is an http check with a protocol,
    # which is what HAProxy calls it too.
    #
    kind = check_kind(text("health_type"))
    health: dict[str, object] = {"type": kind}
    if kind != "disabled" and text("health_port"):
        port = text("health_port")
        if not port.isdigit():
            raise ValueError("the health check port must be a number")
        health["port"] = int(port)
    if kind != "disabled":
        #
        # Left out when nobody wrote them, so the engine's own values stay the
        # engine's. A form that wrote 2s/2/3 into every object would freeze
        # today's defaults into every file it ever saved.
        #
        for field, key in (
            ("health_interval", "interval"),
            ("health_fast_interval", "fast_interval"),
            ("health_down_interval", "down_interval"),
            ("health_rise", "rise"),
            ("health_fall", "fall"),
        ):
            asked = text(field)
            if not asked:
                continue
            if key.endswith("interval"):
                health[key] = asked
                continue
            if not asked.isdigit():
                raise ValueError(f"the health check {key} must be a number of checks")
            health[key] = int(asked)
    if kind != "disabled":
        speaks = check_tls(text("health_type"), text("backend_tls"))
        if speaks is not None:
            health["tls"] = speaks
    if kind == "http":
        health["path"] = text("health_path") or "/"
        if text("health_host"):
            health["host"] = text("health_host")
        if text("health_expect_status"):
            status = text("health_expect_status")
            #
            # A status or a range, held to the model's own rule rather than to
            # a second one written here. The form used to accept a single
            # number only, while the document format and `http-check expect
            # status` both take a range - so `200-299` could be written into an
            # object, read back into this form, and refused on the way out. The
            # probe read it as a range the form could not produce, which is how
            # the difference was found.
            #
            if not STATUS_RANGE.match(status):
                raise ValueError(
                    "the expected status must be a status or a range, such as 200 or 200-299"
                )
            #
            # Written as text, because the model reads it as text: a status is
            # matched against a pattern that also has to accept `200-299`, and
            # a YAML integer is not a string. Until this it was written as a
            # number, so any value typed here produced a document the engine
            # refused - the field could not be used at all, and the refusal
            # named a rule the form gave no way to satisfy.
            #
            health["expect_status"] = status
        if text("health_expect_body"):
            health["expect_body"] = text("health_expect_body")
    if kind == "tcp":
        #
        # A tcp check that sends nothing is a connect check, which is what the
        # type means on its own. These two turn it into a conversation.
        #
        if text("health_send"):
            health["send"] = text("health_send")
        if text("health_expect"):
            health["expect"] = text("health_expect")

    backend: dict[str, object] = {
        "balance": text("balance"),
        "health": health,
        "servers": [] if flag("handwritten_pool") else _servers(text("servers")),
    }
    if text("balance_key"):
        backend["balance_key"] = text("balance_key")
    if text("cookie"):
        backend["cookie"] = text("cookie")
    if text("backend_tls"):
        backend_tls_box: dict[str, str] = {"verify": text("backend_tls")}
        #
        # Written only when it is not the default, so turning the field on and
        # off again leaves the document it started from. A published object that
        # never named a policy would otherwise gain a line the moment somebody
        # opened its page.
        #
        policy = text("backend_tls_policy")
        if policy and policy != DEFAULT_BACKEND_POLICY:
            backend_tls_box["policy"] = policy
        backend["tls"] = backend_tls_box
    if text("max_connections"):
        limit = text("max_connections")
        if not limit.isdigit():
            raise ValueError("the connection limit must be a number")
        backend["max_connections"] = int(limit)
    if text("slow_start"):
        backend["slow_start"] = text("slow_start")
    #
    # A pool the advanced config writes is `servers: []` and nothing else (B224).
    # The form shows no pool fields for it, so whatever they still hold is not
    # something anybody chose for this object.
    #
    if flag("handwritten_pool"):
        backend = {"servers": []}

    hostnames = [name.strip() for name in text("hostnames").replace(",", "\n").splitlines()]
    #
    # The backend's name is carried rather than fixed. Objects written by hand
    # name their backend after what it serves, and a form that could only produce
    # `web` would rename somebody's `console` the first time they opened it -
    # which reads in a diff as a backend removed and another added.
    #
    backend_name = text("backend") or "web"
    document: dict[str, object] = {"schema": 1, "name": text("name")}
    written = [name for name in hostnames if name]
    if protocol == "tcp":
        #
        # A tcp object is an address, a port and one backend. The page keeps one
        # form for both shapes, so the fields the shape has no use for carry no
        # document of their own - but anything a person actually typed is sent
        # along and refused by the engine, in the engine's words. Dropping it
        # here would leave somebody looking at a preview of an object that
        # silently lost the name they wrote, and headers already behave this
        # way; two identical mistakes answered two different ways is the part
        # that misleads.
        #
        document["listen"] = listen
        document["backend"] = backend_name
        if written:
            document["hostnames"] = written
        if text("redirect_path") or text("redirect_location"):
            document["routes"] = _routes(
                text("redirect_path"),
                text("redirect_match"),
                text("redirect_location"),
                text("redirect_status"),
                backend_name,
            )
    else:
        document["hostnames"] = written
        document["listen"] = listen
        document["routes"] = _routes(
            text("redirect_path"),
            text("redirect_match"),
            text("redirect_location"),
            text("redirect_status"),
            backend_name,
        )
    document["backends"] = {backend_name: backend}
    selected = form.get("allow_from", ())
    allowed = (
        [str(name) for name in selected if str(name).strip()]
        if isinstance(selected, (list, tuple))
        else []
    )
    allowed += [
        entry.strip()
        for entry in text("allow_ranges").replace(",", "\n").splitlines()
        if entry.strip()
    ]
    if allowed:
        document["allow_from"] = allowed

    #
    # The one number means requests for a site and new connections for a raw
    # port; the key is chosen here so the form needs no second field that would
    # always be the wrong one for half the objects. The window is written only
    # when somebody wrote it, so an empty box keeps meaning the engine's default.
    #
    denied = _listed(form.get("deny_from", ())) + _entries(text("deny_ranges"))
    if denied:
        document["deny_from"] = {"mode": text("deny_mode") or "log", "sources": denied}
    #
    # A raw port has no requests to refuse on; the fields are hidden for it,
    # and a hidden field still posts, so the shape is decided here as it is for
    # hostnames.
    #
    if protocol != "tcp":
        rules = [_rule_document(rule) for rule in access_rules(form)]
        if rules:
            document["deny_rules"] = rules
        if text("max_request_body"):
            document["max_request_body"] = text("max_request_body")

    if text("rate_limit"):
        limit = text("rate_limit")
        if not limit.isdigit():
            raise ValueError("the rate limit must be a number")
        rate: dict[str, object] = {}
        if text("rate_window"):
            rate["window"] = text("rate_window")
        rate["max_new_connections" if protocol == "tcp" else "max_requests"] = int(limit)
        document["rate_limit"] = rate
    elif text("rate_window"):
        raise ValueError("a rate limit window needs a limit")

    #
    # Written last because it is the one field that is about the object's state
    # rather than its shape, and reading it at the end of the document says so.
    # The message is not defaulted here: the engine requires one, and a default
    # written by the form would be this module quietly deciding what a visitor
    # is told.
    #
    if flag("maintenance"):
        document["maintenance"] = {"message": text("maintenance_message")}
    if text("unavailable_message"):
        document["unavailable"] = {"message": text("unavailable_message")}

    headers = {
        phase: _header_edits(text(f"{phase}_headers"), phase) for phase in ("request", "response")
    }
    if any(headers.values()):
        document["headers"] = {phase: edits for phase, edits in headers.items() if edits}

    #
    # Not stripped like the fields above: the first line's indentation is part of
    # the text. Normalised as the engine stores it, so carrying it through the
    # browser - which sends its line ends as CRLF - changes nothing.
    #
    waf = waf_block(
        text("waf_mode") or "off",
        text("waf_engine_error") or "allow",
        text("waf_paranoia") or "1",
        str(form.get("waf_exceptions", "") or ""),
    )
    if waf is not None:
        document["waf"] = waf

    advanced = normalise_advanced(str(form.get("advanced", "") or ""))
    if advanced:
        document["advanced"] = advanced

    return dump_document(document)


WAF_EXCEPTION_KEYS = ("rule", "field", "paths", "by", "at")


def canonical_waf_exception(value: Any) -> Any:
    """One exception in the form the form writes: its keys in order, empty ones left out.

    Anything that is not the shape of one is handed on as it is, for the engine
    to refuse in its own words.
    """

    if not isinstance(value, Mapping):
        return value
    out: dict[str, Any] = {"rule": value.get("rule")}
    for key in ("field", "paths", "by", "at"):
        item = value.get(key)
        #
        # As the engine reads it: YAML's unquoted time is the same value as the
        # quoted form only in UTC and to the second; any other is left for the
        # engine to refuse.
        #
        if isinstance(item, datetime) and item.utcoffset() == timedelta(0) and not item.microsecond:
            item = item.strftime("%Y-%m-%dT%H:%M:%SZ")
        if key == "paths" and isinstance(item, list) and all(isinstance(p, str) for p in item):
            item = sorted(item)
        if item not in (None, "", []):
            out[key] = item
    out.update({key: item for key, item in value.items() if key not in WAF_EXCEPTION_KEYS})
    return out


def canonical_waf(value: Any) -> Any:
    """`waf` with every setting written out, as the form writes it, or None for none.

    A block that says no more than `mode: off` with the defaults is the same
    object as one without `waf`, and the form writes it as none.
    """

    if not isinstance(value, Mapping):
        return value
    mode = value.get("mode", "log")
    out: dict[str, Any] = {
        "mode": "off" if mode is False else mode,
        "on_engine_error": value.get("on_engine_error", "allow"),
        "paranoia": value.get("paranoia", 1),
    }
    listed = value.get("exceptions", [])
    if isinstance(listed, list):
        if listed:
            out["exceptions"] = [canonical_waf_exception(item) for item in listed]
    else:
        out["exceptions"] = listed
    out.update(
        {key: item for key, item in value.items() if key not in (*out, "exceptions", "mode")}
    )
    if out == {"mode": "off", "on_engine_error": "allow", "paranoia": 1}:
        return None
    return out


def waf_block(
    mode: str, engine_error: str, paranoia: str, exceptions: str
) -> dict[str, Any] | None:
    """The `waf` block the form's four fields describe."""

    try:
        listed = json.loads(exceptions) if exceptions.strip() else []
    except ValueError:
        raise ValueError("the WAF exceptions could not be read") from None
    if not isinstance(listed, list):
        raise ValueError("the WAF exceptions could not be read")
    if not paranoia.isdigit():
        raise ValueError("the WAF strictness must be 1, 2, 3 or 4")
    block = canonical_waf(
        {
            "mode": mode,
            "on_engine_error": engine_error,
            "paranoia": int(paranoia),
            "exceptions": listed,
        }
    )
    return block if isinstance(block, dict) else None


def waf_fields(data: Mapping[str, Any]) -> dict[str, str]:
    """The form's four WAF fields for a stored object."""

    block = canonical_waf(data.get("waf"))
    if not isinstance(block, Mapping):
        return {
            "waf_mode": "off",
            "waf_engine_error": "allow",
            "waf_paranoia": "1",
            "waf_exceptions": "",
        }
    listed = block.get("exceptions", [])
    return {
        "waf_mode": str(block.get("mode", "log")),
        "waf_engine_error": str(block.get("on_engine_error", "allow")),
        "waf_paranoia": str(block.get("paranoia", 1)),
        "waf_exceptions": json.dumps(listed, separators=(",", ":")) if listed else "",
    }


def _routes(
    path: str, match: str, location: str, status: str, backend_name: str
) -> list[dict[str, object]]:
    """The object's routes: the backend, plus one redirect where the form asks.

    The preview builds one backend and one route, which is what the page is for -
    seeing what a shape produces. A redirect is the second route rather than a
    replacement for the first, because a redirect that took the whole object
    would be a site with nowhere to send anything.

    The redirect carries its own match mode, and that is not a detail. The
    field was first written for a path that had moved - `/old` sends you to
    `/new`, and the backend keeps everything else - where a prefix match is the
    obvious reading. The other shape is at least as common: the site root
    answers with a redirect to the entry point the application actually uses,
    and the rest of the site proxies as normal. That one needs `exact`, because
    a prefix redirect on `/` would swallow the very address it points at, and
    because two prefix routes on `/` are the same route twice - which the
    engine refuses, in its own words, rather than guessing which was meant.

    The backend's own route stays a prefix on `/`: it is the catch-all the object
    is built around, and a redirect sorts ahead of it by `order_routes` when it
    is exact.
    """

    routes: list[dict[str, object]] = [{"path": "/", "backend": backend_name}]
    if not path and not location:
        return routes
    if not (path and location):
        raise ValueError("a redirect needs both a path and a location")
    if not status.isdigit():
        raise ValueError("the redirect status must be a number")
    #
    # Named here, in the form's own words, rather than left to the engine. The
    # engine's answer - "routes matches the same path twice" - is true and
    # unhelpful: it describes a document the person never saw, and does not
    # name the field that fixes it. This is the shape somebody reaches for when
    # a site's root sends visitors on to the page the application starts at,
    # which is common enough that meeting it with a puzzle is the wrong answer.
    #
    if path == routes[0]["path"] and match != "exact":
        raise ValueError(
            "the redirect and the backend are both on this path; set the redirect's match to "
            "exact so it answers that one address and the backend keeps the rest"
        )
    redirect: dict[str, object] = {"path": path}
    if match == "exact":
        redirect["match"] = match
    redirect["redirect"] = {"location": location, "status": int(status)}
    routes.append(redirect)
    return routes


def _header_edits(written: str, phase: str) -> dict[str, object]:
    """One line per edit, which is how somebody writes these by hand.

    `Name: value` sets, `+Name: value` adds another field with the same name,
    and `-Name` removes every one. Three shapes rather than three text boxes,
    because the edits belong together and reading them in one place is how a
    contradiction becomes visible.

    Nothing here decides whether a name or a value is usable - the engine does,
    and it is the same refusal a hand-written object gets.
    """

    assigned: dict[str, str] = {}
    added: dict[str, str] = {}
    removed: list[str] = []
    for line in written.splitlines():
        entry = line.strip()
        if not entry:
            continue
        if entry.startswith("-"):
            removed.append(entry[1:].strip())
            continue
        target = added if entry.startswith("+") else assigned
        name, separator, value = entry.lstrip("+").partition(":")
        if not separator:
            raise ValueError(
                f"every {phase} header line must be Name: value, +Name: value or -Name"
            )
        target[name.strip()] = value.strip()

    edits: dict[str, object] = {}
    if assigned:
        edits["set"] = assigned
    if added:
        edits["add"] = added
    if removed:
        edits["delete"] = removed
    return edits


def preview(form: dict[str, object], cluster: Cluster) -> Preview:
    """The whole page's content, or the one thing standing in its way.

    Every refusal below comes from the engine rather than from this module, so
    what the page says about an object is exactly what a publish would say
    about it.
    """

    try:
        document = build_document(form)
    except ValueError as exc:
        return Preview(problem=str(exc), about_the_object=True)

    try:
        proxy = load_proxy(str(form.get("name", "") or "").strip(), document.encode())
    except ModelError as exc:
        return Preview(document=document, problem=str(exc), about_the_object=True)

    try:
        #
        # The configuration half. The preview shows what a person would read in
        # `conf.d`; the certificate lists are named by a bind line and proved by
        # HAProxy, and printing one here would be a file with no context.
        #
        files = generate(
            [proxy],
            vips=cluster.vips,
            default_vip=cluster.default_vip,
            certificates=cluster.certificate_ids,
            resolvers=cluster.resolvers,
            networks=cluster.networks,
            sources=cluster.sources,
            unknown_host=cluster.unknown_host,
            trusted_proxies=cluster.trusted_proxy_cidrs,
            abuse_protection=cluster.abuse_protection,
            certificate_sans=PREVIEW_CERTIFICATE_SANS,
            countries=unchecked_countries([proxy]),
        ).configuration
    except GeneratorError as exc:
        return Preview(document=document, problem=str(exc))

    return Preview(document=document, files=files)


def unchecked_countries(proxies: Sequence[Proxy]) -> geo.Countries:
    """A stand-in for the countries the objects name (B228).

    The interface has no location database - the engine reads it when it
    publishes, and refuses a country it does not know there. The check and the
    preview show the rules, which name each country's file; the file's networks
    are never shown, so the placeholder only lets the generator write them.
    """

    return geo.Countries(
        stamp="unchecked",
        networks={country: ("192.0.2.0/32",) for country in countries_named(proxies)},
    )


def vip_sources(vips: Mapping[str, Any]) -> dict[str, str]:
    """Each VIP's own source address, by VIP name.

    The source a site leaves from when it names none of its own is a property of
    the VIP - what an ADC calls the SNIP - so the form cannot show it until it
    knows which VIP was chosen. Carried as a map for exactly that: the page
    renders the chosen one and swaps it when the choice changes.
    """

    return {name: str(getattr(value, "source", "") or "") for name, value in vips.items()}


def named_addresses(addresses: Mapping[str, Any]) -> list[dict[str, str]]:
    """Name and address together, in the one shape the form's options take.

    Carried as a pair rather than as a name the reader has to look up on
    another page. Which address a site is served on is the thing being chosen;
    a list of names asks somebody to remember the mapping, and the mapping is
    exactly what they came here to be sure about.

    An address that has not been read is left empty rather than guessed. The
    option still names the VIP, because the choice is real either way.
    """

    pairs = []
    for name in sorted(addresses):
        value = addresses[name]
        address = getattr(value, "address", value)
        pairs.append({"name": name, "address": str(address or "")})
    return pairs


def choices(cluster: Cluster) -> dict[str, object]:
    """What the form may offer, taken from the cluster rather than invented."""

    return {
        "vips": named_addresses(cluster.vips),
        "vip_sources": vip_sources(cluster.vips),
        "default_vip": cluster.default_vip,
        "default_vip_address": (
            cluster.vips[cluster.default_vip].address if cluster.default_vip in cluster.vips else ""
        ),
        "certificates": sorted(cluster.certificate_ids),
        "sources": named_addresses(cluster.sources),
        "networks": sorted(cluster.networks),
        "balances": BALANCE,
        "health_types": CHECK_TYPES,
    }


class Unexpressible(Exception):
    """This object says something the form has no field for.

    Raised rather than opened with the extra parts quietly dropped. An editor
    that showed nine of an object's ten backends and then wrote back what it
    showed would delete the tenth on the first save, and every screen in the
    process would have looked correct.
    """


def _server_lines(servers: Any, backend_name: str) -> str:
    """One `host:port` line per server, with `backup` where it stands.

    Written out rather than dropped: a form that showed a standby as an
    ordinary member would turn it into one on the first save, and both screens
    would have looked right. Anything the model grows beyond these three is
    left to the round trip to refuse for the same reason.
    """

    if not isinstance(servers, list):
        raise Unexpressible(f"backends.{backend_name}.servers")
    lines = []
    for server in servers:
        if not isinstance(server, Mapping):
            raise Unexpressible(f"backends.{backend_name}.servers")
        line = f"{server.get('host', '')}:{server.get('port', '')}"
        lines.append(f"{line} backup" if server.get("backup") is True else line)
    return "\n".join(lines)


#
# The most rules the form posts; the engine's own bound (`MAX_DENY_RULES`).
#
MAX_RULES = MAX_DENY_RULES
RULE_FIELDS = (
    "name",
    "mode",
    "path",
    "match",
    "header",
    "header_match",
    "header_value",
    "source",
)


def _listed(selected: Any) -> list[str]:
    if not isinstance(selected, (list, tuple)):
        return []
    return [str(name) for name in selected if str(name).strip()]


def _entries(text: str) -> list[str]:
    return [entry.strip() for entry in text.replace(",", "\n").split() if entry.strip()]


def access_rules(form: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The form's deny rules as one mapping each, in page order (Fas 21).

    Read from the parallel lists the page posts. A list shorter than the
    index reads as empty for that rule rather than raising: the document built
    from it is checked by the engine, which says what is missing.
    """

    def column(name: str) -> list[str]:
        value = form.get(f"rule_{name}", ())
        return [str(item) for item in value] if isinstance(value, (list, tuple)) else []

    indexes = column("index")
    columns = {name: column(name) for name in RULE_FIELDS}
    methods = column("methods")
    negated = set(column("negate"))
    rules: list[dict[str, Any]] = []
    for position, index in enumerate(indexes):
        rule: dict[str, Any] = {
            name: (values[position].strip() if position < len(values) else "")
            for name, values in columns.items()
        }
        rule["index"] = index
        rule["methods"] = [
            entry.partition(":")[2] for entry in methods if entry.partition(":")[0] == index
        ]
        rule["negate"] = index in negated
        rule["summary"] = _rule_summary(rule)
        rules.append(rule)
    return rules


def _rule_summary(rule: Mapping[str, Any]) -> str:
    """The line a folded rule shows: its conditions, in the order they are written."""

    parts = []
    if rule["path"]:
        parts.append(f"{rule['path']}{' exactly' if rule['match'] == 'exact' else ''}")
    if rule["methods"]:
        parts.append(", ".join(rule["methods"]))
    if rule["header"]:
        parts.append(f"{rule['header']} {rule['header_match'] or 'equals'} {rule['header_value']}")
    if rule["source"]:
        parts.append(f"{'not ' if rule['negate'] else ''}from {rule['source']}")
    return " · ".join(parts) or "No condition"


def _rule_document(rule: Mapping[str, Any]) -> dict[str, Any]:
    document: dict[str, Any] = {"name": rule["name"], "mode": rule["mode"] or "log"}
    if rule["path"]:
        document["path"] = rule["path"]
        if rule["match"] == "exact":
            document["match"] = "exact"
    if rule["methods"]:
        document["methods"] = sorted(rule["methods"])
    if rule["header"] or rule["header_value"]:
        document["header"] = {
            "name": rule["header"],
            rule["header_match"] or "equals": rule["header_value"],
        }
    sources = _entries(rule["source"])
    if sources:
        document["source"] = sources
    if rule["negate"]:
        document["source_negate"] = True
    return document


def _access_fields(data: Mapping[str, Any], networks: Collection[str]) -> dict[str, Any]:
    """`deny_from`, `deny_rules` and `max_request_body` as the form holds them."""

    known = set(networks)
    denied = _sub(data, "deny_from")
    sources = denied.get("sources")
    sources = [str(entry) for entry in sources] if isinstance(sources, list) else []
    fields: dict[str, Any] = {
        "deny_from": tuple(entry for entry in sources if entry in known),
        "deny_ranges": "\n".join(entry for entry in sources if entry not in known),
        "deny_mode": str(denied.get("mode", "log") or "log"),
        "max_request_body": str(data.get("max_request_body", "") or ""),
    }
    columns: dict[str, list[str]] = {f"rule_{name}": [] for name in ("index", *RULE_FIELDS)}
    methods: list[str] = []
    negated: list[str] = []
    rules = data.get("deny_rules")
    for position, raw in enumerate(rules if isinstance(rules, list) else []):
        rule = raw if isinstance(raw, Mapping) else {}
        index = str(position)
        header = _sub(rule, "header")
        match = next((key for key in ("equals", "prefix", "contains") if key in header), "equals")
        source = rule.get("source")
        values = {
            "index": index,
            "name": str(rule.get("name", "") or ""),
            "mode": str(rule.get("mode", "log") or "log"),
            "path": str(rule.get("path", "") or ""),
            "match": str(rule.get("match", "prefix") or "prefix"),
            "header": str(header.get("name", "") or ""),
            "header_match": match,
            "header_value": str(header.get(match, "") or ""),
            "source": ", ".join(str(entry) for entry in source) if isinstance(source, list) else "",
        }
        for name, value in values.items():
            columns[f"rule_{name}"].append(value)
        found = rule.get("methods")
        methods += [f"{index}:{method}" for method in (found if isinstance(found, list) else [])]
        if rule.get("source_negate") is True:
            negated.append(index)
    return {**fields, **columns, "rule_methods": methods, "rule_negate": negated}


def _header_lines(edits: Any) -> str:
    """The three shapes written back in the order the form documents them."""

    if not isinstance(edits, Mapping):
        return ""
    lines = []
    for name, value in _sub(edits, "set").items():
        lines.append(f"{name}: {value}")
    for name, value in _sub(edits, "add").items():
        lines.append(f"+{name}: {value}")
    removed = edits.get("delete")
    if isinstance(removed, list):
        lines.extend(f"-{name}" for name in removed)
    return "\n".join(lines)


def _sub(value: Any, key: str) -> Mapping[str, Any]:
    """One nested mapping, or an empty one.

    `value` is typed loosely on purpose: it is read out of a stored document,
    where a route may be a string and a backend a list. Requiring a mapping
    here raised `AttributeError` from inside `form_from_document`, which
    catches `ModelError` and `ValueError` - so an object the form could not
    open answered 500 instead of saying it could not be opened.
    """

    if not isinstance(value, Mapping):
        return {}
    nested = value.get(key)
    return nested if isinstance(nested, Mapping) else {}


def form_from_document(document: str, *, networks: Collection[str] = ()) -> dict[str, Any]:
    """The form fields that would produce this stored object.

    The inverse of `build_document`, and checked as one: the fields are read
    out, the document they would produce is built again, and the two are
    compared. A difference means the form cannot say what the file says, and
    the object is refused instead of opened.

    Comparing the round trip is what makes this honest without maintaining a
    list of unsupported shapes beside the form. Such a list is correct on the
    day it is written and silently wrong the first time either side grows a
    field - and the failure it produces is an object edited down to what the
    form happened to know about.

    `networks` are the cluster's group names, needed only to split `allow_from`
    back into the groups it offers and the addresses it takes as text. Splitting
    it by shape instead would put a group whose name looks like an address in
    the wrong box.
    """

    try:
        data = read_document("object", document.encode())
        form = _form_fields(data, networks)
    except (ModelError, ValueError) as exc:
        raise Unexpressible(str(exc)) from exc

    #
    # `build_document` refuses shapes of its own - a server line that is not a
    # host and port, a redirect with half its fields. A stored object that
    # trips one of them is one the form cannot open, which is the same answer
    # the comparison below gives, so it is reported the same way.
    #
    try:
        rebuilt = read_document("object", build_document(form).encode())
    except (ModelError, ValueError) as exc:
        raise Unexpressible(str(exc)) from exc
    difference = _first_difference(
        _with_normalised_waf(_with_normalised_advanced(_without_a_redundant_check_protocol(data))),
        rebuilt,
    )
    if difference:
        raise Unexpressible(difference)
    return form


def _form_fields(data: Mapping[str, Any], networks: Collection[str]) -> dict[str, Any]:
    listen = _sub(data, "listen")
    backends = _sub(data, "backends")
    #
    # Whatever the object's one backend is called. Reading `web` unconditionally
    # would refuse every object whose backend is named after what it serves, and
    # would refuse it while pointing at a path the file does not contain.
    #
    backend_name = next(iter(backends), "web")
    backend = _sub(backends, backend_name)
    health = _sub(backend, "health")
    hsts = _sub(listen, "hsts")
    headers = _sub(data, "headers")
    rate = _sub(data, "rate_limit")
    protocol = str(listen.get("protocol", "") or "")

    hostnames = data.get("hostnames")
    written = [str(entry) for entry in hostnames] if isinstance(hostnames, list) else []

    allowed = data.get("allow_from")
    allowed = [str(entry) for entry in allowed] if isinstance(allowed, list) else []
    groups = [entry for entry in allowed if entry in set(networks)]
    ranges = [entry for entry in allowed if entry not in set(networks)]

    #
    # The second route is the form's redirect. The first is the backend, which the
    # form does not show because it has no choice to offer about it - every
    # object the form can express sends everything else to `web`.
    #
    routes = data.get("routes")
    routes = routes if isinstance(routes, list) else []
    redirect = _sub(routes[1], "redirect") if len(routes) > 1 else {}

    return {
        "name": str(data.get("name", "") or ""),
        "hostnames": ", ".join(written),
        "protocol": protocol,
        "tcp_port": str(listen.get("port", "") or ""),
        "vip": str(listen.get("vip", "") or ""),
        "source": str(listen.get("source", "") or ""),
        "certificate": str(listen.get("certificate", "") or ""),
        "listen_tls_policy": str(listen.get("tls", "") or ""),
        "redirect_http": listen.get("redirect_http") is True,
        "hsts": bool(hsts),
        #
        # Falls back to the offered lifetime for an object that sends no HSTS.
        # The value only reaches the document when the box is ticked, so a
        # suggestion costs nothing - and the alternative is an empty field that
        # refuses the moment somebody ticks the box beside it.
        #
        "hsts_max_age": str(hsts.get("max_age", "") or "") or str(DEFAULTS["hsts_max_age"]),
        "hsts_subdomains": hsts.get("include_subdomains") is True,
        "balance": str(backend.get("balance", "") or ""),
        "balance_key": str(backend.get("balance_key", "") or ""),
        "cookie": str(backend.get("cookie", "") or ""),
        "backend": backend_name,
        "servers": _server_lines(backend.get("servers"), backend_name),
        #
        # The backend is read with it: a document that says nothing about the
        # check's protocol on a backend reached over TLS describes a TLS check,
        # and the box has to say so rather than read `http`.
        #
        "health_type": check_type_of(health, str(backend.get("tls", {}).get("verify", "") or "")),
        "health_path": str(health.get("path", "") or ""),
        "health_host": str(health.get("host", "") or ""),
        "health_port": str(health.get("port", "") or ""),
        "health_expect_status": str(health.get("expect_status", "") or ""),
        "health_expect_body": str(health.get("expect_body", "") or ""),
        "health_send": str(health.get("send", "") or ""),
        "health_expect": str(health.get("expect", "") or ""),
        #
        # Empty when the object does not say, rather than filled in with the
        # default. The three carry HAProxy's own values when nobody writes
        # them, and a form that showed those as if they had been chosen would
        # write them into every object it saved.
        #
        "health_interval": str(health.get("interval", "") or ""),
        "health_fast_interval": str(health.get("fast_interval", "") or ""),
        "health_down_interval": str(health.get("down_interval", "") or ""),
        "health_rise": str(health.get("rise", "") or ""),
        "health_fall": str(health.get("fall", "") or ""),
        "backend_tls": str(_sub(backend, "tls").get("verify", "") or ""),
        "backend_tls_policy": str(_sub(backend, "tls").get("policy", "") or ""),
        "max_connections": str(backend.get("max_connections", "") or ""),
        "slow_start": str(backend.get("slow_start", "") or ""),
        "allow_from": tuple(groups),
        "allow_ranges": "\n".join(ranges),
        "rate_limit": str(
            rate.get("max_new_connections" if protocol == "tcp" else "max_requests", "") or ""
        ),
        "rate_window": str(rate.get("window", "") or ""),
        **_access_fields(data, networks),
        "maintenance": "maintenance" in data,
        "maintenance_message": str(_sub(data, "maintenance").get("message", "") or ""),
        "unavailable_message": str(_sub(data, "unavailable").get("message", "") or ""),
        "request_headers": _header_lines(headers.get("request")),
        "response_headers": _header_lines(headers.get("response")),
        "redirect_path": str(routes[1].get("path", "") or "") if redirect else "",
        "redirect_match": (
            str(routes[1].get("match", "prefix") or "prefix") if redirect else "prefix"
        ),
        "redirect_location": str(redirect.get("location", "") or ""),
        "redirect_status": str(redirect.get("status", "") or ""),
        #
        # Text only. Anything else is left out here, so the round trip finds the
        # difference and the object is refused rather than saved without it.
        #
        "advanced": data["advanced"] if isinstance(data.get("advanced"), str) else "",
        "handwritten_pool": pool_written_by_hand(backend),
        **waf_fields(data),
    }


def _with_normalised_waf(data: Any) -> Any:
    """The stored object with `waf` written out as the form writes it.

    Defaults left unsaid, an unquoted `off`, exception paths in another order:
    the same settings, and no reason to refuse the object.
    """

    if not isinstance(data, Mapping) or "waf" not in data:
        return data
    block = canonical_waf(data["waf"])
    rest = {key: item for key, item in data.items() if key != "waf"}
    return rest if block is None else {**rest, "waf": block}


def _with_normalised_advanced(data: Any) -> Any:
    """The stored object with its advanced config as the engine would store it.

    A file written by hand may end a line in blanks or carry no final newline,
    and the form writes the text back normalised. That is one change to the
    text, made the same way `haproxy-objects` makes it, and not a reason to
    refuse the object.
    """

    if not isinstance(data, Mapping) or not isinstance(data.get("advanced"), str):
        return data
    return {**data, "advanced": normalise_advanced(data["advanced"])}


def _without_a_redundant_check_protocol(data: Any) -> Any:
    """The stored object with a check protocol that only repeats the backend removed.

    The document has three states for `health.tls` and the form's Type box has
    two answers per kind, which cannot round-trip on its own: `tls: true` on a
    backend already reached over TLS and no `tls` at all are the same check, said
    twice.

    They are the same *configuration* too, which is why this is a normalisation
    and not a loss. Measured on 3.4.4, 2026-09-05: a server line carrying `ssl`
    and a backend carrying `http-check connect ssl` answers `L7OK 200`, and so
    does the same backend without the line - the backend's own TLS is what the
    check inherits either way. So the redundant word is dropped on the next
    save, and the object means exactly what it meant.

    Only the redundant direction. `tls: false` on a TLS backend is `no-check-ssl`
    and says something the backend does not, and `tls: true` on a plain backend is
    the check speaking TLS where the backend does not - both are kept.
    """

    if not isinstance(data, Mapping):
        return data
    backends = data.get("backends")
    if not isinstance(backends, Mapping):
        return data
    cleaned = dict(data)
    cleaned_backends = {}
    for name, backend in backends.items():
        health = _sub(backend, "health")
        backend_is_tls = bool(_sub(backend, "tls"))
        if backend_is_tls and health.get("tls") is True and health.get("type") == "http":
            trimmed = {key: value for key, value in health.items() if key != "tls"}
            cleaned_backends[name] = {**backend, "health": trimmed}
        else:
            cleaned_backends[name] = backend
    cleaned["backends"] = cleaned_backends
    return cleaned


def _first_difference(stored: Any, rebuilt: Any, path: str = "") -> str:
    """The first place the round trip did not reproduce the stored object.

    Compared as data rather than as text. The two documents come from the same
    serialiser, but key order and formatting are the author's and carry no
    meaning - refusing an object because somebody wrote `backends` above
    `routes` would be this module mistaking its own habits for the schema.

    The path is returned rather than the value at it. It is enough to say which
    part of the object the form has no field for, and it keeps a refusal from
    quoting an object's own contents back onto a page.
    """

    if isinstance(stored, Mapping) or isinstance(rebuilt, Mapping):
        left = stored if isinstance(stored, Mapping) else {}
        right = rebuilt if isinstance(rebuilt, Mapping) else {}
        for key in list(left) + [key for key in right if key not in left]:
            if key not in left or key not in right:
                return f"{path}.{key}".lstrip(".")
            found = _first_difference(left[key], right[key], f"{path}.{key}".lstrip("."))
            if found:
                return found
        return ""
    if isinstance(stored, list) or isinstance(rebuilt, list):
        written = stored if isinstance(stored, list) else []
        produced = rebuilt if isinstance(rebuilt, list) else []
        if len(written) != len(produced):
            return path or "the object"
        for index, (one, other) in enumerate(zip(written, produced, strict=True)):
            found = _first_difference(one, other, f"{path}[{index}]")
            if found:
                return found
        return ""
    return "" if stored == rebuilt else (path or "the object")
