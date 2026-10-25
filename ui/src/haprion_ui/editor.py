"""Editing one proxy object against the cluster it is actually served on.

`preview` turns a filled-in form into the object the engine reads. This checks
that object against a real cluster: the VIPs, source addresses, groups and
certificates below are the ones the poller last read from the cluster being
edited, so the refusals a person meets here are the refusals a publish would
give them - a hostname another object already claims, a
certificate that does not answer for the name (B66), a balancing algorithm the
protocol has no use for.

What is deliberately not carried out of the engine is the cluster's *policy*:
what an unmatched hostname is answered with, the abuse brake's thresholds, the
resolver, the trusted proxies. Those live in the engine's own configuration,
which the web identities cannot read, and none of them changes whether an
object is valid. They are given the model's own defaults here and the generated
configuration is not shown, because a configuration that is right about
addresses and invented about policy is the kind of green answer that is worse
than none.
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated

from haprion import address_ranges
from haprion.config import AbuseProtection, UnknownHost, Vip
from haprion.digits import is_digits
from haprion.generate import GeneratorError, generate
from haprion.proxy_model import HTTP_METHODS, WAF_ENGINE_ERROR_DEFAULT, ModelError, load_proxy
from haprion.reservations import NOTHING_RESERVED, Reservations
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from haprion_ui.advanced_dialog import MAX_TEXT
from haprion_ui.certificates import CertificateClusterView
from haprion_ui.network import NetworkClusterView
from haprion_ui.preview import (
    BALANCE_CHOICES,
    CHECK_TYPES,
    MAX_RULES,
    QUERY_TYPES,
    Preview,
    Unexpressible,
    access_rules,
    form_from_document,
    named_addresses,
    saved_document,
    unchecked_countries,
    vip_sources,
)

#
# The policy the validation runs under, and it is not this cluster's. Every
# value here is one the engine's own model defaults to; none of them can make a
# valid object invalid or the reverse. They exist because `generate` needs a
# whole cluster to run at all.
#
VALIDATION_RESOLVERS = ""
VALIDATION_UNKNOWN_HOST = UnknownHost(status=404)
VALIDATION_ABUSE_PROTECTION = AbuseProtection(window="10s", max_requests=100, max_errors=20)
VALIDATION_TRUSTED_PROXIES: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EditorCluster:
    """What the editor may offer, read from the cluster rather than invented.

    `certificate_sans` is carried beside the identifiers because coverage is
    checked against it. An editor that offered a certificate without knowing
    what it answers for would let somebody pick one the publish then refuses,
    which is the refusal arriving one screen too late.
    """

    cluster: str
    default_vip: str
    vips: Mapping[str, Vip]
    sources: Mapping[str, str]
    networks: Mapping[str, tuple[str, ...]]
    certificate_ids: tuple[str, ...]
    certificate_sans: Mapping[str, tuple[str, ...]]
    #
    # False where the poller has not read enough to judge an object against.
    # The editor still opens - a document is worth reading either way - but it
    # says so instead of validating against a cluster it half knows.
    #
    complete: bool
    #
    # The CA certificates a pool on this cluster may be verified against (B276).
    #
    authority_ids: tuple[str, ...] = ()
    #
    # What the handwritten layer keeps for itself (manual/reservations.yaml),
    # as the inventory last read it. A name or a port claimed there was valid
    # here and refused by the publish, holding back the cluster's whole list
    # (review 26-10-24, 15-07).
    #
    reservations: Reservations = NOTHING_RESERVED


def reservations_from_inventory(result: Mapping[str, object] | None) -> Reservations:
    """The inventory's `reservations`, back in the engine's own shape; none when unread."""

    listed = (result or {}).get("reservations")
    if not isinstance(listed, Mapping):
        return NOTHING_RESERVED
    hostnames = listed.get("hostnames")
    ports = listed.get("tcp_ports")
    listeners = listed.get("tcp_listeners")
    pairs: set[tuple[str, int]] = set()
    for entry in listeners if isinstance(listeners, list) else ():
        address, _, port = str(entry).rpartition(":")
        if address and is_digits(port):
            pairs.add((address, int(port)))
    return Reservations(
        hostnames=frozenset(
            name
            for name in (hostnames if isinstance(hostnames, list) else ())
            if isinstance(name, str)
        ),
        tcp_ports=frozenset(
            port
            for port in (ports if isinstance(ports, list) else ())
            if isinstance(port, int) and not isinstance(port, bool)
        ),
        tcp_listeners=frozenset(pairs),
    )


def editor_cluster(
    cluster: str,
    network: NetworkClusterView | None,
    certificates: CertificateClusterView | None,
    reservations: Reservations = NOTHING_RESERVED,
) -> EditorCluster:
    """Assemble one cluster's real choices out of the cached readings."""

    vips = {
        view.name: Vip(name=view.name, address=view.address, source=view.source)
        for view in (network.vips if network else ())
        if view.name
    }
    sources = {
        view.name: view.address for view in (network.named_sources if network else ()) if view.name
    }
    networks = {
        view.name: tuple(view.members) for view in (network.groups if network else ()) if view.name
    }
    usable = tuple(
        view for view in (certificates.certificates if certificates else ()) if view.usable
    )
    return EditorCluster(
        cluster=cluster,
        default_vip=network.default_vip if network else "",
        vips=vips,
        sources=sources,
        networks=networks,
        certificate_ids=tuple(sorted(view.identifier for view in usable)),
        certificate_sans={view.identifier: tuple(view.sans) for view in usable},
        complete=bool(vips) and network is not None and not network.stale,
        authority_ids=tuple(sorted(certificates.authorities)) if certificates else (),
        reservations=reservations,
    )


def choices(cluster: EditorCluster) -> dict[str, object]:
    """The same shape `preview.choices` returns, from real values."""

    return {
        "vips": named_addresses(cluster.vips),
        "vip_sources": vip_sources(cluster.vips),
        "default_vip": cluster.default_vip,
        "default_vip_address": (
            cluster.vips[cluster.default_vip].address if cluster.default_vip in cluster.vips else ""
        ),
        "certificates": list(cluster.certificate_ids),
        "authorities": list(cluster.authority_ids),
        "sources": named_addresses(cluster.sources),
        "networks": sorted(cluster.networks),
        "balances": BALANCE_CHOICES,
        "health_types": CHECK_TYPES,
        "query_types": QUERY_TYPES,
        "methods": sorted(HTTP_METHODS, key=METHOD_ORDER.index),
    }


def check(
    form: Mapping[str, object],
    cluster: EditorCluster,
    *,
    others: Iterable[tuple[str, str]] = (),
) -> Preview:
    """The document this form produces, and the first thing wrong with it.

    `others` are the cluster's remaining objects as `(name, document)`, passed
    through the generator alongside this one. Without them the refusals that
    are about an object's *neighbours* - a hostname another site already
    claims, two objects on one port - cannot be raised at all, and those are
    precisely the ones a person cannot check by reading their own screen.

    An unreadable neighbour is skipped rather than refused. It is somebody
    else's problem, already reported on its own page, and letting it block this
    edit would make one bad object freeze the editor for the whole cluster.
    """

    try:
        document = saved_document(dict(form))
    except ValueError as exc:
        return Preview(problem=str(exc), about_the_object=True)

    name = str(form.get("name", "") or "").strip()
    try:
        #
        # What the form saves is held to what may be written; the neighbours
        # below are read as they are stored (review 26-10-24, 15-06).
        #
        with address_ranges.writing():
            edited = load_proxy(name, document.encode())
    except ModelError as exc:
        return Preview(document=document, problem=str(exc), about_the_object=True)

    neighbours = []
    for other_name, other_document in others:
        if other_name == name:
            continue
        try:
            neighbours.append(load_proxy(other_name, other_document.encode()))
        except ModelError:
            continue

    if not cluster.complete:
        return Preview(document=document)

    try:
        files = generate(
            [edited, *neighbours],
            vips=cluster.vips,
            default_vip=cluster.default_vip,
            certificates=cluster.certificate_ids,
            authorities=cluster.authority_ids,
            resolvers=VALIDATION_RESOLVERS,
            networks=cluster.networks,
            sources=cluster.sources,
            unknown_host=VALIDATION_UNKNOWN_HOST,
            trusted_proxies=VALIDATION_TRUSTED_PROXIES,
            abuse_protection=VALIDATION_ABUSE_PROTECTION,
            certificate_sans=cluster.certificate_sans,
            countries=unchecked_countries([edited, *neighbours]),
            reservations=cluster.reservations,
        ).configuration
    except GeneratorError as exc:
        return Preview(document=document, problem=str(exc))
    return Preview(document=document, files=files, beside_others=True)


def unchanged(document: str, stored: str | None) -> bool:
    """Whether this edit says the same as what is already stored.

    Compared as text after the same serialiser has written both, so a reordered
    key or a requoted value does not read as a change. A draft that carries no
    change is not saved: an empty edit sitting in the table is indistinguishable
    from an intention, and the object page would report work in progress that
    nobody is doing.
    """

    if stored is None:
        return False
    return document.strip() == stored.strip()


def fingerprint(stored: str | None) -> str:
    """The stored object as a page showed it, to tell on submit whether it moved since.

    A draft's revision says whether the *draft* changed; nothing said whether
    the stored object did. With no draft, a tab opened before somebody else's
    publish submitted the old fields against the new commit, and the publish
    wrote the other person's change away (review 2026-10-04, CR-01). Empty for
    an object that is not stored.
    """

    if stored is None:
        return ""
    return hashlib.sha256(stored.strip().encode("utf-8")).hexdigest()


#
# Each field of the form by the words the form gives it, for what moved under a
# draft (0080). Every field is named here - a test holds this to `DEFAULTS` -
# because a field left out would be a change the page did not mention.
# The rule fields are one line, `Rules`; `rule_index` is the form's own
# bookkeeping and never differs on its own.
#
FIELD_LABELS: dict[str, str] = {
    "name": "Name",
    "hostnames": "Hostnames",
    "description": "Description",
    "protocol": "Protocol",
    "tcp_port": "Port",
    "vip": "VIP",
    "source": "Source",
    "certificate": "Certificate",
    "redirect_http": "Redirect HTTP to HTTPS",
    "hsts": "HSTS",
    "hsts_max_age": "HSTS lifetime",
    "hsts_subdomains": "HSTS for subdomains",
    "backend": "Backend name",
    "balance": "Balancing",
    "balance_key": "Balancing key",
    "cookie": "Session cookie",
    "servers": "Servers",
    "health_type": "Health check",
    "health_path": "Health check path",
    "health_host": "Health check host header",
    "health_port": "Health check port",
    "health_expect_status": "Expected status",
    "health_expect_body": "Expected body",
    "health_send": "Health check send",
    "health_expect": "Health check expect",
    "health_query_name": "Query name",
    "health_query_type": "Query type",
    "health_interval": "Check interval",
    "health_fast_interval": "Fast interval",
    "health_down_interval": "Down interval",
    "health_rise": "Checks to rise",
    "health_fall": "Checks to fall",
    "backend_tls": "TLS to the servers",
    "backend_tls_policy": "Server TLS policy",
    "backend_tls_ca": "Server CA",
    "proxy_protocol": "PROXY protocol",
    "listen_tls_policy": "TLS policy",
    "max_connections": "Connections per server",
    "server_timeout": "Server timeout",
    "slow_start": "Slow start",
    "allow_from": "Reachable from — groups",
    "allow_ranges": "Reachable from — addresses",
    "rate_limit": "Rate limit",
    "rate_window": "Rate window",
    "block_requests": "Block on deny rules",
    "block_errors": "Block on errors",
    "block_connections": "Block on new connections",
    "block_window": "Block window",
    "block_for": "Block for",
    "block_status": "Blocked answer",
    "block_exempt_from": "Never blocked — groups",
    "block_exempt_ranges": "Never blocked — addresses",
    "deny_from": "Denied — groups",
    "deny_ranges": "Denied — addresses",
    "deny_mode": "Denied — mode",
    "max_request_body": "Max request body",
    "rule_index": "Rules",
    "rule_name": "Rules",
    "rule_mode": "Rules",
    "rule_path": "Rules",
    "rule_match": "Rules",
    "rule_header": "Rules",
    "rule_header_match": "Rules",
    "rule_header_value": "Rules",
    "rule_source": "Rules",
    "rule_methods": "Rules",
    "rule_negate": "Rules",
    "maintenance": "Maintenance page",
    "maintenance_message": "Maintenance message",
    "unavailable_message": "Unavailable message",
    "request_headers": "Request headers",
    "response_headers": "Response headers",
    "redirect_path": "Redirect path",
    "redirect_match": "Redirect match",
    "redirect_location": "Redirect to",
    "redirect_status": "Redirect status",
    "advanced": "Advanced config",
    "handwritten_pool": "Handwritten pool",
    "waf_mode": "WAF mode",
    "waf_engine_error": "WAF engine not answering",
    "waf_paranoia": "WAF strictness",
    "waf_exceptions": "WAF exceptions",
    "waf_large_bodies": "WAF large bodies",
}
RULES = "Rules"


@dataclass(frozen=True, slots=True)
class Moved:
    """One field of an object as a draft was written against it, and as it is published now."""

    label: str
    before: str
    after: str


def _shown(value: object) -> str:
    if isinstance(value, bool):
        return "On" if value else "Off"
    if isinstance(value, (list, tuple)):
        parts = [_shown(item) for item in value]
        return ", ".join(part for part in parts if part != "—") or "—"
    text = ", ".join(line.strip() for line in str(value).splitlines() if line.strip())
    return text or "—"


def moved(before: str, after: str, *, networks: Collection[str] = ()) -> tuple[Moved, ...]:
    """What changed in the published object between a draft's base and now, field by field.

    `before` and `after` are documents, empty where nothing of that name was
    published. A difference the form cannot express is still a difference,
    and says so rather than going unmentioned.
    """

    if before.strip() == after.strip():
        return ()
    if not before.strip():
        return (Moved("Object", "Not published", "Published"),)
    if not after.strip():
        return (Moved("Object", "Published", "Removed"),)
    try:
        old = form_from_document(before, networks=networks)
        new = form_from_document(after, networks=networks)
    except Unexpressible:
        return (Moved("Settings the form does not show", "", "Changed"),)
    lines: list[Moved] = []
    for key, label in FIELD_LABELS.items():
        if label == RULES:
            continue
        if old.get(key) != new.get(key):
            lines.append(Moved(label, _shown(old.get(key)), _shown(new.get(key))))
    rule_keys = [key for key, label in FIELD_LABELS.items() if label == RULES]
    if any(old.get(key) != new.get(key) for key in rule_keys):
        lines.append(Moved(RULES, _shown(old.get("rule_name")), _shown(new.get("rule_name"))))
    return tuple(lines) or (Moved("Settings the form does not show", "", "Changed"),)


def sequence(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(value for value in values if value)


#
# The form as one declaration instead of thirty parameters on every route that
# takes it. The bounds are part of it: a field without one is a field somebody
# can post a megabyte into, and the limit belongs beside the name it applies to
# rather than in a list a second route has to be kept in step with.
#
# Checkboxes are booleans here. A browser omits an unchecked box entirely, so
# the default is what makes it false; the alternative - a string compared to
# "on" - is the same rule written out by hand at every use.
#
#
# How the form lists the methods: the common ones first, as people read them.
# The set is the engine's (`HTTP_METHODS`); a method missing here fails the
# sort, so the two cannot drift apart unnoticed.
#
METHOD_ORDER = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE")


#
# What a free-text field may hold: a guard against an absurd post and nothing
# more. What an object may say is the engine's to judge, as it judges a file
# applied from the command line. Tighter limits here let the editor open an
# object written there - ninety hostnames - and then refuse to save it, even
# for a change somewhere else (review 26-10-24, 15-08).
#
FORM_TEXT = 64 * 1024


RuleList = Annotated[
    list[Annotated[str, StringConstraints(max_length=64)]], Field(max_length=MAX_RULES)
]


class ObjectForm(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Annotated[str, StringConstraints(max_length=64)] = ""
    description: Annotated[str, StringConstraints(max_length=200)] = ""
    hostnames: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    protocol: Annotated[str, StringConstraints(max_length=8)] = "https"
    tcp_port: Annotated[str, StringConstraints(max_length=5)] = ""
    vip: Annotated[str, StringConstraints(max_length=64)] = ""
    source: Annotated[str, StringConstraints(max_length=64)] = ""
    certificate: Annotated[str, StringConstraints(max_length=255)] = ""
    redirect_http: bool = False
    hsts: bool = False
    hsts_max_age: Annotated[str, StringConstraints(max_length=16)] = ""
    hsts_subdomains: bool = False
    balance: Annotated[str, StringConstraints(max_length=16)] = "roundrobin"
    balance_key: Annotated[str, StringConstraints(max_length=64)] = ""
    cookie: Annotated[str, StringConstraints(max_length=32)] = ""
    backend: Annotated[str, StringConstraints(max_length=64)] = ""
    servers: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    health_type: Annotated[str, StringConstraints(max_length=16)] = "disabled"
    health_path: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    health_host: Annotated[str, StringConstraints(max_length=255)] = ""
    health_port: Annotated[str, StringConstraints(max_length=8)] = ""
    health_interval: Annotated[str, StringConstraints(max_length=8)] = ""
    health_fast_interval: Annotated[str, StringConstraints(max_length=8)] = ""
    health_down_interval: Annotated[str, StringConstraints(max_length=8)] = ""
    health_rise: Annotated[str, StringConstraints(max_length=2)] = ""
    health_fall: Annotated[str, StringConstraints(max_length=2)] = ""
    #
    # The rest of the model's health check, so the form can express every one it
    # allows rather than most of them. An object using a field the form lacked
    # was refused outright - honestly, but with nothing to do about it except
    # edit the file by hand.
    #
    #
    # A status or a range, `200-499` (7-3): three characters held a status
    # only, and a range read back from a document could not be sent again.
    #
    health_expect_status: Annotated[str, StringConstraints(max_length=7)] = ""
    health_expect_body: Annotated[str, StringConstraints(max_length=255)] = ""
    health_send: Annotated[str, StringConstraints(max_length=255)] = ""
    health_expect: Annotated[str, StringConstraints(max_length=255)] = ""
    health_query_name: Annotated[str, StringConstraints(max_length=254)] = ""
    health_query_type: Annotated[str, StringConstraints(max_length=8)] = ""
    backend_tls: Annotated[str, StringConstraints(max_length=16)] = ""
    listen_tls_policy: Annotated[str, StringConstraints(max_length=16)] = ""
    """Terms this site's own certificate is held to, overriding its VIP's.

    Empty means the VIP decides, which is the normal case and what every object
    written before this field existed says.
    """

    backend_tls_policy: Annotated[str, StringConstraints(max_length=16)] = ""
    backend_tls_ca: Annotated[str, StringConstraints(max_length=255)] = ""
    proxy_protocol: bool = False
    """How old a handshake to this backend may be. Empty means the default.

    Empty rather than the name itself, so a form that has never been touched
    and an object that never named one write the same document. What "the
    default" is belongs in one place, and that place is `tls_policy`.
    """
    max_connections: Annotated[str, StringConstraints(max_length=8)] = ""
    server_timeout: Annotated[str, StringConstraints(max_length=8)] = ""
    slow_start: Annotated[str, StringConstraints(max_length=8)] = ""
    allow_from: list[Annotated[str, StringConstraints(max_length=64)]] = Field(default_factory=list)
    allow_ranges: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    rate_limit: Annotated[str, StringConstraints(max_length=8)] = ""
    rate_window: Annotated[str, StringConstraints(max_length=8)] = ""
    #
    # Dynamic blocking (B271). The window, the time and the answer come filled
    # in from `preview.DEFAULTS`; a trigger is what turns it on.
    #
    block_requests: Annotated[str, StringConstraints(max_length=8)] = ""
    block_errors: Annotated[str, StringConstraints(max_length=8)] = ""
    block_connections: Annotated[str, StringConstraints(max_length=8)] = ""
    block_window: Annotated[str, StringConstraints(max_length=8)] = ""
    block_for: Annotated[str, StringConstraints(max_length=8)] = ""
    block_status: Annotated[str, StringConstraints(max_length=3)] = ""
    block_exempt_from: list[Annotated[str, StringConstraints(max_length=64)]] = Field(
        default_factory=list
    )
    block_exempt_ranges: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    #
    # Access rules (Fas 21, B227). A rule is a row of parallel lists, one entry
    # per rule in page order; the boxes a browser leaves out when unticked
    # carry their row's index instead - `2:POST`, `2` - so a missing box
    # cannot shift the next row's ticks onto this one.
    #
    deny_from: list[Annotated[str, StringConstraints(max_length=64)]] = Field(default_factory=list)
    deny_ranges: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    deny_mode: Annotated[str, StringConstraints(max_length=8)] = "log"
    max_request_body: Annotated[str, StringConstraints(max_length=16)] = ""
    rule_index: RuleList = Field(default_factory=list)
    rule_name: RuleList = Field(default_factory=list)
    rule_mode: RuleList = Field(default_factory=list)
    rule_path: Annotated[
        list[Annotated[str, StringConstraints(max_length=FORM_TEXT)]], Field(max_length=MAX_RULES)
    ] = Field(default_factory=list)
    rule_match: RuleList = Field(default_factory=list)
    rule_header: RuleList = Field(default_factory=list)
    rule_header_match: RuleList = Field(default_factory=list)
    rule_header_value: Annotated[
        list[Annotated[str, StringConstraints(max_length=255)]], Field(max_length=MAX_RULES)
    ] = Field(default_factory=list)
    rule_source: Annotated[
        list[Annotated[str, StringConstraints(max_length=FORM_TEXT)]], Field(max_length=MAX_RULES)
    ] = Field(default_factory=list)
    rule_methods: Annotated[
        list[Annotated[str, StringConstraints(max_length=16)]], Field(max_length=MAX_RULES * 9)
    ] = Field(default_factory=list)
    rule_negate: RuleList = Field(default_factory=list)
    maintenance: bool = False
    maintenance_message: Annotated[str, StringConstraints(max_length=200)] = ""
    unavailable_message: Annotated[str, StringConstraints(max_length=200)] = ""
    request_headers: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    response_headers: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    redirect_path: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    redirect_match: Annotated[str, StringConstraints(max_length=8)] = "prefix"
    redirect_location: Annotated[str, StringConstraints(max_length=FORM_TEXT)] = ""
    redirect_status: Annotated[str, StringConstraints(max_length=3)] = "301"
    #
    # Carried through unchanged (Fas 17): edited in the object's own dialog, not
    # here. Bounded well inside the draft's own limit.
    #
    advanced: Annotated[str, StringConstraints(max_length=MAX_TEXT)] = ""
    handwritten_pool: bool = False
    #
    # The WAF engine (Fas 21, B234). The exceptions are made on the WAF page and
    # carried here as JSON; the engine reads them again on every save.
    #
    waf_mode: Annotated[str, StringConstraints(max_length=8)] = "off"
    waf_engine_error: Annotated[str, StringConstraints(max_length=8)] = WAF_ENGINE_ERROR_DEFAULT
    waf_paranoia: Annotated[str, StringConstraints(max_length=1)] = "1"
    waf_exceptions: Annotated[str, StringConstraints(max_length=MAX_TEXT)] = ""
    waf_large_bodies: Annotated[str, StringConstraints(max_length=MAX_TEXT)] = ""

    #
    # The three fields that are about the submission rather than about the
    # object. They live here because FastAPI flattens a form model into the
    # posted fields only when it is the whole body - a second form parameter
    # beside it makes every field nest under a name no browser sends.
    #
    action: Annotated[str, StringConstraints(max_length=16)] = "check"
    #
    # The editor's Remove on one WAF exception: its place in `waf_exceptions`.
    # The page is drawn again without it, unsaved, as any other change here.
    #
    drop_exception: Annotated[str, StringConstraints(max_length=4)] = ""
    #
    # The revisions the page was opened with: the object's draft, and its saved
    # change (B257) - each empty where the object has none.
    #
    expected_revision: Annotated[str, StringConstraints(max_length=16)] = ""
    saved_revision: Annotated[str, StringConstraints(max_length=16)] = ""
    #
    # The stored object as the page showed it, by `fingerprint` (CR-01).
    #
    object_fingerprint: Annotated[str, StringConstraints(max_length=64)] = ""
    csrf_token: Annotated[str, StringConstraints(max_length=128)] = ""

    def fields(self) -> dict[str, object]:
        """What `build_document` and the template both read.

        `allow_from` keeps the empty option out. The form offers "Everywhere" as
        a value of its own so the list is never blank on screen; it means no
        restriction, and a document that wrote it down would restrict the object
        to a group with no name.
        """

        values = self.model_dump()
        for key in (
            "action",
            "expected_revision",
            "saved_revision",
            "object_fingerprint",
            "csrf_token",
        ):
            values.pop(key)
        values["allow_from"] = tuple(entry for entry in self.allow_from if entry)
        values["deny_from"] = tuple(entry for entry in self.deny_from if entry)
        values["block_exempt_from"] = tuple(entry for entry in self.block_exempt_from if entry)
        values["deny_rules"] = access_rules(values)
        return values
