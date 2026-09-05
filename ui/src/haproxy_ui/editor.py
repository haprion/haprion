"""Editing one proxy object against the cluster it is actually served on.

`preview` answers what the generator does with a filled-in form, against a
documented example cluster. This narrows that to a real one: the VIPs, source
addresses, groups and certificates below are the ones the poller last read from
the cluster being edited, so the refusals a person meets here are the refusals a
publish would give them - a hostname another object already claims, a
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

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from haproxy_mgmt.config import AbuseProtection, Cluster, UnknownHost, Vip
from haproxy_mgmt.generate import GeneratorError, generate
from haproxy_mgmt.proxy_model import BALANCE, ModelError, load_proxy
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from haproxy_ui.certificates import CertificateClusterView
from haproxy_ui.network import NetworkClusterView
from haproxy_ui.preview import (
    CHECK_TYPES,
    Preview,
    build_document,
    named_addresses,
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


def editor_cluster(
    cluster: str,
    network: NetworkClusterView | None,
    certificates: CertificateClusterView | None,
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
        "sources": named_addresses(cluster.sources),
        "networks": sorted(cluster.networks),
        "balances": BALANCE,
        "health_types": CHECK_TYPES,
    }


def _validation_cluster(cluster: EditorCluster) -> Cluster:
    """The engine's cluster shape, for the generator to refuse an object with."""

    return Cluster(
        cluster_id=cluster.cluster,
        display_name=cluster.cluster,
        vip=next(iter(cluster.vips.values())).address if cluster.vips else "",
        address_prefix=None,
        address_interface=None,
        vips=dict(cluster.vips),
        default_vip=cluster.default_vip,
        sources=dict(cluster.sources),
        networks=dict(cluster.networks),
        config_path=Path("/editor"),
        publish_path=Path("/editor"),
        node_path="editor",
        validation_certs=Path("/editor"),
        default_certificate=cluster.certificate_ids[0] if cluster.certificate_ids else "",
        certificate_ids=cluster.certificate_ids,
        nodes=(),
        resolvers=VALIDATION_RESOLVERS,
        unknown_host=VALIDATION_UNKNOWN_HOST,
        abuse_protection=VALIDATION_ABUSE_PROTECTION,
        trusted_proxy_cidrs=VALIDATION_TRUSTED_PROXIES,
    )


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
        document = build_document(dict(form))
    except ValueError as exc:
        return Preview(problem=str(exc), about_the_object=True)

    name = str(form.get("name", "") or "").strip()
    try:
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
        generate(
            [edited, *neighbours],
            vips=cluster.vips,
            default_vip=cluster.default_vip,
            certificates=cluster.certificate_ids,
            resolvers=VALIDATION_RESOLVERS,
            networks=cluster.networks,
            sources=cluster.sources,
            unknown_host=VALIDATION_UNKNOWN_HOST,
            trusted_proxies=VALIDATION_TRUSTED_PROXIES,
            abuse_protection=VALIDATION_ABUSE_PROTECTION,
            certificate_sans=cluster.certificate_sans,
        )
    except GeneratorError as exc:
        return Preview(document=document, problem=str(exc))
    return Preview(document=document)


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
class ObjectForm(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Annotated[str, StringConstraints(max_length=64)] = ""
    hostnames: Annotated[str, StringConstraints(max_length=2048)] = ""
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
    backend: Annotated[str, StringConstraints(max_length=64)] = "web"
    servers: Annotated[str, StringConstraints(max_length=4096)] = ""
    health_type: Annotated[str, StringConstraints(max_length=16)] = "disabled"
    health_path: Annotated[str, StringConstraints(max_length=1024)] = ""
    health_host: Annotated[str, StringConstraints(max_length=255)] = ""
    health_port: Annotated[str, StringConstraints(max_length=8)] = ""
    health_interval: Annotated[str, StringConstraints(max_length=8)] = ""
    health_rise: Annotated[str, StringConstraints(max_length=2)] = ""
    health_fall: Annotated[str, StringConstraints(max_length=2)] = ""
    #
    # The rest of the model's health check, so the form can express every one it
    # allows rather than most of them. An object using a field the form lacked
    # was refused outright - honestly, but with nothing to do about it except
    # edit the file by hand.
    #
    health_expect_status: Annotated[str, StringConstraints(max_length=3)] = ""
    health_expect_body: Annotated[str, StringConstraints(max_length=255)] = ""
    health_send: Annotated[str, StringConstraints(max_length=255)] = ""
    health_expect: Annotated[str, StringConstraints(max_length=255)] = ""
    backend_tls: Annotated[str, StringConstraints(max_length=16)] = ""
    listen_tls_policy: Annotated[str, StringConstraints(max_length=16)] = ""
    """Terms this site's own certificate is held to, overriding its VIP's.

    Empty means the VIP decides, which is the normal case and what every object
    written before this field existed says.
    """

    backend_tls_policy: Annotated[str, StringConstraints(max_length=16)] = ""
    """How old a handshake to this pool may be. Empty means the default.

    Empty rather than the name itself, so a form that has never been touched
    and an object that never named one write the same document. What "the
    default" is belongs in one place, and that place is `tls_policy`.
    """
    max_connections: Annotated[str, StringConstraints(max_length=8)] = ""
    slow_start: Annotated[str, StringConstraints(max_length=8)] = ""
    allow_from: list[Annotated[str, StringConstraints(max_length=64)]] = Field(default_factory=list)
    allow_ranges: Annotated[str, StringConstraints(max_length=2048)] = ""
    maintenance: bool = False
    maintenance_message: Annotated[str, StringConstraints(max_length=200)] = ""
    unavailable_message: Annotated[str, StringConstraints(max_length=200)] = ""
    request_headers: Annotated[str, StringConstraints(max_length=2048)] = ""
    response_headers: Annotated[str, StringConstraints(max_length=2048)] = ""
    redirect_path: Annotated[str, StringConstraints(max_length=1024)] = ""
    redirect_match: Annotated[str, StringConstraints(max_length=8)] = "prefix"
    redirect_location: Annotated[str, StringConstraints(max_length=1024)] = ""
    redirect_status: Annotated[str, StringConstraints(max_length=3)] = "301"

    #
    # The three fields that are about the submission rather than about the
    # object. They live here because FastAPI flattens a form model into the
    # posted fields only when it is the whole body - a second form parameter
    # beside it makes every field nest under a name no browser sends.
    #
    action: Annotated[str, StringConstraints(max_length=16)] = "check"
    expected_revision: Annotated[str, StringConstraints(max_length=16)] = ""
    csrf_token: Annotated[str, StringConstraints(max_length=128)] = ""

    def fields(self) -> dict[str, object]:
        """What `build_document` and the template both read.

        `allow_from` keeps the empty option out. The form offers "Everywhere" as
        a value of its own so the list is never blank on screen; it means no
        restriction, and a document that wrote it down would restrict the object
        to a group with no name.
        """

        values = self.model_dump()
        for key in ("action", "expected_revision", "csrf_token"):
            values.pop(key)
        values["allow_from"] = tuple(entry for entry in self.allow_from if entry)
        return values
