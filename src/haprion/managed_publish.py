"""Build the application-owned part of a cluster tree from one network edit.

The privileged helper receives a network document, never a path and never a
finished HAProxy artifact.  It uses this module to construct the *entire*
managed layer from the committed base plus that one document.  Rebuilding the
generated files here matters even though B55 initially edits only addresses:
an existing object may use the default VIP, a named source or an allowlist.
Leaving its old generated file beside a new table would create a version whose
YAML and HAProxy configuration disagree.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import PurePosixPath

from haprion import cluster_settings, crs, geo, ipvs_config
from haprion.config import Cluster, ConfigError
from haprion.generate import countries_named, generate
from haprion.keepalived_fragment import NAME as KEEPALIVED_NAME
from haprion.keepalived_fragment import render as keepalived_addresses
from haprion.managed_network import load_document
from haprion.managed_network import location as network_location
from haprion.object_manifest import REPOSITORY_PATH as MANIFEST_PATH
from haprion.object_manifest import build as build_manifest
from haprion.object_manifest import render as render_manifest
from haprion.proxy_model import NAME, NAME_RULE, Proxy, load_proxy, name_refusal
from haprion.reservations import RESERVATIONS_PATH, load_reservations

MANAGED_PREFIX = "managed/"
#
# The promise a person writes about what the handwritten half already uses.
# Read from the committed base like everything else the generator consults.
#
PROXY_PREFIX = "managed/proxies/"
GENERATED_PREFIX = "managed/generated/"
#
# The second generated layer, and deliberately not inside the first: everything
# under `managed/generated/` is HAProxy configuration that the node's `conf.d`
# loads, and a keepalived fragment there would either be loaded by HAProxy or
# force the rule that keeps that directory to `.cfg` files to be relaxed.
#
KEEPALIVED_PREFIX = "managed/keepalived/"
CRT_LIST_PREFIX = "managed/crt-lists/"
#
# The countries objects name, one network list each (B228). The node's `maps/`,
# which it already fetches and validates against.
#
MAPS_PREFIX = "managed/maps/"
#
# The WAF engine's layer (B229, B233): its configuration, the SPOE file and the
# rule set the manager has installed, all in the version a person can read and
# revert. The node's `waf/`; absent when no object uses the engine.
#
WAF_PREFIX = "managed/waf/"
#
# dnsdist's configuration for the cluster's dns objects (B249). The node's
# `dns/`; absent when no object is dns, which is what stops dnsdist there.
#
DNS_PREFIX = "managed/dns/"
#
# rsyslog's forwarding to the external receivers (B286). The node's `rsyslog/`;
# absent when the traffic log is sent nowhere, which removes it there.
#
RSYSLOG_PREFIX = "managed/rsyslog/"
PLACEHOLDER = ".gitkeep"


def managed_proxies(files: Mapping[str, bytes]) -> list[Proxy]:
    """Load every stored proxy object from committed bytes, never a worktree."""

    proxies: list[Proxy] = []
    for path, document in sorted(files.items()):
        if not path.startswith(PROXY_PREFIX):
            continue
        relative = path.removeprefix(PROXY_PREFIX)
        pure = PurePosixPath(relative)
        if relative == PLACEHOLDER:
            continue
        if len(pure.parts) != 1 or pure.suffix != ".yaml" or not pure.stem:
            raise ConfigError(f"{path} is not a proxy object file")
        proxies.append(load_proxy(pure.stem, document))
    return proxies


def _apply_objects(result: dict[str, bytes], objects: Mapping[str, bytes | None]) -> None:
    """Put one publish's object changes into the managed snapshot.

    A name rather than a path, and held to the model's own pattern before it is
    used to build one. The names arrive in a job payload, so a path assembled
    from an unchecked name is how a publish of a proxy object ends up writing
    somewhere else entirely.

    `None` removes an object. Removing one that is not there is refused rather
    than ignored: it means the tree moved under the draft, and quietly
    succeeding would report that a site was taken down when nothing happened.
    """

    for name, document in sorted(objects.items()):
        if not NAME.match(name):
            raise ConfigError(
                f"{name} is not a usable object name - {name_refusal(name)}; use {NAME_RULE}"
            )
        path = f"{PROXY_PREFIX}{name}.yaml"
        if document is None:
            if path not in result:
                raise ConfigError(f"{name} cannot be removed because this version does not have it")
            del result[path]
            continue
        result[path] = document


def managed_files(
    base_files: Mapping[str, bytes],
    *,
    network_document: bytes,
    cluster: Cluster,
    objects: Mapping[str, bytes | None] | None = None,
    certificate_sans: Mapping[str, Sequence[str]] | None = None,
    allow_certificate_mismatch: bool = False,
    settings_document: bytes | None = None,
    country_reader: geo.CountryReader | None = None,
    rule_set: Callable[[], crs.RuleSet | None] | None = None,
    node_addresses: Callable[[], Sequence[tuple[str, str]]] | None = None,
) -> dict[str, bytes]:
    """Return the complete managed snapshot created by one network document.

    Only paths below ``managed/`` are returned.  The caller passes exactly this
    mapping to the generic snapshot builder, which replaces that one layer and
    preserves every human-owned file from the committed base.

    `settings_document` replaces `managed/cluster.yaml` when given; otherwise
    the base's is carried over. Every publish generates from it, so a network
    or object change keeps the cluster's log targets and exporter.
    """

    network = load_document(
        network_document,
        ownership_vip=cluster.vip,
        location=network_location(),
    )
    result = {
        path: content for path, content in base_files.items() if path.startswith(MANAGED_PREFIX)
    }
    result[network_location()] = network_document
    if settings_document is not None:
        result[cluster_settings.LOCATION] = settings_document
    settings = cluster_settings.load_document(result.get(cluster_settings.LOCATION))

    # Generated output is derived data.  Carrying one file over would make an
    # object deleted in a later UI operation keep serving; carrying all of them
    # would leave source/VIP/group changes invisible.  Start over every time.
    for path in tuple(result):
        if path.startswith(
            (
                GENERATED_PREFIX,
                KEEPALIVED_PREFIX,
                CRT_LIST_PREFIX,
                MAPS_PREFIX,
                WAF_PREFIX,
                DNS_PREFIX,
                RSYSLOG_PREFIX,
            )
        ):
            del result[path]

    _apply_objects(result, objects or {})

    #
    # Read from `result` and not from `base_files`, which is the whole point of
    # the line above: the objects being published are the base's with the
    # snapshot applied, and generating from the base would write configuration
    # for the version nobody asked to publish while storing the one they did.
    #
    proxies = managed_proxies(result)
    #
    # Asked only for the countries the objects being published name, and only
    # when they name any: the reader opens the location database, and a
    # cluster without a country never needs it to exist (B228).
    #
    named = countries_named(proxies)
    countries = country_reader(named) if named and country_reader is not None else None
    #
    # Read before generating when an object uses the engine, as the location
    # database is when one names a country: each exception's counter is its
    # rule's own text (B273). A cluster without the engine never opens it.
    #
    rules = (
        rule_set()
        if rule_set is not None and any(proxy.inspected is not None for proxy in proxies)
        else None
    )
    generated = generate(
        proxies,
        vips=network.vips,
        default_vip=network.default_vip,
        certificates=cluster.certificate_ids,
        authorities=cluster.authority_ids,
        resolvers=cluster.resolvers,
        networks=network.networks,
        sources=network.sources,
        unknown_host=cluster.unknown_host,
        trusted_proxies=cluster.trusted_proxy_cidrs,
        abuse_protection=cluster.abuse_protection,
        traffic_logging=cluster.traffic_logging,
        reservations=load_reservations(base_files.get(RESERVATIONS_PATH, b"{}")),
        #
        # Read by the caller, which has the path policy, and passed in. This
        # module takes a Git tree and a cluster and opens nothing itself - the
        # same discipline as `inventory` - and certificate coverage is not a
        # reason to break it (B66).
        #
        certificate_sans=certificate_sans,
        allow_certificate_mismatch=allow_certificate_mismatch,
        settings=settings,
        countries=countries,
        #
        # Looked up only when the cluster shares its tables or exports metrics -
        # both listen on the nodes' own addresses - as the location database is
        # opened only for a country: a cluster with neither never asks DNS
        # anything here (B270).
        #
        node_addresses=(
            node_addresses()
            if (settings.peers is not None or settings.metrics is not None)
            and node_addresses is not None
            else ()
        ),
        rule_definitions=crs.definitions(rules) if rules is not None else None,
    )
    result.update(
        {
            f"{MAPS_PREFIX}{name}": content.encode("utf-8")
            for name, content in generated.map_files.items()
        }
    )
    if generated.waf_files:
        if rules is None:
            raise ConfigError(
                "objects use the WAF engine and the rule set is not installed on the manager: "
                "install the haprion-crs package"
            )
        result.update(
            {
                f"{WAF_PREFIX}{name}": content.encode("utf-8")
                for name, content in generated.waf_files.items()
            }
        )
        result.update({f"{WAF_PREFIX}crs/{name}": content for name, content in rules.files.items()})
    result.update(
        {
            f"{DNS_PREFIX}{name}": content.encode("utf-8")
            for name, content in generated.dns_files.items()
        }
    )
    result.update(
        {
            f"{RSYSLOG_PREFIX}{name}": content.encode("utf-8")
            for name, content in generated.rsyslog_files.items()
        }
    )
    result.update(
        {
            f"{GENERATED_PREFIX}{name}": content.encode("utf-8")
            for name, content in generated.configuration.items()
        }
    )
    #
    # A third generated layer, and separate for the same reason keepalived's is:
    # `managed/generated/` becomes the node's `conf.d`, and everything there is
    # loaded as configuration. A certificate list read that way is a failed
    # deploy, so it must live where nothing globs for it.
    #
    result.update(
        {
            f"{CRT_LIST_PREFIX}{name}": content.encode("utf-8")
            for name, content in generated.certificate_lists.items()
        }
    )
    #
    # Written into the tree rather than derived when a release is built. The
    # address list is then part of the version a person can read, revert and
    # diff - which is what makes "when did this address appear" answerable by
    # the same history as every other configuration change.
    #
    result[f"{KEEPALIVED_PREFIX}{KEEPALIVED_NAME}"] = keepalived_addresses(
        network.vips,
        network.sources,
        prefix=cluster.address_prefix,
        interface=cluster.address_interface,
    ).encode("utf-8")
    #
    # Beside it, and always: the syslog objects' virtual servers (B256). A file
    # with none removes the previous release's from the nodes, where a missing
    # file would leave them forwarding.
    #
    result[f"{KEEPALIVED_PREFIX}{ipvs_config.FILE}"] = generated.ipvs.encode("utf-8")
    #
    # What each object in this version amounts to, so a later reading can ask
    # whether one object reached the nodes without asking who published it or
    # how long ago. Derived here for the same reason the generated files are:
    # this is where the objects being published are known, and a manifest built
    # anywhere else would describe a different set.
    #
    result[MANIFEST_PATH] = render_manifest(build_manifest(generated.object_parts))
    return result
