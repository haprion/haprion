"""Where the golden cases live and how one is loaded.

A golden case is a directory: the proxy objects that go in, as `.yaml`, and the
configuration that must come out, as `.cfg`. Adding a case is dropping a
directory in - there is no list to remember to update, which is the only kind of
list that stays correct.

Shared between the test that checks the cases and the tool that rewrites them,
so that the two cannot disagree about what a case is. A tool that regenerated
something slightly different from what the test compares would make the test
pass by writing its own expectations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from haprion import cluster_settings, ipvs_config, rsyslog_forward, safe_yaml
from haprion.config import AbuseProtection, UnknownHost, Vip
from haprion.generate import generate
from haprion.proxy_model import Proxy, load_proxy

GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden"

#
# A case may state the cluster's addresses in this file. Most do not: one VIP
# with no separate source address is the normal deployment, and a case that
# does not care about addressing should not have to describe one.
#
NETWORK = "vips.yaml"
#
# Not a proxy object: a leading underscore is no object name, so the file can
# never be read as one.
#
SETTINGS = "_cluster.yaml"

DEFAULT_VIPS = {"main": Vip(name="main", address="192.0.2.20")}


def cases(root: Path = GOLDEN) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir())


def objects(case: Path) -> list[Proxy]:
    """The case's input, read as bytes exactly as the generator will read it."""

    return [
        load_proxy(path.stem, path.read_bytes())
        for path in sorted(case.glob("*.yaml"))
        if path.name not in (NETWORK, SETTINGS)
    ]


def network(case: Path) -> tuple[dict[str, Vip], str]:
    """The addresses the case's cluster serves on."""

    path = case / NETWORK
    if not path.exists():
        return dict(DEFAULT_VIPS), "main"
    document = safe_yaml.load(path.read_text())
    vips = {
        name: Vip(
            name=name,
            address=entry["address"],
            source=entry.get("source"),
            tls_policy=entry.get("tls"),
            http3=entry.get("http3", False),
        )
        for name, entry in document["vips"].items()
    }
    return vips, document.get("default_vip", next(iter(vips)))


def expected(case: Path) -> dict[str, str]:
    return {path.name: path.read_text() for path in sorted(case.glob("*.cfg"))}


#
# dnsdist's file (B249), kept apart from the configuration half: every `.cfg`
# a case produces is loaded by `haproxy -c`, and this is not HAProxy's.
#
DNS_FILES = ("dnsdist.conf",)


def expected_dns(case: Path) -> dict[str, str]:
    return {name: (case / name).read_text() for name in DNS_FILES if (case / name).exists()}


#
# keepalived's IPVS file (B256), apart for the same reason. Every publish
# writes it, but a case holds it only when it has a syslog object: the others'
# would all be the same header.
#
IPVS_FILES = (ipvs_config.FILE,)


def expected_ipvs(case: Path) -> dict[str, str]:
    return {name: (case / name).read_text() for name in IPVS_FILES if (case / name).exists()}


#
# rsyslog's forwarding to the external receivers (B286), apart for the same
# reason: a case holds it only when its settings name a receiver.
#
RSYSLOG_FILES = (rsyslog_forward.FILE,)


def expected_rsyslog(case: Path) -> dict[str, str]:
    return {name: (case / name).read_text() for name in RSYSLOG_FILES if (case / name).exists()}


#
# What the cluster in a golden case distributes. Certificates are named, never
# pathed: the path is the node's business and the allowlist is the cluster's.
#
CERTIFICATES = ("example.com", "example.net", "wildcard-example-com")

#
# The resolvers section a case's cluster declares in `core/`. Named here rather
# than per case: every deployment that has one has exactly one.
#
RESOLVERS = "cluster-dns"

#
# The address groups a case's cluster defines, and what it answers for a name
# no object claims.
#
NETWORKS = {"office": ("198.51.100.0/24",), "vpn": ("203.0.113.0/24",)}
SOURCES = {"outbound": "192.0.2.35"}
UNKNOWN_HOST = UnknownHost(status=404)

#
# The address the golden cases pretend a front-line proxy sits on, so the
# trusted-proxy branch of the forwarded-header rules is in the frozen output
# rather than only in a unit test.
#
TRUSTED_PROXIES = ("198.51.100.0/24",)

#
# The brake, in the frozen output, so its shape is reviewed like everything
# else rather than living only in a unit test.
#
ABUSE_PROTECTION = AbuseProtection(
    window="10s", max_requests=100, max_errors=20, max_new_connections=50
)


#
# The nodes a case shares its tables with, when its `_cluster.yaml` turns
# sharing on (B270). The addresses a publish would have looked up.
#
PEER_NODES = (("node-a", "192.0.2.1"), ("node-b", "192.0.2.2"))


def arguments(case: Path) -> dict[str, Any]:
    """Everything the generator needs besides the objects themselves.

    One place, so the test that compares output and the tool that rewrites it
    cannot disagree about what cluster the case is generated for.
    """

    vips, default_vip = network(case)
    return {
        "vips": vips,
        "default_vip": default_vip,
        "certificates": CERTIFICATES,
        "resolvers": RESOLVERS,
        "networks": NETWORKS,
        "sources": SOURCES,
        "unknown_host": UNKNOWN_HOST,
        "trusted_proxies": TRUSTED_PROXIES,
        "abuse_protection": ABUSE_PROTECTION,
        #
        # A case's own `_cluster.yaml`, when it has one: the log targets and
        # the metrics exporter (Fas 15). Parsed by the one parser there is.
        #
        "settings": cluster_settings.load_document(
            (case / SETTINGS).read_bytes() if (case / SETTINGS).exists() else None
        ),
        "peer_nodes": PEER_NODES,
    }


def produced(case: Path) -> dict[str, str]:
    """The configuration half of a case, which is what the golden files are."""

    return generate(objects(case), **arguments(case)).configuration


def produced_dns(case: Path) -> dict[str, str]:
    """The dnsdist half of a case: empty unless it has a dns object."""

    return generate(objects(case), **arguments(case)).dns_files


def produced_rsyslog(case: Path) -> dict[str, str]:
    """The rsyslog half of a case: empty unless its settings name a receiver."""

    return generate(objects(case), **arguments(case)).rsyslog_files


def produced_ipvs(case: Path) -> dict[str, str]:
    """The IPVS half of a case: empty unless it has a syslog object."""

    proxies = objects(case)
    if not any(proxy.listen.protocol == "syslog" for proxy in proxies):
        return {}
    return {ipvs_config.FILE: generate(proxies, **arguments(case)).ipvs}


def produced_lists(case: Path) -> dict[str, str]:
    """The certificate lists a case's bind lines name.

    Not golden files. What matters about them is whether HAProxy finds and
    accepts them, and only HAProxy can answer that - so they are written beside
    the configuration when a case is validated, in the layout a release has.
    """

    return generate(objects(case), **arguments(case)).certificate_lists
