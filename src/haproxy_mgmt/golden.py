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

import yaml

from haproxy_mgmt.config import UnknownHost, Vip
from haproxy_mgmt.generate import generate
from haproxy_mgmt.proxy_model import Proxy, load_proxy

GOLDEN = Path(__file__).resolve().parents[2] / "tests" / "golden"

#
# A case may state the cluster's addresses in this file. Most do not: one VIP
# with no separate source address is the normal deployment, and a case that
# does not care about addressing should not have to describe one.
#
NETWORK = "vips.yaml"

DEFAULT_VIPS = {"main": Vip(name="main", address="192.0.2.20")}


def cases(root: Path = GOLDEN) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir())


def objects(case: Path) -> list[Proxy]:
    """The case's input, read as bytes exactly as the generator will read it."""

    return [
        load_proxy(path.stem, path.read_bytes())
        for path in sorted(case.glob("*.yaml"))
        if path.name != NETWORK
    ]


def network(case: Path) -> tuple[dict[str, Vip], str]:
    """The addresses the case's cluster serves on."""

    path = case / NETWORK
    if not path.exists():
        return dict(DEFAULT_VIPS), "main"
    document = yaml.safe_load(path.read_text())
    vips = {
        name: Vip(
            name=name,
            address=entry["address"],
            source=entry.get("source"),
            tls_policy=entry.get("tls"),
        )
        for name, entry in document["vips"].items()
    }
    return vips, document.get("default_vip", next(iter(vips)))


def expected(case: Path) -> dict[str, str]:
    return {path.name: path.read_text() for path in sorted(case.glob("*.cfg"))}


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


def arguments(case: Path) -> dict[str, object]:
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
    }


def produced(case: Path) -> dict[str, str]:
    return generate(objects(case), **arguments(case))  # type: ignore[arg-type]
