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

from collections.abc import Mapping
from pathlib import PurePosixPath

from haproxy_mgmt.config import Cluster, ConfigError
from haproxy_mgmt.generate import generate
from haproxy_mgmt.keepalived_fragment import NAME as KEEPALIVED_NAME
from haproxy_mgmt.keepalived_fragment import render as keepalived_addresses
from haproxy_mgmt.managed_network import load_document
from haproxy_mgmt.managed_network import location as network_location
from haproxy_mgmt.proxy_model import Proxy, load_proxy

MANAGED_PREFIX = "managed/"
PROXY_PREFIX = "managed/proxies/"
GENERATED_PREFIX = "managed/generated/"
#
# The second generated layer, and deliberately not inside the first: everything
# under `managed/generated/` is HAProxy configuration that the node's `conf.d`
# loads, and a keepalived fragment there would either be loaded by HAProxy or
# force the rule that keeps that directory to `.cfg` files to be relaxed.
#
KEEPALIVED_PREFIX = "managed/keepalived/"
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


def managed_files(
    base_files: Mapping[str, bytes],
    *,
    network_document: bytes,
    cluster: Cluster,
) -> dict[str, bytes]:
    """Return the complete managed snapshot created by one network document.

    Only paths below ``managed/`` are returned.  The caller passes exactly this
    mapping to the generic snapshot builder, which replaces that one layer and
    preserves every human-owned file from the committed base.
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

    # Generated output is derived data.  Carrying one file over would make an
    # object deleted in a later UI operation keep serving; carrying all of them
    # would leave source/VIP/group changes invisible.  Start over every time.
    for path in tuple(result):
        if path.startswith((GENERATED_PREFIX, KEEPALIVED_PREFIX)):
            del result[path]

    generated = generate(
        managed_proxies(base_files),
        vips=network.vips,
        default_vip=network.default_vip,
        certificates=cluster.certificate_ids,
        resolvers=cluster.resolvers,
        networks=network.networks,
        sources=network.sources,
        unknown_host=cluster.unknown_host,
    )
    result.update(
        {
            f"{GENERATED_PREFIX}{name}": content.encode("utf-8")
            for name, content in generated.items()
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
    return result
