"""The one editable network document the application may publish.

``managed/network.yaml`` is application-owned data, but it is still
configuration: the generator writes its values into HAProxy's bind, source and
allowlist lines.  This module is consequently the one parser and serializer
for the document that crosses the managed-publish boundary.  A form must not
invent a second YAML shape, and a privileged helper must not accept a document
the engine itself would later refuse.
"""

from __future__ import annotations

from typing import Any

import yaml

from haprion import safe_yaml
from haprion.config import NETWORK_FILE, ConfigError, Network, _mapping, parse_network

# Network tables are small by design.  Keeping the bound below the general
# model limit also bounds the JSON request that carries this document over the
# privilege boundary.
MAX_NETWORK_BYTES = 64 * 1024


def load_mapping(raw: Any, *, ownership_vip: str, location: str) -> Network:
    """Apply the network schema to already-decoded untrusted YAML."""

    return parse_network(
        _mapping(raw, location),
        vip=ownership_vip,
        location=location,
        from_repository=True,
    )


def load_document(document: bytes, *, ownership_vip: str, location: str) -> Network:
    """Parse one untrusted network document exactly as a published tree does.

    The cluster repository is intentionally writable by the application, so a
    file there is not trusted merely because it has a familiar path.  Decode,
    YAML parsing and the semantic network checks are all performed before the
    document is allowed to become a Git tree.
    """

    if len(document) > MAX_NETWORK_BYTES:
        raise ConfigError(f"{location} exceeds the {MAX_NETWORK_BYTES} byte size limit")
    try:
        parsed: Any = safe_yaml.load(document.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{location} is not valid YAML") from exc
    return load_mapping(parsed, ownership_vip=ownership_vip, location=location)


def dump_document(network: Network) -> bytes:
    """Return the canonical YAML representation the application publishes.

    Stable field and row order makes a version diff describe the semantic
    change rather than a YAML emitter's dictionary order.  It also means the
    browser, helper and a future API all write byte-identical documents for
    the same network.
    """

    document: dict[str, object] = {
        "vips": {
            name: {
                "address": vip.address,
                **({"source": vip.source} if vip.source else {}),
                #
                # Only when the VIP named one. A key written for every row would
                # turn "core/ decides" into a policy, and a bind line overrides
                # `core/` in both directions - so the cluster nobody had looked
                # at would be the one that changed.
                #
                **({"tls": vip.tls_policy} if vip.tls_policy else {}),
            }
            for name, vip in sorted(network.vips.items())
        },
        "default_vip": network.default_vip,
    }
    if network.sources:
        document["sources"] = dict(sorted(network.sources.items()))
    if network.networks:
        document["networks"] = {
            name: list(members) for name, members in sorted(network.networks.items())
        }
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False).encode("utf-8")


def location() -> str:
    """The fixed repository-relative target, named in one place."""

    return str(NETWORK_FILE)
