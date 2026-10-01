"""Where an object is reached and where its traffic leaves from, as addresses.

An object names its VIP and its source address rather than writing either
down: an address is an environment value and lives in the cluster's network
description (`proxy_model.Listen`). Every page that shows an address therefore
has to look the name up, and this is the one place that does it - the listing's
column, the object page and the search must not come to disagree about which
address a site is on.

The rule is the generator's own (`generate._source_of`): no VIP named means the
cluster's default VIP, and no source named means the VIP's own source, if it
has one. Restating it here is a second copy, so the tests hold it to the
generator's answer.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.proxy_model import ModelError, Proxy, load_proxy


@dataclass(frozen=True, slots=True)
class Address:
    #
    # The address, or empty where the network description does not know the
    # name - an object written against a VIP that has since been removed.
    #
    address: str
    #
    # What the address is, for a title: "VIP main (default)", "Source outbound",
    # "Source of VIP main".
    #
    label: str

    @property
    def shown(self) -> str:
        return self.address or self.label


@dataclass(frozen=True, slots=True)
class ObjectAddresses:
    vip: Address
    vip_name: str
    vip_is_default: bool
    source: Address | None


def network_result(reading: Any) -> Mapping[str, Any]:
    """One cluster's cached network description, or nothing."""

    result = getattr(reading, "result", None)
    return result if isinstance(result, Mapping) else {}


def _entries(result: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    values = result.get(key)
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return []
    return [entry for entry in values if isinstance(entry, Mapping) and entry.get("name")]


def _proxy(name: str, document: str) -> Proxy | None:
    #
    # The engine's own reader, so a page cannot read a document differently
    # from the generator that turns it into configuration.
    #
    try:
        return load_proxy(name, document.encode())
    except (ModelError, UnicodeError):
        return None


def resolve(name: str, document: str, network: Mapping[str, Any]) -> ObjectAddresses | None:
    """The addresses one stored object is served on and leaves from.

    None where the document cannot be read, or where the cluster has no network
    description to look the names up in: an answer made without one would be a
    guess at the default VIP.
    """

    proxy = _proxy(name, document)
    default = str(network.get("default_vip") or "")
    if proxy is None or not default:
        return None
    vip_name = proxy.listen.vip or default
    vips = {str(entry["name"]): entry for entry in _entries(network, "vips")}
    vip = vips.get(vip_name, {})
    is_default = vip_name == default
    source: Address | None = None
    if proxy.listen.source:
        sources = {str(entry["name"]): entry for entry in _entries(network, "sources")}
        source = Address(
            str(sources.get(proxy.listen.source, {}).get("address") or ""),
            f"Source {proxy.listen.source}",
        )
    elif vip.get("source"):
        source = Address(str(vip["source"]), f"Source of VIP {vip_name}")
    return ObjectAddresses(
        vip=Address(
            str(vip.get("address") or ""),
            f"VIP {vip_name}" + (" (default)" if is_default else ""),
        ),
        vip_name=vip_name,
        vip_is_default=is_default,
        source=source,
    )


def servers(name: str, document: str) -> tuple[str, ...]:
    """Every backend server as `host:port`, in the order the document lists them."""

    proxy = _proxy(name, document)
    if proxy is None:
        return ()
    return tuple(
        f"{server.host}:{server.port}"
        for backend in proxy.backends.values()
        for server in backend.servers
    )


def order_key(address: str) -> tuple[int, int, int, str]:
    """Addresses in numeric order, so .9 comes before .10; anything else after, as text."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return (1, 0, 0, address.casefold())
    return (0, parsed.version, int(parsed), "")
