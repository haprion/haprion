"""Where an object is reached and where its traffic leaves from, as addresses.

Read from the objects helper's entry (B222), which works both out with the
generator's own rule against the network description the generator reads. The
interface used to work them out itself from the document, which made it a
second reader of the same file and a second copy of the rule; this only shapes
the answer for a page.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Address:
    #
    # The address, or empty where the network description has no such name -
    # an object written against a VIP that has since been removed.
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


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def from_entry(vip: Any, source: Any) -> ObjectAddresses | None:
    """The helper's `vip` and `source` fields, or None where it reported none."""

    if not isinstance(vip, Mapping) or not _text(vip.get("name")):
        return None
    name = _text(vip.get("name"))
    default = vip.get("default") is True
    found: Address | None = None
    if isinstance(source, Mapping):
        named = _text(source.get("name"))
        found = Address(
            _text(source.get("address")), f"Source {named}" if named else f"Source of VIP {name}"
        )
    return ObjectAddresses(
        vip=Address(_text(vip.get("address")), f"VIP {name}" + (" (default)" if default else "")),
        vip_name=name,
        vip_is_default=default,
        source=found,
    )


def order_key(address: str) -> tuple[int, int, int, str]:
    """Addresses in numeric order, so .9 comes before .10; anything else after, as text."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return (1, 0, 0, address.casefold())
    return (0, parsed.version, int(parsed), "")
