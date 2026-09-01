"""The addresses a node must carry, as keepalived reads them.

The interface can publish a VIP or a source address into `managed/network.yaml`,
but an address no node holds is configuration that looks right and does not
work: HAProxy binds it and nothing on the network answers for it. This module
renders the other half - the address list keepalived puts on the interface -
from the same document, so the two cannot describe different clusters.

What this file deliberately does NOT contain
--------------------------------------------
Everything that can break VRRP. `priority`, `virtual_router_id`, `auth_pass`,
`unicast_src_ip`, `unicast_peer` and the `notify_` lines stay in the node's own
`keepalived.conf`, written by a person. Those fields decide who owns the
address, and getting one wrong gives two masters or none - neither of which
`keepalived --config-test` catches, because both are runtime behaviour rather
than syntax. An extra line in `virtual_ipaddress` cannot cause either. The
boundary is the whole reason this is safe to generate (decision B57).

The file is included from inside the `vrrp_instance`'s `virtual_ipaddress`
block. Proven against a real node's configuration on 2026-09-01: keepalived
2.3.4 reads the included file and validates its contents as though they stood
in place, and reports the included file by name and line when an address in it
is invalid.
"""

from __future__ import annotations

from collections.abc import Mapping

from haproxy_mgmt.config import Vip

#
# The node-relative name, in one place because two sides read it: the artifact
# builder that puts it in a release, and the node helper that installs it.
#
NAME = "addresses.conf"
DIRECTORY = "keepalived"
FRAGMENT = f"{DIRECTORY}/{NAME}"

HEADER = """\
#
# Generated from managed/network.yaml. Do not edit on the node: the next
# deploy overwrites this file.
#
# Included from inside the virtual_ipaddress block of this cluster's
# vrrp_instance. Everything that decides VRRP ownership - priority,
# virtual_router_id, authentication, unicast peers, notify scripts - stays in
# keepalived.conf and is not written from here.
#
"""


def render(vips: Mapping[str, Vip], sources: Mapping[str, str]) -> str:
    """Every address this cluster's nodes carry, one per line.

    Both kinds, because keepalived does not distinguish them: an address is on
    the interface or it is not. The comment on each line says which kind it is,
    since the person reading this on a node is usually asking why an address is
    there rather than what its name is.

    Ordered by name and never by insertion, so that a version diff shows the
    address that changed rather than a reordering. An address named twice - a
    source that repeats a VIP's own address - is emitted once: keepalived would
    otherwise be told to add the same address twice, and the second is at best
    noise in its log.
    """

    lines: list[str] = []
    seen: set[str] = set()

    def add(address: str, note: str) -> None:
        if address in seen:
            return
        seen.add(address)
        lines.append(f"    {address}  # {note}")

    for name in sorted(vips):
        add(vips[name].address, f"vip {name}")
    for name in sorted(vips):
        source = vips[name].source
        if source:
            add(source, f"default source for vip {name}")
    for name in sorted(sources):
        add(sources[name], f"source {name}")

    return HEADER + "\n".join(lines) + "\n"
