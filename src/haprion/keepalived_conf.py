"""Each node's keepalived.conf, written by the product where nobody else does (B313).

B57 kept everything that decides VRRP ownership - priority, router ID,
authentication, peers - out of what the product writes, because getting one of
them wrong gives two masters or none and `keepalived --config-test` catches
neither. B313 takes them on for the nodes of a cluster the product created,
and so they are written here from facts it already holds, in one shape:

  * `state BACKUP` and `nopreempt` on every node: a node that comes back does
    not take the address back (26-10-12: which node holds it is the product's
    concern, not the operator's)
  * the priority from the cluster's node order - 100, 90, 80 ...: decides only
    who takes the address on a cold start
  * unicast to the named peers, with `check_unicast_src`, and no
    authentication. VRRP's password is eight bytes of clear text and RFC 5798
    dropped it; an advert from an address that is not a peer is discarded
    (measured 26-10-15 on keepalived 2.3.3: "unicast source address ... not a
    unicast peer")
  * a node alone names `127.0.0.1` as its peer. An empty list falls back to
    multicast on the segment, and the node's own address makes it read its
    own adverts and warn every second (both measured 26-10-15)
  * the address list and the IPVS file included, as the files a person wrote
    include them (B57, B256)

One file per node, carried in the release as `keepalived/node-<name>.conf`,
one level deep like the address list so the release's shape is unchanged. The
node installs its own, and only over a file that starts with `MARK` or where
there is none: a keepalived.conf a person wrote is theirs.
"""

from __future__ import annotations

from collections.abc import Sequence

#
# The first line of every file written here, and what the node reads to decide
# that a file is the product's to replace. Changing it orphans every installed
# file, which the node then leaves alone.
#
MARK = "# Written by Haprion (B313)."
#
# Where the cluster file names no interface: the node fills in the one that
# carries its own address (`unicast_src_ip`), which it can see and the
# manager cannot.
#
INTERFACE_FROM_NODE = "@INTERFACE@"
PREFIX = "node-"
SUFFIX = ".conf"
LOOPBACK = "127.0.0.1"
#
# The node-side paths the file includes, as `haprion-pull-deploy` installs them.
#
ADDRESSES = "/etc/keepalived/addresses.conf"
IPVS = "/etc/keepalived/ipvs.conf"
STATE_HELPER = "/usr/sbin/haprion-keepalived-state"


def file_name(node: str) -> str:
    """The release's name for a node's file: one level under `keepalived/`."""

    return f"{PREFIX}{node}{SUFFIX}"


def priority(index: int) -> int:
    """100 for the first node, ten less for each after it, never below 1."""

    return max(100 - 10 * index, 1)


def render(
    cluster: str,
    *,
    router_id: int,
    nodes: Sequence[tuple[str, str]],
    node: str,
    interface: str | None,
) -> str:
    """The keepalived.conf for `node`, one of `nodes` (name, address) in cluster order."""

    names = [name for name, _address in nodes]
    if node not in names:
        raise ValueError(f"{node} is not a node of {cluster}")
    index = names.index(node)
    own = nodes[index][1]
    peers = [address for name, address in nodes if name != node] or [LOOPBACK]
    lines = [
        MARK,
        "#",
        f"# keepalived for node {node} of cluster {cluster}. A deploy writes this",
        "# file from the cluster's definition; edits here are replaced. Delete the",
        "# first line to make the file yours: the product then leaves it alone.",
        "#",
        "global_defs {",
        "    enable_script_security",
        "    script_user root",
        "}",
        "",
        f"include {IPVS}",
        "",
        f"vrrp_instance {cluster} {{",
        "    state BACKUP",
        "    nopreempt",
        f"    interface {interface or INTERFACE_FROM_NODE}",
        f"    virtual_router_id {router_id}",
        f"    priority {priority(index)}",
        "    advert_int 1",
        f"    unicast_src_ip {own}",
        "    check_unicast_src",
        "    unicast_peer {",
        *(f"        {peer}" for peer in peers),
        "    }",
        "    virtual_ipaddress {",
        f"        include {ADDRESSES}",
        "    }",
        f'    notify_master "{STATE_HELPER} MASTER"',
        f'    notify_backup "{STATE_HELPER} BACKUP"',
        f'    notify_fault  "{STATE_HELPER} FAULT"',
        "}",
    ]
    return "\n".join(lines) + "\n"


def render_all(
    cluster: str,
    *,
    router_id: int,
    nodes: Sequence[tuple[str, str]],
    interface: str | None,
) -> dict[str, str]:
    """Every node's file, by its name in the release's `keepalived/`."""

    return {
        file_name(name): render(
            cluster, router_id=router_id, nodes=nodes, node=name, interface=interface
        )
        for name, _address in nodes
    }
