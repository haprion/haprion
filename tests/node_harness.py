"""A two-node cluster that can be put into the states a real pair cannot.

Plan §6 makes this a deliverable, not a convenience: split brain, zero VIP
owners, an indeterminate VIP answer and a failing reload cannot be provoked on
the production pair, and the DR node models one node rather than a pair. So the
matrix is driven against this instead.

What it is faithful to
----------------------
The contract, exactly. It answers with the envelope
`schemas/v1/haproxy-status.schema.json` describes, derived the way
`haproxy-status-root` derives it, and it reacts to a trigger the way a node
does: a successful pull moves the node onto the target release, a failing reload
leaves it where it was and reports non-zero, and an unreachable node answers
nothing at all. Ownership of the address is state the harness holds and can hand
between nodes, including handing it to both at once.

What it is NOT faithful to, and must not be claimed to be
---------------------------------------------------------
There is no SSH here, no forced command, no keepalived and no address on an
interface. This proves that the decision, the parsing and the loop agree with
the matrix. It does not prove the wiring to a real node, and it cannot: for that
a rig with two actual machines is still required, and this harness is not a
substitute for one.

The VIP-state derivation below is deliberately a second implementation of the
one in `haproxy-status-root`. That is the point - it stands in for that helper -
but it does mean the two must be kept in step, so the rules are written out in
the same order as the original rather than restructured.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

TARGET_HASH = "1" * 40
OLD_HASH = "0" * 40

#
# Exit codes a node trigger can come back with. 255 is what SSH itself returns
# when it cannot reach the host, which is how an unreachable node shows up.
#
TRIGGER_OK = 0
TRIGGER_RELOAD_FAILED = 1
TRIGGER_UNREACHABLE = 255


@dataclass
class FakeNode:
    """One node, with the handful of properties the matrix actually reads."""

    name: str
    mgmt_host: str
    owns_vip: bool | None = False
    release_hash: str = OLD_HASH
    reachable: bool = True
    #
    # The node answers, but with something that is not a usable status. Kept
    # separate from `reachable` because the two are different rows in the
    # matrix, and because the collecting helper treats "the JSON parsed" as
    # "the status is valid" - so `null` has to be representable.
    #
    answers: str = "status"
    reload_fails: bool = False
    #
    # (id, fingerprint) pairs the node is carrying. None models a node that
    # answers without mentioning certificates at all - which is what every real
    # node does today, because the node-side status script hardcodes an empty
    # list (Ö6/Ö7). The two are different states and the matrix treats them
    # differently, so both have to be representable here.
    #
    certificates: tuple[tuple[str, str], ...] | None = ()

    def status(self) -> Any:
        if self.answers == "null":
            return None
        if self.answers == "garbage":
            return ["not", "a", "status"]
        return {
            "schema_version": 1,
            "node": self.name,
            "cluster": "alpha",
            "haproxy": {"active": True},
            "keepalived": {"active": True, "state": "MASTER" if self.owns_vip else "BACKUP"},
            "vip": {
                "address": "192.0.2.10",
                "interface": "eth0",
                "owner": self.owns_vip,
            },
            "ip_nonlocal_bind": True,
            "release": {
                "cluster": "alpha",
                "version": 7,
                "hash": self.release_hash,
                "timestamp": "2026-01-02T03:04:05+00:00",
            },
            "config_validation": {"valid": True, "validated_at": "2026-01-02T03:04:05+00:00"},
            "stats_ok": True,
            "runtime": {"version": "3.2.1", "uptime_sec": 3600},
            "certificates": self._certificates(),
        }

    def _certificates(self) -> Any:
        """What the node reports carrying, in the shape the status schema wants.

        The metadata around the fingerprint is filled in with fixed values: the
        deploy matrix compares fingerprints and nothing else, and inventing
        plausible subjects and dates here would suggest this harness knows
        something about certificates that it does not.
        """

        if self.certificates is None:
            return None
        return [
            {
                "id": identifier,
                "fingerprint_sha256": fingerprint,
                "common_name": None,
                "sans": [],
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2027-01-01T00:00:00+00:00",
                "issuer": "harness",
                "lifecycle": "static",
                "valid": True,
            }
            for identifier, fingerprint in self.certificates
        ]


@dataclass
class FakeCluster:
    """Two or more nodes, in configured order, plus what happens on a deploy."""

    nodes: list[FakeNode]
    cluster: str = "alpha"
    target_hash: str = TARGET_HASH
    #
    # Scripted consequences: called with the cluster and the node that was just
    # deployed, so a test can say "when node-b is deployed the VIP moves" or
    # "the peer goes away". This is how a mid-run change is provoked.
    #
    on_deploy: Callable[[FakeCluster, FakeNode], None] | None = None
    #
    # When set, a trigger installs these certificates on the node instead of
    # moving it to a release. That is the whole difference between the two
    # operations from a node's point of view.
    #
    target_certificates: tuple[tuple[str, str], ...] | None = None
    reads: int = field(default=0, init=False)
    triggered: list[str] = field(default_factory=list, init=False)

    def node(self, name: str) -> FakeNode:
        for node in self.nodes:
            if node.name == name:
                return node
        raise KeyError(name)

    def move_vip(self, name: str | None) -> None:
        """Hand the address to one node, or to nobody."""

        for node in self.nodes:
            node.owns_vip = node.name == name

    def split_brain(self) -> None:
        for node in self.nodes:
            node.owns_vip = True

    def read_status(self) -> dict[str, Any]:
        """The envelope `haproxy-status-root --json` would print."""

        self.reads += 1
        entries = []
        for node in self.nodes:
            entry: dict[str, Any] = {
                "name": node.name,
                "mgmt_host": node.mgmt_host,
                "reachable": False,
                "status_ok": False,
                "status": None,
                "error": None,
            }
            if not node.reachable:
                entry["error"] = {"code": "ssh_unreachable", "message": "SSH failed with exit 255"}
            else:
                entry["reachable"] = True
                #
                # Set as soon as something parsed, exactly as the real helper
                # does - which is why a node answering `null` still arrives
                # claiming a status it does not have.
                #
                entry["status_ok"] = True
                entry["status"] = node.status()
            entries.append(entry)

        return {
            "schema_version": 1,
            "ok": True,
            "operation": "status",
            "cluster": self.cluster,
            "request_id": "00000000-0000-4000-8000-000000000000",
            "result": {"nodes": entries, "summary": self._summary(entries)},
            "warnings": [],
            "error": None,
        }

    def _summary(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        usable = [
            entry for entry in entries if entry["status_ok"] and isinstance(entry["status"], dict)
        ]
        owners = [entry["name"] for entry in usable if entry["status"]["vip"]["owner"] is True]
        unknown = [entry["name"] for entry in usable if entry["status"]["vip"]["owner"] is None]

        if len(usable) < len(entries):
            state = "incomplete"
        elif unknown:
            state = "unknown"
        elif not owners:
            state = "no_owner"
        elif len(owners) == 1:
            state = "single_owner"
        else:
            state = "split_brain"

        return {
            "configured_nodes": len(entries),
            "reachable_nodes": sum(1 for entry in entries if entry["reachable"]),
            "valid_status_nodes": len(usable),
            "vip_owner_count": len(owners),
            "vip_owners": owners,
            "vip_unknown_nodes": unknown,
            "vip_state": state,
        }

    def trigger(self, name: str) -> int:
        """Pull and reload one node, the way the forced command would."""

        self.triggered.append(name)
        node = self.node(name)

        if not node.reachable:
            return TRIGGER_UNREACHABLE

        if node.reload_fails:
            #
            # The node kept the configuration it had. That is the important part:
            # a failed reload must not look like a successful one that happens to
            # report an error.
            #
            return TRIGGER_RELOAD_FAILED

        if self.target_certificates is None:
            node.release_hash = self.target_hash
        else:
            node.certificates = self.target_certificates
        if self.on_deploy is not None:
            self.on_deploy(self, node)
        return TRIGGER_OK


def pair(**overrides: Any) -> FakeCluster:
    """The ordinary starting point: node-a owns the VIP, both behind."""

    nodes = [
        FakeNode(name="node-a", mgmt_host="node-a.example.com", owns_vip=True),
        FakeNode(name="node-b", mgmt_host="node-b.example.com", owns_vip=False),
    ]
    return FakeCluster(nodes=nodes, **overrides)
