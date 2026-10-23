"""Getting started: what a new installation still has to set up (B316, 26-10-15).

A list on the dashboard, for an admin, until somebody hides it for the whole
installation. Every tick is read from what the installation is - a cluster
serving, a certificate that is not self-signed, a schedule on every cluster -
never from somebody having pressed the item, so the list cannot say done for
something that is not. What a person uses the installation for, such as a
first site, is not on it: a list that waits for that is never finished.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from haprion_ui import labels

#
# How long the dashboard offers a hidden list back (26-10-16). Hide asks
# nothing, so a press by mistake has a way back; after a week the list is
# taken to be done with and the button goes too.
#
OFFERED_AGAIN_FOR = timedelta(days=7)

TLS_LABELS = {
    "intermediate": "TLS 1.2 and 1.3",
    "modern": "TLS 1.3 only",
    "tls12only": "TLS 1.2 only",
}


@dataclass(frozen=True, slots=True)
class Vip:
    address: str
    tls: str | None
    source: str | None


@dataclass(frozen=True, slots=True)
class ClusterFacts:
    """What the list reads about one cluster."""

    name: str
    nodes: tuple[str, ...]
    # The node that holds the VIP; None before the first deploy or in a fault.
    owner: str | None
    vips: tuple[Vip, ...]
    logs_forwarded: bool
    backups_scheduled: bool
    # The published version; None when nothing is published (Fas 18, finding 60).
    target_version: int | None = None


@dataclass(frozen=True, slots=True)
class Facts:
    clusters: tuple[ClusterFacts, ...]
    # None when the served certificate could not be read: not ticked, not said.
    interface_self_signed: bool | None
    accounts: int
    sso: bool
    site_certificates: int
    node_backups_on: bool
    status_access: bool
    features_changed: bool
    # The first cluster's guide, while it has a step to show (B328): the
    # number and the name of that step.
    guide: tuple[int, str] | None = None


@dataclass(frozen=True, slots=True)
class Item:
    title: str
    done: bool
    state: str
    action: str
    href: str
    optional: bool = False
    # A row whose next step is a deploy: the cluster and the version it rolls
    # out, drawn as the deploy form rather than a link (Fas 18, finding 59).
    deploy: str | None = None
    deploy_version: int | None = None


@dataclass(frozen=True, slots=True)
class Checklist:
    items: tuple[Item, ...]

    @property
    def done(self) -> int:
        return sum(item.done for item in self.items)


def _every(clusters: Iterable[ClusterFacts], test: str) -> bool:
    chosen = list(clusters)
    return bool(chosen) and all(getattr(cluster, test) for cluster in chosen)


def _cluster_item(clusters: tuple[ClusterFacts, ...], guide: tuple[int, str] | None) -> Item:
    #
    # The guide is this row's next step while it has one (B328): the dashboard
    # stays the dashboard, and the row leads to the guide's page.
    #
    if guide is not None:
        number, name = guide
        return Item(
            "Nodes and a cluster",
            False,
            "No cluster yet" if number == 1 else f"Step {number}: {name}",
            "Set up" if number == 1 else "Continue",
            "/first-cluster",
        )
    serving = [cluster for cluster in clusters if cluster.nodes and cluster.owner]
    if serving:
        first = serving[0]
        address = first.vips[0].address if first.vips else ""
        state = f"{first.name} · {', '.join(first.nodes)}"
        if address:
            state += f" · {address} on {first.owner}"
        if len(clusters) > 1:
            state += f" · {labels.counted(len(clusters), 'cluster')}"
        return Item("Nodes and a cluster", True, state, "", "")
    if clusters:
        first = clusters[0]
        if first.target_version is None:
            return Item(
                "Nodes and a cluster",
                False,
                f"{first.name} · nothing published yet",
                "Proxies",
                "/proxies",
            )
        return Item(
            "Nodes and a cluster",
            False,
            f"{first.name} · not deployed yet",
            "Deploy configuration",
            "",
            deploy=first.name,
            deploy_version=first.target_version,
        )
    return Item(
        "Nodes and a cluster", False, "No cluster yet", "Create cluster", "/settings/new-cluster"
    )


def _tls_item(clusters: tuple[ClusterFacts, ...]) -> Item:
    vips = [vip for cluster in clusters for vip in cluster.vips]
    chosen = {vip.tls for vip in vips if vip.tls}
    if not vips:
        tls = "No VIP yet"
    elif len(chosen) == 1 and all(vip.tls for vip in vips):
        tls = TLS_LABELS.get(next(iter(chosen)), next(iter(chosen)))
    elif chosen:
        tls = "TLS chosen on some VIPs"
    else:
        tls = "TLS not chosen"
    sources = sum(bool(vip.source) for vip in vips)
    source = (
        labels.counted(sources, "source address", "source addresses")
        if sources
        else "the nodes' own addresses"
    )
    done = bool(vips) and all(vip.tls for vip in vips)
    return Item("TLS and source address", done, f"{tls} · {source}", "Network", "/network")


def checklist(facts: Facts) -> Checklist:
    clusters = facts.clusters
    logs = sum(cluster.logs_forwarded for cluster in clusters)
    scheduled = sum(cluster.backups_scheduled for cluster in clusters)
    if facts.interface_self_signed is None:
        interface = "Could not be read"
    else:
        interface = "Self-signed" if facts.interface_self_signed else "Issued by a CA"
    items = (
        _cluster_item(clusters, facts.guide),
        _tls_item(clusters),
        Item(
            "Interface certificate",
            facts.interface_self_signed is False,
            interface,
            "Replace",
            "/settings",
        ),
        Item(
            "Users and sign-in",
            bool(facts.sso) or facts.accounts > 1,
            "Sign-in through SSO"
            if facts.sso
            else labels.counted(facts.accounts, "account")
            if facts.accounts > 1
            else "Only admin",
            "Users",
            "/settings#users",
        ),
        Item(
            "Certificates for your proxies",
            facts.site_certificates > 0,
            labels.counted(facts.site_certificates, "certificate") + " from ACME or NDES"
            if facts.site_certificates
            else "None from ACME or NDES yet",
            "Certificates",
            "/certificates",
        ),
        Item(
            "Enable the features you want to use",
            facts.features_changed,
            "Chosen" if facts.features_changed else "As installed",
            "Features",
            "/settings#features",
            optional=True,
        ),
        Item(
            "Node backups",
            facts.node_backups_on and _every(clusters, "backups_scheduled"),
            "Off under Features"
            if not facts.node_backups_on
            else f"Scheduled on {scheduled} of {labels.counted(len(clusters), 'cluster')}"
            if scheduled
            else "No schedule",
            "Features" if not facts.node_backups_on else "Schedule",
            "/settings#features" if not facts.node_backups_on else "/backups",
            optional=True,
        ),
        Item(
            "Traffic log off the nodes",
            _every(clusters, "logs_forwarded"),
            f"Forwarded from {logs} of {labels.counted(len(clusters), 'cluster')}"
            if logs
            else "Kept on the nodes only",
            "Logs",
            "/settings#logs-metrics",
            optional=True,
        ),
        Item(
            "External monitoring",
            facts.status_access,
            "Allowed" if facts.status_access else "No address may ask",
            "Allow",
            "/settings/status-access",
            optional=True,
        ),
    )
    return Checklist(items)


def offered_again(hidden_at: datetime, now: datetime) -> bool:
    """Whether a list hidden at `hidden_at` may still be shown again from the dashboard."""

    return now - hidden_at < OFFERED_AGAIN_FOR
