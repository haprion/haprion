"""Read model for a cluster's network description.

Three tables of addresses, as the poller last read them: where traffic arrives,
where it leaves from, and who may reach it. Like every other page, this layer
knows only the cached envelope - it cannot open the cluster repository, and the
identities it runs as are deliberately not in the group that could.

The one judgement made here is `editable`. A description read from
`managed/network.yaml` can be changed by publishing to the repository, the same
way a proxy object is; one derived from the engine's own configuration cannot,
because the interface has no path to that file and should not have one. The
page has to say which it is looking at rather than offering an edit that would
fail, so the distinction is carried out of the envelope and named here.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Literal

from haprion import address_ranges
from haprion.config import ConfigError
from haprion.digits import is_digits
from haprion.managed_network import load_document
from haprion.managed_network import location as network_location

from haprion_ui import labels, moments
from haprion_ui.cluster_identity import accent_index
from haprion_ui.dashboard import observation_label
from haprion_ui.db import ClusterNetwork, Job
from haprion_ui.jobs import Failure, deploys, published

type Tone = Literal["healthy", "warning", "critical", "unknown"]
#
# One tone more than a cluster card has. A job in flight is not a verdict about
# the cluster - it is the interface saying it is still listening - and the
# badge that carries it is the same blue one the dashboard already uses.
#
type BadgeTone = Literal["healthy", "warning", "critical", "unknown", "info"]


@dataclass(frozen=True, slots=True)
class VipView:
    """One address a frontend binds, and what leaves from it by default."""

    name: str
    address: str
    source: str | None
    is_default: bool
    tls_policy: str | None
    """Which TLS versions and ciphers frontends on this address accept.

    Empty means the cluster's `core/` decides, which is what every VIP written
    before this column existed says. Named here rather than defaulted, because
    a bind line overrides `core/` in both directions: a default written on
    somebody's behalf could loosen a cluster nobody had looked at.
    """

    http3: bool = False
    """Whether https on this address is served over QUIC too (B280)."""


@dataclass(frozen=True, slots=True)
class SourceView:
    """One address this cluster connects out from, and what reaches it that way.

    Both kinds of source address are in this list, and that is the point. The
    configuration separates the address a VIP pairs with from the extra ones an
    object may ask for by name, because they are decided in different places -
    but a page that showed only the second told a cluster with a paired source
    that it had none. A paired one carries its VIP's name; which objects leave
    from either kind is the page's *Used by* (`Usage`), not a word about the kind.
    """

    name: str
    address: str


@dataclass(frozen=True, slots=True)
class NamedSourceView:
    """One named source address, as the document itself stores it.

    Deliberately not `SourceView`. That one is the reading: it merges in the
    addresses paired with a VIP, because a person asking "what do we leave
    from" wants both. The form may not, because a paired address belongs to
    its VIP's own row - editing it in two places would let one submission
    carry two answers for one value.
    """

    name: str
    address: str


@dataclass(frozen=True, slots=True)
class GroupView:
    """One named set of addresses an object may restrict itself to."""

    name: str
    members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NetworkClusterView:
    cluster: str
    accent: int | None
    label: str
    tone: Tone
    detail: str
    observed_at: str | None
    observed_iso: str | None
    age_label: str
    stale: bool
    #
    # Whether the tables below can be changed from here at all. False means the
    # cluster still keeps them in the engine's configuration, which this
    # interface can neither read nor write.
    #
    editable: bool
    head: str | None
    default_vip_object_count: int
    default_vip: str
    vips: tuple[VipView, ...]
    sources: tuple[SourceView, ...]
    paired_sources: tuple[SourceView, ...]
    named_sources: tuple[NamedSourceView, ...]
    groups: tuple[GroupView, ...]


def awaiting_deploy(jobs: Iterable[Job], part: str = "network") -> frozenset[str]:
    """Clusters whose network description was published since the last deploy.

    `part` asks the same of the cluster's other one-document-per-cluster
    document, its settings (Fas 15).

    The same question the proxy listing asks about an object, asked about the
    one description a cluster has. The listing no longer asks it of the jobs:
    an object is compared release against release, by fingerprint, because a
    job window ages and knows nothing of what the command line did. A network
    publish carries no object names - the description is one document per
    cluster - so the answer here is the cluster, and the jobs are still what
    says a publish happened and a deploy has not. A publish of saved changes
    names the part in its payload when it carries it (B257).

    Newest first, so the first finished deploy for a cluster ends the search
    for that cluster - and a *Publish & deploy* that finished is one.

    Bounded by whatever window the caller read, which understates rather than
    invents - the safe direction for a page that would otherwise claim a
    deploy is owed when none is.
    """

    waiting: set[str] = set()
    deployed: set[str] = set()
    for job in jobs:
        #
        # A certificate job has no cluster and owes no cluster a deploy.
        #
        if job.cluster is None or job.cluster in deployed:
            continue
        if deploys(job) and job.state == "done":
            deployed.add(job.cluster)
            continue
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        carried = job.operation == "changes_publish" and part in payload
        if carried and published(job):
            waiting.add(job.cluster)
    return frozenset(waiting)


@dataclass(frozen=True, slots=True)
class Deployment:
    """Where this cluster's configuration has got to, as one badge.

    A state and not an event. The first version of this said "Deployed
    successfully" for five seconds and then removed itself, which answers "did
    the thing I pressed work" and nothing else: a page nobody pressed anything
    on had no answer at all, and a person who looked away missed the only one
    there was.

    Read from the machine wherever the machine knows - so it corrects itself
    when somebody deploys from the command line, and it needs no memory of what
    this page did. The exception is a failure, which the machine cannot show:
    a refused job leaves the configuration exactly as it was.
    """

    label: str
    tone: BadgeTone
    running: bool
    code: str | None


def deployment(
    *,
    running: str | None = None,
    failure: Failure | None = None,
    awaiting: bool = False,
    release_state: str = "",
    version: str = "",
) -> Deployment:
    """The four questions in the order they matter.

    Something running now beats what the last one did; a failure beats a state
    that looks well because nothing happened; a publish this cluster owes a
    deploy beats the general "not on one release", which is also true of a node
    that is merely unreachable and is not something a deploy fixes.
    """

    if running:
        return Deployment(running, "info", True, None)
    if failure is not None:
        return Deployment(failure.label, "critical", False, failure.code)
    if awaiting:
        # The proxy listing's words for a changed thing the nodes do not run yet (2026-09-29).
        return Deployment("Reconfigured · deploy to activate", "warning", False, None)
    #
    # "Unknown" is the dashboard's word for a cluster it could not read, and it
    # is not a claim that the nodes are behind. Reading it as one had a cluster
    # whose status was merely stale telling somebody to deploy - which is the
    # one thing this badge must not invent, since a deploy is what it offers a
    # button for.
    #
    if not release_state or release_state.lower() == "unknown":
        return Deployment("Deployment state unknown", "unknown", False, None)
    if release_state.lower() == "incomplete":
        #
        # A node could not be read. Nothing is owed that a deploy mends, so the
        # page keeps Save: the description stays editable while one node is
        # down, which is when an address is most likely to need changing
        # (review 26-10-24, 12-02).
        #
        return Deployment("A node is not reporting", "unknown", False, None)
    if release_state.lower() != "converged":
        #
        # Not "deploy to activate": nothing here was published, and a node that
        # cannot be reached reads as behind for a reason no button mends.
        #
        return Deployment(labels.BEHIND, "warning", False, None)
    return Deployment(f"{version} deployed" if version else "Deployed", "healthy", False, None)


@dataclass(frozen=True, slots=True)
class Usage:
    """Which objects use each VIP, source address and group of one cluster (26-10-10).

    From the objects helper, which works each out with the generator's rule: a
    VIP by name, a source by the address the object leaves from - so a VIP's
    paired source and a named one are answered alike - and the groups an object
    names wherever it names sources. Objects in name order.
    """

    vips: Mapping[str, tuple[str, ...]]
    sources: Mapping[str, tuple[str, ...]]
    groups: Mapping[str, tuple[str, ...]]


def usage(views: Iterable[Any]) -> Usage:
    vips: dict[str, list[str]] = {}
    sources: dict[str, list[str]] = {}
    groups: dict[str, list[str]] = {}
    for view in sorted(views, key=lambda item: item.name):
        addresses = view.addresses
        if addresses is not None:
            vips.setdefault(addresses.vip_name, []).append(view.name)
            if addresses.source is not None and addresses.source.address:
                sources.setdefault(addresses.source.address, []).append(view.name)
        for group in view.groups or ():
            groups.setdefault(group, []).append(view.name)
    return Usage(
        vips={key: tuple(names) for key, names in vips.items()},
        sources={key: tuple(names) for key, names in sources.items()},
        groups={key: tuple(names) for key, names in groups.items()},
    )


@dataclass(frozen=True, slots=True)
class NetworkChange:
    """One VIP, source or group a saved network description changes, and who uses it (B277).

    The users are the objects as the publish leaves them - the published ones
    with the saved objects of the same publish in their place - counted with
    *Used by*'s own rule. `refused` is a removal of something one of them
    still names, which the generator refuses at publish; an object moved off it
    in the same publish no longer counts (26-10-11).
    """

    kind: Literal["vip", "source", "group"]
    name: str
    what: str
    users: tuple[str, ...]
    #
    # What the proxy listing is narrowed by to show the users: the VIP's
    # name, the source's address, the group's name - as *Used by* links.
    #
    match: str
    refused: bool = False

    @property
    def label(self) -> str:
        return {"vip": "VIP", "source": "Source", "group": "Group"}[self.kind] + f" {self.name}"


def _keyed(result: Mapping[str, Any], key: str) -> dict[str, Mapping[str, Any]]:
    return {row["name"]: row for row in _rows(result, key) if isinstance(row.get("name"), str)}


def changes(
    published: Mapping[str, Any], saved: Mapping[str, Any], use: Usage
) -> tuple[NetworkChange, ...]:
    """What a saved network description changes against the published one, by name (B277).

    Both in the reading's shape (`result_from_document` gives the saved one).
    A VIP's own source is the VIP's change - it is edited in the VIP's row
    and used by the VIP's objects.
    """

    found: list[NetworkChange] = []
    before, after = _keyed(published, "vips"), _keyed(saved, "vips")
    default_before, default_after = published.get("default_vip"), saved.get("default_vip")
    for name in sorted(before.keys() | after.keys()):
        users = use.vips.get(name, ())
        if name not in after:
            found.append(NetworkChange("vip", name, "removed", users, name, bool(users)))
            continue
        if name not in before:
            found.append(NetworkChange("vip", name, "added", (), name))
            continue
        what = [
            label
            for field, label in (
                ("address", "address changed"),
                ("source", "source changed"),
                ("tls", "TLS policy changed"),
                ("http3", "HTTP/3 turned " + ("on" if after[name].get("http3") else "off")),
            )
            if before[name].get(field) != after[name].get(field)
            and (field != "http3" or bool(before[name].get(field)) != bool(after[name].get(field)))
        ]
        if default_before != default_after and name == default_after:
            what.append("made the default")
        if what:
            found.append(NetworkChange("vip", name, ", ".join(what), users, name))
    before, after = _keyed(published, "sources"), _keyed(saved, "sources")
    for name in sorted(before.keys() | after.keys()):
        address = str((before.get(name) or after.get(name) or {}).get("address") or "")
        users = use.sources.get(address, ()) if name in before else ()
        if name not in after:
            found.append(NetworkChange("source", name, "removed", users, address, bool(users)))
        elif name not in before:
            found.append(NetworkChange("source", name, "added", (), address))
        elif before[name].get("address") != after[name].get("address"):
            found.append(NetworkChange("source", name, "address changed", users, address))
    before, after = _keyed(published, "groups"), _keyed(saved, "groups")
    for name in sorted(before.keys() | after.keys()):
        users = use.groups.get(name, ())
        if name not in after:
            found.append(NetworkChange("group", name, "removed", users, name, bool(users)))
        elif name not in before:
            found.append(NetworkChange("group", name, "added", (), name))
        elif list(before[name].get("members") or ()) != list(after[name].get("members") or ()):
            found.append(NetworkChange("group", name, "members changed", users, name))
    return tuple(found)


def _text(value: Any, fallback: str = "—") -> str:
    return value if isinstance(value, str) and value else fallback


def _rows(result: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    rows = result.get(key)
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _vips(result: Mapping[str, Any], default_vip: str) -> tuple[VipView, ...]:
    return tuple(
        VipView(
            name=_text(row.get("name")),
            address=_text(row.get("address")),
            source=row.get("source") if isinstance(row.get("source"), str) else None,
            is_default=row.get("name") == default_vip,
            #
            # Missing means the VIP names no policy - and an older helper that
            # cannot report one at all says the same thing. Not `_text`, whose
            # fallback is an em dash: a dash matches no option in the editor's
            # list, so the browser fell back to selecting the first one and the
            # page showed a policy nobody had chosen.
            #
            tls_policy=row.get("tls") if isinstance(row.get("tls"), str) else None,
            http3=row.get("http3") is True,
        )
        for row in _rows(result, "vips")
    )


def default_vip_address(reading: ClusterNetwork | None) -> str:
    """The cluster's default VIP as an address, or empty before the network has been read."""

    if reading is None or reading.outcome != "done" or not isinstance(reading.result, Mapping):
        return ""
    default_vip = reading.result.get("default_vip")
    return next(
        (
            _text(row.get("address"), "")
            for row in _rows(reading.result, "vips")
            if row.get("name") == default_vip
        ),
        "",
    )


def _paired_sources(result: Mapping[str, Any]) -> tuple[SourceView, ...]:
    """The addresses a VIP carries, which are edited in that VIP's own row."""

    return tuple(
        SourceView(
            name=_text(row.get("name")),
            address=_text(row.get("source")),
        )
        for row in _rows(result, "vips")
        if isinstance(row.get("source"), str) and row.get("source")
    )


def _sources(result: Mapping[str, Any]) -> tuple[SourceView, ...]:
    named = tuple(
        SourceView(
            name=_text(row.get("name")),
            address=_text(row.get("address")),
        )
        for row in _rows(result, "sources")
    )
    return _paired_sources(result) + named


def _groups(result: Mapping[str, Any]) -> tuple[GroupView, ...]:
    return tuple(
        GroupView(
            name=_text(row.get("name")),
            members=tuple(
                member for member in row.get("members", []) if isinstance(member, str) and member
            ),
        )
        for row in _rows(result, "groups")
    )


def _named_sources(result: Mapping[str, Any]) -> tuple[NamedSourceView, ...]:
    return tuple(
        NamedSourceView(name=_text(row.get("name")), address=_text(row.get("address")))
        for row in _rows(result, "sources")
    )


def _empty(cluster: str) -> NetworkClusterView:
    return NetworkClusterView(
        cluster=cluster,
        accent=accent_index(cluster),
        label="No network description yet",
        tone="unknown",
        detail="Waiting for the first reading",
        observed_at=None,
        observed_iso=None,
        age_label="Never",
        stale=False,
        editable=False,
        head=None,
        default_vip_object_count=0,
        default_vip="—",
        vips=(),
        sources=(),
        paired_sources=(),
        named_sources=(),
        groups=(),
    )


def _unavailable(reading: ClusterNetwork, *, stale: bool, age_label: str) -> NetworkClusterView:
    error = reading.error or {}
    message = error.get("message") if isinstance(error, Mapping) else None
    return NetworkClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        label="Could not be read",
        tone="critical",
        detail=_text(message or reading.poll_error, "The helper did not answer"),
        observed_at=moments.moment(reading.observed_at),
        observed_iso=reading.observed_at.isoformat(),
        age_label=age_label,
        stale=stale,
        editable=False,
        head=None,
        default_vip_object_count=0,
        default_vip="—",
        vips=(),
        sources=(),
        paired_sources=(),
        named_sources=(),
        groups=(),
    )


def _view(reading: ClusterNetwork, *, stale: bool, age_label: str) -> NetworkClusterView:
    if reading.outcome != "done":
        return _unavailable(reading, stale=stale, age_label=age_label)

    result = reading.result if isinstance(reading.result, Mapping) else {}
    default_vip = _text(result.get("default_vip"))
    head = result.get("head") if isinstance(result.get("head"), str) else None
    editable = result.get("origin") == "repository" and head is not None
    detail = (
        "Edited here and published to the cluster repository"
        if editable
        else "Still described in the engine's configuration, which this interface cannot write"
    )
    return NetworkClusterView(
        cluster=reading.cluster,
        accent=accent_index(reading.cluster),
        #
        # Where the network is kept, not whether this user may change it now:
        # the edit button says that, and "Editable" stood under the header's
        # *Read-only mode* and in front of readers (B331).
        #
        label="Managed here" if editable else "Not managed here",
        tone="healthy" if editable else "warning",
        detail=detail,
        observed_at=moments.moment(reading.observed_at),
        observed_iso=reading.observed_at.isoformat(),
        age_label=age_label,
        stale=stale,
        editable=editable,
        head=head,
        default_vip_object_count=(
            result["default_vip_object_count"]
            if isinstance(result.get("default_vip_object_count"), int)
            and not isinstance(result.get("default_vip_object_count"), bool)
            else 0
        ),
        default_vip=default_vip,
        vips=_vips(result, default_vip),
        sources=_sources(result),
        paired_sources=_paired_sources(result),
        named_sources=_named_sources(result),
        groups=_groups(result),
    )


def result_from_document(document: str, reading: Mapping[str, Any]) -> dict[str, Any] | None:
    """A saved network document as the reading the page and the editor draw (B257).

    Parsed by the engine's own loader, with the reading's ownership VIP, and
    put in the shape `network_result` gives the poller - so a saved
    description is shown, edited and checked against exactly as a published
    one is. The head and the object count stay the reading's: the saved
    document is not yet a version. None for a document the engine refuses,
    which then shows as published rather than as something it cannot read.
    """

    ownership = reading.get("ownership_vip")
    try:
        parsed = load_document(
            document.encode("utf-8"),
            ownership_vip=str(ownership) if ownership else "",
            location=network_location(),
        )
    except ConfigError:
        return None
    return {
        **reading,
        "default_vip": parsed.default_vip,
        "vips": [
            {
                "name": vip.name,
                "address": vip.address,
                "source": vip.source,
                "tls": vip.tls_policy,
                "http3": vip.http3,
            }
            for vip in sorted(parsed.vips.values(), key=lambda entry: entry.name)
        ],
        "sources": [
            {"name": name, "address": parsed.sources[name]} for name in sorted(parsed.sources)
        ],
        "groups": [
            {"name": name, "members": list(parsed.networks[name])}
            for name in sorted(parsed.networks)
        ],
    }


def with_saved(
    readings: Iterable[ClusterNetwork], saved: Mapping[str, str]
) -> list[ClusterNetwork]:
    """The readings, with each cluster's saved document in place of what is published.

    Everything that draws or checks against a cluster's addresses reads this,
    so an object saved for a VIP the same package adds is checked against that
    VIP and not refused for it.
    """

    rows: list[ClusterNetwork] = []
    for reading in readings:
        document = saved.get(reading.cluster)
        result = reading.result if isinstance(reading.result, Mapping) else None
        if document is not None and reading.outcome == "done" and result is not None:
            replaced = result_from_document(document, result)
            if replaced is not None:
                reading = replace(reading, result=replaced)
        rows.append(reading)
    return rows


def build_network_overview(
    clusters: Iterable[str],
    readings: Iterable[ClusterNetwork],
    *,
    now: datetime | None = None,
    stale_after: timedelta,
) -> tuple[NetworkClusterView, ...]:
    """One card per configured cluster, whether or not it has been read yet."""

    moment = now or datetime.now(tz=None).astimezone()
    by_cluster = {reading.cluster: reading for reading in readings}
    views: list[NetworkClusterView] = []
    for cluster in clusters:
        reading = by_cluster.get(cluster)
        if reading is None:
            views.append(_empty(cluster))
            continue
        age = moment - reading.observed_at
        views.append(
            _view(
                reading,
                stale=age > stale_after,
                age_label=observation_label(reading.observed_at, moment),
            )
        )
    return tuple(views)


#
# The write side. The form is a set of parallel row fields rather than a
# document to hand-write, so this is where rows become the one shape the
# engine parses. It stops at the shape: names, pairing and the default's
# identity are decided here because getting them wrong loses a row silently,
# while every question about an address's validity is left to the helper,
# which is the authority and answers it against the cluster.
#


class FormProblem(Exception):
    """The rows cannot be turned into a document, and saying so is the answer."""


@dataclass(frozen=True, slots=True)
class NetworkForm:
    """One submission of the network tables, still in the browser's shape."""

    vip_names: tuple[str, ...]
    vip_addresses: tuple[str, ...]
    vip_sources: tuple[str, ...]
    #
    # Which TLS policy each VIP row named, empty where it named none. Required
    # rather than defaulted: a caller that forgets it would publish a network
    # with every frontend's policy silently cleared, and the type checker
    # naming the caller is cheaper than finding that out from a bind line.
    #
    vip_tls: tuple[str, ...]
    default_vip_row: str
    source_names: tuple[str, ...]
    source_addresses: tuple[str, ...]
    group_names: tuple[str, ...]
    group_members: tuple[str, ...]
    #
    # Removal is a row number rather than a cleared field. An unticked checkbox
    # posts nothing, so what arrives is the short list of rows to drop and the
    # numbers of the rows that stay are untouched - which is what the
    # default-VIP radio counts on.
    #
    removed_vip_rows: frozenset[int] = frozenset()
    #
    # The VIP rows whose HTTP/3 box is ticked (B280), by row number like a
    # removal: an unticked box posts nothing.
    #
    http3_vip_rows: frozenset[int] = frozenset()
    removed_source_rows: frozenset[int] = frozenset()
    removed_group_rows: frozenset[int] = frozenset()


def row_numbers(values: Iterable[str]) -> frozenset[int]:
    """The row numbers a set of checkboxes posted, ignoring anything else.

    The browser sends the values this page put in the boxes; a value that is
    not a row number is a submission this form did not draw, and dropping it
    silently is right because the rows it could not name are the rows that
    stay.
    """

    return frozenset(int(value) for value in values if is_digits(value))


def _cell(values: tuple[str, ...], row: int) -> str:
    return values[row].strip() if row < len(values) else ""


def _named_rows(
    names: tuple[str, ...],
    values: tuple[str, ...],
    *,
    what: str,
    needs: str,
    removed: frozenset[int] = frozenset(),
) -> list[tuple[int, str, str]]:
    """Keep the rows that were filled in; refuse the ones half filled in.

    A row ticked for removal is dropped before it is read at all, so a person
    removing a row never has to empty it first and never meets a complaint
    about what is still in it.

    A spare row nobody touched is how this form adds: it is blank and it is
    dropped. A row with a name and no address is neither that nor a removal,
    and guessing which was meant would either delete an address or publish an
    empty one.

    A refusal names the row's position and never its contents. These strings
    are shown to the person who submitted them, and a message built from a
    field is a field echoed back - the same reason the operations route
    answers a bad payload without quoting it.
    """

    rows: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for row in range(max(len(names), len(values))):
        if row in removed:
            continue
        name = _cell(names, row)
        value = _cell(values, row)
        if not name and not value:
            continue
        if not name:
            raise FormProblem(f"{what} row {row + 1} needs a name.")
        if not value:
            raise FormProblem(f"{what} row {row + 1} needs {needs}.")
        if name in seen:
            raise FormProblem(f"{what} row {row + 1} repeats a name used above it.")
        seen.add(name)
        rows.append((row, name, value))
    return rows


def _members(raw: str) -> list[str]:
    """One address or range per line, the way the preview form takes them."""

    return [member.strip() for member in raw.replace(",", "\n").splitlines() if member.strip()]


def _vip_entry(form: NetworkForm, row: int, address: str) -> dict[str, str | bool]:
    """One VIP as the helper reads it: the address, and only what was chosen.

    An empty cell writes no key at all rather than a key with an empty value.
    The engine refuses a policy it does not know, so "" would be a refusal, and
    a cluster whose `core/` decides is the case that should need no words.
    """

    entry: dict[str, str | bool] = {"address": address}
    if source := _cell(form.vip_sources, row):
        entry["source"] = source
    if policy := _cell(form.vip_tls, row):
        entry["tls"] = policy
    if row in form.http3_vip_rows:
        entry["http3"] = True
    return entry


def document_from_form(form: NetworkForm) -> str:
    """Render one submission as the document the helper parses.

    JSON is YAML 1.2. Rendering this as JSON avoids teaching the interface a
    second YAML emitter; the privileged helper remains the one parser and the
    canonical publisher, so what leaves here only has to be unambiguous.
    """

    vips = _named_rows(
        form.vip_names,
        form.vip_addresses,
        what="VIP",
        needs="an address",
        removed=form.removed_vip_rows,
    )
    if not vips:
        raise FormProblem("A cluster needs at least one VIP.")

    if is_digits(form.default_vip_row) and int(form.default_vip_row) in form.removed_vip_rows:
        #
        # Said before the generic complaint below, because it is a different
        # mistake with a different fix: the row is gone on purpose, and what
        # is missing is the answer to which VIP the objects that name none
        # should follow instead.
        #
        raise FormProblem("Choose another default VIP before removing the one that is default.")

    default_vip = ""
    for row, name, _ in vips:
        if str(row) == form.default_vip_row:
            default_vip = name
    if not default_vip:
        #
        # Reachable by clearing the name of the row the radio still points at.
        # Falling back to the first VIP would move every object that does not
        # name one, which is the change this form makes a person confirm.
        #
        raise FormProblem("Choose which VIP is the default.")

    document: dict[str, object] = {
        "vips": {name: _vip_entry(form, row, address) for row, name, address in vips},
        "default_vip": default_vip,
    }

    sources = _named_rows(
        form.source_names,
        form.source_addresses,
        what="Source address",
        needs="an address",
        removed=form.removed_source_rows,
    )
    if sources:
        document["sources"] = {name: address for _, name, address in sources}

    groups = _named_rows(
        form.group_names,
        form.group_members,
        what="Group",
        needs="at least one address",
        removed=form.removed_group_rows,
    )
    if groups:
        for row, _, raw in groups:
            if any(address_ranges.has_host_bits(member) for member in _members(raw)):
                #
                # The engine's rule and words, said here before the change is
                # saved rather than when it is published (review 26-10-24,
                # 15-06). The row, not what was typed, as the messages above.
                #
                raise FormProblem(f"Group row {row + 1}: {address_ranges.HOST_BITS}.")
        document["networks"] = {name: _members(raw) for _, name, raw in groups}

    return json.dumps(document, indent=2) + "\n"
