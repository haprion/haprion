"""Read model for one proxy object as it is written.

`proxies` builds the overview from the published inventory - what the nodes are
serving. This builds the detail from the objects cache - the document somebody
edited to produce it. Keeping them apart is not tidiness: the two answers are
the same only until an edit is made and not yet published, and the moment they
differ is exactly the moment somebody is looking at this page.

The published row is carried alongside rather than merged into the object. A
merged view would have to pick one of two truths per field and would hide the
one case worth seeing - that the stored document and the running configuration
no longer say the same thing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import observation_label
from haproxy_ui.db import ClusterObjects
from haproxy_ui.history import VersionView
from haproxy_ui.proxies import ProxyView, Tone


@dataclass(frozen=True, slots=True)
class ObjectView:
    """One stored document, and what this version could make of it."""

    name: str
    document: str
    readable: bool
    problem: str | None
    protocol: str | None
    hostnames: tuple[str, ...]
    line_count: int


@dataclass(frozen=True, slots=True)
class Publication:
    """How far this object has travelled: written, released, serving.

    Not "the published row with the same name". The published inventory names
    *frontends* - `mgd-<vip>-<protocol>` - and one of them serves every object
    on that address, so an object and a frontend never share a name. Pairing
    them by name was an assumption that survived only because the fixture was
    written to match it; real data disproved it the first time it was seen.

    What an editor actually asks is whether the change reached the nodes, and
    that is three questions with three answers: is it committed, is the commit
    the release, are the nodes pulling that release.
    """

    label: str
    detail: str
    tone: Tone
    version: str | None


@dataclass(frozen=True, slots=True)
class ObjectDetail:
    cluster: str
    accent: int
    name: str
    #
    # Absent where the cluster has no such object. That is not an error: an
    # unmanaged proxy is served from configuration that was never written here,
    # and the page says so rather than pretending the file is missing.
    #
    stored: ObjectView | None
    publication: Publication | None
    #
    # The address the object is served on. An object that names no VIP is
    # served on the cluster's default one, which is a fact about the cluster
    # rather than about the object - so the page says which, and says the
    # address, instead of leaving the reader to look it up.
    #
    vip: str | None
    vip_address: str | None
    vip_is_default: bool
    #
    # The frontend this object is served through, when one can be named. It is
    # plumbing rather than an answer, so it is carried for reference and never
    # used to decide whether the object is published.
    #
    published: ProxyView | None
    commit: str | None
    short_commit: str | None
    observed_at: datetime | None
    observed_iso: str | None
    age_label: str
    stale: bool
    available: bool
    detail: str


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _hostnames(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(hostname for hostname in value if isinstance(hostname, str) and hostname)


def object_view(value: Any) -> ObjectView | None:
    entry = _mapping(value)
    name = entry.get("name")
    document = entry.get("document")
    if not isinstance(name, str) or not name or not isinstance(document, str):
        return None
    problem = entry.get("problem")
    protocol = entry.get("protocol")
    return ObjectView(
        name=name,
        document=document,
        #
        # `readable` is the helper's answer and is not re-derived from
        # `problem`. The contract check already refuses an entry where the two
        # disagree, and a page that recomputed it would quietly disagree with
        # the command line about the same object.
        #
        readable=entry.get("readable") is True,
        problem=problem if isinstance(problem, str) and problem else None,
        protocol=protocol if isinstance(protocol, str) and protocol else None,
        hostnames=_hostnames(entry.get("hostnames")),
        line_count=len(document.splitlines()),
    )


def cluster_object_views(reading: ClusterObjects | None) -> tuple[ObjectView, ...]:
    """Every readable entry in one cluster's cached objects, by name."""

    if reading is None:
        return ()
    values = _mapping(reading.result).get("objects")
    if not isinstance(values, list):
        return ()
    views = [view for view in (object_view(value) for value in values) if view is not None]
    return tuple(sorted(views, key=lambda view: view.name))


def publication(
    commit: str | None,
    versions: Iterable[VersionView],
    *,
    release_state: str = "",
    node_version: str = "",
) -> Publication:
    """Whether the commit this object was read at has been released and deployed.

    `VersionView.published` is the comparison that matters: it is true for the
    version whose commit is the one the nodes are told to pull. A version can
    exist without being that one, which is a publish that has not happened yet
    rather than a fault.
    """

    versions = tuple(versions)
    match = next((view for view in versions if commit and view.expected_commit == commit), None)
    if commit is None:
        return Publication("Unknown", "The version listing has not been read", "unknown", None)
    if match is None:
        return Publication(
            "Not released",
            "This object is committed but no release names its version",
            "warning",
            None,
        )
    if not match.published:
        #
        # A version can exist without being the release: publishing is its own
        # step, and the history page counts exactly these as unpublished. It is
        # work in progress, not a version that lost a race.
        #
        release = next((view for view in versions if view.published), None)
        behind = f", and {release.version} is the release" if release else ""
        return Publication(
            "Awaiting publish",
            f"{match.version} is committed{behind}",
            "warning",
            match.version,
        )
    #
    # Released is not serving. Publishing writes a release; a deploy is what
    # makes the nodes pull it, and saying "published" for both would report a
    # change as live while every node still serves the previous one.
    #
    # `converged` is the dashboard's word for "every node is on the release".
    # The first version of this compared against "current" - a word nothing
    # produces - so every object read as waiting, including ones the nodes were
    # already serving.
    #
    if release_state and release_state.lower() != "converged":
        return Publication(
            "Waiting for deploy",
            f"{match.version} is the release, and the nodes are on {node_version or 'an older one'}",
            "warning",
            match.version,
        )
    return Publication(
        "Serving", f"{match.version} is released and the nodes are on it", "healthy", match.version
    )


def build_object_detail(
    cluster: str,
    name: str,
    readings: Iterable[ClusterObjects],
    published: Iterable[ProxyView] = (),
    versions: Iterable[VersionView] = (),
    *,
    release_state: str = "",
    node_version: str = "",
    vip: str | None = None,
    vip_address: str | None = None,
    vip_is_default: bool = False,
    now: datetime | None = None,
    stale_after: timedelta,
    captured: bool = False,
) -> ObjectDetail:
    """Combine one cluster's cached objects with the published row of the same name."""

    now = now or datetime.now(UTC)
    reading = next((row for row in readings if row.cluster == cluster), None)
    stored = next((view for view in cluster_object_views(reading) if view.name == name), None)
    running = next((proxy for proxy in published if proxy.name == name), None)

    commit = _mapping(reading.result).get("commit") if reading is not None else None
    commit = commit if isinstance(commit, str) and commit else None
    #
    # The reading is unusable, not merely empty, when the poller could not make
    # it. The distinction matters here more than on a listing: an editor that
    # opened an empty document because a read failed would offer to publish it.
    #
    available = reading is not None and reading.outcome == "done" and not reading.poll_error
    stale = reading is not None and now - reading.observed_at > stale_after

    if reading is None:
        detail = "The objects for this cluster have not been read yet"
    elif not available:
        detail = "The stored objects could not be read"
    elif stored is None and running is not None:
        detail = "Served from configuration that was not written here"
    elif stored is None:
        detail = "No object of that name is stored"
    elif not stored.readable:
        detail = "This version cannot read the stored document"
    elif stale:
        detail = "The stored objects need a fresh read"
    else:
        detail = "Stored in the cluster repository"

    return ObjectDetail(
        cluster=cluster,
        accent=accent_index(cluster),
        name=name,
        stored=stored,
        publication=(
            publication(commit, versions, release_state=release_state, node_version=node_version)
            if stored is not None
            else None
        ),
        vip=vip,
        vip_address=vip_address,
        vip_is_default=vip_is_default,
        published=running,
        commit=commit,
        short_commit=commit[:12] if commit else None,
        observed_at=reading.observed_at if reading is not None else None,
        observed_iso=reading.observed_at.astimezone(UTC).isoformat()
        if reading is not None
        else None,
        age_label=observation_label(reading.observed_at, now, captured=captured)
        if reading is not None
        else "Never",
        stale=stale,
        available=available,
        detail=detail,
    )


def stored_only(
    reading: ClusterObjects | None, published: Iterable[ProxyView] = ()
) -> tuple[ObjectView, ...]:
    """Objects that exist in the repository but in no published frontend.

    These are the ones the overview would otherwise hide, because it is built
    from the published inventory - and they are exactly the objects somebody is
    working on. An edit that cannot be reached from the listing until it has
    been deployed is unreachable during the only period it needs reaching.

    Matched on hostname rather than on name: an object is served through a
    shared frontend named after the address, never after itself, so a name
    comparison would report every object as unpublished.
    """

    serving = {hostname for proxy in published for hostname in proxy.hostnames}
    return tuple(
        view
        for view in cluster_object_views(reading)
        if not view.hostnames or not set(view.hostnames) <= serving
    )
