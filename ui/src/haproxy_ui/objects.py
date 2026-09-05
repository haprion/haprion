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

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from haproxy_mgmt.generate import PORTS

from haproxy_ui.cluster_identity import accent_index
from haproxy_ui.dashboard import observation_label
from haproxy_ui.db import ClusterObjects, Job
from haproxy_ui.history import VersionView
from haproxy_ui.jobs import ATTENTION, error_code
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
    #
    # The port this object will be served on once it is deployed, taken from
    # the engine's own table rather than restated here - the interface must not
    # hold a second opinion about what a protocol binds. Empty for tcp, whose
    # port is written in the document and is not carried in the envelope.
    #
    ports: tuple[int, ...]
    #
    # From the envelope, never re-derived here. `None` is an entry written by a
    # release that predates the field: it said nothing, which is not the same
    # as an object with no backends.
    #
    backend_count: int | None = None
    redirect_http: bool | None = None


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


def _count(value: Any) -> int | None:
    """A whole number, or nothing. `True` is 1 in Python and is not a count."""

    return value if isinstance(value, int) and not isinstance(value, bool) else None


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
        ports=(PORTS[protocol],) if isinstance(protocol, str) and protocol in PORTS else (),
        backend_count=_count(entry.get("backend_count")),
        redirect_http=(
            entry.get("redirect_http") if isinstance(entry.get("redirect_http"), bool) else None
        ),
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
    reconfigured: bool = True,
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
    #
    # And a deploy the nodes owe is not a deploy this object is waiting for.
    # The release is the cluster's, but a release carries only the objects the
    # publish named: every other object is byte for byte what the nodes are
    # already serving. `reconfigured` is that per-object fact, read from the
    # jobs the same way the listing reads it, and without it opening any
    # untouched object during somebody else's pending deploy said the site was
    # waiting on a change nobody had made to it.
    #
    if release_state and release_state.lower() != "converged":
        if not reconfigured:
            return Publication(
                "Serving",
                f"The nodes are on {node_version or 'an earlier release'}, "
                "which serves this object as written",
                "healthy",
                match.version,
            )
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
    reconfigured: bool = True,
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
            publication(
                commit,
                versions,
                release_state=release_state,
                node_version=node_version,
                reconfigured=reconfigured,
            )
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


def names_being_published(jobs: Iterable[Job]) -> frozenset[str]:
    """Objects with a publish job that has not finished.

    Read from the payload rather than from a column, because the job table has
    no notion of what an operation is about - which is deliberate: the worker
    runs a bounded request and never inspects it. This is the one place the
    interface looks inside a payload, and it looks at nothing else.

    `pending` and `running` only. A publish that finished is answered by the
    objects cache instead, and one that failed must not leave a row spinning
    forever as though it were still trying.
    """

    waiting: set[str] = set()
    for job in jobs:
        if job.operation != "objects_publish" or job.state not in {"pending", "running"}:
            continue
        named = job.payload.get("objects") if isinstance(job.payload, Mapping) else None
        if isinstance(named, Mapping):
            waiting.update(name for name in named if isinstance(name, str))
    return frozenset(waiting)


def published_awaiting_deploy(jobs: Iterable[Job]) -> frozenset[str]:
    """Objects published since the last deploy finished.

    The fact a row can honestly carry. That the nodes are behind is true of the
    cluster, and wearing it on every row said three objects had been changed
    when one had - which is worse than saying nothing, because the two that
    were untouched looked like work somebody had forgotten.

    Read from the jobs rather than by comparing documents: a publish job names
    exactly the objects it carried, and a deploy job is what makes them
    current. So the answer is the names published after the newest finished
    deploy, and it empties itself the moment one runs.

    Bounded by whatever window the caller read. A publish older than that is
    not reported, which is the safe direction: this understates rather than
    invents.
    """

    waiting: set[str] = set()
    for job in jobs:
        if job.operation == "deploy" and job.state == "done":
            #
            # Newest first, so the first finished deploy ends the search: every
            # publish older than it has already reached the nodes.
            #
            break
        if job.operation != "objects_publish" or job.state != "done":
            continue
        named = job.payload.get("objects") if isinstance(job.payload, Mapping) else None
        if isinstance(named, Mapping):
            waiting.update(
                name
                for name, document in named.items()
                if isinstance(name, str) and document is not None
            )
    return frozenset(waiting)


def publish_failures(jobs: Iterable[Job]) -> dict[str, str]:
    """Objects whose most recent publish ended badly, and what it blamed.

    Read alongside `names_being_published`, and the two are the same question
    asked about different states: that one says a publish is still trying, this
    one says the last attempt stopped and nothing changed. Until this existed,
    a refused publish was silent everywhere a person actually looks - the row
    stopped spinning, the draft stayed, and the reason was on the jobs page
    behind a click nobody had a reason to make. What that looked like from the
    outside was "save and publish turned my object into a draft".

    Only the newest verdict per name counts. Jobs arrive newest first, so the
    first one naming an object decides: a failure that the next attempt fixed
    is history, and showing it would send somebody after a problem that is
    already gone.

    The code rather than the diagnostics. A row has space for a few words, and
    the full text is on the jobs page - which is where somebody goes once they
    know there is something to go for.
    """

    failures: dict[str, str] = {}
    settled: set[str] = set()
    for job in jobs:
        if job.operation != "objects_publish" or job.state in {"pending", "running"}:
            continue
        named = job.payload.get("objects") if isinstance(job.payload, Mapping) else None
        if not isinstance(named, Mapping):
            continue
        for name in named:
            if not isinstance(name, str) or name in settled:
                continue
            settled.add(name)
            if job.state in ATTENTION:
                failures[name] = error_code(job) or job.state
    return failures


@dataclass(frozen=True, slots=True)
class ListedObject:
    """One object as the listing shows it: the thing somebody wrote.

    Not a frontend. The generator names frontends after the address and the
    protocol - `mgd-<vip>-<protocol>` - and every object on that address shares
    them, so listing frontends showed the implementation instead of the work.
    An https object that redirects plain HTTP appeared twice, under two names
    its author never chose, neither of which was the name in the document.
    """

    name: str
    protocol: str | None
    hostnames: tuple[str, ...]
    ports: tuple[int, ...]
    backend_count: int | None
    redirect_http: bool | None
    readable: bool
    problem: str | None
    serving: bool


def listed_objects(
    reading: ClusterObjects | None,
    published: Iterable[ProxyView] = (),
    served: Collection[str] | None = None,
) -> tuple[ListedObject, ...]:
    """This cluster's objects, each saying whether the nodes are serving it yet.

    `served` is the nodes' own answer: the objects some node reports a backend
    for. It is preferred over everything below because it is measured where the
    traffic is. The published inventory is the *released* configuration, so
    matching against it counted an object as served the moment it was published,
    while the nodes went on serving the release they had - which is the whole
    stretch the badge exists to describe.

    `None` means no node was read, and then the hostname match is the best
    answer there is. Matched on hostname because an object and a frontend never
    share a name: the frontend is named after the address it binds.

    An object that names no hostname cannot be matched that way and is reported
    as not yet serving. That is the safe direction: claiming a deployment that
    has not happened is the answer somebody acts on.
    """

    serving = {hostname for proxy in published for hostname in proxy.hostnames}
    #
    # Not yet serving first, then alphabetical. It is the row that changed, and
    # a cluster's list is long enough that an alphabetical position hides it. A
    # row joins the ordinary order the moment the nodes are serving it.
    #
    return tuple(
        sorted(
            (
                ListedObject(
                    name=view.name,
                    protocol=view.protocol,
                    hostnames=view.hostnames,
                    ports=view.ports,
                    backend_count=view.backend_count,
                    redirect_http=view.redirect_http,
                    readable=view.readable,
                    problem=view.problem,
                    serving=(
                        view.name in served
                        if served is not None
                        else bool(view.hostnames) and set(view.hostnames) <= serving
                    ),
                )
                for view in cluster_object_views(reading)
            ),
            key=lambda listed: (listed.serving, listed.name),
        )
    )


def unmanaged_only(published: Iterable[ProxyView]) -> tuple[ProxyView, ...]:
    """Published frontends this platform did not generate.

    The managed ones are left out because the objects above already describe
    them, and better: they carry the names their authors gave. What remains is
    configuration this platform does not own, where the frontend really is the
    only thing there is to show.
    """

    return tuple(proxy for proxy in published if not proxy.managed)


def removed_names(jobs: Iterable[Job]) -> tuple[str, ...]:
    """Every object a finished publish asked to remove.

    Candidates, not an answer: the repository is where these no longer are, so
    the job is the only place their names survive. Whether one is still being
    served is the nodes' to say.
    """

    names: list[str] = []
    for job in jobs:
        if job.operation != "objects_publish" or job.state != "done":
            continue
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        asked = payload.get("objects")
        if not isinstance(asked, Mapping):
            continue
        names.extend(
            name for name, document in asked.items() if document is None and isinstance(name, str)
        )
    return tuple(sorted(set(names)))


def removed_awaiting_deploy(
    jobs: Iterable[Job], listed: Iterable[ListedObject], served: Collection[str]
) -> tuple[str, ...]:
    """Objects a removal took out of the repository that the nodes still serve.

    A removal is a publish: the object leaves the repository, and the nodes go
    on serving the release they have until somebody deploys. Between the two the
    interface had nothing to show - the object was gone from the objects cache,
    and a managed frontend with no object behind it is listed nowhere - so a
    site that was still answering had vanished from the page that lists what is
    being served.

    The jobs say which names to *ask* about; the nodes say whether the answer is
    yes. That division matters: the first version asked only the jobs, and
    listed every removal in the last twenty as long as the cluster was not
    converged - so an object removed weeks ago, or one removed before it had
    ever been deployed, stayed on the page for ever.
    """

    present = {listing.name for listing in listed}
    return tuple(name for name in removed_names(jobs) if name not in present and name in served)


@dataclass(frozen=True, slots=True)
class ProxyCounts:
    """The three numbers above the table, counted from the table's own rows.

    They were counted from published frontends and were wrong in both
    directions. An https object that redirects plain HTTP is two frontends and
    was counted twice; every object sharing one address goes through one
    frontend and they were counted once between them. Neither is a number
    anybody could check against the list below, which is the only thing a
    summary is for.
    """

    published: int
    managed: int
    unmanaged: int


def counted(
    listed: Mapping[str, Sequence[ListedObject]], unmanaged: Mapping[str, Sequence[ProxyView]]
) -> ProxyCounts:
    """The summary for every cluster on the page.

    `managed` is objects, not frontends: the work somebody wrote. `unmanaged` is
    frontends, because for configuration this platform does not own the frontend
    really is all there is. The total is the two added up, so the cards and the
    rows agree.
    """

    managed = sum(len(objects) for objects in listed.values())
    foreign = sum(len(proxies) for proxies in unmanaged.values())
    return ProxyCounts(published=managed + foreign, managed=managed, unmanaged=foreign)
