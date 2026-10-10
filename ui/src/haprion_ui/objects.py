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

from haprion.generate import PORTS
from haprion.object_manifest import ABSENT as ABSENT
from haprion.object_manifest import CHANGED as CHANGED
from haprion.object_manifest import CURRENT
from haprion.proxy_model import OWN_PORT, SENDERS_ADDRESS, ModelError, read_document

from haprion_ui.addresses import ObjectAddresses, from_entry
from haprion_ui.cluster_identity import accent_index
from haprion_ui.dashboard import observation_label
from haprion_ui.db import ClusterObjects, Job
from haprion_ui.history import VersionView
from haprion_ui.jobs import ATTENTION, deploys, error_code, published
from haprion_ui.proxies import ProxyView, Tone

#
# The engine's own word for an object nothing could be read about. Not a
# state the manifest produces: it is what the status reports when a node did
# not say what it runs, or the release it named carries no manifest.
#
UNKNOWN = "unknown"


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
    #
    # From the envelope too (B222), worked out by the engine with the
    # generator's rule. `None` is a helper that did not say.
    #
    addresses: ObjectAddresses | None = None
    health_checked: bool | None = None
    sourced: bool = False
    #
    # The names HAProxy knows this object's backends by (B250), from the
    # envelope. `None` is a document the engine could not read: a pool's name
    # alone no longer says whose it is, and nothing here guesses.
    #
    runtime_backends: tuple[str, ...] | None = None
    #
    # A raw port's servers as written (26-10-06); empty for a site.
    #
    servers: tuple[str, ...] = ()
    #
    # What the object is for, from the envelope (26-10-10); empty where nobody
    # wrote it or the helper did not say.
    #
    description: str = ""
    #
    # The cluster groups it names as sources, by the generator's rule
    # (26-10-10); None where the helper did not say.
    #
    groups: tuple[str, ...] | None = None


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
    accent: int | None
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


def _note(value: Any) -> str:
    """A note the engine read, or nothing: a helper that did not say, or an unreadable document."""

    return value if isinstance(value, str) else ""


def object_view(value: Any) -> ObjectView | None:
    entry = _mapping(value)
    name = entry.get("name")
    document = entry.get("document")
    if not isinstance(name, str) or not name or not isinstance(document, str):
        return None
    problem = entry.get("problem")
    protocol = entry.get("protocol")
    raw = _raw(protocol, document)
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
        ports=_ports(protocol, raw),
        servers=_servers(raw),
        backend_count=_count(entry.get("backend_count")),
        redirect_http=(
            entry.get("redirect_http") if isinstance(entry.get("redirect_http"), bool) else None
        ),
        addresses=from_entry(entry.get("vip"), entry.get("source")),
        health_checked=(
            entry.get("health_checked") if isinstance(entry.get("health_checked"), bool) else None
        ),
        #
        # Whether its traffic leaves from a fixed address: a named source or
        # the VIP's own. Only the node holding the VIP can bind it, which
        # decides which node may answer for the backend.
        #
        #
        # An object leaving with its senders' addresses has none, but its
        # traffic passes only the node holding the VIP, so its lamp is that
        # node's, as the others' are (Fas 19b B5, `SENDERS_ADDRESS`).
        #
        sourced=isinstance(entry.get("source"), Mapping) or protocol in SENDERS_ADDRESS,
        runtime_backends=_names(entry.get("runtime_backends")),
        description=_note(entry.get("description")),
        groups=_names(entry.get("groups")),
    )


def _raw(protocol: Any, document: str) -> Mapping[str, Any]:
    """A raw port's document - tcp, dns or syslog - read with the engine's own reader."""

    if protocol not in OWN_PORT:
        return {}
    try:
        return read_document("object", document.encode())
    except (ModelError, ValueError, UnicodeError):
        return {}


def _ports(protocol: Any, data: Mapping[str, Any]) -> tuple[int, ...]:
    """The port an object is served on: the cluster's for a site, its own otherwise.

    A tcp, dns or syslog object writes its port in the document, and the envelope does
    not carry it; it is read there (Fas 19a B5).
    """

    if isinstance(protocol, str) and protocol in PORTS:
        return (PORTS[protocol],)
    port = _mapping(data.get("listen")).get("port")
    return (port,) if isinstance(port, int) and not isinstance(port, bool) else ()


def _servers(data: Mapping[str, Any]) -> tuple[str, ...]:
    """A raw port's servers as written, which is what its listing names (26-10-06).

    A site is named by its hostnames; a raw port has none, and the servers behind
    it are what somebody looks for.

    A server's port is added where it is not the object's own (review 26-10-08,
    F6): two receivers on one host otherwise read as the same one twice, and
    a port the cell does not name is one somebody has to open the object for.
    """

    pool = _mapping(_mapping(data.get("backends")).get(str(data.get("backend", ""))))
    servers = pool.get("servers")
    own = _mapping(data.get("listen")).get("port")
    return tuple(
        _server(str(server["host"]), server.get("port"), own)
        for server in (servers if isinstance(servers, list) else ())
        if isinstance(server, Mapping) and isinstance(server.get("host"), str)
    )


def _server(host: str, port: Any, own: Any) -> str:
    if not isinstance(port, int) or isinstance(port, bool) or port == own:
        return host
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _names(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    return tuple(name for name in value if isinstance(name, str) and name)


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
    object_state: str = UNKNOWN,
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
    # already serving. `object_state` is that per-object fact, and it comes
    # from comparing the published release's manifest against the manifest of
    # the release each node reports - not from the jobs, which knew only what
    # this application published recently enough to still be in the listing.
    #
    # Which means the answer can be "we do not know", and it has to be said.
    # The job window could not say it: an object it had no row for looked
    # untouched, so an object changed from the command line, or changed longer
    # ago than the window reaches, or changed by a network edit that never
    # names it, was reported as being served.
    #
    #
    # "Unknown" is what the dashboard says about a cluster it could not read,
    # and it is not the same claim as "behind". Treating it as one had a card
    # report a deploy as owed on the strength of a status nobody had.
    #
    if release_state and release_state.lower() not in {"converged", "unknown"}:
        if object_state == CURRENT:
            return Publication(
                "Serving",
                f"The nodes are on {node_version or 'an earlier release'}, "
                "which serves this object as written",
                "healthy",
                match.version,
            )
        if object_state == UNKNOWN:
            return Publication(
                "Unknown",
                f"{match.version} is the release, and whether the nodes serve "
                "this object as it is written could not be read",
                "unknown",
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
    object_state: str = UNKNOWN,
    vip: str | None = None,
    vip_address: str | None = None,
    vip_is_default: bool = False,
    now: datetime | None = None,
    stale_after: timedelta,
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
    elif stored.description:
        #
        # What it is for says more than where it is kept, once nothing is
        # wrong with the reading (26-10-10).
        #
        detail = stored.description
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
                object_state=object_state,
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
        age_label=observation_label(reading.observed_at, now) if reading is not None else "Never",
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


#
# The publishes whose payload names objects under `objects`: one object's, and
# the saved changes published together (B257).
#
OBJECT_PUBLISHES = frozenset({"objects_publish", "changes_publish"})


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
        if job.operation not in OBJECT_PUBLISHES or job.state not in {"pending", "running"}:
            continue
        named = job.payload.get("objects") if isinstance(job.payload, Mapping) else None
        if isinstance(named, Mapping):
            waiting.update(name for name in named if isinstance(name, str))
    return frozenset(waiting)


def carried_since_deploy(jobs: Iterable[Job]) -> frozenset[str]:
    """Objects a publish named after the newest finished deploy.

    A fallback, and only for what it can say in the positive. The releases
    decide whether an object is in step - two manifests, compared - and this is
    asked only where that comparison has no answer: the nodes run a release
    built before manifests existed, so nothing can be held against anything.

    The distinction is the whole reason this function came back after B103
    removed its predecessor. "A publish job names this object" is a fact about
    something that happened. "No publish job names it" is not a fact about
    anything: the window is bounded, the command line writes no jobs, and a
    network edit carries no object names. The first is used here; the second is
    what made the old status wrong, and it is not used at all.

    So an object nothing can be said about wears no badge rather than a badge
    every object would wear - which is the cluster-wide claim the per-object
    answer was built to remove.
    """

    waiting: set[str] = set()
    for job in jobs:
        if deploys(job) and job.state == "done":
            #
            # Newest first, so the first finished deploy ends the search: every
            # publish older than it has already reached the nodes.
            #
            break
        if job.operation not in OBJECT_PUBLISHES or not published(job):
            continue
        named = job.payload.get("objects") if isinstance(job.payload, Mapping) else None
        if isinstance(named, Mapping):
            waiting.update(
                name
                for name, document in named.items()
                if isinstance(name, str) and document is not None
            )
    return frozenset(waiting)


def awaiting_deploy(states: Mapping[str, str], jobs: Iterable[Job]) -> frozenset[str]:
    """Which objects a pending deploy carries, said as precisely as it can be.

    The releases answer first. Where they cannot - an object whose state is
    unknown, or one the comparison never reached - the jobs are asked, and only
    for the objects they name. Everything else is left alone.
    """

    named = {name for name, state in states.items() if state in {CHANGED, ABSENT}}
    unresolved = carried_since_deploy(jobs)
    return frozenset(named | {name for name in unresolved if states.get(name, UNKNOWN) == UNKNOWN})


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
        if job.operation not in OBJECT_PUBLISHES or job.state in {"pending", "running"}:
            continue
        named = job.payload.get("objects") if isinstance(job.payload, Mapping) else None
        if not isinstance(named, Mapping):
            continue
        for name in named:
            if not isinstance(name, str) or name in settled:
                continue
            settled.add(name)
            #
            # A *Publish & deploy* that published and then failed to deploy
            # ends in the deploy's state; the publish itself went through.
            #
            if job.state in ATTENTION and not published(job):
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
    #
    # The VIP and source address the object is on (B221), as the helper
    # reported them (B222). None where it could not say.
    #
    addresses: ObjectAddresses | None = None
    #
    # A raw port's servers as written (26-10-06), for its Hosts cell.
    #
    servers: tuple[str, ...] = ()


def listed_objects(
    reading: ClusterObjects | None,
    published: Iterable[ProxyView] = (),
    served: Collection[str] | None = None,
    views: Sequence[ObjectView] | None = None,
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
    # Alphabetical, served or not - the badge says what is waiting, not the
    # position (see `_proxy-rows.html`).
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
                    addresses=view.addresses,
                    servers=view.servers,
                )
                for view in (cluster_object_views(reading) if views is None else views)
            ),
            key=lambda listed: listed.name,
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
        if job.operation not in OBJECT_PUBLISHES or not published(job):
            continue
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        asked = payload.get("objects")
        if not isinstance(asked, Mapping):
            continue
        names.extend(
            name for name, document in asked.items() if document is None and isinstance(name, str)
        )
    return tuple(sorted(set(names)))


def removed_backends(jobs: Iterable[Job]) -> dict[str, tuple[str, ...]]:
    """The backends each removed object had, as its removal wrote them down (B250).

    The interface's own bookkeeping on the job, beside the names: a pool is
    named by itself, so once the document is gone nothing else can say which
    backends the nodes still serve for it.
    """

    found: dict[str, tuple[str, ...]] = {}
    for job in jobs:
        if job.operation not in OBJECT_PUBLISHES or not published(job):
            continue
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        written = payload.get("removed_backends")
        if not isinstance(written, Mapping):
            continue
        for name, backends in written.items():
            if isinstance(name, str) and isinstance(backends, list):
                found.setdefault(
                    name, tuple(item for item in backends if isinstance(item, str) and item)
                )
    return found


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
