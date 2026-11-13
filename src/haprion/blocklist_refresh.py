"""What the refresh timer does with the blocklists, apart from where it runs (B500).

Each pass looks at every definition. A list whose time has come is fetched;
a fetch that fails, or brings back something that is not a list, keeps the
last good list and says why in the state. Then every cluster gets each list
with that cluster's exceptions taken out, written under the cluster's
certificate directory, where its nodes fetch it with the key they fetch
certificates with:

    <certificate root>/<cluster>/blocklists/<name>.lst

A file is written only when it differs, and the clusters whose files changed
are what the caller triggers. An exception therefore takes effect on the next
pass without a fetch (B496: *Except* acts at once), and a list that did not
change moves nothing on the nodes.

A failed list is tried again an hour later, or at its own interval when that
is shorter; a source that is down is not asked every pass. A list whose source
changed - the URL, the kind of authorization, the username or the password or
token - is fetched at once, in the pass the save starts, whatever its interval
says; a changed exception, interval or description is not a new source. When
that first fetch fails the last good list stays and is sent on - dropping it
would refuse every publish naming the list - and the state says in its error
that the list kept is from the previous source, for as long as it is.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from haprion import atomic_file, blocklist_store, blocklists
from haprion.blocklist_store import ListState, Stored

DIRECTORY = "blocklists"
RETRY = dt.timedelta(hours=1)

Fetch = Callable[[blocklists.Definition, str], bytes]


@dataclass(frozen=True)
class ClusterTarget:
    """Where one cluster's lists go, and the groups its exceptions may name."""

    cluster: str
    directory: Path
    groups: Mapping[str, Sequence[str]]
    uid: int
    gid: int
    mode: int


@dataclass(frozen=True)
class Written:
    """One list file in one cluster: what it holds, and whether this pass changed it."""

    cluster: str
    name: str
    entries: int
    excepted: int
    unknown_groups: tuple[str, ...]
    changed: bool


@dataclass(frozen=True)
class Pass:
    states: dict[str, ListState]
    written: tuple[Written, ...]

    def changed_clusters(self) -> dict[str, tuple[str, ...]]:
        """Each cluster whose files changed, with the lists that did."""

        found: dict[str, list[str]] = {}
        for item in self.written:
            if item.changed:
                found.setdefault(item.cluster, []).append(item.name)
        return {cluster: tuple(names) for cluster, names in found.items()}


def _when(value: str | None) -> dt.datetime | None:
    return None if value is None else dt.datetime.fromisoformat(value)


def due(stored: Stored, state: ListState | None, now: dt.datetime) -> bool:
    """Whether the list is to be fetched now: never tried, a new source, or its time has come."""

    item = stored.definition
    if state is None or state.attempted_at is None or state.source != stored.source:
        return True
    attempted = _when(state.attempted_at)
    if attempted is None or attempted.tzinfo is None:
        return True
    every = dt.timedelta(hours=item.every_hours)
    failed = state.failed_at is not None and state.failed_at == state.attempted_at
    wait = min(every, RETRY) if failed else every
    return now >= attempted + wait


def fetch_one(
    stored: Stored,
    state: ListState | None,
    now: dt.datetime,
    *,
    fetch: Fetch,
    state_directory: Path,
) -> ListState:
    """Fetch and keep one list; the state it leaves, the last good list kept on failure."""

    stamp = now.isoformat()
    previous = state or ListState()
    try:
        parsed = blocklists.parse(fetch(stored.definition, stored.secret))
    except (blocklists.BlocklistError, ValueError) as exc:
        reason = str(exc)
        if previous.fetched_at is not None and previous.kept_source != stored.source:
            reason = f"{reason[:400].rstrip('.')} (the list kept is from the previous source)"
        return replace(
            previous, attempted_at=stamp, failed_at=stamp, error=reason, source=stored.source
        )
    blocklist_store.keep(stored.definition.name, parsed.networks, directory=state_directory)
    return ListState(
        fetched_at=stamp,
        attempted_at=stamp,
        failed_at=None,
        error="",
        entries=len(parsed.networks),
        skipped=parsed.skipped,
        source=stored.source,
        kept_source=stored.source,
    )


def _secure_subdirectory(target: ClusterTarget) -> Path:
    """`<cluster>/blocklists`, made like the cluster's directory; a link refused."""

    directory = target.directory / DIRECTORY
    if not directory.exists():
        parent = target.directory.lstat()
        directory.mkdir(mode=0o700)
        os.chmod(directory, stat.S_IMODE(parent.st_mode) & 0o750)
        if os.geteuid() == 0:
            os.chown(directory, parent.st_uid, parent.st_gid)
    found = directory.lstat()
    if not stat.S_ISDIR(found.st_mode) or stat.S_ISLNK(found.st_mode):
        raise blocklist_store.StoreError(f"{directory} is not a directory")
    return directory


def write_cluster(
    target: ClusterTarget,
    stored: Stored,
    networks: tuple[blocklists.Network, ...],
) -> Written:
    """One list's file in one cluster, with that cluster's exceptions out; written only if it differs."""

    item = stored.definition
    result = blocklists.subtract(networks, item.excepts, target.groups)
    content = blocklists.render(result.networks)
    path = _secure_subdirectory(target) / f"{item.name}{blocklist_store.LIST_SUFFIX}"
    try:
        changed = path.read_bytes() != content
    except FileNotFoundError:
        changed = True
    if changed:
        owned = os.geteuid() == 0
        atomic_file.write(
            path,
            content,
            mode=target.mode,
            uid=target.uid if owned else None,
            gid=target.gid if owned else None,
        )
    return Written(
        cluster=target.cluster,
        name=item.name,
        entries=len(result.networks),
        excepted=result.excepted,
        unknown_groups=result.unknown_groups,
        changed=changed,
    )


def run(
    definitions: Iterable[Stored],
    targets: Sequence[ClusterTarget],
    now: dt.datetime,
    *,
    fetch: Fetch,
    state_directory: Path = blocklist_store.STATE,
    only: Sequence[str] = (),
    force: bool = False,
) -> Pass:
    """One pass: fetch what is due (or `only`, or everything with `force`), then write every cluster.

    A list never fetched well writes no file: a node is never handed an empty
    list where an object expects one, and a version naming it waits (the
    deploy plan refuses a version whose lists a node does not hold).
    """

    if now.tzinfo is None:
        raise ValueError("the time of a pass is in UTC, with its zone")
    stored = tuple(definitions)
    states = dict(blocklist_store.read_state(directory=state_directory))
    for item in stored:
        name = item.definition.name
        wanted = name in only if only else (force or due(item, states.get(name), now))
        if wanted:
            states[name] = fetch_one(
                item, states.get(name), now, fetch=fetch, state_directory=state_directory
            )
    defined = {item.definition.name for item in stored}
    states = {name: state for name, state in states.items() if name in defined}
    blocklist_store.write_state(states, directory=state_directory)
    for path in state_directory.glob(f"*{blocklist_store.LIST_SUFFIX}"):
        if path.stem not in defined and blocklists.NAME.fullmatch(path.stem):
            path.unlink()
    written: list[Written] = []
    served: set[str] = set()
    for item in stored:
        networks = blocklist_store.kept(item.definition.name, directory=state_directory)
        if networks is None:
            continue
        served.add(item.definition.name)
        for target in targets:
            written.append(write_cluster(target, item, networks))
    for target in targets:
        _remove_unserved(target, served)
    return Pass(states=states, written=tuple(written))


def _remove_unserved(target: ClusterTarget, served: set[str]) -> None:
    """A list no longer defined, or with no good list to send, leaves the cluster's directory.

    With it go the generator's groups. A list with no good list is one made
    again under a removed name and not fetched yet: it must not be offered
    from the old one.

    The nodes keep the file they have: nothing on them is removed, and a
    configuration still naming it keeps loading. A new one naming it is
    refused, as the web refuses removing a list an object names.
    """

    directory = target.directory / DIRECTORY
    if not directory.is_dir():
        return
    for path in directory.glob(f"*{blocklist_store.LIST_SUFFIX}"):
        if path.stem not in served and blocklists.NAME.fullmatch(path.stem):
            path.unlink()
            atomic_file.sync_directory(directory)
