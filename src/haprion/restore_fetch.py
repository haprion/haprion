"""The manager lets a test restore's node fetch, for that run only (B398).

A test restore proves the whole way back, so the VM it builds fetches its
configuration and certificates from this manager as the node would. It has
made fetch keys of its own, which no pull account knows, and the node's lines
name the node's own addresses. The restore therefore writes, once `apply` has
reported the VM's new public keys, a line for each into the two pull accounts'
`authorized_keys`: the format a node's own line has (`node_enrollment.pull_line`),
`from=` the test address alone, ending by itself after two hours, and under the
name `restore-<run>` instead of a node's. It takes them out when the run ends
however it ends, and when the run's directory is put away or discarded.

Written as every change to these files is: under the lock all of them take
(`cluster-file`), as one recorded change (`change_journal`), so a node added
or a `pull-keys` beside it neither loses the line nor writes it twice. A
`pull-keys` leaves a temporary line alone (`TEMPORARY_NODE`).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from haprion import change_journal
from haprion.change_journal import FileChange as Change
from haprion.change_journal import Record
from haprion.cluster_lock import DEFAULT_LOCK_ROOT, LockBusy, hold
from haprion.config import PathPolicy
from haprion.node_enrollment import (
    CERT_PURPOSE,
    CONFIG_PURPOSE,
    TEMPORARY_NODE,
    Locations,
    config_root,
    keys_with,
    keys_without,
    pull_line,
)

OPERATION = "restore access"
CLUSTER_FILE_LOCK = "cluster-file"
LIFETIME = 2 * 3600
# Another node operation can hold the cluster-file lock for as long as a join takes.
LOCK_WAIT = 60.0
PURPOSES = {"config": CONFIG_PURPOSE, "cert": CERT_PURPOSE}
#
# What the target reports as its public keys goes into a file on this host, so
# it is held to the shape of one key and nothing else: no options, no newline,
# no comment.
#
PUBLIC_KEY = re.compile(
    r"^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}$"
)


class FetchAccessError(Exception):
    """The lines could not be written or taken out."""


def name_of(run: str) -> str:
    name = f"restore-{run}"
    if not TEMPORARY_NODE.fullmatch(name):
        raise FetchAccessError(f"{run} is not a run ID")
    return name


def valid_keys(reported: object) -> dict[str, str]:
    """The keys a target reported, or an error: only well-formed public keys are written."""

    if not isinstance(reported, Mapping):
        raise FetchAccessError("the target reported no fetch keys")
    keys: dict[str, str] = {}
    for kind, key in reported.items():
        if kind not in PURPOSES or not isinstance(key, str) or not PUBLIC_KEY.fullmatch(key):
            raise FetchAccessError(f"the target reported a {kind!r} fetch key that is not one")
        keys[kind] = key
    if "config" not in keys:
        raise FetchAccessError("the target reported no configuration fetch key")
    return keys


@dataclass(frozen=True, slots=True)
class FetchAccess:
    """What a test restore asks of the manager, as two calls."""

    grant: Callable[[str, str, str, Mapping[str, str]], None]  # run, cluster, address, keys
    revoke: Callable[[str, str], None]  # run, cluster


def for_policy(
    policy: PathPolicy,
    *,
    locations: Locations | None = None,
    lock_root: Path = DEFAULT_LOCK_ROOT,
    journal: Path = change_journal.JOURNAL,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = LOCK_WAIT,
) -> FetchAccess:
    where = locations or Locations()

    @contextmanager
    def locked() -> Iterator[None]:
        deadline = time.monotonic() + wait
        while True:
            try:
                with hold(CLUSTER_FILE_LOCK, operation=OPERATION, root=lock_root):
                    yield
                return
            except LockBusy as exc:
                if time.monotonic() >= deadline:
                    raise FetchAccessError(
                        f"another node operation holds the cluster file's lock: {exc}"
                    ) from exc
                sleep(1.0)

    def accounts() -> Iterator[tuple[str, str]]:
        yield policy.pull_account, CONFIG_PURPOSE
        yield policy.cert_pull_account, CERT_PURPOSE

    def rewrite(cluster: str, make: Callable[[str, bytes], bytes], what: str) -> None:
        with locked():
            if change_journal.read(journal) is not None:
                change_journal.recover(journal)
            changes = []
            for account, purpose in accounts():
                path = where.authorized_keys(account)
                try:
                    before = path.read_bytes()
                except OSError as exc:
                    raise FetchAccessError(f"{path} cannot be read: {exc}") from exc
                after = make(purpose, before)
                if after != before:
                    changes.append(Change(path, before, after, f"{account}'s authorized_keys"))
            if changes:
                with change_journal.transaction(Record(what, cluster, tuple(changes)), journal):
                    change_journal.apply(changes)

    def grant(run: str, cluster: str, address: str, keys: Mapping[str, str]) -> None:
        name = name_of(run)
        expires = time.strftime("%Y%m%d%H%M", time.gmtime(now() + LIFETIME))
        roots = {
            CONFIG_PURPOSE: config_root(policy, cluster),
            CERT_PURPOSE: policy.certificate_directory(cluster),
        }
        wanted = {PURPOSES[kind]: key for kind, key in keys.items()}

        def make(purpose: str, before: bytes) -> bytes:
            root = roots[purpose]
            if purpose not in wanted or root is None:
                return before
            line = pull_line(root, wanted[purpose], name, purpose, (address,), expires=expires)
            return keys_with(before, line, name, purpose)

        rewrite(cluster, make, OPERATION)

    def revoke(run: str, cluster: str) -> None:
        name = name_of(run)
        rewrite(cluster, lambda purpose, before: keys_without(before, name, purpose), OPERATION)

    return FetchAccess(grant, revoke)


def lazy(load: Callable[[], PathPolicy]) -> FetchAccess:
    """The same, with the policy read when a call needs it: a discard or a sweep that has
    no marker in front of it never reads the policy."""

    def grant(run: str, cluster: str, address: str, keys: Mapping[str, str]) -> None:
        for_policy(load()).grant(run, cluster, address, keys)

    def revoke(run: str, cluster: str) -> None:
        for_policy(load()).revoke(run, cluster)

    return FetchAccess(grant, revoke)
