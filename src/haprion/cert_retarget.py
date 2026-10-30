"""Publishing certificates to more targets, and withdrawing them from some.

The registry says where each certificate goes. Changing that used to be one
certificate at a time, as a whole new target set (`cert_registry.set_targets`),
and it left the copy on a dropped cluster's nodes in place. This module is the
operation the interface's two buttons become - *Publish to…* and *Remove
from…* - and it is a batch with a delta, for two reasons the maintainer gave
on 2026-09-15:

* "I sent 30 certificates to the wrong cluster and want to clean up." The
  queue admits one certificate job at a time, so thirty certificates are one
  request or they are impossible.
* A delta says what was meant. A page drawn from the registry some seconds
  ago cannot know a certificate's current target set, and thirty whole sets
  sent from it would each overwrite whatever changed in between. "Add
  internal" and "remove internal" apply to whatever the registry holds when
  the request runs.

What publishing to a target does
--------------------------------
The registry entry gains the target, the material is published to it, and
each added cluster is rolled out - a pull and a reload on its nodes. A
receiver fetches on its own schedule; publishing to one writes its pair and
waits.

What removing from a target does
--------------------------------
The registry entry loses the target, and the copy that target held goes:
each node of a dropped cluster is asked to remove its copy through the same
verb a deletion uses (no reload - a file nothing names is not loaded), and a
dropped receiver's pair is unlinked on the manager. The receiver host keeps
what it last fetched; the manager cannot reach into it. Nothing else is
touched: not the certificate's material for its remaining targets, not its
certbot lineage, not its registry entry.

The guards are a deletion's, scoped to the dropped target
---------------------------------------------------------
A certificate is refused, and nothing of it touched, when removing it from a
cluster would leave that cluster's committed configuration naming a
certificate it no longer has, when it is that cluster's `default_certificate`,
or when it is that cluster's last certificate (the writer's own coverage
guard). A receiver that is dropped loses this certificate's own directory
there; every certificate has its own, so no other is touched. One refused
certificate stops nothing else in the batch.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from haprion import cert_pending, cert_registry, exit_codes, labels
from haprion.cert_delete import (
    AUTHORITY_NODE_VERB,
    NODE_VERB,
    DeleteError,
    Guards,
    Layer,
    NodeCopy,
    NodeRemover,
    ask_node,
    read_guards,
    remove_node_copies,
)
from haprion.cert_inventory import (
    IMPORT_STORE,
    LETSENCRYPT_LIVE,
    receiver_files_in_any_format,
)
from haprion.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    PublishError,
    prune_receiver_directory,
    publish,
    publish_lock,
    roll_out,
)
from haprion.certificates import authority_path, certificate_path
from haprion.config import (
    AUTHORITY,
    ConfigError,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)

OPERATION = "cert_target"
HELPER = "/opt/haprion/current/bin/haprion-cert-target-helper"
SUDO = "/usr/bin/sudo"

GuardsReader = Callable[[RuntimeConfig, Sequence[str]], Guards]


class RetargetError(Exception):
    """The installation cannot answer the request at all - not one certificate's fault."""

    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.CONFIG):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Change:
    """What the request asks: add these targets, or remove them."""

    action: str
    """`add` or `remove`."""

    clusters: tuple[str, ...] = ()
    receivers: tuple[str, ...] = ()
    formats: Mapping[str, str] = field(default_factory=dict)
    """How an added receiver is written (B159); only `add` carries it."""

    @property
    def targets(self) -> tuple[str, ...]:
        return self.clusters + self.receivers


@dataclass(frozen=True, slots=True)
class Deployment:
    cluster: str
    exit_code: int

    def as_dict(self) -> dict[str, Any]:
        return {"cluster": self.cluster, "exit_code": self.exit_code}


@dataclass(frozen=True, slots=True)
class CertificateOutcome:
    certificate_id: str
    state: str
    """`changed` (the registry and every copy followed), `unchanged` (it already
    was as asked), `refused` (a guard held, nothing touched) or `incomplete` (the
    registry changed but a copy did not follow; the row says which)."""

    reason: str = ""
    code: str = ""
    added: tuple[str, ...] = ()
    abandoned: tuple[str, ...] = ()
    layers: tuple[Layer, ...] = ()
    nodes: tuple[NodeCopy, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "certificate": self.certificate_id,
            "state": self.state,
            "added": list(self.added),
            "abandoned": list(self.abandoned),
        }
        if self.code:
            entry["code"] = self.code
        if self.reason:
            entry["reason"] = self.reason
        if self.layers:
            entry["layers"] = [layer.as_dict() for layer in self.layers]
        if self.nodes:
            entry["nodes"] = [node.as_dict() for node in self.nodes]
        return entry


@dataclass(frozen=True, slots=True)
class Report:
    action: str
    outcomes: tuple[CertificateOutcome, ...]
    deployments: tuple[Deployment, ...] = field(default_factory=tuple)

    def _with(self, state: str) -> tuple[str, ...]:
        return tuple(o.certificate_id for o in self.outcomes if o.state == state)

    @property
    def changed(self) -> tuple[str, ...]:
        return self._with("changed")

    @property
    def unchanged(self) -> tuple[str, ...]:
        return self._with("unchanged")

    @property
    def refused(self) -> tuple[str, ...]:
        return self._with("refused")

    @property
    def incomplete(self) -> tuple[str, ...]:
        return self._with("incomplete")

    @property
    def deploy_failed(self) -> tuple[str, ...]:
        return tuple(d.cluster for d in self.deployments if d.exit_code != 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "certificates": [outcome.as_dict() for outcome in self.outcomes],
            "changed": list(self.changed),
            "unchanged": list(self.unchanged),
            "refused": list(self.refused),
            "incomplete": list(self.incomplete),
            "deployments": [deployment.as_dict() for deployment in self.deployments],
        }


def _load(policy: PathPolicy, require_secure: bool) -> RuntimeConfig:
    try:
        return load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        raise RetargetError("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc


def removal_refusal(
    certificate_id: str,
    abandoned_clusters: Sequence[str],
    runtime: RuntimeConfig,
    guards: Guards,
) -> tuple[str, str] | None:
    """Why this certificate must stay on these clusters, or None when it may go.

    `cert_delete.refusal` asks the same questions of every target at once;
    here only the dropped clusters count. A certificate a committed object
    in *another* cluster names is still that other cluster's to keep.
    """

    dropped = set(abandoned_clusters)
    objects = [
        name
        for name in guards.referenced.get(certificate_id, ())
        if name.split("/", 1)[0] in dropped
    ]
    if objects:
        return (
            "referenced_by_object",
            f"named by the committed {labels.noun(len(objects), 'object')} "
            + ", ".join(objects)
            + f"; change {'it' if len(objects) == 1 else 'them'} first",
        )
    defaults = [c for c in guards.defaults.get(certificate_id, ()) if c in dropped]
    if defaults:
        return (
            "cluster_default",
            "the default certificate of " + ", ".join(defaults) + "; choose another first",
        )
    registry = runtime.registry
    assert registry is not None  # noqa: S101 - `retarget` refused before reading
    uncovered = sorted(
        c for c in abandoned_clusters if tuple(registry.for_cluster(c)) == (certificate_id,)
    )
    if uncovered:
        return (
            "cluster_uncovered",
            "the only certificate of " + ", ".join(uncovered) + ", and a cluster that no "
            "certificate names cannot be loaded; give it another certificate first",
        )
    return None


def _unlink(path: Path) -> Layer:
    try:
        path.unlink()
    except FileNotFoundError:
        return Layer(str(path), "absent")
    except OSError as exc:
        return Layer(str(path), "failed", str(exc))
    return Layer(str(path), "removed")


def _clear_receivers(
    certificate_id: str, receiver_ids: Sequence[str], runtime: RuntimeConfig
) -> tuple[Layer, ...]:
    """A dropped receiver's files for this certificate in either format, and its directory there."""

    registry = runtime.registry
    assert registry is not None  # noqa: S101
    layers: list[Layer] = []
    for receiver_id in receiver_ids:
        receiver = registry.receivers.get(receiver_id)
        if receiver is None:
            continue
        for path in receiver_files_in_any_format(receiver, certificate_id):
            layers.append(_unlink(path))
        prune_receiver_directory(receiver, certificate_id)
    return tuple(layers)


def retarget(
    certificate_ids: Sequence[str],
    change: Change,
    policy: PathPolicy,
    *,
    deploy: bool = True,
    require_secure: bool = True,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    deployer: Deployer | None = None,
    node_remover: NodeRemover = ask_node,
    guards_reader: GuardsReader = read_guards,
    now: datetime | None = None,
) -> Report:
    """Apply one delta to each certificate, guarding each, and say what followed.

    The registry is re-read before every certificate rather than patched in
    memory, so the coverage guard for the second certificate sees the first
    one's change: two certificates that between them cover a cluster are
    refused on the second, not silently on neither.
    """

    if policy.certificate_registry is None:
        raise RetargetError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
        )
    if change.action not in {"add", "remove"}:
        raise RetargetError(
            "bad_input", f"unknown action {change.action!r}", exit_code=exit_codes.REFUSED
        )
    if not change.targets:
        raise RetargetError("bad_input", "the change names no target", exit_code=exit_codes.REFUSED)

    if change.action == "add":
        outcomes, touched_clusters = _add(
            certificate_ids,
            change,
            policy,
            require_secure=require_secure,
            live=live,
            store=store,
            lock_path=lock_path,
            now=now,
        )
        #
        # Rolled out once per added cluster, after every certificate is
        # published: thirty certificates to one cluster are one pull and one
        # reload, not thirty. Asked for by name rather than taken from the
        # publisher's "changed" list - an added cluster can already hold an
        # identical file (left behind by a removal whose unlink failed), which
        # writes nothing new, and its nodes would never be told.
        #
        #
        # And every cluster still marked from an earlier run, after these:
        # a retarget whose rollout failed is finished by running it again,
        # when the registry already says the cluster is added.
        #
        deployments: tuple[Deployment, ...] = ()
        if deploy and deployer is not None:
            registry_path = policy.certificate_registry
            assert registry_path is not None  # noqa: S101 - refused above
            pending_path = cert_pending.pending_path(registry_path)
            try:
                with publish_lock(lock_path):
                    due = cert_pending.Ledger(
                        pending_path,
                        like=registry_path,
                        known=_load(policy, require_secure).clusters,
                    ).order(touched_clusters)
            except (OSError, PublishError):
                due = [(cluster_id, 0) for cluster_id in touched_clusters]
            results, _unsettled = roll_out(
                due, deployer, pending_path=pending_path, like=registry_path, lock_path=lock_path
            )
            deployments = tuple(Deployment(r.cluster, r.exit_code) for r in results)
        return Report("add", tuple(outcomes), deployments)

    #
    # Under the publisher's lock, like a deletion: a renewal that ran between
    # the registry change and the node's removal would be fine from its side
    # and leave nothing behind, but the lock makes the two one step.
    #
    try:
        with publish_lock(lock_path):
            outcomes = _remove(
                certificate_ids,
                change,
                policy,
                require_secure=require_secure,
                node_remover=node_remover,
                guards_reader=guards_reader,
            )
    except PublishError as exc:
        raise RetargetError(exc.code, str(exc), exit_code=exit_codes.REFUSED) from exc
    return Report("remove", tuple(outcomes))


def _entry_or_refusal(
    certificate_id: str, runtime: RuntimeConfig
) -> tuple[tuple[str, ...], tuple[str, ...]] | CertificateOutcome:
    registry = runtime.registry
    assert registry is not None  # noqa: S101
    entry = registry.certificates.get(certificate_id)
    if entry is None:
        return CertificateOutcome(
            certificate_id,
            "refused",
            f"certificate {certificate_id!r} is not in the registry",
            "unknown_certificate",
        )
    return entry.clusters, entry.receivers


def _add(
    certificate_ids: Sequence[str],
    change: Change,
    policy: PathPolicy,
    *,
    require_secure: bool,
    live: Path,
    store: Path,
    lock_path: Path,
    now: datetime | None,
) -> tuple[list[CertificateOutcome], tuple[str, ...]]:
    registry_path = policy.certificate_registry
    assert registry_path is not None  # noqa: S101
    outcomes: list[CertificateOutcome] = []
    touched: list[str] = []
    #
    # Marked before the registry names them (`cert_pending`). The publisher
    # cannot do it for us: an added cluster can already hold an identical
    # file (left behind by a removal whose unlink failed), so it writes
    # nothing new, and a mark made only once the registry names the cluster
    # is the mark a failed rollout would not have: a second run would find
    # no trace of it - the registry would already say "added".
    #
    pending_path = cert_pending.pending_path(registry_path)
    try:
        with publish_lock(lock_path):
            ledger = cert_pending.Ledger(
                pending_path, like=registry_path, known=_load(policy, require_secure).clusters
            )
            ledger.mark(change.clusters)
    except (OSError, PublishError) as exc:
        raise RetargetError(
            "dependency_unavailable",
            f"cannot record the clusters about to be added: {exc}",
            exit_code=exit_codes.BLOCKED
            if isinstance(exc, PublishError) and exc.code == "operation_locked"
            else exit_codes.CONFIG,
        ) from exc
    marked = {
        cluster_id: serial
        for cluster_id, serial in ledger.current.items()
        if cluster_id in change.clusters and cluster_id not in ledger.before
    }
    registered: set[str] = set()
    for certificate_id in certificate_ids:
        runtime = _load(policy, require_secure)
        found = _entry_or_refusal(certificate_id, runtime)
        if isinstance(found, CertificateOutcome):
            outcomes.append(found)
            continue
        before_clusters, before_receivers = found
        clusters = tuple(dict.fromkeys((*before_clusters, *change.clusters)))
        receivers = tuple(dict.fromkeys((*before_receivers, *change.receivers)))
        try:
            written = cert_registry.set_targets(
                registry_path,
                certificate_id=certificate_id,
                clusters=clusters,
                receivers=receivers,
                runtime=runtime,
                formats=change.formats,
                require_secure=require_secure,
            )
        except cert_registry.RegistryError as exc:
            outcomes.append(CertificateOutcome(certificate_id, "refused", str(exc), exc.code))
            continue
        if not written.changed:
            outcomes.append(CertificateOutcome(certificate_id, "unchanged"))
            continue
        registered.update(written.added)
        #
        # Re-read rather than patched in memory: the publisher must see
        # exactly what the next renewal's hook will see.
        #
        refreshed = _load(policy, require_secure)
        try:
            report = publish(
                refreshed,
                policy,
                only=[certificate_id],
                live=live,
                store=store,
                lock_path=lock_path,
                deployer=None,
                now=now,
            )
        except PublishError as exc:
            outcomes.append(
                CertificateOutcome(
                    certificate_id,
                    "incomplete",
                    f"registered but not published: {exc}",
                    exc.code,
                    added=written.added,
                )
            )
            continue
        problems = [entry for entry in report.certificates if entry.error]
        if problems:
            code, message = problems[0].error or ("publish_failed", "not published")
            outcomes.append(
                CertificateOutcome(
                    certificate_id,
                    "incomplete",
                    f"registered but not published: {message}",
                    code,
                    added=written.added,
                )
            )
            continue
        for cluster_id in written.added:
            if cluster_id in change.clusters and cluster_id not in touched:
                touched.append(cluster_id)
        outcomes.append(CertificateOutcome(certificate_id, "changed", added=written.added))
    #
    # A cluster no certificate was added to is no further behind than before.
    # One that was added stays marked even when publishing failed: its nodes
    # may be missing the certificate the registry now gives it.
    #
    for cluster_id, serial in marked.items():
        if cluster_id not in registered:
            # Left marked if this fails: a later rollout finds the nodes current.
            with contextlib.suppress(OSError, PublishError):
                cert_pending.settle(
                    pending_path,
                    cluster_id,
                    serial,
                    like=registry_path,
                    locked=lambda: publish_lock(lock_path),
                )
    return outcomes, tuple(touched)


def _remove(
    certificate_ids: Sequence[str],
    change: Change,
    policy: PathPolicy,
    *,
    require_secure: bool,
    node_remover: NodeRemover,
    guards_reader: GuardsReader,
) -> list[CertificateOutcome]:
    registry_path = policy.certificate_registry
    assert registry_path is not None  # noqa: S101
    runtime = _load(policy, require_secure)
    try:
        guards = guards_reader(runtime, certificate_ids)
    except DeleteError as exc:
        raise RetargetError(exc.code, str(exc), exit_code=exc.exit_code) from exc
    outcomes: list[CertificateOutcome] = []
    for certificate_id in certificate_ids:
        runtime = _load(policy, require_secure)
        found = _entry_or_refusal(certificate_id, runtime)
        if isinstance(found, CertificateOutcome):
            outcomes.append(found)
            continue
        before_clusters, before_receivers = found
        dropped_clusters = tuple(c for c in before_clusters if c in change.clusters)
        dropped_receivers = tuple(r for r in before_receivers if r in change.receivers)
        if not dropped_clusters and not dropped_receivers:
            outcomes.append(CertificateOutcome(certificate_id, "unchanged"))
            continue
        reason = removal_refusal(certificate_id, dropped_clusters, runtime, guards)
        if reason is not None:
            outcomes.append(CertificateOutcome(certificate_id, "refused", reason[1], reason[0]))
            continue
        try:
            written = cert_registry.set_targets(
                registry_path,
                certificate_id=certificate_id,
                clusters=tuple(c for c in before_clusters if c not in change.clusters),
                receivers=tuple(r for r in before_receivers if r not in change.receivers),
                runtime=runtime,
                require_secure=require_secure,
            )
        except cert_registry.RegistryError as exc:
            outcomes.append(CertificateOutcome(certificate_id, "refused", str(exc), exc.code))
            continue
        layers = _clear_receivers(certificate_id, dropped_receivers, runtime)
        #
        # Each cluster has its own copy (B358): the one in a cluster it is
        # taken off is a key pair no entry gives that cluster, in a directory
        # that cluster's nodes may read - the deletion removes it, and so does
        # this (review 2026-09-17, finding 5).
        #
        entry = runtime.registry.certificates.get(certificate_id) if runtime.registry else None
        authority = entry is not None and entry.source.kind == AUTHORITY
        for dropped in dropped_clusters:
            directory = policy.certificate_directory(dropped)
            if directory is None:
                continue
            copy = (
                authority_path(directory, certificate_id)
                if authority
                else certificate_path(directory, certificate_id)
            )
            layers += (_unlink(copy),)
        clusters = [runtime.clusters[c] for c in dropped_clusters if c in runtime.clusters]
        nodes = remove_node_copies(
            clusters,
            certificate_id,
            policy.cert_deploy_identity,
            node_remover,
            verb=AUTHORITY_NODE_VERB if authority else NODE_VERB,
        )
        complete = all(layer.state != "failed" for layer in layers) and all(
            copy.state in {"removed", "absent"} for copy in nodes
        )
        outcomes.append(
            CertificateOutcome(
                certificate_id,
                "changed" if complete else "incomplete",
                "" if complete else "a copy was kept; see the rows, and run the removal again",
                "",
                abandoned=written.abandoned,
                layers=layers,
                nodes=nodes,
            )
        )
    return outcomes
