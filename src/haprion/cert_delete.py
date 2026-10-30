"""Removing certificates: the one operation in the project that deletes key material.

Everything else here publishes, copies or reports, and the helpers say so in
their headers - a deletion can erase a certificate a cluster is serving. B139
keeps that rule as the guards below and adds the operation anyway, because a
registry that only ever grows is not caution: the maintainer's real case is
hundreds of certificates that expired or stopped mattering years ago, and for
those the missing path is what makes the registry unusable.

What a deletion is
------------------
Four layers, in this order, for each certificate in the request:

1. the material - the cluster PEM under the certificate root and the two
   files in every receiver directory the entry named;
2. the certbot lineage - otherwise a dead certificate renews forever - or the
   import store for an imported one;
3. the registry entry - the certificate stops being published. Only once the
   two layers above are gone: an entry that outlives its material is a
   certificate the next run can finish, an entry that is gone before its
   material is one nothing can find again;
4. the copy on every node of every cluster the entry named, through the same
   trigger identity that pulls certificates there.

The whole run holds the publisher's lock (`cert_publish.publish_lock`), like
issue, publish and target do. The renewal timer publishes outside the job
queue, and a renewal that ran between these layers would put the material
of a still-registered certificate back - correctly, from its side - and
leave the node copies of a deleted one behind. Under the lock the layers
are one step as far as the publisher is concerned.

Every layer is idempotent, and the run is meant to be repeated: a layer that
fails is reported on the certificate's row and the entry stays, so the same
selection deleted again picks up where it stopped. A certificate that is no
longer registered is still looked for by name - its PEM, its lineage, its
import directory and the copy on every node - so the one layer that may
lawfully be left behind, a node that did not know the verb or was
unreachable, is cleaned by asking again.

The guards are the operation, not a warning
-------------------------------------------
A certificate is refused, before any of its layers is touched, when:

* a proxy object in a cluster's committed configuration names it - HEAD of
  the cluster repository, read the way the release is derived;
* it is a cluster's `default_certificate`;
* removing it would leave a cluster with no certificate at all - the engine
  refuses to load such a configuration, for every command;
* another registry entry names the same certbot lineage - the lineage is
  not the entry's alone to remove;
* it is not in the registry and nothing of it remains anywhere.

A refused certificate stops nothing else in the batch; it is reported on its
row and the others go through. Drafts are the interface's to check: they live
in its database, which this module cannot see, and the confirmation page and
the worker both refuse a draft-referenced certificate before it is queued.

What is not deleted
-------------------
A node's copy is asked for, not assumed. A node whose trigger does not know
the verb yet answers with an error and the copy is reported as kept, by node,
so an installation can run this before its nodes are updated. The file is
inert there - bind lines name certificates through crt-lists, and a PEM
nothing lists is never loaded.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from haprion import cert_registry, exit_codes, labels, node_ssh
from haprion.cert_inventory import IMPORT_STORE, receiver_files_in_any_format
from haprion.cert_publish import DEFAULT_LOCK_PATH, prune_receiver_directory, publish_lock
from haprion.cert_publish import PublishError as LockError
from haprion.certificates import authority_path, certificate_path
from haprion.config import (
    AUTHORITY,
    CERTIFICATE_ID,
    Cluster,
    ConfigError,
    DeployIdentity,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)
from haprion.git_command import GitError
from haprion.managed_publish import managed_proxies
from haprion.ndes_state import record_path, remove_request
from haprion.proxy_model import ModelError
from haprion.repo_snapshot import PublishError, read_tree_files, resolve_head

OPERATION = "cert_delete"
HELPER = "/opt/haprion/current/bin/haprion-cert-delete-helper"
SUDO = "/usr/bin/sudo"

#
# The verb the node's trigger wrapper is asked for, followed by one ID. It
# lands in SSH_ORIGINAL_COMMAND and is validated on the node before anything
# escalates; a node without the verb refuses it, which is a reported outcome
# here and not an error.
#
NODE_VERB = "cert-remove"
#
# The same for an authority's copy (B276), which the node keeps in a
# directory of its own and reports back in the same words.
#
AUTHORITY_NODE_VERB = "ca-remove"
#
# The node script (`install/node/haprion-cert-remove`) logs one line per
# certificate it removed, in this form. A copy the node never had answers with
# exit 0 as well, and only this line tells the two apart - `absent` is what a
# repeated run sees on every node. The wording is part of the node contract:
# changing it there without changing it here turns every removal into an
# `absent`.
#
NODE_REMOVED_LINE = "Removed {certificate_id}."
#
# A certificate that is nowhere: not registered, and nothing of it left.
#
NOT_REGISTERED = "not_registered"
CERTBOT_TIMEOUT = 120


class DeleteError(Exception):
    """The installation cannot answer the request at all - not one certificate's fault."""

    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.CONFIG):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Layer:
    """One of the four layers, as it ended for one certificate."""

    name: str
    state: str
    """`removed`, `kept` or `failed`; `absent` where there was nothing to remove."""

    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"layer": self.name, "state": self.state}
        if self.detail:
            entry["detail"] = self.detail
        return entry


@dataclass(frozen=True, slots=True)
class NodeCopy:
    cluster: str
    node: str
    state: str
    """`removed`, `absent` (the node had no copy), `kept` (the node refused or does not
    know the verb) or `unreachable`."""

    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"cluster": self.cluster, "node": self.node, "state": self.state}
        if self.detail:
            entry["detail"] = self.detail
        return entry


@dataclass(frozen=True, slots=True)
class CertificateOutcome:
    certificate_id: str
    state: str
    """`removed` (every layer gone), `refused` (a guard held, nothing touched) or
    `incomplete` (a layer stayed; the row says which, and the run can be repeated)."""

    reason: str = ""
    code: str = ""
    layers: tuple[Layer, ...] = ()
    nodes: tuple[NodeCopy, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"certificate": self.certificate_id, "state": self.state}
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
    outcomes: tuple[CertificateOutcome, ...]

    @property
    def removed(self) -> tuple[str, ...]:
        return tuple(o.certificate_id for o in self.outcomes if o.state == "removed")

    @property
    def refused(self) -> tuple[str, ...]:
        return tuple(o.certificate_id for o in self.outcomes if o.state == "refused")

    @property
    def gone(self) -> tuple[str, ...]:
        """Removed now, or refused only because nothing was left anywhere to remove.

        A deletion asked for again finds nothing and is done: the command said
        so with exit 0 while its helper answered `blocked`, so the interface
        and the terminal told one deletion two ways (review 2026-10-22, 4-1).
        """

        return tuple(
            o.certificate_id
            for o in self.outcomes
            if o.state == "removed" or (o.state == "refused" and o.code == NOT_REGISTERED)
        )

    @property
    def incomplete(self) -> tuple[str, ...]:
        return tuple(o.certificate_id for o in self.outcomes if o.state == "incomplete")

    @property
    def touched(self) -> tuple[str, ...]:
        """Certificates that lost at least one layer, complete or not."""

        return tuple(
            o.certificate_id
            for o in self.outcomes
            if any(layer.state == "removed" for layer in o.layers)
            or any(copy.state == "removed" for copy in o.nodes)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "certificates": [outcome.as_dict() for outcome in self.outcomes],
            "removed": list(self.removed),
            "refused": list(self.refused),
            "incomplete": list(self.incomplete),
        }


#
# Injection points, so the module is testable without certbot, ssh or root.
# `LineageRemover` runs certbot; `NodeRemover` asks one node. Both return
# (exit code, output) and never raise for a failed command.
#
LineageRemover = Callable[[Sequence[str]], tuple[int, str]]
#
# (identity, management host, verb, certificate ID) -> (exit code, output).
#
NodeRemover = Callable[[DeployIdentity, str, str, str], tuple[int, str]]
GuardsReader = Callable[[RuntimeConfig, Sequence[str]], "Guards"]


@dataclass(frozen=True, slots=True)
class Guards:
    """What each cluster's committed configuration and cluster file say."""

    referenced: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """certificate ID -> the objects (as cluster/object) whose listener names it."""

    defaults: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """certificate ID -> the clusters whose `default_certificate` it is."""


def read_guards(runtime: RuntimeConfig, certificate_ids: Sequence[str]) -> Guards:
    """Read every cluster's committed objects once, for the whole batch.

    Every cluster, not only the ones the registry says a certificate goes to:
    an object that names a certificate the registry no longer targets at its
    cluster is a configuration that would fail to render, and it is exactly the
    kind of thing a deletion should refuse to make worse.
    """

    wanted = set(certificate_ids)
    referenced: dict[str, list[str]] = {}
    defaults: dict[str, list[str]] = {}
    for cluster_id, cluster in sorted(runtime.clusters.items()):
        if cluster.default_certificate in wanted:
            defaults.setdefault(cluster.default_certificate, []).append(cluster_id)
        try:
            _branch, head = resolve_head(cluster.config_path)
            files = read_tree_files(cluster.config_path, head)
            proxies = managed_proxies(files)
        except (ConfigError, GitError, PublishError, ModelError, OSError) as exc:
            raise DeleteError(
                "dependency_unavailable",
                f"cannot read the committed objects of cluster {cluster_id!r}: {exc}",
            ) from exc
        for proxy in proxies:
            named = {proxy.listen.certificate}
            #
            # A pool verifying against an authority names it too (B276).
            #
            named.update(
                backend.tls.ca
                for backend in proxy.backends.values()
                if backend.tls is not None and backend.tls.ca is not None
            )
            for certificate in sorted(name for name in named if name in wanted):
                referenced.setdefault(certificate, []).append(f"{cluster_id}/{proxy.name}")
    return Guards(
        referenced={key: tuple(value) for key, value in referenced.items()},
        defaults={key: tuple(value) for key, value in defaults.items()},
    )


def refusal(certificate_id: str, runtime: RuntimeConfig, guards: Guards) -> tuple[str, str] | None:
    """Why this certificate must not be deleted, or None when it may be.

    An unregistered certificate is not refused here: the sweep in `delete`
    looks for what is left of it by name and refuses only when nothing is.
    """

    registry = runtime.registry
    assert registry is not None  # noqa: S101 - the helper checks; stated for the reader
    objects = guards.referenced.get(certificate_id, ())
    if objects:
        return (
            "referenced_by_object",
            f"named by the committed {labels.noun(len(objects), 'object')} "
            + ", ".join(objects)
            + f"; change {'it' if len(objects) == 1 else 'them'} first",
        )
    entry = registry.certificates.get(certificate_id)
    if entry is None:
        return None
    if entry.interface:
        #
        # The pair nginx serves this manager's own interface with (B188).
        # Deleting its source would leave nginx serving a certificate that
        # nothing renews; a replacement takes the mark first, and the entry
        # it displaces is deleted once the new one is served.
        #
        return (
            "serves_interface",
            "this certificate serves the manager's own interface; make another certificate "
            "the interface's first",
        )
    defaults = guards.defaults.get(certificate_id, ())
    if defaults:
        return (
            "cluster_default",
            "the default certificate of " + ", ".join(defaults) + "; choose another first",
        )
    uncovered = sorted(
        cluster_id
        for cluster_id in entry.clusters
        if tuple(registry.for_cluster(cluster_id)) == (certificate_id,)
    )
    if uncovered:
        return (
            "cluster_uncovered",
            "the only certificate of " + ", ".join(uncovered) + ", and a cluster that no "
            "certificate names cannot be loaded; give it another certificate first",
        )
    #
    # The lineage and a receiver's pair are removed whole, so they have to be
    # this entry's alone. Nothing in the registry keeps two entries from
    # naming the same one - `lineage:` exists to point at an existing lineage
    # - and the deletion is where sharing would cost the other entry its
    # renewal or its published files.
    #
    others = [
        other for other_id, other in registry.certificates.items() if other_id != certificate_id
    ]
    if entry.source.kind == "acme":
        lineage = entry.source.lineage or certificate_id
        sharing = sorted(
            other.certificate_id
            for other in others
            if other.source.kind == "acme"
            and (other.source.lineage or other.certificate_id) == lineage
        )
        if sharing:
            return (
                "shared_source",
                f"its certbot lineage {lineage!r} is also the source of "
                + ", ".join(sharing)
                + "; deleting it would stop their renewal too",
            )
    return None


def _unlink(path: Path) -> Layer:
    name = str(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return Layer(name, "absent")
    except OSError as exc:
        return Layer(name, "failed", exc.strerror or str(exc))
    return Layer(name, "removed")


def remove_material(
    entry_clusters: Sequence[str],
    entry_receivers: Sequence[str],
    certificate_id: str,
    runtime: RuntimeConfig,
    policy: PathPolicy,
) -> tuple[Layer, ...]:
    """The published copies: one PEM in each cluster's directory, two files per receiver."""

    registry = runtime.registry
    assert registry is not None  # noqa: S101
    layers: list[Layer] = []
    entry = registry.certificates.get(certificate_id)
    authority = entry is not None and entry.source.kind == AUTHORITY
    for cluster_id in entry_clusters:
        directory = policy.certificate_directory(cluster_id)
        if directory is None:
            continue
        layers.append(
            _unlink(
                authority_path(directory, certificate_id)
                if authority
                else certificate_path(directory, certificate_id)
            )
        )
    for receiver_id in entry_receivers:
        receiver = registry.receivers.get(receiver_id)
        if receiver is None:
            continue
        for path in receiver_files_in_any_format(receiver, certificate_id):
            layers.append(_unlink(path))
        prune_receiver_directory(receiver, certificate_id)
    return tuple(layers)


def certbot_delete_arguments(certbot: str, lineage: str) -> tuple[str, ...]:
    """Certbot's own deletion, which removes live, archive and the renewal conf together."""

    return (certbot, "delete", "--cert-name", lineage, "--non-interactive", "--quiet")


def run_certbot(command: Sequence[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(  # noqa: S603 - binary from the policy, arguments fixed above
            list(command),
            capture_output=True,
            text=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            timeout=CERTBOT_TIMEOUT,
            check=False,
        )
    except OSError as exc:
        return 127, f"certbot could not be started: {exc}"
    except subprocess.TimeoutExpired:
        return exit_codes.TIMED_OUT, f"certbot did not finish within {CERTBOT_TIMEOUT} seconds"
    return completed.returncode, ((completed.stdout or "") + (completed.stderr or "")).strip()


def remove_source(
    kind: str,
    lineage: str,
    certificate_id: str,
    *,
    certbot: str,
    renewal_directory: Path,
    store: Path,
    run: LineageRemover,
) -> Layer:
    """Layer three: the lineage for `acme`, the import directory for `import`."""

    if kind == "acme":
        conf = renewal_directory / f"{lineage}.conf"
        if not conf.exists():
            return Layer(f"lineage {lineage}", "absent")
        code, output = run(certbot_delete_arguments(certbot, lineage))
        if code != 0:
            return Layer(f"lineage {lineage}", "failed", output[-500:] or f"certbot exit {code}")
        return Layer(f"lineage {lineage}", "removed")
    if kind in ("import", AUTHORITY):
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            return Layer("import store", "failed", "invalid certificate ID")
        directory = store / certificate_id
        #
        # A swap that died between its two moves leaves the registered material
        # as `.<id>.replaced`; it holds the private key and goes with the rest.
        #
        leftover = store / f".{certificate_id}.replaced"
        removed = False
        try:
            for path in (directory, leftover):
                if path.is_dir():
                    shutil.rmtree(path)
                    removed = True
        except OSError as exc:
            return Layer(f"import {directory}", "failed", exc.strerror or str(exc))
        return Layer(f"import {directory}", "removed" if removed else "absent")
    return Layer(f"source {kind}", "kept", "unknown source kind; nothing removed")


def remove_request_state(policy: PathPolicy, certificate_id: str) -> Layer | None:
    """The NDES request directory and the renewal record, when the policy has an NDES block.

    A request the CA is still holding has a key and its targets there and
    nothing in the registry; a deletion that left it would leave the ID
    unusable and the profile unremovable (review 2026-09-17, finding 2).
    None where the installation has no NDES - not a layer that is absent,
    but a layer that does not exist.
    """

    if policy.ndes is None:
        return None
    name = f"NDES request {certificate_id}"
    try:
        removed = remove_request(policy.ndes.state_root, certificate_id)
        #
        # The renewal pass's record about the certificate goes too: left, a
        # new certificate under the same ID was read with the old one's
        # failure (review 2026-10-29, round 2, BBB01).
        #
        record = record_path(policy.ndes.state_root, certificate_id)
        if record.is_file() or record.is_symlink():
            record.unlink()
            removed = True
    except OSError as exc:
        return Layer(name, "failed", exc.strerror or str(exc))
    return Layer(name, "removed" if removed else "absent")


#
# A removal on a node is one `rm` behind two checks; a node that has not
# answered in two minutes is not going to. Without a limit a node that hung
# held this root helper - and the certificate lock - for as long as the TCP
# session lived (code review 2026-10-22, 4-5).
#
NODE_TIMEOUT_SECONDS = 120


def ask_node(
    identity: DeployIdentity, mgmt_host: str, verb: str, certificate_id: str
) -> tuple[int, str]:
    """The same call `cert-deploy` makes, with a different verb.

    A node that runs out of time keeps its copy, as a refusal does: it is
    reported and asked again on the next run.
    """

    argv = node_ssh.ssh_argv(identity.key, identity.user, mgmt_host, f"{verb} {certificate_id}")
    try:
        completed = node_ssh.run_bounded(argv, timeout=NODE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return exit_codes.TIMED_OUT, f"no answer within {NODE_TIMEOUT_SECONDS} seconds"
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode, output


def remove_node_copies(
    clusters: Sequence[Cluster],
    certificate_id: str,
    identity: DeployIdentity | None,
    ask: NodeRemover,
    *,
    verb: str = NODE_VERB,
) -> tuple[NodeCopy, ...]:
    """Layer four, node by node. A refusal is a kept copy, reported and asked again next run."""

    copies: list[NodeCopy] = []
    for cluster in clusters:
        for node in cluster.nodes:
            if identity is None:
                copies.append(
                    NodeCopy(
                        cluster.cluster_id, node.name, "kept", "no certificate deploy identity"
                    )
                )
                continue
            code, output = ask(identity, node.mgmt_host, verb, certificate_id)
            if code == 0:
                had_copy = NODE_REMOVED_LINE.format(certificate_id=certificate_id) in output
                copies.append(
                    NodeCopy(cluster.cluster_id, node.name, "removed" if had_copy else "absent")
                )
            elif code == 255:
                copies.append(NodeCopy(cluster.cluster_id, node.name, "unreachable", output[-300:]))
            else:
                copies.append(NodeCopy(cluster.cluster_id, node.name, "kept", output[-300:]))
    return tuple(copies)


def delete(
    certificate_ids: Sequence[str],
    policy: PathPolicy,
    *,
    require_secure: bool = True,
    renewal_directory: Path = Path("/etc/letsencrypt/renewal"),
    store: Path = IMPORT_STORE,
    certbot: str,
    lock_path: Path = DEFAULT_LOCK_PATH,
    lineage_remover: LineageRemover = run_certbot,
    node_remover: NodeRemover = ask_node,
    guards_reader: GuardsReader = read_guards,
) -> Report:
    """Delete each certificate through its four layers, guarding each first.

    The registry is re-read before every certificate rather than patched in
    memory, so the coverage guard for the second certificate sees the first
    one gone: two certificates that between them cover a cluster are refused
    on the second, not silently on neither.
    """

    if policy.certificate_registry is None:
        raise DeleteError(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
        )
    try:
        with publish_lock(lock_path):
            return _delete_locked(
                certificate_ids,
                policy,
                require_secure=require_secure,
                renewal_directory=renewal_directory,
                store=store,
                certbot=certbot,
                lineage_remover=lineage_remover,
                node_remover=node_remover,
                guards_reader=guards_reader,
            )
    except LockError as exc:
        raise DeleteError(exc.code, str(exc), exit_code=exit_codes.REFUSED) from exc


def retire_displaced_interface(
    displaced: str | None,
    *,
    served: bool,
    policy: PathPolicy,
    certbot: str,
    require_secure: bool = True,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    lineage_remover: LineageRemover = run_certbot,
    node_remover: NodeRemover = ask_node,
    guards_reader: GuardsReader = read_guards,
) -> dict[str, Any] | None:
    """D5: the entry the interface was served from before, deleted once the new one serves.

    Only after: when the new certificate is not yet what nginx serves - the
    install was refused, or the service could not be reached - the previous
    entry stays, unmarked, visible in the listing as a certificate with no
    target, and the answer says so. The deletion is the ordinary one, guards
    and all.
    """

    if displaced is None:
        return None
    if not served:
        return {
            "id": displaced,
            "state": "kept",
            "reason": "the new interface certificate is not served yet; the previous one is "
            "kept, without the mark",
        }
    try:
        report = delete(
            [displaced],
            policy,
            require_secure=require_secure,
            store=store,
            certbot=certbot,
            lock_path=lock_path,
            lineage_remover=lineage_remover,
            node_remover=node_remover,
            guards_reader=guards_reader,
        )
    except DeleteError as exc:
        return {"id": displaced, "state": "incomplete", "reason": str(exc)}
    outcome = report.outcomes[0]
    return {"id": displaced, "state": outcome.state, "reason": outcome.reason}


def _delete_locked(
    certificate_ids: Sequence[str],
    policy: PathPolicy,
    *,
    require_secure: bool,
    renewal_directory: Path,
    store: Path,
    certbot: str,
    lineage_remover: LineageRemover,
    node_remover: NodeRemover,
    guards_reader: GuardsReader,
) -> Report:
    registry_path = policy.certificate_registry
    assert registry_path is not None  # noqa: S101 - `delete` refused before taking the lock
    try:
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        raise DeleteError("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc
    guards = guards_reader(runtime, certificate_ids)

    outcomes: list[CertificateOutcome] = []
    for certificate_id in certificate_ids:
        reason = refusal(certificate_id, runtime, guards)
        if reason is not None:
            outcomes.append(CertificateOutcome(certificate_id, "refused", reason[1], reason[0]))
            continue
        registry = runtime.registry
        assert registry is not None  # noqa: S101
        entry = registry.certificates.get(certificate_id)
        if entry is None:
            outcomes.append(
                _sweep(
                    certificate_id,
                    runtime,
                    policy,
                    renewal_directory=renewal_directory,
                    store=store,
                    certbot=certbot,
                    lineage_remover=lineage_remover,
                    node_remover=node_remover,
                )
            )
            continue

        layers: list[Layer] = list(
            remove_material(entry.clusters, entry.receivers, certificate_id, runtime, policy)
        )
        layers.append(
            remove_source(
                entry.source.kind,
                entry.source.lineage or certificate_id,
                certificate_id,
                certbot=certbot,
                renewal_directory=renewal_directory,
                store=store,
                run=lineage_remover,
            )
        )
        request_layer = remove_request_state(policy, certificate_id)
        if request_layer is not None:
            layers.append(request_layer)

        #
        # Layer three, only once nothing above it stayed. `cert_registry.write`
        # re-checks coverage before the rename; a refusal there is the same
        # guard as above seen by the writer, and the entry stays with it.
        #
        if all(layer.state in {"removed", "absent"} for layer in layers):
            try:
                document = cert_registry.read_document(registry_path)
                remaining = {
                    key: value
                    for key, value in (document.get("certificates") or {}).items()
                    if key != certificate_id
                }
                cert_registry.write(
                    registry_path,
                    document=document,
                    certificates=remaining,
                    runtime=runtime,
                    require_secure=require_secure,
                )
            except cert_registry.RegistryError as exc:
                layers.append(Layer("registry", "kept", f"{exc.code}: {exc}"))
            else:
                layers.append(Layer("registry", "removed"))
        else:
            layers.append(
                Layer("registry", "kept", "material or source remains; run the deletion again")
            )

        clusters = [runtime.clusters[c] for c in entry.clusters if c in runtime.clusters]
        nodes = remove_node_copies(
            clusters,
            certificate_id,
            policy.cert_deploy_identity,
            node_remover,
            verb=AUTHORITY_NODE_VERB if entry.source.kind == AUTHORITY else NODE_VERB,
        )
        outcomes.append(_outcome(certificate_id, tuple(layers), nodes))
        #
        # The next certificate's guards must see this one gone.
        #
        try:
            runtime = load_runtime_config(policy, require_secure=require_secure)
        except ConfigError as exc:
            raise DeleteError("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc
    return Report(tuple(outcomes))


def _outcome(
    certificate_id: str, layers: tuple[Layer, ...], nodes: tuple[NodeCopy, ...]
) -> CertificateOutcome:
    complete = all(layer.state in {"removed", "absent"} for layer in layers) and all(
        copy.state in {"removed", "absent"} for copy in nodes
    )
    return CertificateOutcome(
        certificate_id,
        "removed" if complete else "incomplete",
        "" if complete else "some layers were kept; see the rows, and run the deletion again",
        "",
        layers,
        nodes,
    )


def _sweep(
    certificate_id: str,
    runtime: RuntimeConfig,
    policy: PathPolicy,
    *,
    renewal_directory: Path,
    store: Path,
    certbot: str,
    lineage_remover: LineageRemover,
    node_remover: NodeRemover,
) -> CertificateOutcome:
    """A certificate the registry no longer names: what is left of it, by name.

    The registry entry is the one layer that says where a certificate went,
    so without it the search is by ID - the PEM in each cluster's directory, a
    lineage of the same name, the import directory, and the copy on every
    node of every cluster. A receiver's pair is not named by the ID and is
    not looked for; the registry layer runs last for exactly that reason, so
    a receiver's files never outlive the entry.

    Refused as `not_registered` only when nothing was found anywhere - the
    nodes included, which had to be asked to know; a node that had nothing
    answers so, and nothing was touched.
    """

    layers: list[Layer] = []
    directories = dict.fromkeys(
        directory
        for cluster_id in runtime.clusters
        if (directory := policy.certificate_directory(cluster_id)) is not None
    )
    layers.extend(_unlink(certificate_path(directory, certificate_id)) for directory in directories)
    layers.append(
        remove_source(
            "acme",
            certificate_id,
            certificate_id,
            certbot=certbot,
            renewal_directory=renewal_directory,
            store=store,
            run=lineage_remover,
        )
    )
    layers.append(
        remove_source(
            "import",
            certificate_id,
            certificate_id,
            certbot=certbot,
            renewal_directory=renewal_directory,
            store=store,
            run=lineage_remover,
        )
    )
    request_layer = remove_request_state(policy, certificate_id)
    if request_layer is not None:
        layers.append(request_layer)
    nodes = remove_node_copies(
        [runtime.clusters[key] for key in sorted(runtime.clusters)],
        certificate_id,
        policy.cert_deploy_identity,
        node_remover,
    )
    nothing_left = all(layer.state == "absent" for layer in layers) and all(
        copy.state == "absent" for copy in nodes
    )
    if nothing_left:
        return CertificateOutcome(
            certificate_id,
            "refused",
            "not in the registry, and nothing of it remains on the manager or the nodes",
            NOT_REGISTERED,
        )
    return _outcome(certificate_id, tuple(layers), nodes)
