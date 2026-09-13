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

1. the registry entry - the certificate stops being published;
2. the material - the cluster PEM under the certificate root and the two
   files in every receiver directory the entry named;
3. the certbot lineage - otherwise a dead certificate renews forever - or the
   import store for an imported one;
4. the copy on every node of every cluster the entry named, through the same
   trigger identity that pulls certificates there.

The order is the safe one. Once the registry no longer names a certificate,
the next renewal hook cannot put the material back, so a step that fails
after the first leaves something to clean up by hand, never something that
comes back. Each layer's outcome is reported on the certificate's own row.

The guards are the operation, not a warning
-------------------------------------------
A certificate is refused, before any of its layers is touched, when:

* a proxy object in a cluster's committed configuration names it - HEAD of
  the cluster repository, read the way the release is derived;
* it is a cluster's `default_certificate`;
* removing it would leave a cluster with no certificate at all - the engine
  refuses to load such a configuration, for every command;
* it is not in the registry.

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

from haproxy_mgmt import cert_registry
from haproxy_mgmt.cert_inventory import FULLCHAIN, IMPORT_STORE, PRIVKEY
from haproxy_mgmt.certificates import certificate_path
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    Cluster,
    ConfigError,
    DeployIdentity,
    PathPolicy,
    RuntimeConfig,
    load_runtime_config,
)
from haproxy_mgmt.git_command import GitError
from haproxy_mgmt.managed_publish import managed_proxies
from haproxy_mgmt.proxy_model import ModelError
from haproxy_mgmt.repo_snapshot import PublishError, read_tree_files, resolve_head

OPERATION = "cert_delete"
HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-delete-helper"
SUDO = "/usr/bin/sudo"

#
# The verb the node's trigger wrapper is asked for, followed by one ID. It
# lands in SSH_ORIGINAL_COMMAND and is validated on the node before anything
# escalates; a node without the verb refuses it, which is a reported outcome
# here and not an error.
#
NODE_VERB = "cert-remove"
CERTBOT_TIMEOUT = 120


class DeleteError(Exception):
    """The installation cannot answer the request at all - not one certificate's fault."""

    def __init__(self, code: str, message: str, *, exit_code: int = 78):
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
    """`removed`, `kept` (the node refused or does not know the verb) or `unreachable`."""

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
    `incomplete` (the registry entry is gone and a later layer is not)."""

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
    def incomplete(self) -> tuple[str, ...]:
        return tuple(o.certificate_id for o in self.outcomes if o.state == "incomplete")

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
NodeRemover = Callable[[DeployIdentity, str, str], tuple[int, str]]
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
            certificate = proxy.listen.certificate
            if certificate in wanted:
                referenced.setdefault(certificate, []).append(f"{cluster_id}/{proxy.name}")
    return Guards(
        referenced={key: tuple(value) for key, value in referenced.items()},
        defaults={key: tuple(value) for key, value in defaults.items()},
    )


def refusal(certificate_id: str, runtime: RuntimeConfig, guards: Guards) -> tuple[str, str] | None:
    """Why this certificate must not be deleted, or None when it may be."""

    registry = runtime.registry
    assert registry is not None  # noqa: S101 - the helper checks; stated for the reader
    entry = registry.certificates.get(certificate_id)
    if entry is None:
        return ("not_registered", "not in the registry")
    objects = guards.referenced.get(certificate_id, ())
    if objects:
        return (
            "referenced_by_object",
            "named by the committed object(s) " + ", ".join(objects) + "; change them first",
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
    """The published copies: one cluster PEM, two files per receiver."""

    registry = runtime.registry
    assert registry is not None  # noqa: S101
    layers: list[Layer] = []
    if entry_clusters and policy.certificate_root is not None:
        layers.append(_unlink(certificate_path(policy.certificate_root, certificate_id)))
    for receiver_id in entry_receivers:
        receiver = registry.receivers.get(receiver_id)
        if receiver is None:
            continue
        layers.append(_unlink(receiver.path / FULLCHAIN))
        layers.append(_unlink(receiver.path / PRIVKEY))
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
        return 124, f"certbot did not finish within {CERTBOT_TIMEOUT} seconds"
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
    if kind == "import":
        if not CERTIFICATE_ID.fullmatch(certificate_id):
            return Layer("import store", "failed", "invalid certificate ID")
        directory = store / certificate_id
        if not directory.is_dir():
            return Layer(f"import {directory}", "absent")
        try:
            shutil.rmtree(directory)
        except OSError as exc:
            return Layer(f"import {directory}", "failed", exc.strerror or str(exc))
        return Layer(f"import {directory}", "removed")
    return Layer(f"source {kind}", "kept", "unknown source kind; nothing removed")


def ask_node(identity: DeployIdentity, mgmt_host: str, certificate_id: str) -> tuple[int, str]:
    """The same call `cert-deploy` makes, with a different verb."""

    from haproxy_mgmt.cli.deploy_helper import SSH, SSH_ENVIRONMENT, SSH_OPTIONS

    completed = subprocess.run(  # noqa: S603 - fixed path, host and ID from validated configuration
        [
            SSH,
            *SSH_OPTIONS,
            "-i",
            str(identity.key),
            f"{identity.user}@{mgmt_host}",
            f"{NODE_VERB} {certificate_id}",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=SSH_ENVIRONMENT,
    )
    output = ((completed.stdout or "") + (completed.stderr or "")).strip()
    return completed.returncode, output


def remove_node_copies(
    clusters: Sequence[Cluster],
    certificate_id: str,
    identity: DeployIdentity | None,
    ask: NodeRemover,
) -> tuple[NodeCopy, ...]:
    """Layer four, node by node. A refusal is a kept copy, reported and not retried."""

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
            code, output = ask(identity, node.mgmt_host, certificate_id)
            if code == 0:
                copies.append(NodeCopy(cluster.cluster_id, node.name, "removed"))
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
    certbot: str = "/usr/bin/certbot",
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
        entry = registry.certificates[certificate_id]

        #
        # Layer one. `cert_registry.write` re-checks coverage before the
        # rename; a refusal there is the same guard as above seen by the
        # writer, and is reported the same way.
        #
        try:
            document = cert_registry.read_document(policy.certificate_registry)
            remaining = {
                key: value
                for key, value in (document.get("certificates") or {}).items()
                if key != certificate_id
            }
            cert_registry.write(
                policy.certificate_registry,
                document=document,
                certificates=remaining,
                runtime=runtime,
                require_secure=require_secure,
            )
        except cert_registry.RegistryError as exc:
            outcomes.append(CertificateOutcome(certificate_id, "refused", str(exc), exc.code))
            continue
        layers: list[Layer] = [Layer("registry", "removed")]

        layers.extend(
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
        clusters = [runtime.clusters[c] for c in entry.clusters if c in runtime.clusters]
        nodes = remove_node_copies(
            clusters, certificate_id, policy.cert_deploy_identity, node_remover
        )

        complete = all(layer.state in {"removed", "absent"} for layer in layers) and all(
            copy.state == "removed" for copy in nodes
        )
        outcomes.append(
            CertificateOutcome(
                certificate_id,
                "removed" if complete else "incomplete",
                "" if complete else "some layers were kept; see the rows",
                "",
                tuple(layers),
                nodes,
            )
        )
        #
        # The next certificate's guards must see this one gone.
        #
        try:
            runtime = load_runtime_config(policy, require_secure=require_secure)
        except ConfigError as exc:
            raise DeleteError("dependency_unavailable", str(exc), exit_code=exc.exit_code) from exc
    return Report(tuple(outcomes))
