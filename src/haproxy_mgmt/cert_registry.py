"""Writing the certificate registry: one implementation, three callers.

The registry (B135) is a root-owned file beside `clusters.yaml` saying which
certificates exist, where each comes from, and which targets each goes to.
Reading it belongs to `config.load_registry`, which every command already uses.
This module owns the other half - changing it - and exists so that issuing a
certificate and retargeting one do not become two YAML writers that agree until
the day they do not.

What a write is here
--------------------
The whole file, rewritten. Not an edit in place: the registry is data, and a
machine writer that tried to keep a person's comments attached to the right
keys would be a second YAML implementation with a worse excuse than the first.
Comments do not survive, and the header says so in the file itself.

Every write is a temporary file with the original's owner and mode, fsynced,
loaded back through the reader every command uses, cross-checked against the
clusters that actually exist, and only then renamed over the original. The
order matters: a registry the engine would refuse is never the file on disk,
not even for the instant between two writes.

What this module will not do
----------------------------
Invent a target. A cluster has to be one `clusters.yaml` defines and a receiver
one the registry already lists, and both are checked here rather than trusted to
the caller - the privileged callers reach this from a job payload, and a target
that can be introduced by a request is a way to publish key material into a
directory nobody registered. Adding a receiver is an installation step (C7), not
an operation.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from haproxy_mgmt.config import ConfigError, RuntimeConfig, load_registry

#
# Kept here, next to the writer that stamps it, rather than in the modules that
# call it. The sentence about hand edits is true because of what this module
# does, so it belongs where that is decided.
#
HEADER = """\
# The certificate registry (B135). Maintained by haproxy-cert-issue and the
# registry helper; hand edits are kept but comments are not, since the file is
# rewritten as a whole. See INSTALLATION.md 1.4.1 for the fields.
"""


class RegistryError(Exception):
    """A registry change that was refused, with the code it is reported under.

    Carries the contract's own vocabulary rather than a bare message: every
    caller of this module answers in an envelope, and a failure that arrived as
    plain text would have its code chosen again at each call site.
    """

    def __init__(self, code: str, message: str, *, exit_code: int = 64):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def read_document(path: Path) -> dict[str, Any]:
    """The registry as raw YAML, for a caller about to change part of it.

    Deliberately not `load_registry`: this is the document that gets written
    back, so it has to keep whatever it holds - including a receiver block this
    change does not touch - rather than the typed view the engine reads from.
    """

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RegistryError(
            "dependency_unavailable", f"cannot read the registry: {exc}", exit_code=78
        ) from exc
    if not isinstance(loaded, dict):
        raise RegistryError("dependency_unavailable", "the registry is not a mapping", exit_code=78)
    return loaded


def write(
    path: Path,
    *,
    document: Mapping[str, Any],
    certificates: Mapping[str, Any],
    runtime: RuntimeConfig,
    require_secure: bool = True,
) -> None:
    """Replace the registry with `certificates`, keeping everything else.

    `document` is what `read_document` returned, so the receiver block and any
    field a later version adds travel through untouched. Only the certificate
    half is the caller's to decide.
    """

    try:
        metadata = path.stat()
    except OSError as exc:
        raise RegistryError(
            "dependency_unavailable", f"cannot read the registry: {exc}", exit_code=78
        ) from exc

    rendered = HEADER + yaml.safe_dump(
        {
            "schema_version": 1,
            "receivers": document.get("receivers") or {},
            "certificates": dict(certificates),
        },
        sort_keys=False,
        allow_unicode=True,
    )

    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchown(handle, metadata.st_uid, metadata.st_gid)
        os.fchmod(handle, metadata.st_mode & 0o777)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        candidate = load_registry(Path(temporary), require_secure=require_secure)
        for certificate in candidate.certificates.values():
            unknown = sorted(set(certificate.clusters) - set(runtime.clusters))
            if unknown:
                raise ConfigError(f"unknown cluster(s): {', '.join(unknown)}")
        #
        # The check that is not obvious from this file, and the one that cost an
        # installation in testing: `load_runtime_config` refuses a cluster that
        # no certificate names, because a cluster with no certificate has no
        # configuration to render. So a retarget that took the last certificate
        # away from a cluster would write a registry the whole engine then
        # refuses to load - every command, not just this one.
        #
        # Refused here, before the rename, and refused as the caller's mistake
        # rather than as a broken installation: the request is answerable, and
        # the answer is which cluster would have been left with nothing.
        #
        uncovered = sorted(
            cluster_id for cluster_id in runtime.clusters if not candidate.for_cluster(cluster_id)
        )
        if uncovered:
            raise RegistryError(
                "cluster_uncovered",
                f"this would leave {', '.join(uncovered)} with no certificate, and a cluster "
                "that no certificate names cannot be loaded. Give the cluster another "
                "certificate first.",
            )
        os.replace(temporary, path)
    except RegistryError:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    except (OSError, ConfigError) as exc:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise RegistryError(
            "dependency_unavailable", f"the registry could not be updated: {exc}", exit_code=78
        ) from exc


@dataclass(frozen=True, slots=True)
class TargetChange:
    """What retargeting one certificate did, in the terms the caller reports.

    `abandoned` is the half that is easy to leave out and the half an operator
    needs: a target dropped from the registry still holds the copy it was last
    published, and nothing in this project deletes certificate material. Saying
    which targets those are is what keeps "published to exactly the chosen
    targets" honest without a helper that can erase a certificate a cluster is
    currently serving.
    """

    certificate_id: str
    clusters: tuple[str, ...]
    receivers: tuple[str, ...]
    added: tuple[str, ...]
    abandoned: tuple[str, ...]
    changed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.certificate_id,
            "targets": {"clusters": list(self.clusters), "receivers": list(self.receivers)},
            "added": list(self.added),
            "abandoned": list(self.abandoned),
            "changed": self.changed,
        }


def set_targets(
    path: Path,
    *,
    certificate_id: str,
    clusters: Sequence[str],
    receivers: Sequence[str],
    runtime: RuntimeConfig,
    require_secure: bool = True,
) -> TargetChange:
    """Replace one certificate's targets with exactly these, and say what moved.

    The whole target set, not an add or a remove. An operation that took a delta
    would have to be applied to whatever the registry held at the moment it ran,
    and the page it came from was drawn from what the registry held some seconds
    earlier - so two people editing two certificates would each write their own
    view of the other's. A replacement states the intended end, and the end is
    what the publisher acts on.

    The certificate must already exist. Bringing one into being is issuing it,
    or importing it, and neither is a target change.
    """

    document = read_document(path)
    certificates = dict(document.get("certificates") or {})
    entry = certificates.get(certificate_id)
    if not isinstance(entry, dict):
        raise RegistryError(
            "unknown_certificate",
            f"certificate {certificate_id!r} is not in the registry",
        )

    registry = load_registry(path, require_secure=require_secure)
    #
    # Both target kinds are checked against what exists rather than against what
    # was asked for. A cluster comes from `clusters.yaml` and a receiver from the
    # registry's own receiver block, and neither can be brought into existence by
    # naming it here: these parameters arrive from a job payload, and a target a
    # request can invent is a way to write key material into a directory nobody
    # registered. Registering a receiver is an installation step.
    #
    unknown_clusters = sorted(set(clusters) - set(runtime.clusters))
    if unknown_clusters:
        raise RegistryError(
            "unknown_cluster",
            f"unknown cluster(s): {', '.join(unknown_clusters)}",
        )
    unknown_receivers = sorted(set(receivers) - set(registry.receivers))
    if unknown_receivers:
        raise RegistryError(
            "unknown_receiver",
            f"unknown receiver(s): {', '.join(unknown_receivers)}. Register a receiver "
            "during installation before publishing to it.",
        )

    before_clusters = tuple(entry.get("clusters") or ())
    before_receivers = tuple(entry.get("receivers") or ())
    after_clusters = tuple(sorted(set(clusters)))
    after_receivers = tuple(sorted(set(receivers)))

    updated = {"source": entry["source"]}
    if after_clusters:
        updated["clusters"] = list(after_clusters)
    if after_receivers:
        updated["receivers"] = list(after_receivers)
    certificates[certificate_id] = updated

    before = set(before_clusters) | set(before_receivers)
    after = set(after_clusters) | set(after_receivers)
    change = TargetChange(
        certificate_id=certificate_id,
        clusters=after_clusters,
        receivers=after_receivers,
        added=tuple(sorted(after - before)),
        abandoned=tuple(sorted(before - after)),
        changed=before != after,
    )
    if not change.changed:
        #
        # Nothing to write, and not written. Rewriting the file to the bytes it
        # already holds would give every no-op retarget a new mtime, which is
        # the one signal a person has for "when did the registry last change".
        #
        return change

    write(
        path,
        document=document,
        certificates=certificates,
        runtime=runtime,
        require_secure=require_secure,
    )
    return change
