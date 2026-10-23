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
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from haprion import exit_codes, safe_yaml
from haprion.cert_lock import DEFAULT_LOCK_PATH, LOCK_WAIT_SECONDS, hold
from haprion.config import (
    DEFAULT_RECEIVER_FORMAT,
    ConfigError,
    Registry,
    RuntimeConfig,
    load_registry,
)

#
# Kept here, next to the writer that stamps it, rather than in the modules that
# call it. The sentence about hand edits is true because of what this module
# does, so it belongs where that is decided.
#
HEADER = """\
# The certificate registry (B135). Maintained by haprion-cert-issue and the
# registry helper; hand edits are kept but comments are not, since the file is
# rewritten as a whole. See user-manual.md, 'The certificate registry', for the fields.
"""


class RegistryError(Exception):
    """A registry change that was refused, with the code it is reported under.

    Carries the contract's own vocabulary rather than a bare message: every
    caller of this module answers in an envelope, and a failure that arrived as
    plain text would have its code chosen again at each call site.
    """

    def __init__(self, code: str, message: str, *, exit_code: int = exit_codes.USAGE):
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
        loaded = safe_yaml.load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RegistryError(
            "dependency_unavailable",
            f"cannot read the registry: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
    if not isinstance(loaded, dict):
        raise RegistryError(
            "dependency_unavailable", "the registry is not a mapping", exit_code=exit_codes.CONFIG
        )
    return loaded


@contextmanager
def locked(path: Path = DEFAULT_LOCK_PATH, *, wait: int | None = None) -> Iterator[None]:
    """Hold the certificate lock around a read-modify-write of the registry.

    `read_document` and `write` are two calls with the caller's change between
    them, and a second writer in that gap - the renewal timer, an operator's
    command - is a lost update the loader cannot see. Every writer that is not
    already inside `cert_publish.publish_lock` takes this; it is the same lock
    on the same path, so a caller that holds one must not take the other.
    """

    with hold(
        path,
        wait=LOCK_WAIT_SECONDS if wait is None else wait,
        refuse=lambda message: RegistryError(
            "operation_locked", message, exit_code=exit_codes.BLOCKED
        ),
    ):
        yield


def render(
    document: Mapping[str, Any],
    certificates: Mapping[str, Any],
    receivers: Mapping[str, Any] | None = None,
) -> str:
    """The registry file as `write` puts it on disk, for a caller changing it with other files."""

    return HEADER + yaml.safe_dump(
        {
            "schema_version": 1,
            "receivers": (document.get("receivers") or {})
            if receivers is None
            else dict(receivers),
            "certificates": dict(certificates),
        },
        sort_keys=False,
        allow_unicode=True,
    )


def write(
    path: Path,
    *,
    document: Mapping[str, Any],
    certificates: Mapping[str, Any],
    runtime: RuntimeConfig,
    receivers: Mapping[str, Any] | None = None,
    require_secure: bool = True,
) -> None:
    """Replace the registry with `certificates`, keeping everything else.

    `document` is what `read_document` returned, so the receiver block and any
    field a later version adds travel through untouched. Only the certificate
    half is the caller's to decide - except for `haprion-cert-receiver`, root
    work with its own command, which passes `receivers` and is the only caller
    that may: a receiver that could be introduced by a job payload would be a
    directory key material lands in that nobody registered.
    """

    try:
        metadata = path.stat()
    except OSError as exc:
        raise RegistryError(
            "dependency_unavailable",
            f"cannot read the registry: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc

    rendered = render(document, certificates, receivers)

    try:
        handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    except OSError as exc:
        # Seen as a traceback once: a sandbox that opened the registry file's
        # readers but not its directory, which is where the temporary goes.
        raise RegistryError(
            "dependency_unavailable",
            f"the registry could not be updated: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc
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
        # A cluster that had certificates is not left with none by a retarget.
        # A new cluster starts without any and loads (B302), but one that has
        # served certificates has listeners that name them, and taking the last
        # away turns its next publish into a refusal nobody asked for. Refused
        # here, before the rename, as the caller's mistake: the answer is which
        # cluster would have been left with nothing.
        #
        uncovered = sorted(
            cluster_id
            for cluster_id in runtime.clusters
            if runtime.clusters[cluster_id].certificate_ids
            and not candidate.for_cluster(cluster_id)
        )
        if uncovered:
            raise RegistryError(
                "cluster_uncovered",
                f"this would leave {', '.join(uncovered)} with no certificate, and a cluster "
                "that no certificate names cannot be loaded. Give the cluster another "
                "certificate first.",
            )
        #
        # The same refusal one step further: a cluster's `default_certificate`
        # (clusters.yaml) must be one the registry gives that cluster, or the
        # loader refuses the whole configuration - `default_certificate is not
        # allowlisted` - for every command, not just this one. Seen 2026-09-19:
        # an enrollment dropped the clusters from the default certificate's
        # entry, the registry was renamed into place, and the manager was
        # blind until the file was edited by hand.
        #
        undefaulted = sorted(
            f"{cluster_id} ({cluster.default_certificate})"
            for cluster_id, cluster in runtime.clusters.items()
            if cluster.default_certificate is not None
            and cluster.default_certificate not in candidate.for_cluster(cluster_id)
        )
        if undefaulted:
            raise RegistryError(
                "default_certificate_unassigned",
                f"this would take a cluster's default certificate away from it: {', '.join(undefaulted)}. "
                "The default certificate in clusters.yaml must stay assigned to its cluster; "
                "change the default first.",
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
            "dependency_unavailable",
            f"the registry could not be updated: {exc}",
            exit_code=exit_codes.CONFIG,
        ) from exc


def claim_interface(certificates: dict[str, Any], certificate_id: str) -> str | None:
    """Mark this entry as the interface's, and take the mark from the one that had it (B188).

    Returns the entry that lost it, if another did. That entry stays in the
    registry, unmarked and with no targets, until the new certificate is
    served (D5); only then is it deleted, so a replacement nginx refused
    leaves the previous certificate where a person can see it.
    """

    displaced: str | None = None
    for other_id, other in list(certificates.items()):
        if other_id != certificate_id and isinstance(other, dict) and other.get("interface"):
            certificates[other_id] = {k: v for k, v in other.items() if k != "interface"}
            displaced = other_id
    entry = certificates[certificate_id]
    entry["interface"] = True
    return displaced


def set_receiver(
    path: Path,
    *,
    receiver_id: str,
    fields: Mapping[str, Any],
    runtime: RuntimeConfig,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> None:
    """Put one receiver into the registry, through the same checked write as the rest.

    Registration is root work with its own command (C7), and this is its last
    layer: by the time it runs, the account, the directory and the lock exist,
    so the entry names something real. The write goes through `write`, which
    loads the candidate back through the reader before renaming it into place
    - a receiver block the engine would refuse is never the file on disk.
    """

    with locked(lock_path):
        document = read_document(path)
        receivers = dict(document.get("receivers") or {})
        receivers[receiver_id] = dict(fields)
        write(
            path,
            document=document,
            certificates=document.get("certificates") or {},
            receivers=receivers,
            runtime=runtime,
            require_secure=require_secure,
        )


def drop_receiver(
    path: Path,
    *,
    receiver_id: str,
    runtime: RuntimeConfig,
    require_secure: bool = True,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> None:
    """Take one receiver out. Refused by the reader while a certificate names it."""

    with locked(lock_path):
        document = read_document(path)
        receivers = dict(document.get("receivers") or {})
        receivers.pop(receiver_id, None)
        write(
            path,
            document=document,
            certificates=document.get("certificates") or {},
            receivers=receivers,
            runtime=runtime,
            require_secure=require_secure,
        )


def receiver_in_use(registry: Registry, receiver_id: str) -> tuple[str, ...]:
    """Spärr 4 (B138): the certificates that name this receiver, in registry order.

    Asked by `haprion-cert-receiver remove`, which may not take an account,
    a directory and a key out from under a certificate that still publishes
    there. Answered here, beside the rules, rather than counted again at the
    call site.
    """

    return tuple(
        certificate.certificate_id
        for certificate in registry.certificates.values()
        if receiver_id in certificate.receivers
    )


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
    reformatted: tuple[str, ...] = ()
    """Receivers kept and written in another format than before (B159)."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.certificate_id,
            "targets": {"clusters": list(self.clusters), "receivers": list(self.receivers)},
            "added": list(self.added),
            "abandoned": list(self.abandoned),
            "reformatted": list(self.reformatted),
            "changed": self.changed,
        }


def named_receivers(entry: Mapping[str, Any]) -> tuple[tuple[str, ...], dict[str, str]]:
    """The receiver IDs in a raw entry, and the formats stated beside them.

    The raw document, not the typed registry: this is the half that gets
    written back, and an element it does not understand is an element it must
    not drop. Reading it here is what keeps a retarget from quietly turning a
    receiver's PKCS#12 bundle back into a PEM pair at the next target change.
    """

    named: list[str] = []
    formats: dict[str, str] = {}
    for item in entry.get("receivers") or ():
        if isinstance(item, Mapping):
            receiver_id = str(item.get("id"))
            stated = item.get("format")
            if isinstance(stated, str):
                formats[receiver_id] = stated
        else:
            receiver_id = str(item)
        named.append(receiver_id)
    return tuple(named), formats


def receiver_elements(
    receivers: Sequence[str], formats: Mapping[str, str]
) -> list[str | dict[str, str]]:
    """The receiver list as it is written back: a bare ID unless a format is stated."""

    elements: list[str | dict[str, str]] = []
    for receiver_id in receivers:
        form = formats.get(receiver_id, DEFAULT_RECEIVER_FORMAT)
        if form == DEFAULT_RECEIVER_FORMAT:
            elements.append(receiver_id)
        else:
            elements.append({"id": receiver_id, "format": form})
    return elements


def set_targets(
    path: Path,
    *,
    certificate_id: str,
    clusters: Sequence[str],
    receivers: Sequence[str],
    runtime: RuntimeConfig,
    formats: Mapping[str, str] | None = None,
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
    if registry.certificates[certificate_id].interface:
        #
        # The entry is the interface's own certificate (B188). It has no
        # targets to replace, and the rewrite below keeps only `source` and the
        # target lists - it would drop the flag and leave nginx's certificate
        # looking like an ordinary one with nowhere to go.
        #
        raise RegistryError(
            "bad_input",
            f"{certificate_id} is the interface certificate and has no targets",
        )
    if registry.certificates[certificate_id].exportable:
        #
        # Exportable (B255): its key may be taken out of the interface, so it
        # is never given a target - a certificate a cluster or a receiver
        # carries must be one whose key nobody can download.
        #
        raise RegistryError(
            "bad_input",
            f"{certificate_id} is exportable and has no targets; issue another certificate "
            "for a cluster or a receiver",
        )
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
    before_receivers, before_formats = named_receivers(entry)
    after_clusters = tuple(sorted(set(clusters)))
    after_receivers = tuple(sorted(set(receivers)))
    #
    # A format the caller did not mention is the format the pair already had.
    # The interface changes which targets a certificate has far more often
    # than it changes how one of them is written, and a caller that had to
    # restate every format to move an unrelated target would lose one the day
    # it forgot.
    #
    after_formats = {
        receiver_id: (formats or {}).get(receiver_id, before_formats.get(receiver_id))
        for receiver_id in after_receivers
    }

    updated: dict[str, Any] = {"source": entry["source"]}
    if after_clusters:
        updated["clusters"] = list(after_clusters)
    if after_receivers:
        updated["receivers"] = receiver_elements(
            after_receivers,
            {k: v for k, v in after_formats.items() if v is not None},
        )
    certificates[certificate_id] = updated

    before = set(before_clusters) | set(before_receivers)
    after = set(after_clusters) | set(after_receivers)
    #
    # A kept receiver whose format changed is a change too: the publisher
    # writes a different file for it, and a retarget that only compared the
    # names would have recorded the new format and never written it.
    #
    reformatted = tuple(
        receiver_id
        for receiver_id in after_receivers
        if receiver_id in before
        and (after_formats.get(receiver_id) or DEFAULT_RECEIVER_FORMAT)
        != (before_formats.get(receiver_id) or DEFAULT_RECEIVER_FORMAT)
    )
    change = TargetChange(
        certificate_id=certificate_id,
        clusters=after_clusters,
        receivers=after_receivers,
        added=tuple(sorted(after - before)),
        abandoned=tuple(sorted(before - after)),
        reformatted=reformatted,
        changed=before != after or bool(reformatted),
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
