"""Turning a queued job into the exact command that performs it.

The interface never builds a request envelope of its own. Each write operation's
envelope is built by the engine module that owns it - the same function the
command line calls - because the helper validates the envelope strictly and two
constructions of one request drift apart in ways that look correct on both
sides. This module is the lookup and the payload check, and nothing else.

The payload check is an allowlist. A job's payload arrives from a form and has
been sitting in a table since; by the time a worker reads it, the only honest
assumption is that it may say anything. A key nobody expected is refused rather
than ignored, because ignoring it silently performs a different operation from
the one that was asked for.
"""

from __future__ import annotations

import base64
import binascii
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from haproxy_mgmt import (
    backup_schedule_write,
    cert_request_state,
    cert_upload,
    dns_profiles,
    ndes_profiles,
)
from haproxy_mgmt.cli import (
    backup_job_ask,
    backup_job_helper,
    cert_delete_helper,
    cert_deploy,
    cert_issue_helper,
    cert_publish_helper,
    cert_receiver_ask,
    cert_receiver_helper,
    cert_request_helper,
    cert_scep_helper,
    cert_target_helper,
    deploy,
    managed_network_publish,
    managed_objects_publish,
    node_restore_ask,
    node_restore_helper,
    revert,
)
from haproxy_mgmt.config import CERTIFICATE_ID, RECEIVER_FORMATS, RECEIVER_ID, RECEIVER_TRANSPORTS
from haproxy_mgmt.proxy_model import NAME

# The installation key's identifier as `dns_profile_keys.key_id_of` makes it.
KEY_ID = re.compile(r"^[0-9a-f]{16}$")

#
# How long an operation may run before the worker stops it. Deliberately
# generous: a deploy reaches every node in the cluster over SSH, and a timeout
# that fires during normal work would turn a slow day into an `unknown` job.
#
TIMEOUT_SECONDS = 900.0

#
# `-n` because a worker has no terminal to answer a password prompt with, and
# `--` so a helper path could never be read as an option. The paths themselves
# come from the engine modules rather than being written again here.
#
SUDO_FLAGS = ("-n", "--")

#
# The receiver client runs in this service's own venv, as this account: the
# interpreter that runs the worker also has `haproxy_mgmt`, and `-m` names the
# module rather than a script whose path would have to be found. What it talks
# to is root, on the other side of a socket (B163).
#
RECEIVER_CLIENT = (sys.executable, "-m", cert_receiver_ask.__name__)
BACKUP_CLIENT = (sys.executable, "-m", backup_job_ask.__name__)
RESTORE_CLIENT = (sys.executable, "-m", node_restore_ask.__name__)


class UnknownOperation(Exception):
    """The job asks for something this worker does not know how to run."""


class BadPayload(Exception):
    """The payload is not what this operation accepts.

    Refused before anything runs. A payload that cannot be understood is not a
    reason to run the operation with defaults - the defaults are not what was
    asked for.
    """


@dataclass(frozen=True, slots=True)
class Prepared:
    """One command, ready to run: its argv and the envelope for its stdin.

    `lifeline` has to travel with the request rather than being decided by the
    runner, because the two ends must agree exactly. A caller that holds the
    pipe open for a helper that is not watching it leaves that helper blocked on
    a read for input that will never come - which is not a slow operation but a
    stopped one.
    """

    argv: tuple[str, ...]
    request: str
    lifeline: bool = False


def _flag(payload: Mapping[str, Any], name: str, *, default: bool) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise BadPayload(f"{name} must be true or false")
    return value


def _only(payload: Mapping[str, Any], *allowed: str) -> None:
    unexpected = sorted(set(payload) - set(allowed))
    if unexpected:
        raise BadPayload(f"unexpected parameters: {', '.join(unexpected)}")


def _restore(
    operation: str, cluster: str, request_id: UUID, payload: Mapping[str, Any]
) -> Prepared:
    """One of the five restore jobs, checked by the helper's own parameter check.

    The same `validate` the root helper and the command line run, so a payload
    the web built cannot pass here and be refused there, or the other way round.
    """

    _only(
        payload,
        *node_restore_helper.KEYS[operation],
        *node_restore_helper.OPTIONAL[operation],
    )
    try:
        request = node_restore_helper.build_request(
            operation, cluster, str(request_id), dict(payload)
        )
    except node_restore_helper.ParameterProblem as exc:
        raise BadPayload(str(exc)) from exc
    return Prepared(argv=RESTORE_CLIENT, request=request)


def _targets(payload: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The two target lists, checked here as well as in the helper.

    Both ends check them for the reason this module's docstring gives: a payload
    has been sitting in a table since a form built it. This end refuses with a
    sentence the page can show; the helper's own refusal would arrive as a failed
    job instead, after the operation had been queued and claimed.
    """

    lists = []
    for name in ("clusters", "receivers"):
        value = payload.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise BadPayload(f"{name} must be a list of identifiers")
        lists.append(tuple(value))
    if not lists[0] and not lists[1]:
        raise BadPayload("at least one target (cluster or receiver) is required")
    return lists[0], lists[1]


def _formats(payload: Mapping[str, Any], receivers: tuple[str, ...]) -> dict[str, str]:
    """How each chosen receiver is written (B159), checked like the targets are.

    An object beside `receivers`, `{receiver_id: "pem" | "pkcs12"}`, and only
    for receivers the payload names: a format for a receiver the request does
    not have is a request that disagrees with itself, refused here with a
    sentence rather than in the helper as a failed job.
    """

    raw = payload.get("formats")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise BadPayload("formats must be an object of receiver to format")
    checked: dict[str, str] = {}
    for receiver_id, form in raw.items():
        if receiver_id not in receivers:
            raise BadPayload(f"formats names {receiver_id!r}, which is not a chosen receiver")
        if form not in RECEIVER_FORMATS:
            raise BadPayload(f"the format for {receiver_id} must be pem or pkcs12")
        checked[str(receiver_id)] = str(form)
    return checked


CERTIFICATE_OPERATIONS = frozenset(
    {
        "cert_issue",
        "cert_publish",
        "cert_target",
        "dns_profile_apply",
        "ndes_profile_apply",
        "cert_delete",
        "cert_scep",
        "cert_receiver",
        "cert_import",
        "cert_request",
    }
)

#
# The helper takes at most this many in one request (`cert_job.MAX_TARGETS`),
# and a bulk cleanup that wants more is two jobs, which the page says.
#
MAX_DELETE_BATCH = 32


@dataclass(frozen=True, slots=True)
class SealedProfileRow:
    """What `prepare` needs from a profile row to build the apply request.

    Mirrors `db.SealedProfile` without importing it: this module knows
    operations, not the database, and the worker hands the lookup in.
    """

    id: str
    provider_id: str
    schema_version: int
    key_id: str
    revision: int
    ciphertext: bytes


ProfileLookup = Callable[[str], SealedProfileRow | None]

#
# Which of the named certificates a draft still names, as certificate ID to
# `cluster/object` rows. The web asks its own database and hands the answer
# in when it queues; the worker does not, because the worker holds no grant
# on `proxy_draft` (INSTALLATION.md: it publishes from the payload, never
# from the table) - a run-time check from the worker was tried on
# 2026-09-13 and took the whole process down with `InsufficientPrivilege`.
# So the last look at the drafts is the moment of queueing, and a draft
# written after that names a certificate that may already be gone; its
# publish then fails on a missing file, which is recoverable, where a worker
# that can read drafts is not the privilege model.
#
DraftReferences = Callable[[tuple[str, ...]], Mapping[str, tuple[str, ...]]]


def _certificate_operation(
    *,
    operation: str,
    request_id: UUID,
    payload: Mapping[str, Any],
    profile_lookup: ProfileLookup | None,
    draft_references: DraftReferences | None,
) -> Prepared:
    """The three operations scoped by certificate rather than by cluster.

    Split out so `prepare` can return here before it requires a cluster, which
    is what lets the rest of it treat one as present rather than checking for it
    in every branch.

    None of the three takes a lifeline. The worker holds stdin open for helpers
    that can be stopped at a checkpoint, and these three have no such point: a
    certbot run is one external call, and abandoning a publish halfway would
    leave a target holding a file the registry says came from a run that did not
    finish. They are short - C3 measured the whole of an issue at 21 seconds -
    so the lease outlives them.
    """

    if operation == "cert_issue":
        _only(
            payload, "domain", "method", "dns_profile", "clusters", "receivers", "formats", "renew"
        )
        domain = payload.get("domain")
        if not isinstance(domain, str) or not domain:
            raise BadPayload("domain must be a non-empty string")
        if _flag(payload, "renew", default=False):
            #
            # The round again for a lineage the registry holds (C9c): the
            # name and nothing else, because the helper reads the lineage's
            # names, challenge and targets where they already are.
            #
            _only(payload, "domain", "renew")
            if not CERTIFICATE_ID.fullmatch(domain):
                raise BadPayload("domain must be a certificate ID")
            return Prepared(
                argv=(cert_issue_helper.SUDO, *SUDO_FLAGS, cert_issue_helper.HELPER),
                request=cert_issue_helper.build_request(
                    str(request_id), domain=domain, method="", renew=True
                ),
            )
        method = payload.get("method")
        #
        # Named here rather than passed through, so an unknown method is a
        # sentence on the form rather than a certbot invocation that fails.
        # The helper checks it again against the engine's own list.
        #
        if method not in {"dns-01", "http-01"}:
            raise BadPayload("method must be dns-01 or http-01")
        dns_profile_value = payload.get("dns_profile")
        dns_profile = None
        if dns_profile_value is not None:
            try:
                dns_profile = dns_profiles.check_profile_id(dns_profile_value)
            except dns_profiles.ProfileError as exc:
                raise BadPayload(str(exc)) from exc
            if method != "dns-01":
                raise BadPayload("dns_profile belongs to dns-01 only")
        clusters, receivers = _targets(payload)
        formats = _formats(payload, receivers)
        return Prepared(
            argv=(cert_issue_helper.SUDO, *SUDO_FLAGS, cert_issue_helper.HELPER),
            request=cert_issue_helper.build_request(
                str(request_id),
                domain=domain,
                method=method,
                clusters=clusters,
                receivers=receivers,
                dns_profile=dns_profile,
                formats=formats,
            ),
        )

    if operation == "cert_scep":
        _only(payload, "id", "profile", "domains", "clusters", "receivers", "formats", "resume")
        certificate_id = payload.get("id")
        if not isinstance(certificate_id, str) or not CERTIFICATE_ID.fullmatch(certificate_id):
            raise BadPayload("id must be a certificate ID")
        resume = _flag(payload, "resume", default=False)
        #
        # A resume names the certificate and nothing else: the request's own
        # root-only record holds the profile, the names and the targets it
        # was made with, and the helper refuses a resume that disagrees.
        #
        if resume:
            _only(payload, "id", "resume")
            return Prepared(
                argv=(cert_scep_helper.SUDO, *SUDO_FLAGS, cert_scep_helper.HELPER),
                request=cert_scep_helper.build_request(
                    str(request_id),
                    certificate_id=certificate_id,
                    profile_id="",
                    domains=(),
                    resume=True,
                ),
            )
        try:
            profile_id = dns_profiles.check_profile_id(payload.get("profile"))
        except dns_profiles.ProfileError as exc:
            raise BadPayload(str(exc)) from exc
        domains = payload.get("domains")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(isinstance(name, str) and name for name in domains)
        ):
            raise BadPayload("domains must be a non-empty list of DNS names")
        if domains[0].startswith("*."):
            raise BadPayload("the first name is the CN and cannot be a wildcard")
        clusters, receivers = _targets(payload)
        formats = _formats(payload, receivers)
        return Prepared(
            argv=(cert_scep_helper.SUDO, *SUDO_FLAGS, cert_scep_helper.HELPER),
            request=cert_scep_helper.build_request(
                str(request_id),
                certificate_id=certificate_id,
                profile_id=profile_id,
                domains=tuple(domains),
                clusters=clusters,
                receivers=receivers,
                resume=resume,
                formats=formats,
            ),
        )

    if operation == "cert_import":
        #
        # The file rides sealed in the payload (B165): the web sealed it
        # against the installation's public key before the job was queued,
        # and nothing that reads the queue can open it. The ID and key ID
        # travel beside it so the helper can hold the box to the job before
        # it looks inside; a job the payload cannot name is refused here.
        #
        _only(payload, "id", "key_id", "ciphertext", "clusters", "receivers", "formats")
        certificate_id = payload.get("id")
        if not isinstance(certificate_id, str) or not CERTIFICATE_ID.fullmatch(certificate_id):
            raise BadPayload("id must be a certificate ID")
        key_id = payload.get("key_id")
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
            raise BadPayload("key_id must be a key ID")
        encoded = payload.get("ciphertext")
        if not isinstance(encoded, str) or len(encoded) > cert_upload.MAX_CIPHERTEXT * 2:
            raise BadPayload("ciphertext must be base64")
        try:
            ciphertext = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BadPayload("ciphertext must be base64") from exc
        if not ciphertext or len(ciphertext) > cert_upload.MAX_CIPHERTEXT:
            raise BadPayload("ciphertext is empty or larger than an upload can be")
        clusters, receivers = _targets(payload)
        formats = _formats(payload, receivers)
        return Prepared(
            argv=(cert_upload.SUDO, *SUDO_FLAGS, cert_upload.HELPER),
            request=cert_upload.build_request(
                str(request_id),
                certificate_id=certificate_id,
                key_id=key_id,
                ciphertext=ciphertext,
                clusters=clusters,
                receivers=receivers,
                formats=formats,
            ),
        )

    if operation == "cert_request":
        #
        # A key made on the manager and a CSR for somebody else to sign
        # (C9b): the names, the key type from the short list, the targets.
        # Nothing secret rides in the payload, and nothing secret comes
        # back - the envelope carries the CSR.
        #
        _only(payload, "id", "domains", "key_type", "clusters", "receivers", "formats")
        certificate_id = payload.get("id")
        if not isinstance(certificate_id, str) or not CERTIFICATE_ID.fullmatch(certificate_id):
            raise BadPayload("id must be a certificate ID")
        domains = payload.get("domains")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(isinstance(name, str) and name for name in domains)
        ):
            raise BadPayload("domains must be a non-empty list of DNS names")
        if domains[0].startswith("*."):
            raise BadPayload("the first name is the CN and cannot be a wildcard")
        key_type = payload.get("key_type", cert_request_state.DEFAULT_KEY_TYPE)
        if not isinstance(key_type, str) or key_type not in cert_request_state.KEY_TYPES:
            raise BadPayload("key_type must be one of the offered key types")
        clusters, receivers = _targets(payload)
        formats = _formats(payload, receivers)
        return Prepared(
            argv=(cert_request_helper.SUDO, *SUDO_FLAGS, cert_request_helper.HELPER),
            request=cert_request_helper.build_request(
                str(request_id),
                certificate_id=certificate_id,
                domains=tuple(domains),
                key_type=key_type,
                clusters=clusters,
                receivers=receivers,
                formats=formats,
            ),
        )

    if operation == "dns_profile_apply":
        #
        # The payload names the profile and the revision the person saved;
        # the box itself is read from the row at run time, never copied into
        # the queue. A row replaced between queueing and running carries a
        # higher revision, which the helper accepts (B146: never lower), so
        # the file that lands is the newest one - and a row that vanished is
        # a refusal here rather than a helper run with nothing to open.
        #
        _only(payload, "profile", "revision", "remove")
        try:
            profile_id = dns_profiles.check_profile_id(payload.get("profile"))
            revision = dns_profiles.check_revision(payload.get("revision"))
        except dns_profiles.ProfileError as exc:
            raise BadPayload(str(exc)) from exc
        remove = _flag(payload, "remove", default=False)
        if profile_lookup is None:
            raise BadPayload("dns_profile_apply needs the profile row and none was offered")
        row = profile_lookup(profile_id)
        if row is None:
            raise BadPayload(f"profile {profile_id} no longer exists")
        if row.revision < revision or (remove and row.revision != revision):
            raise BadPayload(f"profile {profile_id} is at revision {row.revision}, not {revision}")
        return Prepared(
            argv=(dns_profiles.SUDO, *SUDO_FLAGS, dns_profiles.HELPER),
            request=dns_profiles.build_request(
                str(request_id),
                profile_id=row.id,
                provider_id=row.provider_id,
                schema_version=row.schema_version,
                key_id=row.key_id,
                revision=row.revision,
                ciphertext=row.ciphertext,
                remove=remove,
            ),
        )

    if operation == "ndes_profile_apply":
        _only(payload, "profile", "revision", "remove")
        try:
            profile_id = dns_profiles.check_profile_id(payload.get("profile"))
            revision = dns_profiles.check_revision(payload.get("revision"))
        except dns_profiles.ProfileError as exc:
            raise BadPayload(str(exc)) from exc
        remove = _flag(payload, "remove", default=False)
        row = profile_lookup(profile_id) if profile_lookup is not None else None
        if (
            row is None
            or row.id != profile_id
            or row.provider_id != "ndes"
            or row.revision < revision
            or (remove and row.revision != revision)
        ):
            raise BadPayload("NDES profile row is missing, stale or has the wrong type")
        return Prepared(
            argv=(dns_profiles.SUDO, *SUDO_FLAGS, ndes_profiles.HELPER),
            request=ndes_profiles.build_request(
                str(request_id),
                profile_id=row.id,
                schema_version=row.schema_version,
                key_id=row.key_id,
                revision=row.revision,
                ciphertext=row.ciphertext,
                remove=remove,
            ),
        )

    if operation == "cert_publish":
        _only(payload, "certificates", "deploy")
        certificates = payload.get("certificates", [])
        if not isinstance(certificates, list) or not all(
            isinstance(item, str) and item for item in certificates
        ):
            raise BadPayload("certificates must be a list of certificate IDs")
        return Prepared(
            argv=(cert_publish_helper.SUDO, *SUDO_FLAGS, cert_publish_helper.HELPER),
            request=cert_publish_helper.build_request(
                str(request_id),
                certificates=tuple(certificates),
                deploy=_flag(payload, "deploy", default=True),
            ),
        )

    if operation == "cert_delete":
        #
        # A list of registered IDs and nothing else. What each one means -
        # which files, which lineage, which nodes - is the helper's to read
        # from the registry; the payload cannot name a path or a target.
        #
        _only(payload, "certificates")
        certificates = payload.get("certificates")
        if (
            not isinstance(certificates, list)
            or not certificates
            or not all(
                isinstance(item, str) and CERTIFICATE_ID.fullmatch(item) for item in certificates
            )
        ):
            raise BadPayload("certificates must be a non-empty list of certificate IDs")
        if len(certificates) > MAX_DELETE_BATCH:
            raise BadPayload(f"at most {MAX_DELETE_BATCH} certificates in one job")
        if len(set(certificates)) != len(certificates):
            raise BadPayload("certificates contains a duplicate")
        if draft_references is not None:
            referenced = draft_references(tuple(certificates))
            if referenced:
                named = "; ".join(
                    f"{certificate} by {', '.join(rows)}"
                    for certificate, rows in sorted(referenced.items())
                )
                raise BadPayload(f"a draft still names a certificate: {named}")
        return Prepared(
            argv=(cert_delete_helper.SUDO, *SUDO_FLAGS, cert_delete_helper.HELPER),
            request=cert_delete_helper.build_request(
                str(request_id), certificates=tuple(certificates)
            ),
        )

    if operation == "cert_receiver":
        #
        # One receiver and one action (B142). The transport and the pasted
        # public key, or the https allowlist, are checked for shape here; what
        # they mean - the account, the directory, the lock - is the helper's,
        # as when the operator types `haproxy-cert-receiver`. The key is text
        # from the form and never a path: a helper that took a path would
        # read any file root can.
        #
        # Not through sudo (B163). The helper writes /etc - useradd, an sshd
        # drop-in, an nginx snippet - and a helper this unit starts inherits
        # its ProtectSystem=strict. So it answers on a socket from a unit of
        # its own, and what runs here is the client that carries the request
        # there and the answer back, in the same stdin/stdout shape.
        #
        _only(payload, "receiver", "action", "transport", "public_key", "allow")
        receiver = payload.get("receiver")
        if not isinstance(receiver, str) or not RECEIVER_ID.fullmatch(receiver):
            raise BadPayload("receiver must be a receiver ID")
        action = payload.get("action")
        if action not in {"add", "remove"}:
            raise BadPayload("action must be add or remove")
        transport = payload.get("transport")
        public_key = payload.get("public_key")
        allow_raw = payload.get("allow", [])
        if action == "remove":
            if transport is not None or public_key is not None or allow_raw:
                raise BadPayload("a removal takes no transport, key or allowlist")
            return Prepared(
                argv=RECEIVER_CLIENT,
                request=cert_receiver_helper.build_request(
                    str(request_id), receiver=receiver, action="remove"
                ),
            )
        if transport not in RECEIVER_TRANSPORTS:
            raise BadPayload("transport must be rsync, sftp or https")
        if not isinstance(allow_raw, list) or not all(
            isinstance(item, str) and item for item in allow_raw
        ):
            raise BadPayload("allow must be a list of addresses or networks")
        allow = tuple(allow_raw)
        if transport == "https":
            if public_key is not None:
                raise BadPayload("an https receiver has no key")
            if not allow:
                raise BadPayload("an https receiver needs at least one address in allow")
        else:
            if allow:
                raise BadPayload("allow belongs to an https receiver only")
            if not isinstance(public_key, str) or not public_key.strip():
                raise BadPayload("public_key is required for rsync and sftp")
            if len(public_key) > cert_receiver_helper.MAX_PUBLIC_KEY:
                raise BadPayload("public_key is longer than a public key")
        return Prepared(
            argv=RECEIVER_CLIENT,
            request=cert_receiver_helper.build_request(
                str(request_id),
                receiver=receiver,
                action="add",
                transport=str(transport),
                public_key=public_key if isinstance(public_key, str) else None,
                allow=allow,
            ),
        )

    if operation == "cert_target":
        #
        # A list of registered IDs and one delta - `add` or `remove` of
        # clusters and receivers - checked here for shape only. Whether the
        # targets exist is the helper's to read from the registry. A remove
        # from a cluster is refused while a draft in that cluster names the
        # certificate, the way a deletion is: the draft lives in this
        # database and the helper cannot see it.
        #
        _only(payload, "certificates", "action", "clusters", "receivers", "formats", "deploy")
        certificates = payload.get("certificates")
        if (
            not isinstance(certificates, list)
            or not certificates
            or not all(
                isinstance(item, str) and CERTIFICATE_ID.fullmatch(item) for item in certificates
            )
        ):
            raise BadPayload("certificates must be a non-empty list of certificate IDs")
        if len(certificates) > MAX_DELETE_BATCH:
            raise BadPayload(f"at most {MAX_DELETE_BATCH} certificates in one job")
        if len(set(certificates)) != len(certificates):
            raise BadPayload("certificates contains a duplicate")
        action = payload.get("action")
        if action not in {"add", "remove"}:
            raise BadPayload("action must be add or remove")
        clusters, receivers = _targets(payload)
        formats = _formats(payload, receivers)
        if action == "remove" and formats:
            raise BadPayload("a removal does not take formats")
        if action == "remove" and clusters and draft_references is not None:
            referenced = {
                certificate: tuple(row for row in rows if row.split("/", 1)[0] in clusters)
                for certificate, rows in draft_references(tuple(certificates)).items()
            }
            named = "; ".join(
                f"{certificate} by {', '.join(rows)}"
                for certificate, rows in sorted(referenced.items())
                if rows
            )
            if named:
                raise BadPayload(f"a draft still names a certificate: {named}")
        return Prepared(
            argv=(cert_target_helper.SUDO, *SUDO_FLAGS, cert_target_helper.HELPER),
            request=cert_target_helper.build_request(
                str(request_id),
                certificates=tuple(certificates),
                action=action,
                clusters=clusters,
                receivers=receivers,
                deploy=_flag(payload, "deploy", default=True),
                formats=formats,
            ),
        )

    raise UnknownOperation(operation)


def prepare(
    *,
    operation: str,
    cluster: str | None,
    request_id: UUID,
    payload: Mapping[str, Any],
    profile_lookup: ProfileLookup | None = None,
    draft_references: DraftReferences | None = None,
) -> Prepared:
    """Build the command for one job, or refuse it.

    `json_mode` is always true here. The command line renders progress for a
    person; the worker has to store a result, and a machine-readable envelope is
    the only form it can honestly parse into one.

    `cluster` is optional because the certificate operations have none: a
    certificate is scoped by the registry, where the wildcard names two clusters
    and the PVE certificates name none. The queue says the same thing in
    migration 0024, and the three helpers below take a null cluster in their
    requests. Every other operation still requires one, and is given one by the
    check at the end of this function rather than by trusting its caller.
    """

    if operation in CERTIFICATE_OPERATIONS:
        #
        # Refused rather than ignored. A certificate job that arrived carrying a
        # cluster was built by something that disagrees with the queue about what
        # this operation is, and running it would mean acting on the half of that
        # disagreement this process happens to hold.
        #
        if cluster is not None:
            raise BadPayload(f"{operation} names no cluster; this job carries {cluster!r}")
        return _certificate_operation(
            operation=operation,
            request_id=request_id,
            payload=payload,
            profile_lookup=profile_lookup,
            draft_references=draft_references,
        )

    #
    # Everything below acts on one cluster, and from here it has one: the
    # database's own constraint says so, and this says it again for a caller
    # that reached `prepare` without going through the queue.
    #
    if cluster is None:
        raise BadPayload(f"{operation} acts on a cluster and this job names none")

    if operation == "backup_run":
        _only(payload)
        return Prepared(
            argv=BACKUP_CLIENT,
            request=backup_job_helper.build_run_request(cluster, str(request_id)),
        )

    if operation == "backup_schedule":
        _only(payload, *backup_job_helper.SCHEDULE_KEYS)
        try:
            requested = backup_schedule_write.schedule(payload)
        except backup_schedule_write.ScheduleWriteError as exc:
            raise BadPayload(str(exc)) from exc
        enabled = _flag(payload, "enabled", default=False)
        return Prepared(
            argv=BACKUP_CLIENT,
            request=backup_job_helper.build_schedule_request(
                cluster, str(request_id), schedule=requested, enabled=enabled
            ),
        )

    #
    # Four branches rather than one test for membership: the test that holds
    # this module, the queue's constraint and the worker's outcomes together
    # reads the operations off these lines.
    #
    if operation == "node_restore_prepare":
        return _restore(operation, cluster, request_id, payload)
    if operation == "node_restore_preview":
        return _restore(operation, cluster, request_id, payload)
    if operation == "node_restore":
        return _restore(operation, cluster, request_id, payload)
    if operation == "node_restore_discard":
        return _restore(operation, cluster, request_id, payload)
    if operation == "node_restore_status":
        return _restore(operation, cluster, request_id, payload)

    if operation == "deploy":
        _only(payload, "allow_vip_unknown")
        return Prepared(
            argv=(deploy.SUDO, *SUDO_FLAGS, deploy.HELPER),
            request=deploy.build_request(
                cluster,
                str(request_id),
                allow_vip_unknown=_flag(payload, "allow_vip_unknown", default=False),
                json_mode=True,
                #
                # The worker holds a lease it can lose, and it cannot signal a
                # helper running as root. Holding stdin open is how it keeps a
                # way to say "I have let go" - and the kernel says it for the
                # worker if the worker dies first.
                #
                lifeline=True,
            ),
            lifeline=True,
        )

    if operation == "cert_deploy":
        _only(payload, "allow_vip_unknown")
        return Prepared(
            argv=(cert_deploy.SUDO, *SUDO_FLAGS, cert_deploy.HELPER),
            request=cert_deploy.build_request(
                cluster,
                str(request_id),
                allow_vip_unknown=_flag(payload, "allow_vip_unknown", default=False),
                json_mode=True,
                #
                # The worker holds a lease it can lose, and it cannot signal a
                # helper running as root. Holding stdin open is how it keeps a
                # way to say "I have let go" - and the kernel says it for the
                # worker if the worker dies first.
                #
                lifeline=True,
            ),
            lifeline=True,
        )

    if operation == "revert":
        #
        # No lifeline, and deliberately not by omission.
        #
        # A revert reaches no node. It validates the candidate in the sandbox,
        # commits and publishes - all local, and over in seconds against a
        # sixty-second lease - so there is no window worth building a checkpoint
        # protocol for. The case a lifeline would guard against is closed twice
        # over anyway: `expected_commit` makes a second worker's revert refuse
        # once the commit has moved, and the engine holds the cluster's lock for
        # the length of the operation.
        #
        # What would change this answer: a revert that grows a step touching a
        # node. It should get a lifeline the same day, because everything above
        # stops being true at that point. Reviewed and decided 2026-08-31 as F4.
        #
        _only(payload, "version", "expected_commit")
        version = payload.get("version")
        commit = payload.get("expected_commit")
        #
        # A bool is an int in Python, and `version: true` would otherwise revert
        # to version 1. Checked here rather than trusted to the helper, because
        # the helper's refusal would arrive after the cluster's lock was taken.
        #
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise BadPayload("version must be a positive integer")
        if not isinstance(commit, str) or not commit:
            raise BadPayload("expected_commit must be a commit id")
        return Prepared(
            argv=(revert.SUDO, *SUDO_FLAGS, revert.HELPER),
            request=revert.build_request(
                cluster, str(request_id), version=version, expected_commit=commit
            ),
        )

    if operation == "network_publish":
        _only(payload, "network", "expected_head", "comment", "allow_certificate_mismatch")
        network = payload.get("network")
        expected_head = payload.get("expected_head")
        comment = payload.get("comment")
        override = payload.get("allow_certificate_mismatch", False)
        if not isinstance(network, str) or not network:
            raise BadPayload("network must be a non-empty document")
        if not isinstance(expected_head, str) or not expected_head:
            raise BadPayload("expected_head must be a commit id")
        if not isinstance(comment, str) or not comment:
            raise BadPayload("comment must be a non-empty string")
        #
        # Only a real boolean reaches the helper. A string "false" arriving as
        # true is how an override turns itself on without anybody deciding to.
        #
        if not isinstance(override, bool):
            raise BadPayload("allow_certificate_mismatch must be true or false")
        return Prepared(
            argv=(
                managed_network_publish.SUDO,
                *SUDO_FLAGS,
                managed_network_publish.HELPER,
            ),
            request=managed_network_publish.build_request(
                cluster,
                str(request_id),
                network=network,
                expected_head=expected_head,
                comment=comment,
                allow_certificate_mismatch=override,
            ),
        )

    if operation == "objects_publish":
        _only(payload, "objects", "expected_head", "comment", "allow_certificate_mismatch", "draft")
        #
        # `draft` is the interface's own bookkeeping: which draft row this
        # publish came from, so the row can be recognised as published
        # afterwards rather than guessed at from its text. It is checked here
        # because everything in a payload is - a job is what the worker runs as
        # root, and an unchecked field in one is an unchecked field either way -
        # and it is deliberately not passed on below. The helper's parameters
        # are named one at a time, so nothing reaches it that is not listed.
        #
        draft = payload.get("draft")
        if draft is not None:
            if not isinstance(draft, Mapping) or set(draft) != {"id", "revision"}:
                raise BadPayload("draft must name an id and a revision")
            if not isinstance(draft.get("id"), str) or not draft["id"]:
                raise BadPayload("the draft id must be a non-empty string")
            if not isinstance(draft.get("revision"), int) or isinstance(draft["revision"], bool):
                raise BadPayload("the draft revision must be a whole number")
        objects = payload.get("objects")
        expected_head = payload.get("expected_head")
        comment = payload.get("comment")
        override = payload.get("allow_certificate_mismatch", False)
        #
        # A mapping of name to document, where `None` asks for a removal. Every
        # key and every value is checked here rather than trusted to the helper:
        # this payload was built from a form, and the helper's own refusal would
        # arrive as a failed job instead of as a page saying what was wrong.
        #
        if not isinstance(objects, Mapping) or not objects:
            raise BadPayload("objects must be a non-empty mapping")
        for name, document in objects.items():
            if not isinstance(name, str) or not NAME.match(name):
                raise BadPayload(f"{name!r} is not a usable object name")
            if document is not None and (not isinstance(document, str) or not document):
                raise BadPayload(f"the document for {name} must be a non-empty string or null")
        if not isinstance(expected_head, str) or not expected_head:
            raise BadPayload("expected_head must be a commit id")
        if not isinstance(comment, str) or not comment:
            raise BadPayload("comment must be a non-empty string")
        #
        # Only a real boolean reaches the helper, for the reason the network
        # publish gives: a string "false" arriving as true is how an override
        # turns itself on without anybody deciding to.
        #
        if not isinstance(override, bool):
            raise BadPayload("allow_certificate_mismatch must be true or false")
        return Prepared(
            argv=(
                managed_objects_publish.SUDO,
                *SUDO_FLAGS,
                managed_objects_publish.HELPER,
            ),
            request=managed_objects_publish.build_request(
                cluster,
                str(request_id),
                objects=objects,
                expected_head=expected_head,
                comment=comment,
                allow_certificate_mismatch=override,
            ),
        )

    raise UnknownOperation(operation)
