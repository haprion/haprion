"""Metadata about the certificates a cluster can be given, and nothing more.

Only metadata leaves this module. The published files are private key plus full
chain, and what reaches the X.509 parser is the leaf block alone - extracted by
`certificates.leaf_block`, which the key never survives. So "the key does not
leave the helper" is a property of what is passed, not a rule to remember.

A real parser, borrowed rather than written
-------------------------------------------
Subject, SAN and validity need X.509, and `certificates` explains why this
project does not grow a parser for them: it carries one runtime dependency, and
a root-run helper is the last place to add a second. openssl is already on the
management host, is already trusted to validate the configuration, and is asked
here for exactly the fields that are reported.

`lifecycle` is measured, not declared
--------------------------------------
It answers one question - is anything renewing this? - and the answer is in
certbot's own archive: a distributed certificate whose leaf appears there came
from a renewal, and one that does not came from somewhere else. The archive
rather than the live link, because a renewal writes the new certificate before
the deploy hook publishes it, and during that window the distributed copy is the
lineage's *previous* certificate. Comparing against the live link alone would
report "nothing renews this" about a certificate that had just been renewed.
See B27.
"""

from __future__ import annotations

import contextlib
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haproxy_mgmt.cert_registry import receiver_in_use
from haproxy_mgmt.cert_request_state import pending_csrs, request_is_interface
from haproxy_mgmt.certificates import (
    CERTIFICATE_OPENING,
    MAX_CERTIFICATE_BYTES,
    CertificateError,
    certificate_path,
    leaf_block,
    leaf_fingerprint,
)
from haproxy_mgmt.config import (
    DEFAULT_RECEIVER_FORMAT,
    Cluster,
    Receiver,
    RegisteredCertificate,
    Registry,
)
from haproxy_mgmt.ndes_state import pending_requests, renewal_record, request_is_pending

OPENSSL = "/usr/bin/openssl"
LETSENCRYPT_ROOT = Path("/etc/letsencrypt")
LETSENCRYPT_LIVE = LETSENCRYPT_ROOT / "live"
#
# Where imported material lives on the manager: one directory per certificate
# ID with the same two files certbot's live directory has. Root-only. The
# import helper (C6) is the only writer; everything here only reads.
#
IMPORT_STORE = Path("/etc/haproxy-manager/certificates")
FULLCHAIN = "fullchain.pem"
PRIVKEY = "privkey.pem"
#
# The PKCS#12 pair (B159): one bundle and the password that opens it, named
# after the certificate so a `flat` directory could hold several - which it
# may not, but the name is what a receiver's script looks for either way.
#
PKCS12_SUFFIX = ".pfx"
PASSWORD_SUFFIX = ".password"  # noqa: S105 - a file name, not a password


def receiver_directory(receiver: Receiver, certificate_id: str) -> Path:
    """Where this certificate's files live for this receiver (B138 layout).

    One function rather than five, because five readers ask it: the publisher
    that writes, the retarget and delete paths that unlink, the listing that
    reports when the manager last wrote, and the registration command that
    creates the directory. A reader that guessed `flat` while the registry
    said `per-certificate` would unlink a file that is not there and report a
    receiver as never published.
    """

    if receiver.layout == "per-certificate":
        return receiver.path / certificate_id
    return receiver.path


def receiver_files(
    receiver: Receiver, certificate_id: str, *, form: str = DEFAULT_RECEIVER_FORMAT
) -> tuple[Path, ...]:
    """The files this receiver holds for this certificate, in this form."""

    directory = receiver_directory(receiver, certificate_id)
    if form == "pkcs12":
        return (
            directory / f"{certificate_id}{PKCS12_SUFFIX}",
            directory / f"{certificate_id}{PASSWORD_SUFFIX}",
        )
    return (directory / FULLCHAIN, directory / PRIVKEY)


def receiver_witness(
    receiver: Receiver, certificate_id: str, *, form: str = DEFAULT_RECEIVER_FORMAT
) -> Path:
    """The file whose timestamp says when the manager last published here."""

    return receiver_files(receiver, certificate_id, form=form)[0]


SAN_DNS = re.compile(r"DNS:([^,\s]+)")
OPENSSL_TIMEOUT = 10


class CertInventoryError(Exception):
    """The distribution root itself cannot be read, which is not a per-file fact."""


@dataclass(frozen=True, slots=True)
class Facts:
    common_name: str | None
    sans: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    issuer: str
    #
    # The subject as openssl prints it (RFC 2253). Read beside the issuer so
    # a self-signed certificate - the interface's starting point - can be
    # told from one a CA signed without a second openssl run.
    #
    subject: str = ""


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _openssl_time(text: str) -> datetime:
    #
    # openssl prints its own format rather than ISO, and always in GMT. Parsed
    # explicitly rather than with a locale-dependent helper: the month is an
    # English abbreviation whatever the host language is set to.
    #
    return datetime.strptime(text.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)


def describe(leaf: str) -> Facts:
    """Subject, SAN, issuer and validity for one leaf certificate."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed path, no caller argv
            [
                OPENSSL,
                "x509",
                "-noout",
                "-subject",
                "-issuer",
                "-startdate",
                "-enddate",
                "-ext",
                "subjectAltName",
                "-nameopt",
                "RFC2253",
            ],
            input=leaf,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CertificateError(f"openssl could not read the certificate: {exc}") from exc
    if completed.returncode != 0:
        raise CertificateError("openssl could not read the certificate")

    fields: dict[str, str] = {}
    sans: list[str] = []
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("subject", "issuer", "notBefore", "notAfter"):
            fields[key] = value.strip()
        elif "DNS:" in line:
            sans.extend(SAN_DNS.findall(line))

    missing = sorted({"subject", "issuer", "notBefore", "notAfter"} - fields.keys())
    if missing:
        raise CertificateError(f"openssl reported no {', '.join(missing)}")

    common = re.search(r"(?:^|,)CN=([^,]+)", fields["subject"])
    return Facts(
        common_name=common.group(1) if common else None,
        sans=tuple(dict.fromkeys(sans)),
        not_before=_openssl_time(fields["notBefore"]),
        not_after=_openssl_time(fields["notAfter"]),
        issuer=fields["issuer"] or "unknown",
        subject=fields["subject"],
    )


def renewed_fingerprints(root: Path = LETSENCRYPT_ROOT) -> frozenset[str]:
    """Every leaf certbot has issued, by fingerprint, across all its lineages.

    Unreadable or unparseable files are skipped rather than raised on. This
    answers "is anything renewing this", and one damaged file in an unrelated
    lineage must not turn the whole listing into an error.
    """

    found: set[str] = set()
    for directory in ("archive", "live"):
        base = root / directory
        try:
            candidates = sorted(base.glob("*/cert*.pem"))
        except OSError:
            continue
        for path in candidates:
            try:
                if path.stat().st_size > MAX_CERTIFICATE_BYTES:
                    continue
                found.add(leaf_fingerprint(path.read_text(encoding="ascii", errors="strict")))
            except (OSError, UnicodeDecodeError, CertificateError):
                continue
    return frozenset(found)


def source_directory(entry: RegisteredCertificate, *, live: Path, store: Path) -> Path:
    """Where a registered certificate's own material lives.

    Here rather than in the publisher because the listing needs the same answer.
    A certificate that goes only to receivers has no file in the distribution
    directory at all, so the only place to read its subject, SAN and expiry from
    is its source - and a second implementation of "where is that" would be a
    second thing to keep in step with the publisher.
    """

    if entry.source.kind == "acme":
        assert entry.source.lineage is not None  # noqa: S101 - the loader sets it for acme
        return live / entry.source.lineage
    return store / entry.certificate_id


def _registered(entry: RegisteredCertificate | None) -> dict[str, Any]:
    """What the registry says about a certificate: where from, and where to.

    `None` for both when the installation has no registry, or the certificate
    is a file in the distribution directory that no registry entry names -
    which is a fact worth showing, not an error: it is what a certificate
    published before the registry existed looks like.
    """

    if entry is None:
        return {"source": None, "targets": None}
    return {
        "source": _source(entry),
        "targets": {"clusters": list(entry.clusters), "receivers": list(entry.receivers)},
    }


def _source(entry: RegisteredCertificate) -> dict[str, Any]:
    result = {"kind": entry.source.kind, "lineage": entry.source.lineage}
    if entry.source.dns_profile is not None:
        result["dns_profile"] = entry.source.dns_profile
    if entry.source.ndes_profile is not None:
        result["ndes_profile"] = entry.source.ndes_profile
    return result


def _one(
    root: Path,
    identifier: str,
    *,
    referenced: bool,
    renewed: frozenset[str],
    now: datetime,
    registered: RegisteredCertificate | None = None,
) -> dict[str, Any]:
    #
    # A certificate that cannot be read still gets an entry: `deployable` and
    # `validation_error` exist precisely so a referenced-but-missing file is
    # visible, and dropping it would hide the case the listing is most needed
    # for. The measured fields then have no true value to carry, and schema v1
    # requires all nine - so they are filled with something inert.
    #
    # THIS IS THE ONE PLACE IN THE FILE WHERE A FIELD IS NOT A MEASUREMENT.
    # Nothing may read fingerprint, dates, issuer, lifecycle or valid without
    # checking `deployable` first. A v2 schema should make them nullable and
    # remove the need for the rule.
    #
    entry: dict[str, Any] = {
        "id": identifier,
        "referenced_by_cluster": referenced,
        "deployable": False,
        "validation_error": None,
        "fingerprint_sha256": "0" * 64,
        "common_name": None,
        "sans": [],
        "not_before": _timestamp(now),
        "not_after": _timestamp(now),
        "issuer": "unknown",
        "lifecycle": "static",
        "valid": False,
        **_registered(registered),
    }
    try:
        fingerprint, facts = _measure(certificate_path(root, identifier))
    except FileNotFoundError:
        #
        # A referenced certificate that is not in the distribution directory is
        # the case this listing exists to make visible: cert-deploy refuses the
        # whole cluster for it, and the operator should learn that here rather
        # than from a refused rollout.
        #
        entry["validation_error"] = "not present in the distribution directory"
        return entry
    except (OSError, UnicodeDecodeError, CertificateError) as exc:
        entry["validation_error"] = str(exc)
        return entry

    entry.update(
        deployable=True,
        fingerprint_sha256=fingerprint,
        common_name=facts.common_name,
        sans=list(facts.sans),
        not_before=_timestamp(facts.not_before),
        not_after=_timestamp(facts.not_after),
        issuer=facts.issuer,
        lifecycle="acme" if fingerprint in renewed else "static",
        valid=facts.not_before <= now <= facts.not_after,
    )
    return entry


#
# The inert values a v1 entry must carry when nothing could be measured. Same
# rule as `_one`: nothing may read them without checking the error field first,
# and a v2 schema should make them nullable instead.
#
def _unmeasured(now: datetime) -> dict[str, Any]:
    return {
        "fingerprint_sha256": None,
        "common_name": None,
        "sans": [],
        "not_before": _timestamp(now),
        "not_after": _timestamp(now),
        "issuer": "unknown",
        "lifecycle": "static",
        "valid": False,
    }


def _measure(path: Path) -> tuple[str, Facts]:
    """One certificate file's fingerprint and facts, from its leaf block alone.

    The private key is never opened. This reads `fullchain.pem`, and what
    reaches the parser is `leaf_block`, so "no key material leaves here" is a
    property of what is passed rather than a rule to remember.
    """

    if path.stat().st_size > MAX_CERTIFICATE_BYTES:
        raise CertificateError("the file is implausibly large")
    pem = path.read_text(encoding="ascii", errors="strict")
    return leaf_fingerprint(pem), describe(leaf_block(pem))


def _published(
    path: Path, source_fingerprint: str | None, *, measurable: bool = True
) -> dict[str, Any]:
    """Whether one target holds this certificate, and since when.

    Two facts and no third. `published_at` is the file's own timestamp, which
    says when the manager last wrote it - not when anything fetched it. A
    receiver pulls on its own schedule with its own key, reports nothing back,
    and by §14.1 what it does with the certificate is its own business. So this
    reports publication, and the interface must not translate it into arrival.

    `current` is null rather than false where it could not be decided: an
    unreadable source and an out-of-date target are different facts, and the
    one thing worse than not knowing is saying the wrong one confidently.

    `measurable` is false for a PKCS#12 bundle (B159), which cannot be read
    without the password that opens it. The bundle's timestamp still says when
    the manager wrote it, and `current` stays null - not knowing, said as not
    knowing, rather than a listing that opens key material to decorate a
    column.
    """

    try:
        stat = path.stat()
    except OSError:
        return {"published_at": None, "current": None if source_fingerprint is None else False}
    fingerprint: str | None = None
    if measurable:
        try:
            fingerprint, _ = _measure(path)
        except (OSError, UnicodeDecodeError, CertificateError):
            fingerprint = None
    current = None
    if source_fingerprint is not None and fingerprint is not None:
        current = fingerprint == source_fingerprint
    return {
        "published_at": _timestamp(datetime.fromtimestamp(stat.st_mtime, UTC)),
        "current": current,
    }


def _receiver_row(
    receiver: Receiver, certificate_id: str, form: str, fingerprint: str | None
) -> dict[str, Any]:
    """One receiver's line in a certificate's targets: where it goes and how.

    The form is reported even when it is the default, so a caller reading the
    listing never has to know what the default was on the day it was written.
    """

    return {
        "id": receiver.receiver_id,
        "format": form,
        **_published(
            receiver_witness(receiver, certificate_id, form=form),
            fingerprint,
            measurable=form != "pkcs12",
        ),
    }


def measure_registered(
    entry: RegisteredCertificate, *, certificate_root: Path, live: Path, store: Path
) -> tuple[str, Facts, str] | str:
    """A registered certificate's fingerprint and facts, and where they were read.

    At its source first: that is what a renewal writes first, so a target that
    has not been published yet would otherwise report the previous certificate.

    When the source holds nothing - an imported certificate registered before
    the import helper exists - the published cluster copy is measured instead,
    and the answer says so. That copy is real material the clusters are
    serving; calling the certificate unreadable because its import directory
    is empty would tell the reader the opposite of what the nodes are doing.
    Only where a cluster names it: a receiver-only certificate has no
    published copy this manager can open. The publisher still calls such an
    entry skipped and leaves the copy alone; this is a listing, not a source.

    Returns the reason as a string when nothing could be read.
    """

    try:
        fingerprint, facts = _measure(source_directory(entry, live=live, store=store) / FULLCHAIN)
        return fingerprint, facts, "source"
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError, CertificateError) as exc:
        return str(exc)

    if not entry.clusters:
        return "no material at its source yet"
    try:
        fingerprint, facts = _measure(certificate_path(certificate_root, entry.certificate_id))
        return fingerprint, facts, "distribution"
    except FileNotFoundError:
        return "no material at its source yet"
    except (OSError, UnicodeDecodeError, CertificateError) as exc:
        return str(exc)


def registry_result(
    registry: Registry,
    *,
    certificate_root: Path,
    renewed: frozenset[str],
    now: datetime,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    request_root: Path | None = None,
    manager: str | None = None,
    interface_served: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Every certificate the manager holds, measured at its source.

    The per-cluster listing answers "what can this cluster be given", and a
    certificate that goes only to receivers is nobody's there - it has no file
    in the distribution directory at all. This answers the other question, the
    one the central view asks: what exists, where does each come from, and
    where does each go.

    Measured at the source rather than at a target because the source is what a
    renewal writes first. A target that has not been published yet would
    otherwise report the previous certificate's expiry, or none at all.
    """

    entries: list[dict[str, Any]] = []
    for entry in registry.certificates.values():
        row: dict[str, Any] = {
            "id": entry.certificate_id,
            "source": _source(entry),
            #
            # Additive (B188): only on the entry that is the interface's, so
            # every other row reads exactly as it did.
            #
            **({"interface": True} if entry.interface else {}),
            **({"exportable": True} if entry.exportable else {}),
            "readable": False,
            "validation_error": None,
            "measured_at": None,
            **_unmeasured(now),
        }
        fingerprint: str | None = None
        measured = measure_registered(
            entry, certificate_root=certificate_root, live=live, store=store
        )
        if isinstance(measured, str):
            row["validation_error"] = measured
            #
            # An import whose material has not arrived may be a request the
            # CA is still holding (C6). Said as its own field so the listing
            # can tell "waiting" from "broken" without parsing the sentence.
            #
            if (
                request_root is not None
                and entry.source.kind == "import"
                and request_is_pending(request_root, entry.certificate_id)
            ):
                row["request_state"] = "pending"
        else:
            fingerprint, facts, row["measured_at"] = measured
            #
            # The chain an exportable certificate is downloaded as (B255). It
            # is public - the same bytes any client of the device is shown -
            # and the web cannot read the store, so it travels here, as a
            # signing request's CSR does. Only for exportable entries: the
            # rest would grow the listing by a chain each and nobody reads it.
            #
            if entry.exportable:
                with contextlib.suppress(OSError, UnicodeDecodeError):
                    chain = (source_directory(entry, live=live, store=store) / FULLCHAIN).read_text(
                        encoding="ascii"
                    )
                    if (
                        chain.startswith(CERTIFICATE_OPENING + "\n")
                        and len(chain) <= 65536
                        and "PRIVATE KEY" not in chain
                    ):
                        row["fullchain_pem"] = chain
            #
            # What the scheduled renewal last did to an NDES certificate,
            # if it has tried: the material above is still the measurement,
            # this is the run's own word, for the row to say "renewal
            # failed" with the CA's sentence rather than an expiry creeping.
            #
            if request_root is not None and entry.source.ndes_profile is not None:
                renewal = renewal_record(request_root, entry.certificate_id)
                if renewal is not None:
                    row["renewal"] = renewal
            row.update(
                readable=True,
                fingerprint_sha256=fingerprint,
                common_name=facts.common_name,
                sans=list(facts.sans),
                not_before=_timestamp(facts.not_before),
                not_after=_timestamp(facts.not_after),
                issuer=facts.issuer,
                lifecycle="acme" if fingerprint in renewed else "static",
                valid=facts.not_before <= now <= facts.not_after,
            )

        row["targets"] = {
            "clusters": list(entry.clusters),
            "receivers": [
                _receiver_row(
                    registry.receivers[receiver_id],
                    entry.certificate_id,
                    entry.format_for(receiver_id),
                    fingerprint,
                )
                for receiver_id in entry.receivers
                if receiver_id in registry.receivers
            ],
        }
        #
        # One fact, not one per cluster: every cluster reads the same file out
        # of the same shared distribution directory. Which nodes are actually
        # carrying it is a different measurement, and it is already in the node
        # status - it does not belong to this helper.
        #
        row["distribution"] = (
            _published(certificate_path(certificate_root, entry.certificate_id), fingerprint)
            if entry.clusters
            else None
        )
        entries.append(row)

    #
    # Requests the CA is still holding are not in the registry - an entry
    # without material refused every rollout to the clusters it named
    # (review 2026-09-17, finding 1) - so they are read from the request
    # state itself, with the targets kept beside each request. Same row
    # shape as an unreadable entry, with `request_state` saying why.
    #
    if request_root is not None:
        listed = {row["id"] for row in entries}
        for pending in pending_requests(request_root):
            if pending.certificate_id in listed:
                continue
            entries.append(
                {
                    "id": pending.certificate_id,
                    "source": {
                        "kind": "import",
                        "lineage": None,
                        "ndes_profile": pending.profile_id,
                    },
                    "readable": False,
                    "validation_error": "no material at its source yet",
                    "request_state": "pending",
                    "measured_at": None,
                    **_unmeasured(now),
                    "targets": {
                        "clusters": list(pending.clusters),
                        "receivers": [
                            _receiver_row(
                                registry.receivers[receiver_id],
                                pending.certificate_id,
                                DEFAULT_RECEIVER_FORMAT,
                                None,
                            )
                            for receiver_id in pending.receivers
                            if receiver_id in registry.receivers
                        ],
                    },
                    "distribution": None,
                }
            )

    #
    # Requests made here and waiting for a signature (C9b) are not in the
    # registry either, for the same reason, and their key waits in the import
    # store. Same row shape again, with `request` carrying the CSR - public
    # by construction, and the one thing the row exists to hand out.
    #
    listed = {row["id"] for row in entries}
    for csr in pending_csrs(store):
        if csr.certificate_id in listed:
            continue
        entries.append(
            {
                "id": csr.certificate_id,
                "source": {"kind": "import", "lineage": None},
                # A request made for the interface's own certificate (B188).
                **({"interface": True} if request_is_interface(store, csr.certificate_id) else {}),
                "readable": False,
                "validation_error": "no material at its source yet",
                "request_state": "pending",
                "request": csr.as_row_fields(),
                "measured_at": None,
                **_unmeasured(now),
                "targets": {
                    "clusters": list(csr.clusters),
                    "receivers": [
                        _receiver_row(
                            registry.receivers[receiver_id],
                            csr.certificate_id,
                            csr.formats.get(receiver_id, DEFAULT_RECEIVER_FORMAT),
                            None,
                        )
                        for receiver_id in csr.receivers
                        if receiver_id in registry.receivers
                    ],
                },
                "distribution": None,
            }
        )

    #
    # `receivers` stays the list of names the interface has read since C5.
    # `receiver_records` is what its receivers page shows (B142): the
    # transport, the layout, the account, the directory and which
    # certificates name each one. `flat` is the form registered before C7;
    # the interface calls it legacy, like the command's `list`. `manager` is
    # the name a receiver reaches this host by, for the fetch commands the
    # page writes out; the helper reads it, so a test never does.
    #
    return {
        "certificates": entries,
        "receivers": sorted(registry.receivers),
        "manager": manager,
        #
        # What nginx serves the interface with now, read from the pair
        # itself (B188): the registry's marked entry once it is installed,
        # the installer's self-signed pair before that.
        #
        "interface_served": dict(interface_served) if interface_served is not None else None,
        "receiver_records": [
            {
                "id": receiver_id,
                "transport": receiver.transport,
                "layout": receiver.layout,
                "owner": receiver.owner,
                "path": str(receiver.path),
                "allow": list(receiver.allow),
                "certificates": list(receiver_in_use(registry, receiver_id)),
            }
            for receiver_id, receiver in sorted(registry.receivers.items())
        ],
    }


def coverage(root: Path, cluster: Cluster) -> dict[str, tuple[str, ...]]:
    """What each of the cluster's certificates answers for, by name.

    The publishing path asks this so the generator can refuse a site served
    under a certificate that does not cover its hostnames (B66). Separate from
    `cert_list_result` because it answers one question and must never raise:
    a listing is something a person asked for, and this is a check that runs
    inside somebody else's publish.

    A certificate that cannot be read is left out rather than reported as
    covering nothing. The generator reads an absence as "not checked", which is
    the honest answer - the alternative is refusing a publish because a file
    was briefly unreadable.
    """

    if not root.is_dir():
        return {}

    covered: dict[str, tuple[str, ...]] = {}
    for identifier in cluster.certificate_ids:
        try:
            path = certificate_path(root, identifier)
            if path.stat().st_size > MAX_CERTIFICATE_BYTES:
                continue
            facts = describe(leaf_block(path.read_text(encoding="ascii", errors="strict")))
        except (OSError, UnicodeDecodeError, CertificateError, CertInventoryError):
            continue
        names = list(facts.sans)
        #
        # The common name counts where there are no SANs at all. Every current
        # issuer writes them, but a certificate old enough to predate that is
        # still a certificate a client would accept.
        #
        if not names and facts.common_name:
            names = [facts.common_name]
        covered[identifier] = tuple(names)
    return covered


def cert_list_result(
    root: Path,
    cluster: Cluster,
    *,
    letsencrypt_root: Path = LETSENCRYPT_ROOT,
    now: datetime | None = None,
    registry: Registry | None = None,
    import_store: Path = IMPORT_STORE,
    request_root: Path | None = None,
    manager: str | None = None,
    interface_served: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The cluster's referenced certificates, then the rest of the directory.

    Both, because the two answer different questions. The referenced ones are
    what a rollout would send; the others are what could be chosen next, and a
    picker that could only see what is already configured would be no picker.

    With a registry, each entry also says where the certificate comes from and
    which clusters and receivers it goes to. A certificate published to a
    receiver only is not in this directory and so not in this listing - it is
    a per-cluster answer, and that certificate is nobody's here.
    """

    if not root.is_dir():
        raise CertInventoryError(f"the certificate root {root} is not a directory")
    clock = now or datetime.now(UTC)
    renewed = renewed_fingerprints(letsencrypt_root)

    referenced = tuple(cluster.certificate_ids)
    try:
        present = sorted(path.name.removesuffix(".pem") for path in root.glob("*.pem"))
    except OSError as exc:
        raise CertInventoryError(f"the certificate root {root} could not be read: {exc}") from exc

    order = list(referenced) + [name for name in present if name not in referenced]
    entries = registry.certificates if registry is not None else {}
    result: dict[str, Any] = {
        "certificates": [
            _one(
                root,
                name,
                referenced=name in referenced,
                renewed=renewed,
                now=clock,
                registered=entries.get(name),
            )
            for name in order
        ]
    }
    #
    # The same block in every cluster's answer, because it is the same file
    # read the same way. Carried here rather than by a helper of its own: the
    # poller is indexed by cluster in every one of its cache tables, so a
    # clusterless source would have cost a new table, a migration and the two
    # releases that a schema revision drags with it. The interface reads this
    # from the freshest cluster row, so a registry written between two clusters'
    # polls is never shown half.
    #
    if registry is not None:
        result["registry"] = registry_result(
            registry,
            certificate_root=root,
            renewed=renewed,
            now=clock,
            live=letsencrypt_root / "live",
            store=import_store,
            request_root=request_root,
            manager=manager,
            interface_served=interface_served,
        )
    return result
