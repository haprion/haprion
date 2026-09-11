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

import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haproxy_mgmt.certificates import (
    MAX_CERTIFICATE_BYTES,
    CertificateError,
    certificate_path,
    leaf_block,
    leaf_fingerprint,
)
from haproxy_mgmt.config import Cluster, RegisteredCertificate, Registry

OPENSSL = "/usr/bin/openssl"
LETSENCRYPT_ROOT = Path("/etc/letsencrypt")
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
        "source": {"kind": entry.source.kind, "lineage": entry.source.lineage},
        "targets": {"clusters": list(entry.clusters), "receivers": list(entry.receivers)},
    }


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
        path = certificate_path(root, identifier)
        if path.stat().st_size > MAX_CERTIFICATE_BYTES:
            raise CertificateError("the file is implausibly large")
        pem = path.read_text(encoding="ascii", errors="strict")
        fingerprint = leaf_fingerprint(pem)
        facts = describe(leaf_block(pem))
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
    return {
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
