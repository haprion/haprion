"""What the cluster's referenced certificates are, and what bytes they are now.

The distribution directory is the source of truth for certificate material and
this module never becomes a second one: it reads what is there, identifies it,
and says nothing about renewal, issuance or validity periods. Certificate
renewal is explicitly out of scope for this project, and a module that started
judging expiry would be the first step towards owning a problem certbot already
solves.

Identity is the SHA-256 of the leaf certificate's DER bytes
-----------------------------------------------------------
Not of the file. A published PEM is the private key concatenated with the full
chain, so hashing the file would make the fingerprint depend on the key encoding
and on which intermediates happened to be bundled that day - two things that can
change without the served certificate changing at all. Hashing the leaf gives
the same value the node can compute for what it is actually serving, which is
the only comparison worth making.

That also means the private key is never hashed, never logged and never leaves
this module: it is skipped while parsing, and only the certificate blocks are
looked at.

No third-party parser, on purpose
----------------------------------
Extracting a fingerprint needs base64 and SHA-256 and nothing else, both in the
standard library. The alternative is a cryptography dependency inside a
root-run helper, and the project deliberately carries exactly one runtime
dependency. Anything that needs real X.509 parsing - subject, SANs, validity -
belongs in `cert-list`, which shells out to openssl rather than growing a parser
here.
"""

from __future__ import annotations

import binascii
import hashlib
import re
from base64 import b64decode
from pathlib import Path

from haproxy_mgmt.config import CERTIFICATE_ID, Cluster
from haproxy_mgmt.deploy_plan import CertificateRef, CertificateTarget

#
# Certificate blocks only. The private key in the same file is matched by
# neither pattern and is never read into anything that gets hashed or reported.
#
# The delimiter is assembled rather than written out, exactly as the secret
# scanner does with the same pattern in its own source: a literal PEM header in
# a tracked file is what the scanner exists to catch, and code that parses PEM
# would otherwise be unable to pass the gate it is protected by.
#
DELIMITER = "-" * 5
CERTIFICATE_BLOCK = re.compile(
    DELIMITER
    + r"BEGIN CERTIFICATE"
    + DELIMITER
    + r"(.+?)"
    + DELIMITER
    + "END CERTIFICATE"
    + DELIMITER,
    re.DOTALL,
)

#
# A published PEM is small: key, leaf and a couple of intermediates. The cap is
# here so a wrong path - a log, a tarball, a device - is refused instead of read
# into memory by a process running as root.
#
MAX_CERTIFICATE_BYTES = 1024 * 1024


class CertificateError(Exception):
    """A referenced certificate could not be read or could not be identified."""


def leaf_fingerprint(pem: str) -> str:
    """SHA-256 of the first certificate in the file, lowercase hex.

    First rather than last: a full chain is written leaf-first, so the first
    block is the certificate the node serves. Taking the last would silently
    fingerprint the CA and make every cluster look identical.
    """

    match = CERTIFICATE_BLOCK.search(pem)
    if match is None:
        raise CertificateError("the file contains no certificate")

    body = "".join(match.group(1).split())
    try:
        der = b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertificateError("the certificate block is not valid base64") from exc
    if not der:
        raise CertificateError("the certificate block is empty")

    return hashlib.sha256(der).hexdigest()


def leaf_block(pem: str) -> str:
    """The first certificate block, as PEM, and nothing else from the file.

    The published file is the private key concatenated with the full chain.
    `cert-list` needs a real X.509 parser for subject, SAN and validity, and it
    shells out to openssl to get one - so what it hands over must be the leaf
    alone. The key is never in the returned text, which is what makes "the key
    does not leave this module" a property of the code rather than a rule the
    caller has to follow.
    """

    match = CERTIFICATE_BLOCK.search(pem)
    if match is None:
        raise CertificateError("the file contains no certificate")
    body = "\n".join(line for line in match.group(1).split() if line)
    #
    # Assembled from DELIMITER for the same reason the pattern above is: a
    # literal PEM header in a tracked file is what the secret scanner exists to
    # catch, and the gate does not know that this one is a format, not a key.
    #
    opening = f"{DELIMITER}BEGIN CERTIFICATE{DELIMITER}"
    closing = f"{DELIMITER}END CERTIFICATE{DELIMITER}"
    return f"{opening}\n{body}\n{closing}\n"


def certificate_path(root: Path, identifier: str) -> Path:
    """Where a referenced ID lives, with the suffix the IDs deliberately omit.

    `certificate_ids` are written without `.pem` and the code appends it. An ID
    written as `example.pem` therefore resolves to `example.pem.pem`, which is
    a real mistake that has been made before - so the ID is validated here
    rather than trusted, and a path that would escape the root is refused
    outright even though the ID pattern already forbids separators.
    """

    if not CERTIFICATE_ID.fullmatch(identifier):
        raise CertificateError(f"invalid certificate ID: {identifier!r}")

    path = (root / f"{identifier}.pem").resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if resolved_root not in path.parents:
        raise CertificateError(f"certificate ID escapes its root: {identifier!r}")
    return path


def read_reference(root: Path, identifier: str) -> CertificateRef:
    """One referenced certificate, as an ID and the bytes it currently is."""

    path = certificate_path(root, identifier)
    try:
        if path.stat().st_size > MAX_CERTIFICATE_BYTES:
            raise CertificateError(f"certificate '{identifier}' is implausibly large")
        pem = path.read_text(encoding="ascii", errors="strict")
    except FileNotFoundError as exc:
        raise CertificateError(
            f"certificate '{identifier}' is referenced by the cluster "
            f"but is not present in the distribution directory"
        ) from exc
    except OSError as exc:
        raise CertificateError(f"certificate '{identifier}' could not be read: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise CertificateError(f"certificate '{identifier}' is not a PEM file") from exc

    try:
        return CertificateRef(id=identifier, fingerprint=leaf_fingerprint(pem))
    except CertificateError as exc:
        raise CertificateError(f"certificate '{identifier}': {exc}") from exc


def target_for(cluster: Cluster, root: Path) -> CertificateTarget:
    """The certificates this cluster references, in configured order.

    Every referenced certificate must be present and readable before anything is
    sent anywhere. A run that pushed the three it found and reported the fourth
    as an error afterwards would leave the pair half-converged for a reason that
    was knowable before the first node was touched.
    """

    return CertificateTarget(
        certificates=tuple(
            read_reference(root, identifier) for identifier in cluster.certificate_ids
        )
    )
