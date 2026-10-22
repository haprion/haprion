"""The manager's side of joining a new node (B317).

A node's package prints a v2 block with the private half of a one-time key.
Typed into a terminal, the block reaches the root helper as it is; pasted into
the interface, the web seals the key against the installation's public key
before the job is queued - the pair and the `crypto_box_seal` that carry DNS
provider credentials and uploaded certificates (B146, B165) - so neither the
job row nor the audit ever holds it. The root helper opens it here, bound to
the cluster and the node it was sealed for, and connects once as
_haprion-join with it: the node's host key, already pinned in root's
known_hosts by the change in hand, is the only one ssh accepts.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from haprion import node_ssh
from haprion.config import NAME
from haprion.dns_profile_keys import (
    DnsProfilePrivateKey,
    DnsProfilePublicKey,
    KeyFileError,
    open_sealed,
    seal,
)
from haprion.node_enrollment import JOIN_USER, EnrollmentError, private_key
from haprion.status_collect import NodeResponse

SCHEMA_VERSION = 1
MAX_CIPHERTEXT = 8192
_HEADER_KEYS = frozenset({"schema_version", "cluster", "node", "key_id"})
#
# The join runs step 4 on the node, apt included: seconds on a node with its
# packages, a few minutes behind a slow mirror. The node gives up at 840 s.
#
JOIN_TIMEOUT_SECONDS = 870
TIMED_OUT = 124


def seal_join_key(public_key: DnsProfilePublicKey, *, cluster: str, node: str, key: str) -> bytes:
    """The one-time key, bound to the cluster and the node, sealed for root."""

    if not NAME.fullmatch(node):
        raise EnrollmentError("enrollment_invalid", "the block names no valid node")
    header = {
        "schema_version": SCHEMA_VERSION,
        "cluster": cluster,
        "node": node,
        "key_id": public_key.key_id,
    }
    line = json.dumps(header, separators=(",", ":")).encode()
    return seal(public_key, line + b"\n" + key.encode("ascii"))


def open_join_key(key: DnsProfilePrivateKey, ciphertext: bytes, *, cluster: str, node: str) -> str:
    """Open the box and hold it to the cluster and node the request names."""

    if len(ciphertext) > MAX_CIPHERTEXT:
        raise EnrollmentError("join_key_mismatch", "the sealed one-time key is too large")
    try:
        plaintext = open_sealed(key, ciphertext)
    except KeyFileError:
        raise EnrollmentError(
            "join_key_mismatch", f"the one-time key was not sealed against key {key.key_id}"
        ) from None
    line, separator, data = plaintext.partition(b"\n")
    try:
        header = json.loads(line) if separator else None
    except ValueError:
        header = None
    if not isinstance(header, dict) or set(header) != _HEADER_KEYS:
        raise EnrollmentError("join_key_mismatch", "the opened one-time key has not its shape")
    if header["schema_version"] != SCHEMA_VERSION or header["key_id"] != key.key_id:
        raise EnrollmentError("join_key_mismatch", "the one-time key was sealed for another key")
    if header["cluster"] != cluster or header["node"] != node:
        raise EnrollmentError(
            "join_key_mismatch", "the one-time key was sealed for another cluster or node"
        )
    return private_key(base64.b64encode(data).decode())


def ssh_join(
    node_host: str, key: str, document: dict[str, Any], *, known_hosts: Path
) -> NodeResponse:
    """Connect once as _haprion-join with the one-time key and hand the document over."""

    with tempfile.TemporaryDirectory(prefix="haprion-join-") as directory:
        identity = Path(directory) / "join_key"
        descriptor = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(key)
        try:
            completed = node_ssh.run_bounded(
                node_ssh.ssh_argv(
                    identity,
                    JOIN_USER,
                    node_host,
                    options=("-o", f"UserKnownHostsFile={known_hosts}"),
                ),
                request=json.dumps(document),
                timeout=JOIN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return NodeResponse(exit_code=TIMED_OUT, stdout="", stderr="the join timed out")
    return NodeResponse(
        exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
    )


def private_keys(paths: tuple[Path, ...], *, require_secure: bool) -> list[DnsProfilePrivateKey]:
    """The installation's sealing keys, as the certificate import reads them."""

    from haprion.dns_profile_keys import read_private_key  # noqa: PLC0415

    try:
        return [read_private_key(path, require_secure=require_secure) for path in paths]
    except KeyFileError as exc:
        raise EnrollmentError("dependency_unavailable", str(exc), 78) from None
