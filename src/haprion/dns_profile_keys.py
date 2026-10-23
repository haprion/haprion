"""The key pair that seals DNS provider credentials between the web and root.

The web process encrypts a provider profile against the installation's public
key and can never read it back; the root helper holds the private key and is
the only thing that decrypts (B146, libsodium's `crypto_box_seal` through
PyNaCl).  This module owns the two key files and the identifier that binds a
ciphertext to the key it was made against.

A key file is one line, a tag and 64 hexadecimal characters, so a private key
put where a public one belongs is refused by name rather than read as a
32-byte value that happens to fit.  The key identifier is derived from the
public key bytes, never assigned by hand: the web reads it off the public
file, the helper computes the same value from the private key, and a
ciphertext whose plaintext names another identifier is rejected by the helper
before its fields are looked at.

The pair is created by the platform installation (step 15), never by the
application.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

from haprion import atomic_file

PUBLIC_TAG = "haproxy-dns-profile-public-key-v1"
PRIVATE_TAG = "haproxy-dns-profile-private-key-v1"
KEY_LINE = re.compile(r"^(?P<tag>[a-z0-9-]+):(?P<hex>[0-9a-f]{64})$")
KEY_ID_LENGTH = 16


class KeyFileError(ValueError):
    """A key file is not the one shape this module writes."""


@dataclass(frozen=True, slots=True)
class DnsProfilePublicKey:
    key_id: str
    key: PublicKey


@dataclass(frozen=True, slots=True)
class DnsProfilePrivateKey:
    key_id: str
    key: PrivateKey


def key_id_of(public_key: PublicKey) -> str:
    """The identifier a ciphertext carries: a digest of the public key bytes."""

    return hashlib.sha256(bytes(public_key)).hexdigest()[:KEY_ID_LENGTH]


def _parse(text: str, expected_tag: str, location: str) -> bytes:
    lines = text.splitlines()
    if len(lines) != 1:
        raise KeyFileError(f"{location} must hold exactly one line")
    match = KEY_LINE.fullmatch(lines[0])
    if match is None:
        raise KeyFileError(f"{location} is not a key file")
    if match.group("tag") != expected_tag:
        raise KeyFileError(f"{location} holds a {match.group('tag')}, not a {expected_tag}")
    return bytes.fromhex(match.group("hex"))


def parse_public_key(text: str, location: str = "public key") -> DnsProfilePublicKey:
    public_key = PublicKey(_parse(text, PUBLIC_TAG, location))
    return DnsProfilePublicKey(key_id=key_id_of(public_key), key=public_key)


def parse_private_key(text: str, location: str = "private key") -> DnsProfilePrivateKey:
    private_key = PrivateKey(_parse(text, PRIVATE_TAG, location))
    return DnsProfilePrivateKey(key_id=key_id_of(private_key.public_key), key=private_key)


def read_public_key(path: Path) -> DnsProfilePublicKey:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyFileError(f"cannot read public key {path}: {exc.strerror}") from exc
    return parse_public_key(text, str(path))


def read_private_key(
    path: Path, *, require_secure: bool = True, owner: int = 0
) -> DnsProfilePrivateKey:
    """The private key, refused unless the file is its owner's alone.

    The owner is root for the DNS profile helper. The OIDC helper runs as an
    account of its own (B196), and passes that account's uid: the file must
    still be that one account's, 0600.

    `require_secure` is only ever relaxed by tests that build the files in a
    temporary directory; the helpers always hold it.
    """

    try:
        status = path.lstat()
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyFileError(f"cannot read private key {path}: {exc.strerror}") from exc
    if require_secure and (
        status.st_uid != owner or (status.st_mode & 0o777) != 0o600 or not path.is_file()
    ):
        who = "root" if owner == 0 else f"uid {owner}"
        raise KeyFileError(f"private key {path} must be a regular file owned by {who}, mode 0600")
    return parse_private_key(text, str(path))


def render_public_key(key: DnsProfilePublicKey) -> str:
    return f"{PUBLIC_TAG}:{bytes(key.key).hex()}\n"


def render_private_key(key: DnsProfilePrivateKey) -> str:
    return f"{PRIVATE_TAG}:{bytes(key.key).hex()}\n"


def seal(key: DnsProfilePublicKey, plaintext: bytes) -> bytes:
    """Encrypt for the holder of the private key; the sender keeps no way back."""

    return bytes(SealedBox(key.key).encrypt(plaintext))


def open_sealed(key: DnsProfilePrivateKey, ciphertext: bytes) -> bytes:
    try:
        return bytes(SealedBox(key.key).decrypt(ciphertext))
    except CryptoError as exc:
        raise KeyFileError("the ciphertext was not sealed against this key") from exc


def generate() -> tuple[DnsProfilePrivateKey, DnsProfilePublicKey]:
    private_key = PrivateKey.generate()
    key_id = key_id_of(private_key.public_key)
    return (
        DnsProfilePrivateKey(key_id=key_id, key=private_key),
        DnsProfilePublicKey(key_id=key_id, key=private_key.public_key),
    )


def write_key_pair(
    private_path: Path, public_path: Path, *, group: int | None = None
) -> DnsProfilePublicKey:
    """Create a new pair on disk: private root 0600, public root:group 0640.

    Both files are written to temporary names and renamed into place, and an
    existing file at either path is a refusal - a key is rotated by adding a
    pair, never by overwriting one, because a ciphertext in the database only
    decrypts with the key it was sealed against.
    """

    for path in (private_path, public_path):
        if path.exists() or path.is_symlink():
            raise KeyFileError(f"{path} already exists; a key is never overwritten")
    private_key, public_key = generate()
    _write_private(private_path, render_private_key(private_key))
    try:
        _write_public(public_path, render_public_key(public_key), group)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    return public_key


def _write_private(path: Path, text: str) -> None:
    atomic_file.write(path, text.encode("utf-8"), mode=0o600)


def _write_public(path: Path, text: str, group: int | None) -> None:
    atomic_file.write(path, text.encode("utf-8"), mode=0o640, gid=group)
