"""The HAProxy package repository a restored node gets, for its own distribution (B178, B179).

A restore no longer writes back the archive's APT sources: they name the
release the archive was taken on, and a node restored onto a newer Ubuntu or
onto Debian would be pointed at the wrong one. Instead the target gets the
HAProxy repository for its own distribution and codename, on the same branch
its neighbour runs - Vincent Bernat's PPA on Ubuntu, haproxy.debian.net on
Debian - and the distribution's own sources stay as the target has them.

The signing keys ship with the product and are held to a fingerprint written
here (B179). A key is never fetched at restore time: that would be trusting
whatever a server answers at that moment. A repository that changes its key
stops a restore until the key is updated here, which is the point.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from importlib.resources import files

#
# The installations a restore goes to (B178). Both write their network as
# Netplan when installed from their cloud images, which is what is supported.
#
SUPPORTED = frozenset({("ubuntu", "26.04"), ("debian", "13")})

KEYRINGS = "/etc/apt/keyrings"
SOURCES = "/etc/apt/sources.list.d"
PREFERENCES = "/etc/apt/preferences.d"
BRANCH = re.compile(r"^(?:\d+:)?(\d+\.\d+)\.")
CODENAME = re.compile(r"^[a-z]+$")


class RepositoryError(ValueError):
    """The repository cannot be written for this target."""


@dataclass(frozen=True, slots=True)
class Repository:
    key_file: str
    fingerprint: str
    uri: str
    suite: str
    #
    # haproxy.debian.net marks its suites NotAutomatic, so APT would keep
    # Debian's own older HAProxy without a pin. The PPA needs none: its
    # packages are simply newer than the distribution's.
    #
    pin_origin: str | None = None


REPOSITORIES = {
    #
    # Launchpad's API and keyserver.ubuntu.com both give this fingerprint, and
    # it is the key production nodes already trust (checked 2026-09-24).
    #
    "ubuntu": Repository(
        key_file="haproxy-ubuntu-ppa.asc",
        fingerprint="3D653970FBAB0A890E4E4E9A0F14D8B0CF4EFE96",
        uri="https://ppa.launchpadcontent.net/vbernat/haproxy-{branch}/ubuntu",
        suite="{codename}",
    ),
    #
    # The key haproxy.debian.net serves, which is the same key Debian's own
    # keyring holds for its maintainer (checked 2026-09-24).
    #
    "debian": Repository(
        key_file="haproxy-debian-net.asc",
        fingerprint="AEF2348766F371C689A7360095A42FE8353525F9",
        uri="https://haproxy.debian.net",
        suite="{codename}-backports-{branch}",
        pin_origin="PPA-haproxy",
    ),
}


@dataclass(frozen=True, slots=True)
class RepositoryFile:
    path: str
    data: bytes


def supported(os_release: dict[str, str]) -> bool:
    return (os_release.get("ID", ""), os_release.get("VERSION_ID", "")) in SUPPORTED


def branch_of(version: str) -> str:
    """`3.4` out of an installed version such as `3.4.4-1ppa1~resolute`."""

    found = BRANCH.match(version)
    if found is None:
        raise RepositoryError(f"the archive's HAProxy version {version!r} names no branch")
    return found.group(1)


def _packet(data: bytes) -> tuple[int, bytes]:
    """The first OpenPGP packet's tag and body (RFC 4880 §4.2)."""

    if not data or not data[0] & 0x80:
        raise RepositoryError("the key is not an OpenPGP packet")
    first = data[0]
    if first & 0x40:
        tag = first & 0x3F
        octet = data[1]
        if octet < 192:
            length, start = octet, 2
        elif octet < 224:
            length, start = ((octet - 192) << 8) + data[2] + 192, 3
        elif octet == 255:
            length, start = int.from_bytes(data[2:6], "big"), 6
        else:
            raise RepositoryError("the key's first packet has a partial length")
    else:
        tag = (first >> 2) & 0x0F
        size = {0: 1, 1: 2, 2: 4}.get(first & 0x03)
        if size is None:
            raise RepositoryError("the key's first packet has an indeterminate length")
        length, start = int.from_bytes(data[1 : 1 + size], "big"), 1 + size
    body = data[start : start + length]
    if len(body) != length:
        raise RepositoryError("the key is truncated")
    return tag, body


def fingerprint(armored: bytes) -> str:
    """The v4 fingerprint of an armored public key's primary key (RFC 4880 §12.2)."""

    lines = armored.decode("ascii").splitlines()
    try:
        begin = lines.index("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        end = lines.index("-----END PGP PUBLIC KEY BLOCK-----")
    except ValueError as exc:
        raise RepositoryError("the key is not an armored public key block") from exc
    block = lines[begin + 1 : end]
    body = block[block.index("") + 1 :] if "" in block else block
    encoded = "".join(line for line in body if not line.startswith("="))
    tag, packet = _packet(base64.b64decode(encoded, validate=True))
    if tag != 6 or not packet or packet[0] != 4:
        raise RepositoryError("the key's primary packet is not a version 4 public key")
    digest = hashlib.sha1(b"\x99" + len(packet).to_bytes(2, "big") + packet)  # noqa: S324
    return digest.hexdigest().upper()


def key(distribution: str) -> bytes:
    """The shipped key for a distribution, refused unless it is the pinned one."""

    repository = REPOSITORIES[distribution]
    data = files("haprion").joinpath("apt-keys", repository.key_file).read_bytes()
    if fingerprint(data) != repository.fingerprint:
        raise RepositoryError(
            f"{repository.key_file} is not the key {repository.fingerprint}; "
            "a shipped repository key was changed without its fingerprint"
        )
    return data


def repository_files(os_release: dict[str, str], branch: str) -> tuple[RepositoryFile, ...]:
    """The key, the deb822 source and, where needed, the pin - for this target."""

    distribution = os_release.get("ID", "")
    codename = os_release.get("VERSION_CODENAME", "")
    if not supported(os_release):
        raise RepositoryError(
            f"{distribution} {os_release.get('VERSION_ID', '')} is not a supported target; "
            "restore onto Ubuntu 26.04 or Debian 13"
        )
    if not CODENAME.fullmatch(codename):
        raise RepositoryError("the target's os-release names no release codename")
    if not re.fullmatch(r"\d+\.\d+", branch):
        raise RepositoryError(f"{branch!r} is not a HAProxy branch")
    repository = REPOSITORIES[distribution]
    keyring = f"{KEYRINGS}/{repository.key_file}"
    source = (
        "Types: deb\n"
        f"URIs: {repository.uri.format(branch=branch)}\n"
        f"Suites: {repository.suite.format(codename=codename, branch=branch)}\n"
        "Components: main\n"
        f"Signed-By: {keyring}\n"
    )
    written = [
        RepositoryFile(keyring, key(distribution)),
        RepositoryFile(f"{SOURCES}/haproxy-{branch}.sources", source.encode()),
    ]
    if repository.pin_origin is not None:
        pin = (
            "Package: haproxy*\n"
            f"Pin: release o={repository.pin_origin},n="
            f"{repository.suite.format(codename=codename, branch=branch)}\n"
            "Pin-Priority: 600\n"
        )
        written.append(RepositoryFile(f"{PREFERENCES}/haproxy-{branch}.pref", pin.encode()))
    return tuple(written)
