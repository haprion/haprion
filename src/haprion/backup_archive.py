"""Validate one node state archive without extracting it.

The archive is a disaster-recovery input, not merely a gzip file.  A valid tar
whose node configuration, host key or management scripts are absent is still
an unusable backup.  The node exporter therefore writes ``meta/manifest.json``
after staging every other path, and this module checks the archive against that
manifest before the manager gives it a permanent name.

Nothing is extracted here.  That both avoids traversal as a class of bug and
keeps validation from briefly placing password hashes or private keys anywhere
except the root-only archive file the backup engine already owns.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST = "meta/manifest.json"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
#
# What a header that carries no file - a GNU long name or link, a pax extended
# header - may declare. tarfile reads such a header whole, at the size it
# declares, before it yields the member it belongs to: an archive of 0.4 MB
# compressed made root allocate 2.4 GiB (code review 2026-10-22, 5-5). Newer
# Pythons read it in 1 MiB chunks, which bounds each allocation but not the
# sum, so the size is refused before the first byte is read.
#
MAX_EXTENDED_HEADER_BYTES = 64 * 1024
_EXTENDED_HEADER_TYPES = frozenset(
    {
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
    }
)
#
# PATH_MAX. Longer is no file a node exports, and every message below names
# the path.
#
MAX_NAME_CHARACTERS = 4096

# These are the minimum state a clean node needs before the rebuild path can
# restore identity and let central management put current configuration and
# certificates back.  Optional traffic-log configuration is checked separately
# by the exporter when enabled; its scripts are always part of the node package.
REQUIRED_PATHS = frozenset(
    {
        "rootfs/etc/hostname",
        "rootfs/etc/hosts",
        "rootfs/etc/netplan",
        "rootfs/etc/keepalived/keepalived.conf",
        "rootfs/etc/keepalived/addresses.conf",
        "rootfs/etc/default/haproxy",
        "rootfs/etc/sysctl.d/60-haproxy.conf",
        "rootfs/etc/haprion/node.conf",
        "rootfs/etc/haprion/node-installation.json",
        "rootfs/etc/ssh/sshd_config",
        "rootfs/etc/ssh/ssh_host_ed25519_key",
        "rootfs/etc/ssh/ssh_host_ed25519_key.pub",
        "rootfs/usr/sbin/haprion-pull-deploy",
        "rootfs/usr/sbin/haprion-cert-pull",
        "rootfs/usr/sbin/haprion-cert-remove",
        "rootfs/usr/sbin/haprion-cert-trigger",
        "rootfs/usr/sbin/haprion-node-status",
        "rootfs/usr/sbin/haprion-health-probe",
        "rootfs/usr/sbin/haprion-keepalived-state",
        "rootfs/usr/sbin/haprion-state-export",
        "rootfs/usr/sbin/haprion-traffic-log-read",
        "rootfs/usr/sbin/haprion-traffic-log-enable",
        "rootfs/usr/sbin/haprion-traffic-log-prune",
        "rootfs/usr/sbin/haprion-server-state",
        "rootfs/usr/sbin/haprion-server-state-trigger",
        "meta/backup-created.txt",
        "meta/hostname.txt",
        "meta/fqdn.txt",
        "meta/os-release",
        "meta/users.txt",
        "meta/groups.txt",
        "meta/group-definitions.txt",
        "meta/shadow.txt",
        "meta/packages.txt",
        "meta/package-versions.txt",
        "meta/services.txt",
    }
)


class ArchiveError(ValueError):
    """The stream is not a complete, internally consistent DR archive."""


@dataclass(frozen=True, slots=True)
class ArchiveFacts:
    members: int
    files: int
    size_bytes: int
    hostname: str

    def as_dict(self) -> dict[str, int | str]:
        return {
            "members": self.members,
            "files": self.files,
            "size_bytes": self.size_bytes,
            "hostname": self.hostname,
        }


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise ArchiveError("the archive contains an unsafe path")
    canonical = path.as_posix().removeprefix("./")
    if canonical not in {"rootfs", "meta"} and not canonical.startswith(("rootfs/", "meta/")):
        raise ArchiveError(f"the archive contains a path outside rootfs and meta: {canonical}")
    return canonical


def _type(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    raise ArchiveError(f"the archive contains an unsupported file type: {member.name}")


def _manifest(document: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "entries"}:
        raise ArchiveError("the archive manifest is not a versioned entries object")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise ArchiveError("the archive manifest schema_version is not 1")
    entries = document["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_MEMBERS:
        raise ArchiveError("the archive manifest has an invalid number of entries")
    indexed: dict[str, dict[str, Any]] = {}
    for raw in entries:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            raise ArchiveError("the archive manifest contains an invalid entry")
        name = _safe_name(raw["path"])
        if name in indexed or name in {"rootfs", "meta", MANIFEST}:
            raise ArchiveError("the archive manifest contains a duplicate or reserved path")
        if raw.get("type") not in {"file", "directory", "symlink"}:
            raise ArchiveError(f"the archive manifest has an invalid type for {name}")
        for field in ("mode", "uid", "gid"):
            value = raw.get(field)
            if type(value) is not int or value < 0:
                raise ArchiveError(f"the archive manifest has invalid {field} for {name}")
        indexed[name] = raw
    return indexed


class _BoundedTarInfo(tarfile.TarInfo):
    """A header, refused when it is an extended one larger than `MAX_EXTENDED_HEADER_BYTES`.

    `_proc_member` is where tarfile turns a header into a member and, for the
    extended types, reads their data; the size is in the header already.
    """

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        if self.type in _EXTENDED_HEADER_TYPES and self.size > MAX_EXTENDED_HEADER_BYTES:
            raise ArchiveError("the state export has an extended header over the size limit")
        member: tarfile.TarInfo = super()._proc_member(archive)  # type: ignore[misc]
        return member


def validate(path: Path) -> ArchiveFacts:
    """Return bounded, non-secret facts after validating every manifest entry."""

    try:
        archive_size = path.stat().st_size
        if not 1 <= archive_size <= MAX_ARCHIVE_BYTES:
            raise ArchiveError("the state export has an invalid compressed size")
        # Opened separately so parse failures become the same bounded archive
        # error; the context immediately below owns and closes it.
        archive = tarfile.open(path, mode="r:gz", tarinfo=_BoundedTarInfo)  # noqa: SIM115
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise ArchiveError("the state export is not a readable tar.gz archive") from exc

    with archive:
        #
        # One header at a time, stopped at the first one over a limit: with
        # `getmembers()` every header was parsed, and the data between them
        # decompressed, before the count was looked at (security review
        # 26-10-13, S06). Reading on to the next header passes through this
        # member's data, so the running size also bounds what is unpacked.
        #
        members: list[tarfile.TarInfo] = []
        unpacked = 0
        try:
            for member in archive:
                if len(member.name) > MAX_NAME_CHARACTERS:
                    raise ArchiveError("the state export has a path name over the limit")
                members.append(member)
                unpacked += member.size
                if len(members) > MAX_MEMBERS:
                    raise ArchiveError("the state export has an invalid number of members")
                if unpacked > MAX_UNPACKED_BYTES:
                    raise ArchiveError("the state export is too large when unpacked")
        except (OSError, EOFError, tarfile.TarError) as exc:
            raise ArchiveError("the state export is not a readable tar.gz archive") from exc
        if not members:
            raise ArchiveError("the state export has an invalid number of members")
        indexed: dict[str, tarfile.TarInfo] = {}
        for member in members:
            name = _safe_name(member.name)
            _type(member)
            if name in indexed:
                raise ArchiveError(f"the state export contains a duplicate path: {name}")
            indexed[name] = member

        if any(name not in indexed or not indexed[name].isdir() for name in ("rootfs", "meta")):
            raise ArchiveError("the state export roots are not directories")

        manifest_member = indexed.get(MANIFEST)
        if manifest_member is None or not manifest_member.isfile():
            raise ArchiveError("the state export has no file manifest")
        if manifest_member.size > MAX_MANIFEST_BYTES:
            raise ArchiveError("the state export manifest is too large")
        stream = archive.extractfile(manifest_member)
        if stream is None:
            raise ArchiveError("the state export manifest cannot be read")
        try:
            document = json.loads(stream.read(MAX_MANIFEST_BYTES + 1).decode("utf-8"))
        except (ValueError, RecursionError) as exc:
            raise ArchiveError("the state export manifest is not valid JSON") from exc
        declared = _manifest(document)

        actual_names = set(indexed) - {"rootfs", "meta", MANIFEST}
        if set(declared) != actual_names:
            missing = sorted(set(declared) - actual_names)
            extra = sorted(actual_names - set(declared))
            detail = missing[0] if missing else extra[0]
            raise ArchiveError(f"the state export disagrees with its manifest at {detail}")
        missing_required = sorted(REQUIRED_PATHS - set(declared))
        if missing_required:
            raise ArchiveError(
                f"the state export is missing required DR state: {missing_required[0]}"
            )
        netplan_files = {
            name
            for name, entry in declared.items()
            if name.startswith("rootfs/etc/netplan/")
            and name.endswith((".yaml", ".yml"))
            and entry["type"] == "file"
        }
        if not netplan_files:
            raise ArchiveError("the state export is missing required DR state: a Netplan YAML file")

        file_count = 0
        for name, expected in declared.items():
            member = indexed[name]
            kind = _type(member)
            if kind != expected["type"]:
                raise ArchiveError(f"the state export type differs from its manifest at {name}")
            if (
                member.mode != expected["mode"]
                or member.uid != expected["uid"]
                or member.gid != expected["gid"]
            ):
                raise ArchiveError(f"the state export metadata differs from its manifest at {name}")
            if kind == "symlink":
                if member.linkname != expected.get("target"):
                    raise ArchiveError(f"the state export link differs from its manifest at {name}")
                continue
            if kind != "file":
                continue
            file_count += 1
            if member.size != expected.get("size"):
                raise ArchiveError(f"the state export size differs from its manifest at {name}")
            source = archive.extractfile(member)
            if source is None:
                raise ArchiveError(f"the state export cannot read {name}")
            digest = hashlib.sha256()
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
            if digest.hexdigest() != expected.get("sha256"):
                raise ArchiveError(f"the state export checksum differs from its manifest at {name}")

        hostname_member = indexed["meta/hostname.txt"]
        hostname_stream = archive.extractfile(hostname_member)
        try:
            hostname = (
                "" if hostname_stream is None else hostname_stream.read(256).decode("utf-8").strip()
            )
        except UnicodeDecodeError as exc:
            raise ArchiveError("the state export carries an invalid hostname") from exc
        if not hostname or len(hostname) > 253 or any(char.isspace() for char in hostname):
            raise ArchiveError("the state export carries an invalid hostname")
        return ArchiveFacts(
            members=len(indexed), files=file_count, size_bytes=archive_size, hostname=hostname
        )
