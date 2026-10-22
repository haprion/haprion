from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haprion import backup_archive
from haprion.backup_archive import REQUIRED_PATHS, ArchiveError, validate


class BackupArchiveTests(unittest.TestCase):
    def make_archive(
        self,
        root: Path,
        *,
        omit: str | None = None,
        wrong_checksum: str | None = None,
        omit_netplan: bool = False,
        hostname: bytes = b"node-a\n",
        manifest_text: str | None = None,
    ) -> Path:
        stage = root / "stage"
        for name in REQUIRED_PATHS:
            if name == omit:
                continue
            path = stage / name
            if name == "rootfs/etc/netplan":
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            content = hostname if name == "meta/hostname.txt" else f"{name}\n".encode()
            path.write_bytes(content)

        if not omit_netplan:
            netplan = stage / "rootfs/etc/netplan/50-haproxy.yaml"
            netplan.write_text("network: {version: 2}\n", encoding="utf-8")

        entries: list[dict[str, object]] = []
        for tree in (stage / "rootfs", stage / "meta"):
            for path in sorted(tree.rglob("*")):
                name = path.relative_to(stage).as_posix()
                info = path.lstat()
                entry: dict[str, object] = {
                    "path": name,
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                    "type": "directory" if path.is_dir() else "file",
                }
                if path.is_file():
                    content = path.read_bytes()
                    entry.update(
                        size=len(content),
                        sha256=(
                            "0" * 64
                            if name == wrong_checksum
                            else hashlib.sha256(content).hexdigest()
                        ),
                    )
                entries.append(entry)
        manifest = stage / "meta/manifest.json"
        manifest.write_text(
            manifest_text
            or json.dumps(
                {"schema_version": 1, "entries": entries},
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

        archive = root / "state.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(stage / "rootfs", arcname="rootfs")
            output.add(stage / "meta", arcname="meta")
        return archive

    def test_a_complete_manifest_bound_archive_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = self.make_archive(Path(raw))
            facts = validate(archive)

        self.assertEqual(facts.hostname, "node-a")
        self.assertGreaterEqual(facts.files, len(REQUIRED_PATHS) - 1)

    def test_missing_dr_state_is_refused(self) -> None:
        missing = "rootfs/etc/haprion/node-installation.json"
        with tempfile.TemporaryDirectory() as raw:
            archive = self.make_archive(Path(raw), omit=missing)
            with self.assertRaisesRegex(ArchiveError, missing):
                validate(archive)

    def test_content_that_disagrees_with_the_manifest_is_refused(self) -> None:
        changed = "rootfs/etc/keepalived/keepalived.conf"
        with tempfile.TemporaryDirectory() as raw:
            archive = self.make_archive(Path(raw), wrong_checksum=changed)
            with self.assertRaisesRegex(ArchiveError, "checksum"):
                validate(archive)

    def test_an_empty_netplan_directory_is_not_a_recoverable_node(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = self.make_archive(Path(raw), omit_netplan=True)
            with self.assertRaisesRegex(ArchiveError, "Netplan YAML"):
                validate(archive)

    def test_a_hostname_that_is_not_utf8_is_an_archive_error(self) -> None:
        """Code review 26-10-22, 5-11: a `UnicodeDecodeError` the caller did not
        catch stopped the backup of every node after this one."""

        with tempfile.TemporaryDirectory() as raw:
            archive = self.make_archive(Path(raw), hostname=b"node-\xff\n")
            with self.assertRaisesRegex(ArchiveError, "hostname"):
                validate(archive)

    def test_a_manifest_nested_past_the_parser_is_an_archive_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = self.make_archive(Path(raw), manifest_text="[" * 200_000)
            with self.assertRaisesRegex(ArchiveError, "not valid JSON"):
                validate(archive)

    def test_a_long_name_header_is_refused_before_it_is_read(self) -> None:
        """Code review 26-10-22, 5-5: tarfile reads a GNU long-name header whole,
        so a few hundred kilobytes compressed asked root for gigabytes."""

        import tracemalloc

        for name, form in (("GNU", tarfile.GNU_FORMAT), ("pax", tarfile.PAX_FORMAT)):
            with self.subTest(name), tempfile.TemporaryDirectory() as raw:
                archive = Path(raw) / "state.tar.gz"
                with tarfile.open(archive, "w:gz", format=form) as output:
                    info = tarfile.TarInfo("rootfs/" + "a" * (24 * 1024 * 1024))
                    output.addfile(info, io.BytesIO())
                tracemalloc.start()
                try:
                    with self.assertRaises(ArchiveError) as refused:
                        validate(archive)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()

                self.assertLess(peak, 4 * 1024 * 1024)
                self.assertIn("extended header", str(refused.exception))

    def test_the_member_limit_stops_reading_at_the_first_header_over_it(self) -> None:
        """S06 (security review 26-10-13): every header was parsed, and the data
        between them unpacked, before the count was looked at."""

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "many.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for number in range(50):
                    archive.addfile(tarfile.TarInfo(f"rootfs/empty-{number}"), io.BytesIO())
            parsed: list[str] = []
            real_next = tarfile.TarFile.next

            def counted(archive: tarfile.TarFile) -> tarfile.TarInfo | None:
                member = real_next(archive)
                if member is not None:
                    parsed.append(member.name)
                return member

            with (
                mock.patch.object(backup_archive, "MAX_MEMBERS", 5),
                mock.patch.object(tarfile.TarFile, "next", counted),
                self.assertRaisesRegex(ArchiveError, "number of members"),
            ):
                validate(path)
        # The limit plus the one over it; tarfile reads the first header once
        # more when it opens the archive. Before: all 50, and the trailer.
        self.assertEqual(len(parsed), 7)

    def test_a_path_outside_the_two_archive_roots_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = self.make_archive(root)
            unsafe = root / "unsafe.tar.gz"
            with tarfile.open(archive, "r:gz") as source, tarfile.open(unsafe, "w:gz") as output:
                for member in source.getmembers():
                    stream = source.extractfile(member) if member.isfile() else None
                    output.addfile(member, stream)
                member = tarfile.TarInfo("../outside")
                member.size = 0
                output.addfile(member)
            with self.assertRaisesRegex(ArchiveError, "unsafe path"):
                validate(unsafe)


if __name__ == "__main__":
    unittest.main()
