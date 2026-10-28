"""The SCEP client package: pinned inputs, its bundle, installed by step 16 (B381, B383)."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

BASE = Path(__file__).resolve().parents[1]


def tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "build_scep_package", BASE / "tools/build-scep-package.py"
    )
    assert spec is not None and spec.loader is not None  # local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = tool()
BUNDLE = "certmonger-0.79.21-1-ubuntu-26.04-amd64.zip"


class ThePostinst(unittest.TestCase):
    """Run as written, with its fixed paths moved under a temporary directory."""

    def install(self, raw: str, *, set_up: bool, step_fails: bool = False) -> tuple[Path, str]:
        top = Path(raw)
        root, lib, step = top / "opt/haprion-scep", top / "usr/lib/haprion/scep", top / "step16"
        lib.mkdir(parents=True)
        (lib / "PAYLOAD").write_text(f"BUNDLE={BUNDLE}\nBUNDLE_SHA256={'0' * 64}\n")
        step.write_text(
            '#!/bin/sh\necho "step 16 $*"\necho "SCEP runtime library check failed" >&2\nexit 1\n'
            if step_fails
            else '#!/bin/sh\necho "step 16 $*"\n'
        )
        step.chmod(0o755)
        if set_up:
            (root / "releases/0.79.21-1-old").mkdir(parents=True)
            (root / "current").symlink_to("releases/0.79.21-1-old")
        script = (
            TOOL.POSTINST.replace(TOOL.ROOT, str(root))
            .replace(f"/{TOOL.LIB}", str(lib))
            .replace(TOOL.STEP, str(step))
        )
        done = subprocess.run(
            ["/bin/sh", "-c", script, "postinst", "configure"],
            capture_output=True,
            text=True,
            check=True,
        )
        return lib, done.stdout + done.stderr

    def test_a_first_installation_leaves_it_to_setup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            _, said = self.install(raw, set_up=False)

            self.assertNotIn("step 16", said)
            self.assertIn("haprion-setup installs it", said)

    def test_a_manager_with_the_client_installs_the_new_bundle_without_apt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lib, said = self.install(raw, set_up=True)

            self.assertIn(f"step 16 {lib}/{BUNDLE} {'0' * 64} --no-satisfy", said)

    def test_a_failed_install_is_said_and_does_not_fail_the_package(self) -> None:
        """The interface depends on this package; a refused bundle must not leave it unconfigured."""

        with tempfile.TemporaryDirectory() as raw:
            _, said = self.install(raw, set_up=True, step_fails=True)

            self.assertIn(f"the SCEP client {BUNDLE} was not installed", said)
            self.assertIn("the previous client stays current", said)


class ThePins(unittest.TestCase):
    def test_every_distribution_the_interface_is_built_for_has_one(self) -> None:
        self.assertEqual(set(TOOL.PINS), set(TOOL.ui.DISTRIBUTIONS))

    def test_each_pins_a_package_and_its_complete_source_by_digest(self) -> None:
        for name, pin in TOOL.PINS.items():
            with self.subTest(distribution=name):
                self.assertTrue(pin.pool.startswith("https://"))
                self.assertTrue(pin.pool.endswith("/certmonger/"))
                upstream = pin.version.split("-", 1)[0]
                self.assertEqual(pin.orig[0], f"certmonger_{upstream}.orig.tar.gz")
                self.assertEqual(pin.debian[0], f"certmonger_{pin.version}.debian.tar.xz")
                for digest in (pin.deb, pin.dsc, pin.orig[1], pin.debian[1]):
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_other_bytes_than_the_pinned_ones_are_refused(self) -> None:
        answer = mock.MagicMock()
        answer.__enter__.return_value.read.return_value = b"other bytes"
        with (
            mock.patch.object(TOOL.urllib.request, "urlopen", return_value=answer),
            self.assertRaisesRegex(TOOL.ui.BuildError, "not the pinned file"),
        ):
            TOOL.fetch("https://archive.example.com/certmonger.deb", "0" * 64)


class WhatTheSetupReads(unittest.TestCase):
    def test_the_interface_needs_it(self) -> None:
        self.assertIn("haprion-scep", TOOL.ui.depends("3.13", 1).split(", "))

    def test_the_setup_reads_the_payload_the_package_writes(self) -> None:
        setup = (BASE / "install/haprion-setup").read_text()
        self.assertIn(f'SCEP_PAYLOAD="/{TOOL.LIB}/PAYLOAD"', setup)
        self.assertIn("s/^BUNDLE=//p", setup)
        self.assertIn("s/^BUNDLE_SHA256=//p", setup)
        self.assertIn(f"16-platform-scep /{TOOL.LIB}/${{scep_bundle}}", setup)
        self.assertTrue(TOOL.STEP.endswith("/install/platform/16-platform-scep"))
        self.assertTrue((BASE / "install/platform/16-platform-scep").is_file())

    def test_the_release_build_makes_it_for_each_distribution(self) -> None:
        text = (BASE / "tools/build-release-packages").read_text()
        self.assertIn('tools / "build-scep-package.py"', text)


@unittest.skipUnless(
    Path("/usr/bin/dpkg-deb").is_file() and Path("/usr/bin/git").is_file(), "needs dpkg-deb and git"
)
class TheBuild(unittest.TestCase):
    """A package from fixture inputs: what the archive's pool would serve, imitated."""

    def test_the_package_carries_the_bundle_and_certmonger_s_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            top = Path(raw)
            files = self.fixture(top / "pool")
            pin = TOOL.Pin(
                "ubuntu",
                "26.04",
                "https://archive.example.com/pool/c/certmonger/",
                "0.79.21-1",
                hashlib.sha256(files["certmonger_0.79.21-1_amd64.deb"]).hexdigest(),
                hashlib.sha256(files["certmonger_0.79.21-1.dsc"]).hexdigest(),
                (
                    "certmonger_0.79.21.orig.tar.gz",
                    hashlib.sha256(files["certmonger_0.79.21.orig.tar.gz"]).hexdigest(),
                ),
                (
                    "certmonger_0.79.21-1.debian.tar.xz",
                    hashlib.sha256(files["certmonger_0.79.21-1.debian.tar.xz"]).hexdigest(),
                ),
            )

            def fetch(url: str, digest: str) -> bytes:
                data = files[url.rsplit("/", 1)[-1]]
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                return data

            source = self.repository(top / "src")
            with (
                mock.patch.dict(TOOL.PINS, {"ubuntu26.04": pin}),
                mock.patch.object(TOOL, "fetch", side_effect=fetch),
                mock.patch.object(
                    TOOL.client,
                    "osv_query",
                    side_effect=lambda body: (
                        {"vulns": [{"affected": [{"package": {"ecosystem": "Ubuntu:26.04:LTS"}}]}]}
                        if body["package"]["name"] == "openssl"
                        else {}
                    ),
                ),
            ):
                built = TOOL.build(source, top / "out", "ubuntu26.04")

            fields = self.fields(built)
            self.assertEqual(fields["Package"], "haprion-scep")
            self.assertRegex(
                fields["Version"], r"^0\.79\.21\+git\d{14}\.[0-9a-f]{12}~ubuntu26\.04$"
            )
            self.assertEqual(fields["Depends"], "python3, libc6 (>= 2.38), dbus")
            listed = subprocess.run(
                ["/usr/bin/dpkg-deb", "--contents", str(built)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertIn(f"./usr/lib/haprion/scep/{BUNDLE}", listed)
            self.assertIn("./usr/lib/haprion/scep/PAYLOAD", listed)

    def fixture(self, pool: Path) -> dict[str, bytes]:
        """certmonger as a pool serves it: package, source description and archives."""

        tree = pool / "tree"
        (tree / "DEBIAN").mkdir(parents=True)
        (tree / "DEBIAN/control").write_text(
            "Package: certmonger\nVersion: 0.79.21-1\nArchitecture: amd64\n"
            "Maintainer: Example <admin@example.com>\nDescription: test package\n"
            "Depends: libc6 (>= 2.38), dbus\n"
        )
        for member in TOOL.client.PROGRAMS.values():
            target = tree / member.removeprefix("./")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"\x7fELFexample" if "copyright" not in member else b"license")
        deb = pool / "certmonger_0.79.21-1_amd64.deb"
        subprocess.run(
            ["/usr/bin/dpkg-deb", "--build", "--root-owner-group", str(tree), str(deb)],
            check=True,
            capture_output=True,
        )
        files = {deb.name: deb.read_bytes()}
        rows = []
        for name in ("certmonger_0.79.21.orig.tar.gz", "certmonger_0.79.21-1.debian.tar.xz"):
            files[name] = f"example {name}".encode()
            rows.append(f" {hashlib.sha256(files[name]).hexdigest()} {len(files[name])} {name}")
        files["certmonger_0.79.21-1.dsc"] = (
            "Source: certmonger\nVersion: 0.79.21-1\nChecksums-Sha256:\n"
            + "\n".join(rows)
            + "\nFiles:\n"
        ).encode()
        return files

    def repository(self, path: Path) -> Path:
        path.mkdir()
        (path / "LICENSE").write_text("example license\n")
        for command in (
            ["init", "-q"],
            ["add", "LICENSE"],
            ["-c", "user.name=admin", "-c", "user.email=admin@example.com", "commit", "-qm", "x"],
        ):
            subprocess.run(
                ["/usr/bin/git", "-C", str(path), *command], check=True, capture_output=True
            )
        return path

    def fields(self, built: Path) -> dict[str, str]:
        control = subprocess.run(
            ["/usr/bin/dpkg-deb", "--field", str(built)], capture_output=True, text=True, check=True
        ).stdout
        return dict(
            line.split(": ", 1) for line in control.splitlines() if ": " in line and line[0] != " "
        )


if __name__ == "__main__":
    unittest.main()
