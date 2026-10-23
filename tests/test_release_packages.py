"""The release build and the repository key (B325)."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

BASE = Path(__file__).resolve().parents[1]


def load(name: str, relative: str) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(BASE / relative))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


RELEASE = load("build_release_packages", "tools/build-release-packages")
KEYRING = load("build_keyring_package", "tools/build-keyring-package.py")
ENGINE = load("build_coraza_package_release", "tools/build-coraza-package.py")
REPO = load("build_apt_repo", "tools/build-apt-repo")
sys.path.insert(0, str(BASE / "src"))
from haprion.debian_package import package, write  # noqa: E402 - after the path


class TheToolchainIsPinned(unittest.TestCase):
    def test_the_engine_go_has_its_digest(self) -> None:
        # A Go bump in the engine tool without its archive digest fails here,
        # not in CI after the tag.
        self.assertIn(ENGINE.GO_VERSION, RELEASE.GO_ARCHIVES)
        for digest in RELEASE.GO_ARCHIVES.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_the_engine_tool_is_read_from_the_tree(self) -> None:
        # The build reads the pins from the tree it builds; a loader that could
        # not import the tool stopped the first full build (26-10-17).
        tool = RELEASE.engine_tool(BASE)
        self.assertEqual(tool.GO_VERSION, ENGINE.GO_VERSION)
        self.assertEqual(tool.CORAZA.sha256, ENGINE.CORAZA.sha256)

    def test_a_relative_cache_is_made_absolute_before_go_sees_it(self) -> None:
        # `--cache packages/x` stopped `go install`: GOPATH must be absolute.
        class Stop(Exception):
            pass

        seen: list[Path] = []

        def fetched(sources: Path, *_: str) -> Path:
            seen.append(sources)
            raise Stop

        pin = SimpleNamespace(file="x", url="https://example.org/x", sha256="0" * 64)
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "tree"
            tree.mkdir()
            git = [
                "/usr/bin/git",
                "-C",
                str(tree),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.org",
            ]
            subprocess.run([*git, "init", "-q"], check=True)  # fixed arguments
            subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "t"], check=True)
            os.chdir(directory)
            with (
                unittest.mock.patch.object(
                    RELEASE, "engine_tool", return_value=SimpleNamespace(CORAZA=pin, CRS=pin)
                ),
                unittest.mock.patch.object(RELEASE, "fetched", side_effect=fetched),
                self.assertRaises(Stop),
            ):
                RELEASE.build(tree, Path("out"), Path("uv"), Path("cache"), "podman")
        self.assertTrue(seen[0].is_absolute())

    def test_only_https_is_fetched(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RELEASE.BuildError):
            RELEASE.fetched(Path(directory), "x", "http://example.org/x", "0" * 64)

    def test_a_cached_file_with_other_bytes_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "x").write_bytes(b"other")
            with self.assertRaises(RELEASE.BuildError):
                RELEASE.fetched(Path(directory), "x", "https://example.org/x", "0" * 64)


class TheKeyIsTheOneThePackageNames(unittest.TestCase):
    def test_the_key_file_has_the_pinned_digest(self) -> None:
        key = (BASE / KEYRING.KEY_FILE).read_bytes()
        self.assertEqual(
            hashlib.sha256(key).hexdigest(), KEYRING.PINNED_SHA256, "new key: new VERSION too"
        )

    def test_the_key_is_public_only(self) -> None:
        key = (BASE / KEYRING.KEY_FILE).read_text()
        self.assertTrue(key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"))
        self.assertNotIn("PRIVATE", key)


@unittest.skipUnless(shutil.which("dpkg-deb") and shutil.which("git"), "needs dpkg-deb and git")
class TheKeyringPackage(unittest.TestCase):
    def tree(self, directory: Path) -> Path:
        """A commit holding the key file, as the package is built from one."""
        tree = directory / "tree"
        (tree / "keys").mkdir(parents=True)
        shutil.copyfile(BASE / KEYRING.KEY_FILE, tree / KEYRING.KEY_FILE)
        env = {
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.org",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.org",
            "GIT_AUTHOR_DATE": "2026-10-17T12:00:00Z",
            "GIT_COMMITTER_DATE": "2026-10-17T12:00:00Z",
        }
        for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "key"]):
            subprocess.run(["/usr/bin/git", "-C", str(tree), *command], check=True, env=env)
        return tree

    def test_same_commit_same_bytes_and_the_key_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tree = self.tree(Path(directory))
            first = KEYRING.build(tree, Path(directory) / "a")
            second = KEYRING.build(tree, Path(directory) / "b")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.name, f"haprion-archive-keyring_{KEYRING.VERSION}_all.deb")
            listing = subprocess.run(
                ["/usr/bin/dpkg-deb", "--contents", str(first)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("./" + KEYRING.TARGET, listing)

    def test_another_key_without_a_new_version_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tree = self.tree(Path(directory))
            (tree / KEYRING.KEY_FILE).write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nother\n")
            env = {
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.org",
                "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.org",
            }
            subprocess.run(
                ["/usr/bin/git", "-C", str(tree), "commit", "-qam", "other"], check=True, env=env
            )
            with self.assertRaises(KEYRING.KeyringError):
                KEYRING.build(tree, Path(directory) / "a")


def fake_deb(
    directory: Path, name: str, version: str, architecture: str = "all", marker: bytes = b""
) -> Path:
    with tempfile.TemporaryDirectory() as tree:
        root = Path(tree) / "root"
        write(root, f"usr/share/doc/{name}/marker", marker or version.encode(), 0o644)
        fields = {
            "Package": name,
            "Version": version,
            "Architecture": architecture,
            "Section": "misc",
            "Priority": "optional",
            "Description": "test\n test package",
        }
        return package(root, fields, directory, 1_700_000_000)


@unittest.skipUnless(
    shutil.which("dpkg-deb") and shutil.which("gpg") and shutil.which("gpgv"),
    "needs dpkg-deb and gpg",
)
class TheRepository(unittest.TestCase):
    work: ClassVar[Path]
    signing_key: ClassVar[Path]
    public: ClassVar[Path]
    keyring: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        cls.work = Path(tempfile.mkdtemp(prefix="haprion-repo-test-"))
        home = cls.work / "gnupg"
        home.mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "GNUPGHOME": str(home)}
        gpg = [
            "/usr/bin/gpg",
            "--batch",
            "--quiet",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]
        subprocess.run(
            [*gpg, "--quick-gen-key", "test", "ed25519", "sign", "1d"], check=True, env=env
        )
        cls.signing_key = cls.work / "signing.asc"
        cls.public = cls.work / "public.asc"
        cls.signing_key.write_bytes(
            subprocess.run(
                [*gpg, "--armor", "--export-secret-keys"], check=True, env=env, capture_output=True
            ).stdout
        )
        cls.public.write_bytes(
            subprocess.run(
                [*gpg, "--armor", "--export"], check=True, env=env, capture_output=True
            ).stdout
        )
        cls.keyring = cls.work / "public.gpg"
        cls.keyring.write_bytes(
            subprocess.run([*gpg, "--export"], check=True, env=env, capture_output=True).stdout
        )
        subprocess.run(["/usr/bin/gpgconf", "--kill", "all"], check=False, env=env)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.work)

    def releases(self) -> list[Path]:
        old, new = self.work / f"{self.id()}-old", self.work / f"{self.id()}-new"
        for directory in (old, new):
            directory.mkdir()
        fake_deb(old, "haprion-node", "0.8.0+git1.a")
        fake_deb(old, "haprion-ui", "0.8.0+git1.a~deb13", "amd64")
        fake_deb(old, "haprion-ui", "0.8.0+git1.a~ubuntu26.04", "amd64")
        fake_deb(new, "haprion-node", "0.9.0+git2.b")
        fake_deb(new, "haprion-node", "0.10.0+git3.c")
        fake_deb(new, "haprion-ui", "0.9.0+git2.b~deb13", "amd64")
        return [old, new]

    def site(self, keep: int = 2) -> Path:
        site = self.work / f"{self.id()}-site"
        REPO.build(
            self.releases(), site, self.signing_key, self.public, keep, REPO.datetime.now(REPO.UTC)
        )
        return site

    def packages(self, site: Path, suite: str) -> list[tuple[str, str]]:
        text = (site / "dists" / suite / "main/binary-amd64/Packages").read_text()
        found = []
        for block in text.strip().split("\n\n"):
            fields = dict(
                line.split(": ", 1)
                for line in block.splitlines()
                if ": " in line and not line.startswith(" ")
            )
            found.append((fields["Package"], fields["Version"]))
        return found

    def test_a_suffix_is_one_suite_and_none_is_both(self) -> None:
        site = self.site()
        self.assertIn(
            ("haprion-ui", "0.8.0+git1.a~ubuntu26.04"), self.packages(site, "ubuntu26.04")
        )
        self.assertNotIn(("haprion-ui", "0.8.0+git1.a~ubuntu26.04"), self.packages(site, "deb13"))
        for suite in REPO.SUITES:
            self.assertIn(("haprion-node", "0.10.0+git3.c"), self.packages(site, suite))

    def test_the_newest_versions_stay_as_dpkg_orders_them(self) -> None:
        # 0.10 is newer than 0.9 to dpkg, older to a string comparison.
        nodes = [v for p, v in self.packages(self.site(keep=2), "deb13") if p == "haprion-node"]
        self.assertEqual(nodes, ["0.9.0+git2.b", "0.10.0+git3.c"])

    def test_release_is_signed_and_names_the_indexes(self) -> None:
        site = self.site()
        suite = site / "dists" / "deb13"
        for signed in (
            ["--keyring", str(self.keyring), str(suite / "InRelease")],
            ["--keyring", str(self.keyring), str(suite / "Release.gpg"), str(suite / "Release")],
        ):
            subprocess.run(["/usr/bin/gpgv", *signed], check=True, capture_output=True)
        release = (suite / "Release").read_text()
        packages = suite / "main/binary-amd64/Packages"
        self.assertIn(f" {hashlib.sha256(packages.read_bytes()).hexdigest()} ", release)
        self.assertNotIn("Valid-Until", release)
        for name in ("haprion-archive-keyring.asc", "index.html", ".nojekyll"):
            self.assertTrue((site / name).exists(), name)

    def test_pool_holds_what_the_index_names(self) -> None:
        site = self.site()
        text = (site / "dists/deb13/main/binary-amd64/Packages").read_text()
        for line in text.splitlines():
            if line.startswith("Filename: "):
                self.assertTrue((site / line.removeprefix("Filename: ")).is_file(), line)

    def test_one_version_with_two_files_is_refused(self) -> None:
        releases = self.releases()
        fake_deb(releases[0], "haprion-crs", "4.25.2-1", marker=b"one")
        other = self.work / f"{self.id()}-other"
        other.mkdir()
        fake_deb(other, "haprion-crs", "4.25.2-1", marker=b"two")
        with self.assertRaises(REPO.RepoError):
            REPO.build(
                [*releases, other],
                self.work / f"{self.id()}-x",
                self.signing_key,
                self.public,
                2,
                REPO.datetime.now(REPO.UTC),
            )

    def test_a_site_with_content_is_not_overwritten(self) -> None:
        site = self.work / f"{self.id()}-busy"
        site.mkdir()
        (site / "old").write_text("x")
        with self.assertRaises(REPO.RepoError):
            REPO.build(
                self.releases(), site, self.signing_key, self.public, 2, REPO.datetime.now(REPO.UTC)
            )

    def serve(self, site: Path) -> Any:
        def get(url: str) -> bytes:
            path = site / url.removeprefix("https://example.org/repo/")
            if not path.is_file():
                raise REPO.urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return path.read_bytes()

        return unittest.mock.patch.object(REPO, "_get", get)

    def test_the_site_is_the_starting_point(self) -> None:
        # An engine update built on main is on the site only; the next release keeps it.
        site = self.site()
        kept = self.work / f"{self.id()}-kept"
        with self.serve(site):
            count = REPO.fetch_site("https://example.org/repo", self.public, kept)
        self.assertEqual(count, len(list((site / "pool").rglob("*.deb"))))
        newer = self.work / f"{self.id()}-newer"
        newer.mkdir()
        fake_deb(newer, "haprion-coraza-spoa", "0.9.0-9", "amd64")
        again = self.work / f"{self.id()}-again"
        REPO.build(
            [kept, newer], again, self.signing_key, self.public, 2, REPO.datetime.now(REPO.UTC)
        )
        names = self.packages(again, "deb13")
        self.assertIn(("haprion-coraza-spoa", "0.9.0-9"), names)
        self.assertIn(("haprion-node", "0.10.0+git3.c"), names)

    def test_an_empty_site_gives_nothing(self) -> None:
        empty = self.work / f"{self.id()}-empty"
        empty.mkdir()
        with self.serve(empty):
            self.assertEqual(
                REPO.fetch_site(
                    "https://example.org/repo", self.public, self.work / f"{self.id()}-k"
                ),
                0,
            )

    def test_a_changed_index_is_refused(self) -> None:
        site = self.site()
        index = site / "dists/deb13/main/binary-amd64/Packages"
        index.write_text(index.read_text().replace("Section: misc", "Section: evil", 1))
        with self.serve(site), self.assertRaises(REPO.RepoError):
            REPO.fetch_site("https://example.org/repo", self.public, self.work / f"{self.id()}-k")

    def test_a_changed_package_is_refused(self) -> None:
        site = self.site()
        deb = next((site / "pool").rglob("*.deb"))
        deb.write_bytes(deb.read_bytes() + b"x")
        with self.serve(site), self.assertRaises(REPO.RepoError):
            REPO.fetch_site("https://example.org/repo", self.public, self.work / f"{self.id()}-k")

    def test_another_key_is_refused(self) -> None:
        site = self.site()
        other = self.work / f"{self.id()}-gnupg"
        other.mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "GNUPGHOME": str(other)}
        gpg = [
            "/usr/bin/gpg",
            "--batch",
            "--quiet",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]
        subprocess.run(
            [*gpg, "--quick-gen-key", "other", "ed25519", "sign", "1d"], check=True, env=env
        )
        public = self.work / f"{self.id()}-other.asc"
        public.write_bytes(
            subprocess.run(
                [*gpg, "--armor", "--export"], check=True, env=env, capture_output=True
            ).stdout
        )
        subprocess.run(["/usr/bin/gpgconf", "--kill", "all"], check=False, env=env)
        with self.serve(site), self.assertRaises(REPO.RepoError):
            REPO.fetch_site("https://example.org/repo", public, self.work / f"{self.id()}-k")

    def test_only_https_is_read(self) -> None:
        with self.assertRaises(REPO.RepoError):
            REPO._get("http://example.org/repo/dists/deb13/InRelease")


if __name__ == "__main__":
    unittest.main()
