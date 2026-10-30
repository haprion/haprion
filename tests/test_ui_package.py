"""The web interface package: built where it runs, carried as an archive (B266)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import accounts, node_package
from tests.test_package_commands import manager_scripts, node_scripts

BASE = Path(__file__).resolve().parents[1]


def tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "build_ui_package", BASE / "tools/build-ui-package.py"
    )
    assert spec is not None and spec.loader is not None  # local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = tool()


class Distributions(unittest.TestCase):
    def test_each_package_takes_only_the_python_its_venv_was_built_for(self) -> None:
        self.assertEqual(
            TOOL.depends("3.14", 1).split(", ")[:2], ["python3 (>= 3.14)", "python3 (<< 3.15)"]
        )
        self.assertEqual(TOOL.DISTRIBUTIONS["ubuntu26.04"].python, "3.14")
        self.assertEqual(TOOL.DISTRIBUTIONS["debian13"].python, "3.13")
        self.assertIn("haprion-cli", TOOL.depends("3.13", 1))

    def test_it_needs_an_engine_at_the_level_the_release_requires(self) -> None:
        """Review 2026-10-22, 6-4: a CLI downgrade changed the engine under the interface unseen."""

        self.assertIn("haprion-engine (>= 31)", TOOL.depends("3.13", 31).split(", "))
        commit = TOOL._git(BASE, "rev-parse", "HEAD").decode().strip()
        self.assertGreaterEqual(TOOL.required_engine_api(BASE, commit), 1)

    def test_the_versions_sort_apart_per_distribution(self) -> None:
        self.assertEqual(
            {d.suffix for d in TOOL.DISTRIBUTIONS.values()}, {"~ubuntu26.04", "~deb13"}
        )


class TheBuild(unittest.TestCase):
    """What makes the release the same bytes twice, and runnable where it lands."""

    def test_it_is_built_at_its_final_path_against_the_system_python(self) -> None:
        self.assertIn('R="/opt/haprion-ui/releases/$RELEASE_ID"', TOOL.BUILD)
        self.assertIn("--python /usr/bin/python3 --python-preference only-system", TOOL.BUILD)
        self.assertIn("--locked --no-dev --no-editable", TOOL.BUILD)

    def test_what_varies_between_builds_is_left_out(self) -> None:
        build = TOOL.BUILD
        # Our two distributions from reproducible wheels, not from source trees.
        self.assertIn("--no-install-project --no-install-package haprion", build)
        self.assertIn("uv_cache.json", build)
        self.assertIn("-name __pycache__ -prune -exec rm -rf {} +", build)
        # The import proof writes no bytecode after the cleanup.
        self.assertIn('venv/bin/python" -B -c', build)
        self.assertIn('--sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0', build)
        # Modes set, not taken from the cache the operator's umask made.
        self.assertIn("--mode=u+rw,go=rX", build)

    def test_the_archive_modes_are_set_whatever_the_files_came_with(self) -> None:
        # What the uv cache and uv itself leave: 0664 under umask 002, 0666 locks.
        given = {"cached.py": 0o664, ".lock": 0o666, "private": 0o600, "tool": 0o775}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tree").mkdir(mode=0o700)
            for name, mode in given.items():
                (root / "tree" / name).write_text("")
                os.chmod(root / "tree" / name, mode)
            subprocess.run(  # fixed arguments
                ["/usr/bin/tar", "--mode=u+rw,go=rX", "-cf", str(root / "a.tar"),
                 "-C", str(root), "tree"],
                check=True,
            )  # fmt: skip
            with tarfile.open(root / "a.tar") as archive:
                modes = {member.name: member.mode for member in archive.getmembers()}
        self.assertEqual(
            modes,
            {"tree": 0o755, "tree/cached.py": 0o644, "tree/.lock": 0o644,
             "tree/private": 0o644, "tree/tool": 0o755},
        )  # fmt: skip

    def test_the_migration_bundle_travels_with_the_release(self) -> None:
        self.assertIn('cp /src/ui/alembic.ini "$R/migration/alembic.ini"', TOOL.BUILD)

    def test_the_migration_tool_is_locked_and_kept_out_of_the_services_venv(self) -> None:
        build = TOOL.BUILD
        self.assertIn("--locked --only-group migrate", build)
        self.assertIn('--target "$R/migration/lib" --require-hashes', build)
        self.assertIn('PYTHONPATH="$R/migration/lib"', build)


class TheTree(unittest.TestCase):
    def test_the_package_carries_the_archive_its_digest_and_the_image(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            archive = work / "release.tar"
            archive.write_bytes(b"release")
            root = work / "root"
            tree = work / "src"
            moved = [entry for entry, _ in TOOL.MOVED]
            for relative, *_ in [(e, None) for e in (*TOOL.SHARED, *TOOL.TOOLS, *moved)]:
                path = tree / relative
                if relative.endswith("/"):
                    path.mkdir(parents=True)
                    (path / "file").write_text(relative)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(relative)
            for command in TOOL.COMMANDS:
                (tree / f"install/platform/bin/haprion-{command}").parent.mkdir(
                    parents=True, exist_ok=True
                )
                (tree / f"install/platform/bin/haprion-{command}").write_text(command)

            TOOL.assemble(
                root,
                tree=tree,
                archive=archive,
                release_id="0.1.0-0123456789ab",
                licence=b"licence\n",
                commit="0" * 40,
                image="docker.io/library/debian:13",
                digest="sha256:" + "1" * 64,
            )

            lib = root / "usr/lib/haprion/ui"
            self.assertEqual((lib / "release-0.1.0-0123456789ab.tar").read_bytes(), b"release")
            payload = (lib / "PAYLOAD").read_text()
            self.assertIn("RELEASE_ID=0.1.0-0123456789ab\n", payload)
            self.assertIn(f"RELEASE_SHA256={TOOL.sha256(archive)}\n", payload)
            self.assertIn(
                "image: docker.io/library/debian:13@sha256:" + "1" * 64,
                (root / "usr/share/doc/haprion-ui/BUILD").read_text(),
            )
            postinst = (root / "DEBIAN/postinst").read_text()
            # An installed release is never unpacked over; a new one is
            # checked against its digest, unpacked beside and moved in whole.
            self.assertIn('if [ ! -d "$release" ]; then', postinst)
            self.assertIn("sha256sum --check", postinst)
            self.assertIn(
                'mv -T "$unpack/opt/haprion-ui/releases/$RELEASE_ID" "$release"', postinst
            )
            self.assertLess(postinst.index("sha256sum"), postinst.index("tar -xf"))
            # Over a running installation the update is the whole of it (D2).
            self.assertIn(
                '/usr/share/haprion-ui/install/platform/update-platform-release "$RELEASE_ID"',
                postinst,
            )
            share = root / "usr/share/haprion-ui"
            self.assertTrue((share / "install/lib.sh").is_file())
            self.assertTrue((share / "install/node-lib.sh").is_file())
            self.assertTrue((share / "install/platform/file").is_file())
            self.assertTrue((share / "tools/dns-profile-keys.py").is_file())
            for command in TOOL.COMMANDS:
                self.assertEqual(
                    (root / f"usr/sbin/haprion-{command}").stat().st_mode & 0o777, 0o755
                )
            # The manager is installed from the packages alone: haprion-setup
            # runs from beside its steps, which the package carries.
            setup = root / "usr/sbin/haprion-setup"
            self.assertEqual(setup.stat().st_mode & 0o777, 0o755)
            self.assertIn(
                'exec /usr/share/haprion-ui/install/haprion-setup "$@"', setup.read_text()
            )
            for step in (
                "haprion-setup",
                "01-manager-prepare",
                "02-manager-config",
                "03-manager-keys",
            ):
                self.assertTrue((share / "install" / step).is_file(), step)
            self.assertIn("sudo haprion-setup", postinst)

    PARTS = (
        "venv/bin/python",
        "migration/alembic.ini",
        "migration/migrations/env.py",
        "migration/lib/alembic",
    )

    def configure(self, *, current: bool, marker: bool) -> str:
        return self.configured(current=current, marker=marker)[0].stdout

    def configured(
        self, *, current: bool, marker: bool, missing: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        """The package's postinst run for real, its fixed paths moved into a directory.

        The release on disk has its four parts but `missing`; the archive that
        unpacks it again holds all four, and a file in the unpacked one says
        which of the two the release on disk came from.
        """

        with tempfile.TemporaryDirectory() as raw:
            here = Path(raw)
            script = (
                TOOL.POSTINST.replace(TOOL.UPDATE_MARKER, f"{here}/marker")
                .replace(TOOL.ROOT, f"{here}/opt")
                .replace(f"/{TOOL.LIB}", f"{here}/lib")
                .replace(f"/{TOOL.SHARE}", f"{here}/share")
            )
            (here / "lib").mkdir()
            release = here / "opt/releases/0.1.0-0123456789ab"
            release.mkdir(parents=True)
            archive = here / "lib/release.tar"
            with tarfile.open(archive, "w") as packed:
                for part in self.PARTS:
                    source = here / "source" / part
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("from the archive\n")
                    packed.add(source, f"{here}/opt/releases/0.1.0-0123456789ab/{part}".lstrip("/"))
            (here / "lib/PAYLOAD").write_text(
                "RELEASE_ID=0.1.0-0123456789ab\nRELEASE_ARCHIVE=release.tar\n"
                f"RELEASE_SHA256={TOOL.sha256(archive)}\n"
            )
            for part in self.PARTS:
                if part != missing:
                    (release / part).parent.mkdir(parents=True, exist_ok=True)
                    (release / part).write_text("on disk\n")
            (here / "opt/releases/0.0.9-ba9876543210").mkdir()
            (here / "opt/current").symlink_to(
                release if current else here / "opt/releases/0.0.9-ba9876543210"
            )
            if marker:
                (here / "marker").write_text(
                    "RELEASE=0.1.0-0123456789ab\nPREVIOUS=0.0.9-ba9876543210\n"
                )
            update = here / "share/install/platform/update-platform-release"
            update.parent.mkdir(parents=True)
            update.write_text('#!/bin/sh\necho "updating to $1"\n')
            update.chmod(0o755)
            done = subprocess.run(  # fixed interpreter, the package's own script
                ["/bin/sh", "-c", script, "postinst", "configure"],
                capture_output=True,
                text=True,
                check=False,
            )
            parts = [
                (release / part).read_text() if (release / part).exists() else ""
                for part in self.PARTS
            ]
        return done, parts

    def test_an_update_under_way_is_run_again_with_its_release_current(self) -> None:
        """Review 26-10-29, A02: `dpkg --configure -a` after a failed restore said "already current"."""

        self.assertEqual(
            self.configure(current=True, marker=False),
            "haprion-ui: release 0.1.0-0123456789ab is already current\n",
        )
        self.assertEqual(
            self.configure(current=True, marker=True), "updating to 0.1.0-0123456789ab\n"
        )
        self.assertEqual(
            self.configure(current=False, marker=False), "updating to 0.1.0-0123456789ab\n"
        )
        update = (BASE / "install/platform/update-platform-release").read_text()
        self.assertEqual(TOOL.UPDATE_MARKER, f"{accounts.UI_DATA}/platform-update/update")
        self.assertIn('state="${UI_DATA}/platform-update"\nmarker="${state}/update"\n', update)

    def test_a_release_with_a_part_missing_is_unpacked_again_unless_it_runs(self) -> None:
        """Review 26-10-30, U5: "reinstall the haprion-ui package" found the directory and left it."""

        whole, parts = self.configured(current=False, marker=False)
        self.assertEqual(whole.returncode, 0, whole.stderr)
        self.assertEqual(parts, ["on disk\n"] * 4)
        for part in self.PARTS:
            with self.subTest(part=part):
                damaged, parts = self.configured(current=False, marker=False, missing=part)
                self.assertEqual(damaged.returncode, 0, damaged.stderr)
                self.assertIn(f"has no {part}; unpacking it again", damaged.stdout)
                self.assertIn("updating to 0.1.0-0123456789ab", damaged.stdout)
                self.assertEqual(parts, ["from the archive\n"] * 4)
                running, parts = self.configured(current=True, marker=False, missing=part)
                self.assertEqual(running.returncode, 1)
                self.assertIn(f"has no {part}", running.stderr)
                self.assertIn("sudo haprion-rollback", running.stderr)
                self.assertIn("sudo dpkg --configure -a", running.stderr)
                self.assertNotIn("already current", running.stdout)

    def test_a_purge_takes_the_update_s_state_with_the_releases(self) -> None:
        """Review 26-10-29, AA04: the marker outlived the releases it names.

        After a purge and a new installation it named a release no longer on
        disk, and every update stopped on it. The data beside it stays.
        """

        for argument, gone in (("purge", True), ("remove", False)):
            with self.subTest(argument=argument), tempfile.TemporaryDirectory() as raw:
                here = Path(raw)
                state = here / "data/platform-update"
                (state / "kept").mkdir(parents=True)
                (state / "update").write_text("RELEASE=b\nPREVIOUS=a\n")
                (here / "data/backups").mkdir()
                (here / "opt/releases/a").mkdir(parents=True)
                script = TOOL.POSTRM.replace(TOOL.UPDATE_STATE, str(state)).replace(
                    TOOL.ROOT, f"{here}/opt"
                )
                subprocess.run(  # fixed interpreter, the package's own script
                    ["/bin/sh", "-c", script, "postrm", argument], check=True
                )
                self.assertEqual(state.exists(), not gone)
                self.assertEqual((here / "opt").exists(), not gone)
                self.assertTrue((here / "data/backups").exists())
        self.assertEqual(TOOL.UPDATE_MARKER, f"{TOOL.UPDATE_STATE}/update")

    def test_the_update_test_takes_the_way_back_and_asks_the_check(self) -> None:
        """Review 26-10-29, A04: only the way that works had run, and no check after it."""

        text = (BASE / "tools/install-test").read_text()
        self.assertIn(f'UPDATE_MARKER = "{TOOL.UPDATE_MARKER}"\n', text)
        start = text.index("def run_upgrade(")
        body = text[start : text.index("\ndef main(", start)]
        for after in ('compatible("the update")', 'compatible(f"the rollback to {to}")'):
            with self.subTest(after=after):
                self.assertIn(after, body)
        self.assertIn('compatible("a failed update was restored")', body)
        self.assertIn('&& dpkg --configure -a")', body)
        self.assertLess(
            body.index("a_failed_update_is_undone_and_run_again,"),
            body.index("updated to this release with apt"),
        )

    def install_test(self) -> Any:
        loader = importlib.machinery.SourceFileLoader(
            "install_test", str(BASE / "tools/install-test")
        )
        spec = importlib.util.spec_from_loader("install_test", loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        # Its dataclasses look their module up while they are made.
        sys.modules["install_test"] = module
        self.addCleanup(sys.modules.pop, "install_test", None)
        loader.exec_module(module)
        return module

    def test_the_failed_update_is_said_as_what_it_runs(self) -> None:
        """Review 26-10-29, AA05: "after its migration", over two releases with none between.

        The activation is what fails; whether a migration ran before it is
        read from the schema before and after, and said.
        """

        text = (BASE / "tools/install-test").read_text()
        body = text[text.index("def run_upgrade(") : text.index("\ndef main(")]
        self.assertNotIn("after its migration", body)
        self.assertIn("failed after its activation", body)
        self.assertIn('"/usr/share/haprion-ui/install/platform/migrate "', body)
        self.assertIn('f"--release {shlex.quote(release)} current 2>/dev/null "', body)
        # Review 26-10-29, a's cosmetics: a reading that failed was an empty schema.
        start = body.index("    def schema(")
        self.assertIn('"set -o pipefail; "', body[start : body.index("\n    def ", start + 1)])

    def test_a_failed_update_whose_rollback_fails_too_is_kept_and_finished(self) -> None:
        """AA05: the way the marker exists for - the previous release not restored - never ran.

        The web refuses every release; the rollback fails, the candidate runs
        unproved, the marker stays and the package `iF`. With the cause gone,
        `dpkg --configure -a` finishes the update and the marker goes.
        """

        text = (BASE / "tools/install-test").read_text()
        body = text[text.index("def run_upgrade(") : text.index("\ndef main(")]
        start = body.index("def a_failed_update_is_undone_and_run_again(")
        way = body[start : body.index("\n    def ", start + 1)]
        restored = way.index("FAULT_UNIT.format(release=previous)")
        refused = way.index("stdin=FAULT_EVERY")
        finished = way.rindex('&& dpkg --configure -a")')
        self.assertLess(restored, refused)
        self.assertLess(refused, finished)
        between = way[refused:finished]
        for said in ('!= "iF"', "test -e {UPDATE_MARKER}", "!= packaged"):
            with self.subTest(said=said):
                self.assertIn(said, between)
        self.assertIn("test ! -e {UPDATE_MARKER}", way[finished:])

    def test_the_faults_refuse_what_they_say(self) -> None:
        """The drop-ins' commands, as systemd hands them to the shell (`$$` is `$`)."""

        module = self.install_test()
        with tempfile.TemporaryDirectory() as raw:
            here = Path(raw)
            for release in ("0.1-a", "0.2-b"):
                (here / "releases" / release).mkdir(parents=True)
            for unit, current, code in (
                (module.FAULT_UNIT.format(release="0.1-a"), "0.1-a", 0),
                (module.FAULT_UNIT.format(release="0.1-a"), "0.2-b", 1),
                (module.FAULT_EVERY, "0.1-a", 1),
                (module.FAULT_EVERY, "0.2-b", 1),
            ):
                with self.subTest(unit=unit, current=current):
                    link = here / "current"
                    link.unlink(missing_ok=True)
                    link.symlink_to(here / "releases" / current)
                    line = next(
                        line for line in unit.splitlines() if line.startswith("ExecStartPre=")
                    )
                    command = line.removeprefix("ExecStartPre=").replace("$$", "$")
                    command = command.replace("/opt/haprion-ui/current", str(link))
                    done = subprocess.run(  # fixed interpreter, the drop-in's own command
                        ["/bin/sh", "-c", f"exec {command}"], check=False
                    )
                    self.assertEqual(done.returncode, code)

    def test_what_the_manager_steps_read_beside_them_is_carried(self) -> None:
        carried = {relative for relative, _ in TOOL.shared_files(BASE)}
        for needed in (
            "install/sysusers/haprion.conf",
            "install/tmpfiles/haprion.conf",
            "install/apt-keys/powerdns-dnsdist.asc",
            "install/apt-keys/haproxy-debian-net.asc",
            "install/apt-keys/haproxy-ubuntu-ppa.asc",
            "tools/dns-profile-keys.py",
            "certbot/uv.lock",
        ):
            self.assertIn(needed, carried)
        # A src/haprion in the package would pass for a source tree: the
        # tools would import the engine from it (install test, 26-10-17).
        self.assertEqual({path for path in carried if path.startswith("src/")}, set())

    def test_every_packaged_path_the_documents_name_is_carried(self) -> None:
        """Review 26-10-24, 12-12: install.md sent a reader to the source tree for a
        file the package carries; a path under the packages' share that the
        documents name is one of their files."""

        documents = "".join(
            (BASE / "docs" / name).read_text() for name in ("install.md", "user-manual.md")
        )
        for share, carried in (
            ("usr/share/haprion-ui/", {relative for relative, _ in TOOL.shared_files(BASE)}),
            (
                "usr/share/haprion-node/",
                {
                    path.removeprefix("usr/share/haprion-node/")
                    for path in node_package.CONTENTS
                    if path.startswith("usr/share/haprion-node/")
                },
            ),
        ):
            named = set(re.findall(rf"/{share}([A-Za-z0-9_./-]*[A-Za-z0-9_/-])", documents))
            missing = sorted(
                name
                for name in named
                if name not in carried
                and not any(path.startswith(name.rstrip("/") + "/") for path in carried)
            )
            with self.subTest(share=share):
                self.assertEqual(missing, [])
        self.assertIn("/usr/share/haprion-ui/install/answers.example.env", documents)

    #
    # A path a script reads from beside it that is no file of the package, with
    # why. Step 14 installed the certbot hook from `../certbot-deploy-hook`, a
    # file only a source tree had: on a package installation nothing put the
    # hook in place (review 2026-10-24). Read from the scripts, not listed, so
    # the next such file fails here too; review 26-10-24, 14-03, widened it to
    # every script the packages carry and to paths of more than one part.
    #
    NOT_CARRIED = {
        ("install/node-lib.sh", "../src/haprion/apt-keys/"): (
            "a source tree's HAProxy keys; the package carries them in install/apt-keys/, "
            "where node-lib.sh looks first"
        ),
        ("install/platform/05-platform-nginx", "../sites-available/haprion"): (
            "the target of a link, which nginx resolves in /etc/nginx/sites-enabled"
        ),
        **{
            (f"install/platform/{step}", "../.."): "the tree the step runs from"
            for step in (
                "14-platform-certbot",
                "15-platform-dns-keys",
                "16-platform-scep",
                "17-platform-oidc",
            )
        },
    }
    BESIDE = re.compile(
        r"""(?:^|[\s"'(=])(\.\./[A-Za-z0-9_./-]*)"""
        r"""|^\s*(?:source|apply_sysusers|apply_tmpfiles) +(\.?/?[A-Za-z0-9_][A-Za-z0-9_./-]*)$""",
        re.MULTILINE,
    )

    def beside(self, scripts: list[Path]) -> tuple[set[str], set[tuple[str, str]]]:
        """What the scripts read from beside them, by path in the tree, and the
        exceptions they used."""

        named: set[str] = set()
        excepted: set[tuple[str, str]] = set()
        for script in scripts:
            relative = script.relative_to(BASE).as_posix()
            text = "\n".join(
                line
                for line in script.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("#")
            )
            for match in self.BESIDE.finditer(text):
                name = match.group(1) or match.group(2)
                if (relative, name) in self.NOT_CARRIED:
                    excepted.add((relative, name))
                    continue
                # A node command reads from the package's install directory,
                # where it changes to first (haprion-node-key).
                here = script.parent.parent if script.parent.name == "node" else script.parent
                path = Path(os.path.normpath(here / name))
                with self.subTest(script=relative, name=name):
                    self.assertTrue(path.exists(), f"{relative} reads {name}, which is not there")
                named.add(path.relative_to(BASE).as_posix() + ("/" if path.is_dir() else ""))
        return named, excepted

    @staticmethod
    def missing(named: set[str], carried: set[str]) -> list[str]:
        return sorted(
            name
            for name in named
            if not (
                any(path.startswith(name) for path in carried)
                if name.endswith("/")
                else name in carried
            )
        )

    def test_every_file_a_manager_script_reads_from_beside_it_is_carried(self) -> None:
        carried = {relative for relative, _ in TOOL.shared_files(BASE)}
        named, excepted = self.beside(manager_scripts())
        self.assertIn("install/certbot-deploy-hook", named)
        self.assertIn("install/sysusers/haprion.conf", named)
        self.assertEqual(self.missing(named, carried), [])
        self.assertEqual(sorted(set(self.NOT_CARRIED) - excepted), [])

    def test_every_file_the_node_step_reads_from_beside_it_is_carried(self) -> None:
        carried = {source for source, _ in node_package.CONTENTS.values()}
        named, _ = self.beside(node_scripts())
        self.assertIn("install/sysusers/haprion-node.conf", named)
        self.assertEqual(self.missing(named, carried), [])


if __name__ == "__main__":
    unittest.main()
