"""The node package is built from one commit, reproducibly, and verified before use."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from haproxy_mgmt import debian_package, node_package, restore_agent

BASE = Path(__file__).resolve().parents[1]
COMMIT = "0123456789ab" + "0" * 28


def contents(deb: Path) -> dict[str, str]:
    """Path -> 'mode owner' for every file, as dpkg-deb lists it."""

    listed = subprocess.run(  # noqa: S603 - fixed reader, test package
        ["/usr/bin/dpkg-deb", "--contents", str(deb)], check=True, capture_output=True, text=True
    ).stdout
    rows = {}
    for line in listed.splitlines():
        fields = line.split()
        if not fields[0].startswith("d"):
            rows[fields[5].removeprefix("./")] = f"{fields[0]} {fields[1]}"
    return rows


def field(deb: Path, name: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed reader, test package
        ["/usr/bin/dpkg-deb", "--field", str(deb), name], check=True, capture_output=True, text=True
    ).stdout.strip()


class NodePackageBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        for relative, mode in node_package.CONTENTS.values():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"payload:{relative}\n")
            path.chmod(mode)
        (self.source / "pyproject.toml").write_text(
            '[project]\nname = "haprion"\nversion = "1.2.3"\n'
        )
        self.git("init", "-q")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "payload")

    def git(self, *arguments: str) -> str:
        return subprocess.run(  # noqa: S603 - fixed executable, test repository
            ["/usr/bin/git", "-C", str(self.source), *arguments],
            check=True,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "Node package test",
                "GIT_AUTHOR_EMAIL": "node-package@example.invalid",
                "GIT_COMMITTER_NAME": "Node package test",
                "GIT_COMMITTER_EMAIL": "node-package@example.invalid",
                "GIT_AUTHOR_DATE": "2026-10-09T12:00:00+00:00",
                "GIT_COMMITTER_DATE": "2026-10-09T12:00:00+00:00",
            },
        ).stdout.strip()

    def build(self, output: str = "out") -> tuple[Path, node_package.PackageFacts]:
        return node_package.build_package(self.source, self.root / output)

    def test_it_holds_the_scripts_in_usr_sbin_and_the_step_beside_its_library(self) -> None:
        deb, facts = self.build()
        commit = self.git("rev-parse", "HEAD")

        self.assertEqual(facts.version, f"1.2.3+git20261009120000.{commit[:12]}")
        self.assertEqual(facts.commit, commit)
        self.assertEqual(deb.name, f"haprion-node_{facts.version}_all.deb")
        rows = contents(deb)
        self.assertEqual(set(rows), set(node_package.FILES))
        for name in node_package.NODE_SCRIPTS:
            self.assertEqual(rows[f"usr/sbin/{name}"], "-rwxr-xr-x root/root")
        install = "usr/share/haprion-node/install"
        self.assertEqual(rows[f"{install}/04-node-prepare"], "-rwxr-xr-x root/root")
        self.assertEqual(rows[f"{install}/lib.sh"], "-rw-r--r-- root/root")
        self.assertEqual(field(deb, "Architecture"), "all")
        self.assertIn("python3", field(deb, "Depends"))

    def test_two_builds_of_the_same_commit_are_byte_identical(self) -> None:
        first, _ = self.build("a")
        second, _ = self.build("b")

        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_a_release_is_a_clean_commit(self) -> None:
        (self.source / "install/lib.sh").write_text("changed\n")

        with self.assertRaisesRegex(node_package.PackageError, "uncommitted"):
            self.build()

    def test_a_payload_file_with_the_wrong_mode_is_refused(self) -> None:
        (self.source / "install/lib.sh").chmod(0o755)
        self.git("add", "install/lib.sh")
        self.git("commit", "-q", "-m", "mode")

        with self.assertRaisesRegex(node_package.PackageError, "Git mode"):
            self.build()

    def test_an_existing_package_is_not_overwritten(self) -> None:
        self.build()

        with self.assertRaisesRegex(node_package.PackageError, "exists"):
            self.build()


class NodePackageVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.deb = node_package.write_package(
            self.root / "out",
            {path: f"# {path}\n".encode() for path in node_package.CONTENTS},
            upstream="0.1.0",
            epoch=1_790_000_000,
            commit=COMMIT,
        )

    def test_it_answers_the_version_and_commit(self) -> None:
        facts = node_package.verify_package(self.deb)

        self.assertEqual(facts.version, f"0.1.0+git20260921141320.{COMMIT[:12]}")
        self.assertEqual(facts.commit, COMMIT)

    def test_a_wrong_digest_is_refused(self) -> None:
        with self.assertRaisesRegex(node_package.PackageError, "SHA-256"):
            node_package.verify_package(self.deb, "0" * 64)

    def test_another_package_is_refused(self) -> None:
        tree = self.root / "other"
        debian_package.write(tree, "usr/sbin/haprion-pull-deploy", b"x", 0o755)
        other = debian_package.package(
            tree,
            {"Package": "haprion-other", "Version": "1.0", "Architecture": "all"},
            self.root,
            1_790_000_000,
        )

        with self.assertRaisesRegex(node_package.PackageError, "not a haprion-node"):
            node_package.verify_package(other)

    def test_a_package_with_a_file_more_is_refused(self) -> None:
        files = {path: b"x" for path in node_package.CONTENTS}
        with patch.dict(node_package.CONTENTS, {"usr/sbin/extra": ("install/extra", 0o755)}):
            deb = node_package.write_package(
                self.root / "extra",
                {**files, "usr/sbin/extra": b"x"},
                upstream="0.1.0",
                epoch=1_790_000_000,
                commit=COMMIT,
            )

        with self.assertRaisesRegex(node_package.PackageError, "exactly the node files"):
            node_package.verify_package(deb)

    def test_the_restore_agent_knows_the_versions_this_module_builds(self) -> None:
        # The agent imports nothing from the package (it runs on the node alone).
        self.assertEqual(restore_agent.PACKAGE_VERSION.pattern, node_package.VERSION.pattern)
        self.assertEqual(restore_agent.PACKAGE_FILE, node_package.RELEASE_PACKAGE)
        self.assertEqual(restore_agent.NODE_PREPARE, f"{node_package.INSTALL_DIR}/04-node-prepare")


class NodeCommandPathTests(unittest.TestCase):
    """Every node command the manager's side names is one the package installs, where it does.

    26-10-09: the collector's forced command still named /usr/local/sbin after
    the scripts moved, and no test read that step.
    """

    FILES = (
        "install/03-manager-keys",
        "install/04-node-prepare",
        "install/platform/13-platform-traffic-collector",
        "install/examples/keepalived.conf.example",
    )

    def test_each_named_node_command_is_in_the_package_s_directory(self) -> None:
        found = 0
        for name in self.FILES:
            text = (BASE / name).read_text()
            for path in re.findall(r"(/[a-z/]+/haprion-[a-z-]+)", text):
                if Path(path).name not in node_package.NODE_SCRIPTS:
                    continue
                found += 1
                with self.subTest(file=name, path=path):
                    self.assertEqual(str(Path(path).parent), node_package.SBIN)
        self.assertGreater(found, 8)

    def test_the_step_s_own_directory_is_the_package_s(self) -> None:
        text = (BASE / "install/04-node-prepare").read_text()
        self.assertIn(f'SBIN="{node_package.SBIN}"', text)

    def test_an_earlier_installation_is_taken_over_before_the_accounts_are_made(self) -> None:
        """B266: renamed before sysusers runs, or the node gets a second set of accounts."""

        text = (BASE / "install/04-node-prepare").read_text()
        before = text.index("./migrate-legacy-node before")
        self.assertLess(before, text.index("apply_sysusers sysusers/haprion-node.conf"))
        self.assertGreater(
            text.index("./migrate-legacy-node finish"), text.index('step "Sudo rules"')
        )
        self.assertIn(
            ("install/migrate-legacy-node", 0o755),
            list(node_package.CONTENTS.values()),
        )


class NodePackageTransportContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = (BASE / "tools" / "install-node-package").read_text()

    def test_one_shared_ssh_session_carries_the_install(self) -> None:
        self.assertIn("ControlMaster=auto", self.script)
        self.assertIn("ControlPersist=180", self.script)
        self.assertIn("ControlPath=${control_dir}/%r@%h", self.script)

    def test_the_package_is_verified_before_any_remote_staging(self) -> None:
        verify = self.script.index('verify --package "$node_package" --sha256 "$expected_sha"')
        staging = self.script.index("mktemp -d /tmp/haprion-node-package")
        self.assertLess(verify, staging)

    def test_state_is_backed_up_on_both_sides_of_the_remote_install(self) -> None:
        before, after = [
            index
            for index, line in enumerate(self.script.splitlines())
            if line.strip() == 'sudo "$STATE_BACKUP" -c "$cluster"'
        ]
        install = self.script.splitlines().index(
            'ssh -tt "${ssh_opts[@]}" "$node" "$remote_install"'
        )
        self.assertLess(before, install)
        self.assertGreater(after, install)
        self.assertIn("STATE_BACKUP=/opt/haprion/current/bin/haprion-state-backup", self.script)

    def test_staging_has_a_narrow_shape_and_is_deleted(self) -> None:
        self.assertIn("^/tmp/haprion-node-package\\.[A-Za-z0-9]+$", self.script)
        self.assertIn("find '$remote_dir' -depth -delete", self.script)

    def test_dry_run_stops_before_backups_and_staging(self) -> None:
        dry_run = self.script.index('if [[ "$dry_run" == "yes" ]]')
        backup = self.script.index('sudo "$STATE_BACKUP" -c "$cluster"')
        staging = self.script.index("mktemp -d /tmp/haprion-node-package")
        self.assertLess(dry_run, backup)
        self.assertLess(dry_run, staging)

    def test_an_extra_package_is_verified_and_its_architecture_checked_before_any_write(
        self,
    ) -> None:
        verify = self.script.index("sha256sum -c --quiet -")
        arch = self.script.index("the package is built for")
        dry_run = self.script.index('if [[ "$dry_run" == "yes" ]]')
        self.assertLess(verify, dry_run)
        self.assertLess(arch, dry_run)
        self.assertIn("^haprion-[a-z0-9-]+$", self.script)

    def test_both_packages_are_checked_on_the_node_and_installed_before_the_step(self) -> None:
        node_check = self.script.index("'$expected_sha' node.deb | sha256sum -c -")
        install = self.script.index("sudo apt-get install ${apt_options} ${packages}")
        prepare = self.script.index("sudo '${NODE_PREPARE}'")
        self.assertLess(node_check, install)
        self.assertLess(install, prepare)
        self.assertIn("NODE_PREPARE=/usr/share/haprion-node/install/04-node-prepare", self.script)

    def test_going_back_to_an_older_package_is_asked_for_by_name(self) -> None:
        self.assertIn('apt_options="-y --no-install-recommends"', self.script)
        self.assertIn(
            '[[ "$downgrade" == "yes" ]] && apt_options+=" --allow-downgrades"', self.script
        )
        self.assertEqual(self.script.count("--allow-downgrades"), 1)


if __name__ == "__main__":
    unittest.main()
