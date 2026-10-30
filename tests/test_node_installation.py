"""The node reports both its declared API and the bytes actually installed."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install/node/haprion-node-status"
INSTALLER = Path(__file__).resolve().parents[1] / "install/04-node-prepare"
READING = re.compile(r"^def read_installation\(.*?(?=^def run\()", re.DOTALL | re.MULTILINE)
NODE_SCRIPTS = (
    "haprion-pull-deploy",
    "haprion-cert-pull",
    "haprion-cert-remove",
    "haprion-cert-trigger",
    "haprion-node-status",
    "haprion-health-probe",
    "haprion-keepalived-state",
    "haprion-state-export",
    "haprion-traffic-log-read",
    "haprion-traffic-log-enable",
    "haprion-traffic-log-prune",
    "haprion-server-state",
    "haprion-server-state-trigger",
)


class NodeInstallationReadingTests(unittest.TestCase):
    def setUp(self) -> None:
        found = READING.search(SCRIPT.read_text())
        assert found, "the installation reader is no longer where the test extracts it from"
        self.source = found.group(0)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sbin = self.root / "sbin"
        self.sbin.mkdir()
        self.metadata = self.root / "node-installation.json"
        self.installed: dict[str, str] = {"haprion-node": "0.99.6+git20261029120000.0123456789ab"}
        self.configured = True

    def read(self) -> dict[str, Any]:
        namespace: dict[str, Any] = {
            "Path": Path,
            "hashlib": hashlib,
            "json": json,
            "re": re,
            "NODE_INSTALLATION": self.metadata,
            "SBIN": self.sbin,
            "MAX_INSTALLATION_BYTES": 64 * 1024,
            "SHA256": re.compile(r"^[0-9a-f]{64}$"),
            "NODE_SCRIPTS": NODE_SCRIPTS,
            "NODE_PACKAGE": "haprion-node",
            "package_state": lambda name: (self.installed.get(name), self.configured),
        }
        exec(self.source, namespace)  # noqa: S102 - verbatim function from the node script
        result: dict[str, Any] = namespace["read_installation"]()
        return result

    def install(self, content: bytes = b"script\n") -> None:
        for name in NODE_SCRIPTS:
            (self.sbin / name).write_bytes(content)
        self.metadata.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "node_api": 1,
                    "scripts": {name: hashlib.sha256(content).hexdigest() for name in NODE_SCRIPTS},
                }
            )
        )

    def test_matching_metadata_reports_a_current_bundle(self) -> None:
        self.install()
        result = self.read()
        self.assertEqual(result["node_api"], 1)
        self.assertIs(result["scripts_current"], True)

    def test_the_node_package_version_is_reported_beside_the_scripts(self) -> None:
        """26-10-29: the manager compares it with the node package its release carries."""

        self.install()
        self.assertEqual(self.read()["version"], "0.99.6+git20261029120000.0123456789ab")

    def test_the_version_is_reported_without_usable_metadata_too(self) -> None:
        self.install()
        self.metadata.write_text("{}")
        result = self.read()
        self.assertIsNone(result["node_api"])
        self.assertEqual(result["version"], "0.99.6+git20261029120000.0123456789ab")

    def test_a_node_without_the_package_reports_no_version(self) -> None:
        self.install()
        self.installed.clear()
        self.assertIsNone(self.read()["version"])
        self.assertNotIn("configured", self.read())

    def test_a_package_dpkg_did_not_finish_configuring_says_so(self) -> None:
        """Review 26-10-29, A06: it was reported as not installed."""

        self.install()
        self.assertIs(self.read()["configured"], True)
        self.configured = False
        result = self.read()
        self.assertEqual(result["version"], "0.99.6+git20261029120000.0123456789ab")
        self.assertIs(result["configured"], False)

    def test_installer_and_status_attest_the_same_node_package(self) -> None:
        # Since 26-10-24 (03-01) the list is in the file step 4 and the postinst share.
        listed = (INSTALLER.parent / "node-installation.sh").read_text()
        match = re.search(r"^SCRIPTS=\(\n(.*?)^\)", listed, re.MULTILINE | re.DOTALL)
        assert match is not None
        installed = tuple(re.findall(r"^\s+(haprion-[a-z0-9-]+)$", match.group(1), re.MULTILINE))
        self.assertEqual(installed, NODE_SCRIPTS)

    def test_a_script_left_out_of_the_attestation_is_left_out_on_purpose(self) -> None:
        """Review 26-10-30: the list looked complete; what it leaves out is named."""

        shipped = {
            path.name
            for path in (INSTALLER.parent / "node").iterdir()
            if path.is_file() and path.name.startswith("haprion-")
        }
        left_out = shipped - set(NODE_SCRIPTS)
        self.assertEqual(
            left_out, {"haprion-node-key", "haprion-node-join", "haprion-node-prepare"}
        )
        text = (INSTALLER.parent / "node-installation.sh").read_text()
        for name in left_out:
            self.assertIn(f"{name}", text.split("SCRIPTS=(")[0])

    def test_the_status_script_reads_the_same_list_it_is_installed_with(self) -> None:
        """26-10-09: the list in the status script itself was never compared.

        The reader above runs with this file's list, so the node's own one could
        lag behind the installer's - and a node given two new scripts rejected
        its own metadata and reported no API and nothing current.
        """

        from haprion.node_package import NODE_SCRIPTS as PACKAGED

        match = re.search(
            r"^NODE_SCRIPTS = \(\n(.*?)^\)", SCRIPT.read_text(), re.MULTILINE | re.DOTALL
        )
        assert match is not None
        listed = tuple(re.findall(r'^\s+"(haprion-[a-z0-9-]+)",$', match.group(1), re.MULTILINE))
        self.assertEqual(listed, NODE_SCRIPTS)
        self.assertEqual(PACKAGED, NODE_SCRIPTS)

    def test_no_node_script_takes_a_lock_in_the_shared_lock_directory(self) -> None:
        """Review 26-10-24, 10-06: any local account can create a file in /run/lock
        (1777) or hold its lock, and every deploy then answered "already running"."""

        scripts = sorted(path for path in (INSTALLER.parent / "node").iterdir() if path.is_file())
        for script in scripts:
            with self.subTest(script=script.name):
                self.assertNotIn("/run/lock/", script.read_text())

    def test_release_root_denies_unprivileged_service_accounts(self) -> None:
        self.assertIn("ensure_dir /etc/haproxy/releases root:root 750", INSTALLER.read_text())

    def test_only_the_waf_engine_passes_through_the_release_root(self) -> None:
        """26-10-03: the engine's DynamicUser could not reach /etc/haproxy/waf through it."""

        installer = INSTALLER.read_text()
        # Pass, not list, and only for a group with no members.
        self.assertIn("a+ /etc/haproxy/releases - - - - group:${WAF_GROUP}:--x", installer)
        self.assertIn(
            "readonly WAF_GROUP=_haprion-waf", (INSTALLER.parent / "accounts.sh").read_text()
        )
        self.assertIn("has members; only the WAF engine may pass", installer)
        # Given to the engine beside its package, which names no account of ours.
        self.assertIn(
            'WAF_ENGINE_DROPIN="/etc/systemd/system/coraza-spoa.service.d/haprion.conf"',
            installer,
        )
        self.assertIn("SupplementaryGroups=${WAF_GROUP}", installer)
        # After the directory exists, so a fresh node gets the entry too.
        self.assertLess(
            installer.index("ensure_dir /etc/haproxy/releases root:root 750"),
            installer.index('systemd-tmpfiles --create "$WAF_ENGINE_TMPFILES"'),
        )

    def test_the_service_accounts_own_nothing_in_their_homes(self) -> None:
        """B131: a key file or dotfile the account could write is its way out of the forced command."""

        library = (INSTALLER.parent / "node-lib.sh").read_text()
        account = library[
            library.index("ensure_forced_home() {") : library.index(
                "\n}\n", library.index("ensure_forced_home() {")
            )
        ]
        # Both sides of the forced commands: the nodes' accounts on the manager
        # too (review 26-10-24, 10-01).
        self.assertIn('ensure_forced_home "$user"', INSTALLER.read_text())
        self.assertIn(
            'ensure_forced_home "$user"', (INSTALLER.parent / "01-manager-prepare").read_text()
        )

        self.assertIn('ensure_dir "$home" root:root 755', account)
        self.assertIn('ensure_dir "${home}/.ssh" root:root 755', account)
        self.assertIn("install -o root -g root -m 644 /dev/null", account)
        self.assertIn('chown root:root "$keys"', account)
        self.assertIn("! -name .ssh ! -user root -print0", account)
        self.assertIn('refuse_link "$keys"', account)
        self.assertIn('refuse_link "$entry"', account)
        self.assertNotIn("--create-home", account)
        self.assertNotIn('-o "$user"', account)

    def test_a_link_in_an_account_s_home_stops_the_step(self) -> None:
        """Review 26-10-24, 10-01/10-02: root followed it and changed what it pointed at."""

        library = (INSTALLER.parent / "node-lib.sh").read_text()
        start = library.index("ensure_forced_home() {")
        body = library[start : library.index("\n}\n", start) + 3]
        refuse = library[library.index("refuse_link() {") :]
        refuse = refuse[: refuse.index("\n}\n") + 3]
        for link in (".ssh/authorized_keys", ".bashrc"):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                home = root / "svc-pull"
                (home / ".ssh").mkdir(parents=True)
                target = root / "shadow"
                target.write_text("secret\n")
                (home / link).symlink_to(target)
                done = subprocess.run(  # fixed interpreter, the library's own functions
                    [
                        "/bin/bash",
                        "-c",
                        'log() { :; }; die() { echo "ERROR: $*"; exit 1; }; '
                        'ensure_dir() { :; }; chown() { echo "chown $*"; }; '
                        'chmod() { echo "chmod $*"; }; install() { :; }; '
                        f"{refuse}{body.replace('/home/', f'{root}/')}"
                        'ensure_forced_home svc-pull "empty"',
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(done.returncode, 1, done.stdout)
                self.assertIn(f"{home / link} is a symbolic link", done.stdout)
                self.assertNotIn(f"chown root:root {home / link}", done.stdout)
                self.assertEqual(target.read_text(), "secret\n")

    def test_a_changed_script_is_not_hidden_by_its_metadata(self) -> None:
        self.install()
        (self.sbin / "haprion-node-status").write_bytes(b"changed\n")
        result = self.read()
        self.assertIs(result["scripts_current"], False)

    def test_missing_or_malformed_metadata_is_unknown(self) -> None:
        result = self.read()
        self.assertIsNone(result["node_api"])
        self.assertIs(result["scripts_current"], False)
        self.assertEqual(set(result["scripts"]), set(NODE_SCRIPTS))
        self.assertTrue(all(row["installed_sha256"] is None for row in result["scripts"].values()))
        self.metadata.write_text("{}")
        self.assertEqual(self.read(), result)

    def test_missing_metadata_still_inventories_installed_scripts(self) -> None:
        (self.sbin / "haprion-node-status").write_bytes(b"installed\n")
        result = self.read()
        self.assertEqual(
            result["scripts"]["haprion-node-status"]["installed_sha256"],
            hashlib.sha256(b"installed\n").hexdigest(),
        )
        self.assertIsNone(result["scripts"]["haprion-node-status"]["expected_sha256"])


PACKAGE_STATE = re.compile(
    r"^CONFIGURED_STATES = .*?(?=^def read_waf_engine\()", re.DOTALL | re.MULTILINE
)


class PackageStateTests(unittest.TestCase):
    """dpkg's `want eflag status`, read for its status alone (review 26-10-29, A06).

    A package on hold - `apt-mark hold haprion-node`, to update one node at a
    time - is `hold ok installed`, and was reported as not installed.
    """

    def state(self, status: str, version: str = "0.99.6+git1.0123456789ab") -> Any:
        found = PACKAGE_STATE.search(SCRIPT.read_text())
        assert found, "the package reader is no longer where the test extracts it from"
        answer = subprocess.CompletedProcess([], 0 if status else 1, f"{status}\t{version}", "")
        namespace: dict[str, Any] = {"run": lambda *argv: answer}
        exec(found.group(0), namespace)  # noqa: S102 - verbatim functions from the node script
        return namespace["package_state"]("haprion-node"), namespace["package_version"](
            "haprion-node"
        )

    def test_a_held_package_is_installed(self) -> None:
        for status in ("install ok installed", "hold ok installed", "install ok triggers-pending"):
            with self.subTest(status=status):
                self.assertEqual(
                    self.state(status),
                    (("0.99.6+git1.0123456789ab", True), "0.99.6+git1.0123456789ab"),
                )

    def test_a_package_not_configured_has_its_version_and_says_so(self) -> None:
        for status in (
            "install ok half-configured",
            "hold ok unpacked",
            "install reinstreq half-installed",
        ):
            with self.subTest(status=status):
                self.assertEqual(self.state(status), (("0.99.6+git1.0123456789ab", False), None))

    def test_a_package_not_there_has_no_version(self) -> None:
        for status in ("", "deinstall ok config-files", "unknown ok not-installed"):
            with self.subTest(status=status):
                self.assertEqual(self.state(status), ((None, True), None))


if __name__ == "__main__":
    unittest.main()
