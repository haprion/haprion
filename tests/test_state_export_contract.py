from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.backup_archive import REQUIRED_PATHS

BASE = Path(__file__).resolve().parents[1]


def shell_array(text: str, name: str) -> tuple[str, ...]:
    matched = re.search(rf"^{name}=\(\n(?P<body>.*?)^\)", text, re.MULTILINE | re.DOTALL)
    if matched is None:
        raise AssertionError(f"{name} is missing")
    return tuple(line.strip() for line in matched.group("body").splitlines() if line.strip())


class StateExportContractTests(unittest.TestCase):
    def test_export_and_installer_name_the_same_node_bundle(self) -> None:
        installer = (BASE / "install/04-node-prepare").read_text(encoding="utf-8")
        exporter = (BASE / "install/node/haproxy-state-export").read_text(encoding="utf-8")
        self.assertEqual(shell_array(exporter, "DR_SCRIPTS"), shell_array(installer, "SCRIPTS"))

    def test_every_node_bundle_script_is_required_by_the_archive_validator(self) -> None:
        installer = (BASE / "install/04-node-prepare").read_text(encoding="utf-8")
        expected = {f"rootfs/usr/local/sbin/{name}" for name in shell_array(installer, "SCRIPTS")}
        self.assertLessEqual(expected, REQUIRED_PATHS)

    def test_only_forced_command_accounts_are_required_to_have_authorized_keys(self) -> None:
        # node.conf's template, used by 04-node-prepare, lives in lib.sh.
        template = (BASE / "install/lib.sh").read_text(encoding="utf-8")
        exporter = (BASE / "install/node/haproxy-state-export").read_text(encoding="utf-8")
        self.assertIn('BACKUP_SERVICE_ACCOUNTS=\\"${TRIGGER_USER}', template)
        required_keys = exporter.split("# The manifest is the archive's content contract.", 1)[0]
        self.assertIn("for user in $BACKUP_SERVICE_ACCOUNTS; do", required_keys)


def shell_function(text: str, name: str) -> str:
    matched = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
    if matched is None:
        raise AssertionError(f"{name} is missing")
    return matched.group(0)


def pattern(text: str) -> str:
    matched = re.search(r"^\s*EXTRA_PATH_PATTERN='([^']+)'$", text, re.MULTILINE)
    if matched is None:
        raise AssertionError("EXTRA_PATH_PATTERN is missing")
    return matched.group(1)


class TheOperatorsOwnPaths(unittest.TestCase):
    """EXTRA_BACKUP_PATHS: carried by name, or the export fails.

    Run for real against a scratch tree - the function copies with `cp -a`, so
    the paths it is given are this test's own files, not the host's.
    """

    exporter: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.exporter = (BASE / "install/node/haproxy-state-export").read_text(encoding="utf-8")

    def export(self, extra: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", str(work)], check=False)
        (work / "rootfs").mkdir()
        (work / "meta").mkdir()
        program = (
            "set -euo pipefail\n"
            f"ROOTFS='{work}/rootfs'; META='{work}/meta'\n"
            f"EXTRA_PATH_PATTERN='{pattern(self.exporter)}'\n"
            + shell_function(self.exporter, "copy_path")
            + shell_function(self.exporter, "copy_extra_paths")
            + "copy_extra_paths\n"
        )
        result = subprocess.run(  # noqa: S603 - fixed program over test-owned paths
            ["/bin/bash", "-c", program],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "EXTRA_BACKUP_PATHS": extra},
        )
        return result, work

    def source(self) -> Path:
        source = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ["rm", "-rf", str(source)], check=False)
        return source

    def test_files_and_directories_are_carried_and_listed(self) -> None:
        source = self.source()
        (source / "local.cfg").write_text("GRUB_CMDLINE_LINUX_DEFAULT=x\n")
        (source / "conf.d").mkdir()
        (source / "conf.d" / "99-site.conf").write_text("server ntp.example.com\n")

        result, work = self.export(f"{source}/local.cfg  {source}/conf.d")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((work / f"rootfs{source}/local.cfg").is_file())
        self.assertTrue((work / f"rootfs{source}/conf.d/99-site.conf").is_file())
        self.assertEqual(
            (work / "meta/extra-paths.txt").read_text().splitlines(),
            [f"{source}/local.cfg", f"{source}/conf.d"],
        )

    def test_a_path_overlapping_what_is_carried_is_merged_not_nested(self) -> None:
        source = self.source()
        (source / "netplan").mkdir()
        (source / "netplan" / "50-site.yaml").write_text("network: {}\n")
        (source / "netplan" / "60-extra.yaml").write_text("network: {}\n")

        result, work = self.export(f"{source}/netplan {source}/netplan/50-site.yaml {source}")

        self.assertEqual(result.returncode, 0, result.stderr)
        carried = work / f"rootfs{source}"
        self.assertTrue((carried / "netplan" / "50-site.yaml").is_file())
        self.assertTrue((carried / "netplan" / "60-extra.yaml").is_file())
        self.assertFalse((carried / "netplan" / "netplan").exists())
        self.assertFalse((carried / source.name).exists())

    def test_nothing_listed_carries_nothing_and_says_so(self) -> None:
        result, work = self.export("")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((work / "meta/extra-paths.txt").read_text(), "")
        self.assertEqual(list((work / "rootfs").iterdir()), [])

    def test_a_missing_path_fails_the_export_instead_of_being_skipped(self) -> None:
        source = self.source()
        result, _ = self.export(f"{source}/not-there.cfg")

        self.assertEqual(result.returncode, 78)
        self.assertIn("does not exist on this node", result.stderr)

    def test_a_socket_or_pipe_inside_a_directory_fails_the_export(self) -> None:
        source = self.source()
        (source / "dir").mkdir()
        os.mkfifo(source / "dir" / "pipe")

        result, _ = self.export(f"{source}/dir")

        self.assertEqual(result.returncode, 78)
        self.assertIn("socket, pipe or device", result.stderr)

    def test_paths_that_could_escape_expand_or_glob_are_refused(self) -> None:
        for unusable in (
            "relative/path",
            "/etc/../root/.ssh",
            "/etc/./x",
            "/etc//x",
            "/",
            "/proc/self/environ",
            "/run/secret",
            "/etc/*",
            "/etc/$(id)",
            '/etc/"x"',
        ):
            with self.subTest(path=unusable):
                result, work = self.export(unusable)
                self.assertEqual(result.returncode, 78)
                self.assertIn("unusable path", result.stderr)
                self.assertEqual(list((work / "rootfs").iterdir()), [])

    def test_the_installer_holds_node_conf_to_the_same_pattern(self) -> None:
        installer = (BASE / "install/04-node-prepare").read_text(encoding="utf-8")

        self.assertEqual(pattern(installer), pattern(self.exporter))
        self.assertIn("render_node_conf", installer)
        template = (BASE / "install/lib.sh").read_text(encoding="utf-8")
        self.assertIn('EXTRA_BACKUP_PATHS=\\"${EXTRA_BACKUP_PATHS:-}\\"', template)


if __name__ == "__main__":
    unittest.main()
