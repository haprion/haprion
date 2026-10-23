"""The installers' shared shell functions, run by bash as the installers run them."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[1] / "install" / "lib.sh"


def stamp(days_ago: float) -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() - days_ago * 86400))


class RollbackCopies(unittest.TestCase):
    """`.replaced-` copies are kept 30 days; the newest per file always stays."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        self.file = self.work / "node.conf"
        self.file.write_text("same\n")

    def copy(self, days_ago: float, path: Path | None = None) -> Path:
        copy = Path(f"{path or self.file}.replaced-{stamp(days_ago)}")
        copy.write_text("old\n")
        return copy

    def install_file(self, content: str = "same") -> str:
        owner = f"{os.getuid()}:{os.getgid()}"
        return subprocess.run(  # fixed interpreter, the repository's library
            [
                "/bin/bash",
                "-c",
                'source "$0"; install_file "$1" "$2" 600 "$3"',
                str(LIB),
                str(self.file),
                owner,
                content,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def left(self) -> list[str]:
        return sorted(path.name for path in self.work.iterdir())

    def test_copies_past_thirty_days_go_and_the_newest_stays(self) -> None:
        old, older, recent = self.copy(40), self.copy(60), self.copy(10)
        printed = self.install_file()
        self.assertEqual(self.left(), sorted(["node.conf", recent.name]))
        self.assertIn(f"pruned   {old}", printed)
        self.assertIn(f"pruned   {older}", printed)

    def test_the_newest_copy_stays_however_old(self) -> None:
        self.copy(90)
        newest = self.copy(40)
        self.install_file()
        self.assertEqual(self.left(), sorted(["node.conf", newest.name]))

    def test_a_write_prunes_too_and_keeps_the_copy_it_just_made(self) -> None:
        self.copy(40)
        self.copy(50)
        self.install_file("changed")
        names = self.left()
        self.assertEqual(len(names), 2, names)
        self.assertEqual(self.file.read_text(), "changed\n")

    def test_only_this_file_s_dated_copies_are_touched(self) -> None:
        other = self.copy(40, self.work / "node-installation.json")
        odd = self.work / "node.conf.replaced-by-hand"
        odd.write_text("kept\n")
        self.copy(40)
        self.copy(35)
        self.install_file()
        self.assertIn(other.name, self.left())
        self.assertIn(odd.name, self.left())


def run_lib(script: str, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # fixed interpreter, the repository's library
        ["/bin/bash", "-c", f'source "$0"; {script}', str(LIB), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
    )


class AFileInADirectoryNotThereYet(unittest.TestCase):
    """/etc/haprion did not exist on a new node when the step wrote into it (Fas 18, finding 22)."""

    def test_the_directory_is_made_and_the_file_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "etc" / "haprion" / "node-installation.json"
            # Not root: chown is what the step does as root, so it is left out here.
            done = run_lib('chown() { :; }; install_file "$1" root:root 644 "{}"', str(target))
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual(target.read_text(), "{}\n")
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o755)


class ThePackagesOwnConfigurationFile(unittest.TestCase):
    """is_packaged_conffile: only bytes dpkg itself recorded count as the package's sample."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        self.file = self.work / "haproxy.cfg"
        self.file.write_text("global\n")
        digest = subprocess.run(  # fixed tool
            ["/usr/bin/md5sum", str(self.file)], capture_output=True, text=True, check=True
        )
        self.sample_md5 = digest.stdout.split()[0]

    def packaged(self, recorded: str) -> bool:
        # dpkg-query's ${Conffiles}: one " <path> <md5>" line per file.
        fake = 'dpkg-query() { printf " %s %s\\n" /etc/other 0000 "$FILE" "$SUM"; }; '
        done = subprocess.run(  # fixed interpreter, the repository's library
            [
                "/bin/bash",
                "-c",
                f'source "$0"; {fake} is_packaged_conffile haproxy "$FILE"',
                str(LIB),
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "FILE": str(self.file), "SUM": recorded},
        )
        return done.returncode == 0

    def test_the_unchanged_sample_is_the_package_s(self) -> None:
        self.assertTrue(self.packaged(self.sample_md5))

    def test_a_changed_file_is_the_operator_s(self) -> None:
        self.file.write_text("global\n    maxconn 10\n")
        self.assertFalse(self.packaged(self.sample_md5))

    def test_a_link_or_an_unknown_package_is_not(self) -> None:
        self.assertFalse(self.packaged(""))
        target = self.work / "elsewhere.cfg"
        self.file.rename(target)
        self.file.symlink_to(target)
        self.assertFalse(self.packaged(self.sample_md5))


class TheSystemBusIsStarted(unittest.TestCase):
    """A bus apt has just installed is not running until the next boot (finding 46)."""

    def run_with(self, active: bool) -> list[str]:
        fake = (
            'systemctl() { echo "$*" >> "$CALLS"; '
            f'[[ "$1" != is-active ]] || {"true" if active else "false"}; }}; '
        )
        with tempfile.NamedTemporaryFile("r") as calls:
            done = subprocess.run(  # fixed interpreter, the repository's library
                ["/bin/bash", "-c", f'source "$0"; {fake} ensure_system_bus', str(LIB)],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "CALLS": calls.name},
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            return calls.read().splitlines()

    def test_an_inactive_bus_is_started(self) -> None:
        self.assertIn("start dbus.socket", self.run_with(active=False))

    def test_a_running_one_is_left_alone(self) -> None:
        self.assertNotIn("start dbus.socket", self.run_with(active=True))


class ThePackagesOwnEmptyDirectory(unittest.TestCase):
    """is_packaged_empty_dir: empty, and dpkg names the package among its owners."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work)
        self.directory = self.work / "conf.d"
        self.directory.mkdir()

    def packaged(self, owners: str) -> bool:
        # dpkg-query -S: "<package>[, <package>...]: <path>"
        fake = 'dpkg-query() { [[ -n "$OWNERS" ]] && printf "%s: %s\\n" "$OWNERS" "$DIR"; }; '
        done = subprocess.run(  # fixed interpreter, the repository's library
            [
                "/bin/bash",
                "-c",
                f'source "$0"; {fake} is_packaged_empty_dir haproxy "$DIR"',
                str(LIB),
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "DIR": str(self.directory), "OWNERS": owners},
        )
        return done.returncode == 0

    def test_an_empty_directory_of_the_package_s_is_its(self) -> None:
        self.assertTrue(self.packaged("haproxy"))
        self.assertTrue(self.packaged("other, haproxy"))

    def test_one_with_a_file_in_it_or_of_another_package_is_not(self) -> None:
        self.assertFalse(self.packaged(""))
        self.assertFalse(self.packaged("haproxy-other"))
        (self.directory / "mine.cfg").write_text("mine\n")
        self.assertFalse(self.packaged("haproxy"))


if __name__ == "__main__":
    unittest.main()


#
# ensure_haproxy with what it installs recorded under a scratch root and apt
# left out; dpkg-query answers from a file, the version before the install and
# then the one after it.
#
ENSURE_HAPROXY = (
    'source "$0"; cd "$(dirname "$0")"; '
    'install_file() { mkdir -p "$ROOT$(dirname "$1")"; printf "%s\\n" "$4" > "$ROOT$1"; }; '
    "install() { :; }; apt_update() { :; }; "
    'apt-get() { echo "$*" >> "$APT_CALLS"; }; '
    'apt-cache() { echo "  Candidate: ${CANDIDATE}"; }; '
    'systemctl() { echo "$*" >> "$CALLS"; }; '
    'dpkg-query() { local first; first="$(head -n 1 "$ANSWERS")"; sed -i 1d "$ANSWERS"; '
    'echo "$first"; }; '
    'ensure_haproxy "$1"'
)


class HaproxyFromItsMaintainer(unittest.TestCase):
    """ensure_haproxy writes what a restored node gets (haproxy_repository), byte for byte."""

    def run_step(
        self,
        os_id: str,
        codename: str,
        before: str,
        role: str = "",
        serving: bool = False,
        candidate: str = "3.4.7-1",
    ) -> tuple[int, str, dict[str, bytes]]:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        root = work / "root"
        root.mkdir()
        self.calls = work / "systemctl"
        self.calls.touch()
        self.apt_calls = work / "apt-get"
        self.apt_calls.touch()
        answers = work / "dpkg"
        answers.write_text(f"{before}\n3.4.7-1\n")
        os_release = work / "os-release"
        os_release.write_text(f"ID={os_id}\nVERSION_CODENAME={codename}\n")
        current = work / "current"
        if serving:
            (work / "20261015-120000").mkdir()
            current.symlink_to(work / "20261015-120000")
        done = subprocess.run(  # fixed interpreter, the repository's library
            ["/bin/bash", "-c", ENSURE_HAPROXY, str(LIB), role],
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "ROOT": str(root),
                "ANSWERS": str(answers),
                "OS_RELEASE": str(os_release),
                "HAPROXY_CURRENT": str(current),
                "CALLS": str(self.calls),
                "APT_CALLS": str(self.apt_calls),
                "CANDIDATE": candidate,
            },
        )
        files = {
            "/" + path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }
        return done.returncode, done.stdout + done.stderr, files

    def test_each_distribution_gets_what_a_restore_writes(self) -> None:
        from haprion import haproxy_repository

        for os_id, version, codename in (
            ("debian", "13", "trixie"),
            ("ubuntu", "26.04", "resolute"),
        ):
            with self.subTest(os_id=os_id):
                code, output, files = self.run_step(os_id, codename, "3.0.11-1+deb13u3")
                self.assertEqual(code, 0, output)
                expected = {
                    written.path: written.data
                    for written in haproxy_repository.repository_files(
                        {"ID": os_id, "VERSION_ID": version, "VERSION_CODENAME": codename},
                        "3.4",
                    )
                }
                self.assertEqual(files, expected)
                self.assertIn("ok       haproxy 3.4.7-1", output)

    def test_a_host_already_on_the_branch_is_left_as_it_is(self) -> None:
        code, output, files = self.run_step("ubuntu", "resolute", "3.4.6-1ppa1~resolute")
        self.assertEqual((code, files), (0, {}), output)
        self.assertIn("ok       haproxy 3.4.6-1ppa1~resolute", output)

    def test_a_node_serving_a_release_is_not_upgraded(self) -> None:
        code, output, files = self.run_step(
            "debian", "trixie", "3.0.11-1", role="node", serving=True
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(files, {})
        self.assertIn("this node serves a release", output)

    def test_a_new_node_is(self) -> None:
        code, output, files = self.run_step("debian", "trixie", "3.0.11-1", role="node")
        self.assertEqual(code, 0, output)
        self.assertIn("/etc/apt/sources.list.d/haproxy-3.4.sources", files)

    def test_the_upgraded_haproxy_is_started_again_from_its_new_unit(self) -> None:
        # Debian's 3.0 master kept reloading 3.4 without conf.d (install test, 26-10-15).
        code, output, _ = self.run_step("debian", "trixie", "3.0.11-1", role="node")
        self.assertEqual(code, 0, output)
        self.assertEqual(
            self.calls.read_text().splitlines(),
            ["daemon-reload", "is-active --quiet haproxy", "restart haproxy"],
        )

    def test_one_already_on_the_branch_is_not_restarted(self) -> None:
        self.run_step("ubuntu", "resolute", "3.4.6-1ppa1~resolute")
        self.assertEqual(self.calls.read_text(), "")

    def test_a_repository_that_did_not_answer_installs_nothing_older(self) -> None:
        # apt-get update exits 0 when a source answers 503, and the
        # distribution's 3.2 is then the candidate (26-10-21).
        code, output, _ = self.run_step("ubuntu", "resolute", "", candidate="3.2.9-1ubuntu2.2")
        self.assertNotEqual(code, 0)
        self.assertIn("ppa.launchpadcontent.net/vbernat/haproxy-3.4/ubuntu offers no 3.4", output)
        self.assertIn("apt would install '3.2.9-1ubuntu2.2'", output)
        self.assertEqual(self.apt_calls.read_text(), "")
        self.assertEqual(self.calls.read_text(), "")

    def test_another_distribution_is_refused(self) -> None:
        code, output, files = self.run_step("debian", "bookworm", "2.6.12-1")
        self.assertNotEqual(code, 0)
        self.assertEqual(files, {})
        self.assertIn("not a supported distribution", output)


ENSURE_DNSDIST = (
    'source "$0"; cd "$(dirname "$0")"; '
    "install_file() { :; }; install() { :; }; apt_update() { :; }; systemctl() { :; }; "
    'apt-get() { echo "$*" >> "$APT_CALLS"; }; '
    'apt-cache() { echo "  Candidate: ${CANDIDATE}"; }; '
    'dnsdist() { echo "dnsdist 2.1.3 (Lua 5.4)"; }; '
    "ensure_dnsdist"
)


class DnsdistFromPowerDns(unittest.TestCase):
    def run_step(self, candidate: str) -> tuple[int, str, str]:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        calls = work / "apt-get"
        calls.touch()
        done = subprocess.run(  # fixed interpreter, the repository's library
            ["/bin/bash", "-c", ENSURE_DNSDIST, str(LIB)],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "APT_CALLS": str(calls), "CANDIDATE": candidate},
        )
        return done.returncode, done.stdout + done.stderr, calls.read_text()

    def test_the_2_1_series_is_installed(self) -> None:
        code, output, calls = self.run_step("2.1.3-1pdns.ubuntu26.04")
        self.assertEqual(code, 0, output)
        self.assertIn("install -y -q dnsdist", calls)

    def test_a_repository_that_did_not_answer_installs_nothing_older(self) -> None:
        # apt-get update exits 0 when a source does not answer (26-10-21).
        code, output, calls = self.run_step("1.9.10-1")
        self.assertNotEqual(code, 0)
        self.assertIn("repo.powerdns.com offers no 2.1 (apt would install '1.9.10-1')", output)
        self.assertEqual(calls, "")
