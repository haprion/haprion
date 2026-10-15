"""04-node-prepare reports what listens on every address (26-10-15).

sshd's `0.0.0.0:22` held port 22 on the virtual address, and a tcp object on 22
failed every deploy. The node step checks for it rather than changing sshd;
`wildcard_listeners` is the part that reads `ss`, run here on captured lines.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

NODE_PREPARE = Path(__file__).resolve().parents[1] / "install" / "04-node-prepare"
LIB = NODE_PREPARE.parent / "lib.sh"

#
# `ss -Hltnp` as a node answers it: sshd socket activated (systemd alone while
# no session runs, sshd beside it while one does), HAProxy on the virtual
# address and on its metrics port, and listeners on one address only.
#
LISTENING = """\
LISTEN 0      4096         0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=457508,fd=3),("systemd",pid=1,fd=238))
LISTEN 0      4096            [::]:22       [::]:* users:(("sshd",pid=457508,fd=4),("systemd",pid=1,fd=239))
LISTEN 0      4096         0.0.0.0:9100  0.0.0.0:* users:(("systemd",pid=1,fd=90))
LISTEN 0      4096         0.0.0.0:8405  0.0.0.0:* users:(("haproxy",pid=2934330,fd=9))
LISTEN 0      4096         0.0.0.0:9521  0.0.0.0:* users:(("dnsdist",pid=1500,fd=21))
LISTEN 0      4096         0.0.0.0:6556  0.0.0.0:* users:(("cmk-agent-ctl",pid=900,fd=9))
LISTEN 0      4096     192.0.2.20:443    0.0.0.0:* users:(("haproxy",pid=2934330,fd=12))
LISTEN 0      4096     192.0.2.11:2222   0.0.0.0:* users:(("sshd",pid=1200,fd=3))
LISTEN 0      4096       127.0.0.1:9520  0.0.0.0:* users:(("coraza-spoa",pid=800,fd=7))
LISTEN 0      511                *:5000        *:*
"""


def wildcard_listeners(text: str) -> list[str]:
    script = NODE_PREPARE.read_text()
    found = re.search(r"^wildcard_listeners\(\) \{\n.*?^\}\n", script, re.MULTILINE | re.DOTALL)
    assert found is not None, "04-node-prepare has no wildcard_listeners"
    run = subprocess.run(  # noqa: S603 - fixed binary, the function from the script
        ["/bin/bash", "-c", f"set -Eeuo pipefail\n{found.group(0)}wildcard_listeners"],
        input=text,
        capture_output=True,
        text=True,
        check=True,
    )
    return run.stdout.splitlines()


class TheNodeStepReportsWhatListensOnEveryAddress(unittest.TestCase):
    def test_programs_on_every_address_are_named_once_a_port(self) -> None:
        self.assertEqual(
            wildcard_listeners(LISTENING),
            [
                "22 sshd",
                "5000 an unnamed program",
                "6556 cmk-agent-ctl",
                "9100 systemd",
                "9521 dnsdist",
            ],
        )

    def test_haproxy_and_one_address_listeners_are_left_out(self) -> None:
        reported = " ".join(wildcard_listeners(LISTENING))
        for port in ("8405", "443", "2222", "9520"):
            self.assertNotIn(port, reported.split())

    def test_nothing_on_every_address_reports_nothing(self) -> None:
        self.assertEqual(wildcard_listeners(""), [])

    def test_the_step_warns_about_each(self) -> None:
        script = NODE_PREPARE.read_text()
        self.assertIn('wildcard_report="$(wildcard_listeners <<<"$listening")"', script)


def function(script: str, name: str) -> str:
    found = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", script, re.MULTILINE | re.DOTALL)
    assert found is not None, f"04-node-prepare has no {name}"
    return found.group(0)


#
# Stand-ins for what the step asks: sshd answers by whether the drop-in exists,
# and so does ss - unless sshd_config itself names every address (STUCK).
#
FAKES = {
    "sshd": """#!/bin/bash
[[ "$1" == -t ]] && exit 0
echo "port 22"
if [[ -f "$SSHD_LISTEN" ]]; then echo "listenaddress 192.0.2.11:22"; fi
if [[ ! -f "$SSHD_LISTEN" || -n "${STUCK:-}" || -n "${CHOSEN:-}" ]]; then
    [[ -n "${CHOSEN:-}" ]] && echo "listenaddress 192.0.2.11:22" || echo "listenaddress 0.0.0.0:22"
fi
""",
    "ss": """#!/bin/bash
if [[ -f "$SSHD_LISTEN" ]]; then echo "LISTEN 0 4096 192.0.2.11:22 0.0.0.0:*"; fi
if [[ ! -f "$SSHD_LISTEN" || -n "${STUCK:-}" ]]; then echo "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*"; fi
""",
    "systemctl": '#!/bin/bash\necho "$*" >> "$CALLS"\n[[ "$1" == is-active ]] && exit 1\nexit 0\n',
    "getent": '#!/bin/bash\necho "192.0.2.5 STREAM mgr"\n',
    "ip": """#!/bin/bash
case "$*" in
    *"route get"*) echo "192.0.2.5 dev eth0 src ${SOURCE:-192.0.2.11} uid 0" ;;
    *"addr show"*) echo "2: eth0    inet 192.0.2.11/24 brd 192.0.2.255 scope global eth0" ;;
esac
""",
    "sleep": "#!/bin/sh\nexit 0\n",
}


class TheNodeStepTakesSshdOffTheVirtualAddress(unittest.TestCase):
    """B310: sshd on the node's own address, or put back as it was."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="sshd-listen-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name, text in FAKES.items():
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.drop_in = self.root / "05-haprion-listen.conf"
        self.calls = self.root / "calls"
        script = NODE_PREPARE.read_text()
        self.program = "\n".join(
            (
                f"source {LIB}",
                #
                # The file itself, without the chown only root may do.
                #
                'install_file() { printf "%s\\n" "$4" > "$1"; log "  written  $1"; }',
                f'SSHD_LISTEN="{self.drop_in}"',
                function(script, "sshd_restart"),
                function(script, "sshd_put_back"),
                function(script, "sshd_off_the_virtual_address"),
                "sshd_off_the_virtual_address",
            )
        )
        self.env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "SSHD_LISTEN": str(self.drop_in),
            "CALLS": str(self.calls),
            "MANAGER_HOST": "mgr",
            "CLUSTER": "alpha",
            "VIP_alpha": "192.0.2.20",
        }

    def run_step(self, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed binary, the step's own functions
            ["/bin/bash", "-c", self.program],
            env={**os.environ, **self.env, **extra},
            capture_output=True,
            text=True,
            check=False,
        )

    def restarts(self) -> list[str]:
        if not self.calls.exists():
            return []
        return [line for line in self.calls.read_text().splitlines() if "restart" in line]

    def test_sshd_on_every_address_is_given_the_node_s_own(self) -> None:
        run = self.run_step()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("ListenAddress 192.0.2.11\n", self.drop_in.read_text())
        self.assertIn("applied  sshd listens on 192.0.2.11:22 only", run.stdout)
        self.assertEqual(self.restarts(), ["restart ssh.service"])

    def test_sshd_already_on_chosen_addresses_is_left_alone(self) -> None:
        run = self.run_step(CHOSEN="1")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("ok       sshd listens on chosen addresses only", run.stdout)
        self.assertFalse(self.drop_in.exists())
        self.assertEqual(self.restarts(), [])

    def test_the_virtual_address_is_never_written(self) -> None:
        run = self.run_step(SOURCE="192.0.2.20")
        self.assertEqual(run.returncode, 1)
        self.assertIn("from the virtual address", run.stderr)
        self.assertFalse(self.drop_in.exists())
        self.assertEqual(self.restarts(), [])

    def test_sshd_still_on_every_address_is_put_back(self) -> None:
        run = self.run_step(STUCK="1")
        self.assertEqual(run.returncode, 1)
        self.assertIn("put back as it was", run.stderr)
        self.assertFalse(self.drop_in.exists())
        self.assertEqual(self.restarts(), ["restart ssh.service", "restart ssh.service"])


class AFreshNodeTakesTheReleaseLayout(unittest.TestCase):
    """Fas 18 findings 23 and 24, on a node with nothing on it but the packages."""

    def setUp(self) -> None:
        self.script = NODE_PREPARE.read_text()
        self.etc = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.etc)

    def link(self, packaged: bool, name: str = "haproxy.cfg") -> subprocess.CompletedProcess[str]:
        body = function(self.script, "link_into_current").replace("/etc/haproxy/", f"{self.etc}/")
        verdict = "true" if packaged else "false"
        return subprocess.run(  # noqa: S603 - fixed interpreter, the step's own function
            [
                "/bin/bash",
                "-c",
                f'log() {{ echo "$*"; }}; warn() {{ echo "WARNING: $*"; }}; '
                f"is_packaged_conffile() {{ {verdict}; }}; is_packaged_empty_dir() {{ {verdict}; }}; "
                f"{body} link_into_current {name}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_package_s_sample_is_kept_beside_and_the_link_made(self) -> None:
        (self.etc / "haproxy.cfg").write_text("sample\n")
        done = self.link(packaged=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(os.readlink(self.etc / "haproxy.cfg"), "current/haproxy.cfg")
        self.assertEqual((self.etc / "haproxy.cfg.packaged").read_text(), "sample\n")

    def test_an_operator_s_file_is_left_alone(self) -> None:
        (self.etc / "haproxy.cfg").write_text("mine\n")
        done = self.link(packaged=False)
        self.assertIn("not touching it", done.stdout)
        self.assertEqual((self.etc / "haproxy.cfg").read_text(), "mine\n")
        self.assertFalse((self.etc / "haproxy.cfg.packaged").exists())

    def test_the_package_s_empty_conf_d_gives_way_to_the_release_s(self) -> None:
        (self.etc / "conf.d").mkdir()
        done = self.link(packaged=True, name="conf.d")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(os.readlink(self.etc / "conf.d"), "current/conf.d")
        self.assertNotIn("WARNING", done.stdout)

    def test_a_conf_d_of_the_operator_s_is_left_alone(self) -> None:
        (self.etc / "conf.d").mkdir()
        (self.etc / "conf.d" / "mine.cfg").write_text("mine\n")
        done = self.link(packaged=False, name="conf.d")
        self.assertIn("not touching it", done.stdout)
        self.assertTrue((self.etc / "conf.d" / "mine.cfg").exists())

    def test_without_a_node_path_the_node_takes_the_cluster_id(self) -> None:
        found = re.search(r'^node_path="\$\(cluster_value .*?\n(?=\n)', self.script, re.M | re.S)
        assert found, "04-node-prepare no longer looks the node path up where the test reads it"
        for answers, expected in (("", "alpha"), ("NODE_PATH_alpha=a", "a")):
            with self.subTest(answers=answers):
                done = subprocess.run(  # noqa: S603 - fixed interpreter, the step's own lines
                    [
                        "/bin/bash",
                        "-c",
                        f'source "{LIB}"; CLUSTER=alpha; {answers}\n{found.group(0)}\n'
                        'printf %s "$node_path"',
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual((done.returncode, done.stdout), (0, expected), done.stderr)


class DocumentationDpkgLeftOutIsNoChange(unittest.TestCase):
    """Ubuntu's minimal images exclude /usr/share/doc; dpkg --verify then
    reported the package's own documentation missing and step 4 stopped
    (Fas 18, the install test, 26-10-15)."""

    def changes(self, report: str) -> str:
        body = function(NODE_PREPARE.read_text(), "node_package_changes")
        done = subprocess.run(  # noqa: S603 - fixed interpreter, the step's own function
            [
                "/bin/bash",
                "-c",
                f'dpkg() {{ printf "%s" "$REPORT"; [[ -z "$REPORT" ]]; }}; {body} node_package_changes',
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "REPORT": report},
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_excluded_documentation_is_not_a_change(self) -> None:
        report = (
            "missing     /usr/share/doc/haprion-node/copyright\n"
            "missing   c /usr/share/doc/haprion-node/changelog\n"
        )
        self.assertEqual(self.changes(report), "")

    def test_an_edited_script_still_is(self) -> None:
        report = "missing     /usr/share/doc/haprion-node/copyright\n??5??????   /usr/sbin/haprion-pull-deploy\n"
        self.assertEqual(self.changes(report), "??5??????   /usr/sbin/haprion-pull-deploy\n")

    def test_a_missing_script_still_is(self) -> None:
        report = "missing     /usr/sbin/haprion-pull-deploy\n"
        self.assertEqual(self.changes(report), report)


if __name__ == "__main__":
    unittest.main()
