"""The node's dnsdist steps, exercised as the shell they actually are (B249).

The functions are extracted from `install/node/haprion-pull-deploy` verbatim and
run with `systemctl`, `ss` and dnsdist replaced by recording stubs, as
`test_node_waf_engine` does for the WAF engine. dnsdist's answers are the ones
measured on 2.1.2: `--check-config` exits 0 and warns on a key it does not
know, and exits 1 on a configuration it cannot load.

What this does not prove is systemd itself - the drop-in, `_dnsdist` reaching
the file through its group. That is measured on the first node.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-pull-deploy"
FUNCTIONS = ("validate_dns_candidate", "dns_listening", "sync_dns_listener")

SYSTEMCTL = """#!/bin/bash
echo "systemctl $*" >> "$RECORD"
case "$1" in
    is-active) [[ "${ACTIVE:-0}" == 1 ]] ;;
    is-enabled) [[ "${ENABLED:-0}" == 1 ]] ;;
    *) exit "${SYSTEMCTL_EXIT:-0}" ;;
esac
"""
SS = """#!/bin/bash
echo "ss $*" >> "$RECORD"
[[ "${LISTEN:-0}" == 1 ]] && echo "UNCONN 0 0 192.0.2.10:53 0.0.0.0:* users:((\\"dnsdist\\",pid=7,fd=9))"
[[ "${LISTEN:-0}" == other ]] && echo "UNCONN 0 0 192.0.2.10:53 0.0.0.0:* users:((\\"named\\",pid=8,fd=3))"
exit 0
"""
DNSDIST = """#!/bin/bash
echo "dnsdist $*" >> "$RECORD"
echo "${CHECK_OUTPUT:-msg=\\"Configuration OK\\" prio=\\"Info\\"}"
exit "${CHECK_EXIT:-0}"
"""
LISTENER = 'setLocal("192.0.2.10:53")\nnewServer({address="198.51.100.53:53"})\n'


def extract(name: str, text: str) -> str:
    found = re.search(rf"^{name}\(\) \{{.*?^\}}$", text, re.DOTALL | re.MULTILINE)
    assert found, f"{name} is no longer where the test extracts it from"
    return found.group(0)


class TheDnsListenerSteps(unittest.TestCase):
    def setUp(self) -> None:
        text = SCRIPT.read_text()
        self.functions = "\n".join(extract(name, text) for name in FUNCTIONS)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, body in (("systemctl", SYSTEMCTL), ("ss", SS)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.dnsdist = self.root / "dnsdist"
        self.dnsdist.write_text(DNSDIST)
        self.dnsdist.chmod(0o755)
        self.dropin = self.root / "dropin.conf"
        self.dropin.write_text("[Service]\n")
        self.current = self.root / "current"
        self.current.mkdir()
        self.previous = self.root / "previous"
        self.previous.mkdir()
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.record = self.root / "record"

    def listener(self, release: Path, text: str = LISTENER) -> None:
        (release / "dns").mkdir(exist_ok=True)
        (release / "dns" / "dnsdist.conf").write_text(text)

    def run_step(
        self, call: str, *, dnsdist: Path | None = None, **environment: str
    ) -> tuple[int, str]:
        script = self.root / "step.sh"
        script.write_text(
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            f'CURRENT="{self.current}"\n'
            f'DNSDIST="{dnsdist or self.dnsdist}"\n'
            'DNS_UNIT="dnsdist.service"\n'
            f'DNS_DROPIN="{self.dropin}"\n'
            "DNS_WAIT_SECONDS=1\n"
            f"{self.functions}\n"
            f"{call}\n"
        )
        finished = subprocess.run(  # bash running the extracted functions
            ["/bin/bash", str(script)],
            capture_output=True,
            text=True,
            env={"PATH": f"{self.bin}:/usr/bin:/bin", "RECORD": str(self.record), **environment},
            check=False,
            timeout=30,
        )
        return finished.returncode, finished.stdout

    def calls(self) -> str:
        return self.record.read_text() if self.record.exists() else ""

    # - validation -----------------------------------------------------------

    def test_a_candidate_without_a_listener_is_not_shown_to_dnsdist(self) -> None:
        code, _ = self.run_step(f'validate_dns_candidate "{self.candidate}"')

        self.assertEqual((code, self.calls()), (0, ""))

    def test_a_listener_on_a_node_not_prepared_for_one_is_refused(self) -> None:
        self.listener(self.candidate)
        for missing in ("binary", "dropin"):
            with self.subTest(missing):
                if missing == "dropin":
                    self.dropin.unlink()
                code, output = self.run_step(
                    f'validate_dns_candidate "{self.candidate}"',
                    dnsdist=self.root / "absent" if missing == "binary" else None,
                )
                self.assertEqual(code, 1)
                self.assertIn("run  sudo haprion-node-prepare  on this node", output)

    def test_a_clean_check_passes_and_names_the_candidates_file(self) -> None:
        self.listener(self.candidate)

        code, _ = self.run_step(f'validate_dns_candidate "{self.candidate}"')

        self.assertEqual(code, 0)
        self.assertIn(f"--check-config -C {self.candidate}/dns/dnsdist.conf", self.calls())

    def test_a_warning_refuses_although_dnsdist_exits_0(self) -> None:
        self.listener(self.candidate)

        code, output = self.run_step(
            f'validate_dns_candidate "{self.candidate}"',
            CHECK_OUTPUT='msg="Unknown key, ignored" prio="Warning" key="x"',
        )

        self.assertEqual(code, 1)
        self.assertIn("Unknown key", output)

    def test_a_failed_check_refuses(self) -> None:
        self.listener(self.candidate)

        code, _ = self.run_step(f'validate_dns_candidate "{self.candidate}"', CHECK_EXIT="1")

        self.assertEqual(code, 1)

    # - running --------------------------------------------------------------

    def test_without_a_listener_a_running_dnsdist_is_stopped(self) -> None:
        code, _ = self.run_step(f'sync_dns_listener "{self.previous}"', ACTIVE="1")

        self.assertEqual(code, 0)
        self.assertIn("systemctl disable --quiet --now dnsdist.service", self.calls())

    def test_without_a_listener_a_stopped_dnsdist_is_left_alone(self) -> None:
        self.run_step(f'sync_dns_listener "{self.previous}"')

        self.assertNotIn("disable", self.calls())

    def test_a_stopped_dnsdist_is_started_and_must_listen(self) -> None:
        self.listener(self.current)

        code, output = self.run_step(f'sync_dns_listener "{self.previous}"', ACTIVE="0", LISTEN="1")

        self.assertIn("systemctl enable --quiet --now dnsdist.service", self.calls())
        # The stub says inactive throughout, so the wait sees no service.
        self.assertEqual(code, 1)
        self.assertIn("did not start listening", output)

    def test_a_changed_file_restarts_a_running_dnsdist(self) -> None:
        self.listener(self.current)
        self.listener(self.previous, LISTENER.replace("198.51.100.53", "198.51.100.54"))

        code, output = self.run_step(
            f'sync_dns_listener "{self.previous}"', ACTIVE="1", ENABLED="1", LISTEN="1"
        )

        self.assertEqual(code, 0, output)
        self.assertIn("systemctl restart dnsdist.service", self.calls())
        self.assertIn("dnsdist listening", output)

    def test_an_unchanged_file_does_not_restart(self) -> None:
        self.listener(self.current)
        self.listener(self.previous)

        code, _ = self.run_step(f'sync_dns_listener "{self.previous}"', ACTIVE="1", ENABLED="1")

        self.assertEqual(code, 0)
        self.assertNotIn("restart", self.calls())

    def test_a_port_held_by_another_process_is_not_listening(self) -> None:
        self.listener(self.current)
        self.listener(self.previous, LISTENER.replace("198.51.100.53", "198.51.100.54"))

        code, output = self.run_step(
            f'sync_dns_listener "{self.previous}"', ACTIVE="1", ENABLED="1", LISTEN="other"
        )

        self.assertEqual(code, 1)
        self.assertIn("did not start listening", output)


STATUS = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"


class TheStatusReport(unittest.TestCase):
    """What the node tells the manager about dnsdist (B249), in the WAF engine's shape."""

    def report(self, dpkg: tuple[int, str], active: bool) -> dict[str, object]:
        text = STATUS.read_text()
        helper = re.search(r"^def package_version\(.*?(?=^\S)", text, re.DOTALL | re.MULTILINE)
        reader = re.search(r"^def read_dns_listener\(.*?(?=^\S)", text, re.DOTALL | re.MULTILINE)
        assert helper and reader, "the dns report is no longer where the test extracts it from"
        self.asked = 0

        def counters() -> dict[str, object]:
            self.asked += 1
            return {"uptime_sec": 9, "pools": [], "servers": []}

        namespace: dict[str, object] = {
            "DNS_PACKAGE": "dnsdist",
            "DNS_UNIT": "dnsdist.service",
            "run": lambda *argv: subprocess.CompletedProcess(argv, dpkg[0], dpkg[1], ""),
            "service_active": lambda name: active,
            "dns_counters": counters,
        }
        exec(helper.group(0) + reader.group(0), namespace)  # noqa: S102 - the script's own functions
        reading = namespace["read_dns_listener"]
        assert callable(reading)
        report: dict[str, object] = reading()
        return report

    def test_an_installed_dnsdist_reports_its_package_version_and_counters(self) -> None:
        self.assertEqual(
            self.report((0, "install ok installed\t2.1.2-1pdns.debian13"), True),
            {
                "version": "2.1.2-1pdns.debian13",
                "active": True,
                "counters": {"uptime_sec": 9, "pools": [], "servers": []},
            },
        )
        self.assertEqual(self.asked, 1)

    def test_a_missing_package_reports_none(self) -> None:
        self.assertEqual(
            self.report((1, ""), False), {"version": None, "active": False, "counters": None}
        )

    def test_a_stopped_dnsdist_is_not_asked_for_its_counters(self) -> None:
        """null rather than an empty reading: nothing was counted, nothing was read."""

        report = self.report((0, "install ok installed\t2.1.2-1pdns.debian13"), False)
        self.assertIsNone(report["counters"])
        self.assertEqual(self.asked, 0)


if __name__ == "__main__":
    unittest.main()
