"""The node's WAF engine steps, exercised as the shell they actually are.

The functions are extracted from `install/node/haproxy-pull-deploy` verbatim and
run with `systemctl`, `journalctl`, `ss` and the engine replaced by recording
stubs - the same method as the keepalived step. The engine's own answers are
the lines it was measured to log (2026-10-02, Coraza SPOA v0.9.0):
"Configuration successfully reloaded" and "Failed to reload configuration".

What this does not prove is systemd itself - DynamicUser, the unit's sandbox,
the journal reaching the unit's lines. That is measured on the first node.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-pull-deploy"
FUNCTIONS = ("validate_waf_candidate", "waf_listening", "waf_journal", "sync_waf_engine")

#
# systemctl answers from the state in the environment and records every call;
# a reload appends the engine's answer to the journal, as the real engine does.
#
SYSTEMCTL = """#!/bin/bash
echo "systemctl $*" >> "$RECORD"
quiet=""
[[ "$2" == --quiet ]] && quiet=1
case "$1" in
    is-active) [[ "${ACTIVE:-0}" == 1 ]] ;;
    is-enabled) [[ "${ENABLED:-0}" == 1 ]] ;;
    reload) [[ -z "${REPLY_LINE:-}" ]] || echo "$REPLY_LINE" >> "$JOURNAL"; exit "${RELOAD_EXIT:-0}" ;;
    show) echo "${NAMESPACE:-}" ;;
    *) exit "${SYSTEMCTL_EXIT:-0}" ;;
esac
"""
JOURNALCTL = """#!/bin/bash
echo "journalctl $*" >> "$RECORD"
for argument in "$@"; do
    [[ "$argument" == --show-cursor ]] && { echo "-- cursor: s=example"; exit 0; }
done
cat "$JOURNAL" 2>/dev/null || true
"""
SS = """#!/bin/bash
echo "ss $*" >> "$RECORD"
[[ "${LISTEN:-0}" == 1 ]] && echo "LISTEN 0 4096 127.0.0.1:12345 0.0.0.0:* users:((\\"coraza-spoa\\",pid=7,fd=3))"
[[ "${LISTEN:-0}" == other ]] && echo "LISTEN 0 4096 127.0.0.1:12345 0.0.0.0:* users:((\\"python3\\",pid=8,fd=3))"
exit 0
"""
ENGINE = """#!/bin/bash
echo "engine $*" >> "$RECORD"
exit "${VALIDATE_EXIT:-0}"
"""


def extract(name: str, text: str) -> str:
    found = re.search(rf"^{name}\(\) \{{.*?^\}}$", text, re.DOTALL | re.MULTILINE)
    assert found, f"{name} is no longer where the test extracts it from"
    return found.group(0)


class TheWafEngineSteps(unittest.TestCase):
    def setUp(self) -> None:
        text = SCRIPT.read_text()
        self.functions = "\n".join(extract(name, text) for name in FUNCTIONS)
        self.root = Path(tempfile.mkdtemp())
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, body in (("systemctl", SYSTEMCTL), ("journalctl", JOURNALCTL), ("ss", SS)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.engine = self.root / "coraza-spoa"
        self.engine.write_text(ENGINE)
        self.engine.chmod(0o755)
        self.current = self.root / "current"
        self.current.mkdir()
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.record = self.root / "record"
        self.journal = self.root / "journal"

    def with_rules(self, release: Path) -> None:
        (release / "waf").mkdir()
        (release / "waf" / "coraza.yaml").write_text("bind: 127.0.0.1:12345\napplications: []\n")

    def run_step(
        self, call: str, *, engine: Path | None = None, **environment: str
    ) -> tuple[int, str]:
        script = self.root / "step.sh"
        script.write_text(
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            f'CURRENT="{self.current}"\n'
            f'WAF_ENGINE="{engine or self.engine}"\n'
            'WAF_UNIT="coraza-spoa.service"\n'
            "WAF_WAIT_SECONDS=1\n"
            f"{self.functions}\n"
            f"{call}\n"
        )
        finished = subprocess.run(
            ["/bin/bash", str(script)],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "RECORD": str(self.record),
                "JOURNAL": str(self.journal),
                **environment,
            },
            check=False,
            timeout=30,
        )
        return finished.returncode, finished.stdout

    def calls(self) -> str:
        return self.record.read_text() if self.record.exists() else ""

    # - validation -----------------------------------------------------------

    def test_a_candidate_without_rules_is_not_shown_to_the_engine(self) -> None:
        code, _ = self.run_step(f'validate_waf_candidate "{self.candidate}"')

        self.assertEqual(code, 0)
        self.assertEqual(self.calls(), "")

    def test_rules_on_a_node_without_the_engine_are_refused(self) -> None:
        self.with_rules(self.candidate)

        code, output = self.run_step(
            f'validate_waf_candidate "{self.candidate}"', engine=self.root / "absent"
        )

        self.assertEqual(code, 1)
        self.assertIn("haproxy-manager-coraza-spoa", output)

    def test_rules_the_engine_rejects_are_refused(self) -> None:
        self.with_rules(self.candidate)

        code, output = self.run_step(
            f'validate_waf_candidate "{self.candidate}"', VALIDATE_EXIT="1"
        )

        self.assertEqual(code, 1)
        self.assertIn("rejected the candidate rules", output)

    def test_the_engine_compiles_the_candidate_and_not_the_live_rules(self) -> None:
        self.with_rules(self.candidate)

        code, _ = self.run_step(f'validate_waf_candidate "{self.candidate}"')

        self.assertEqual(code, 0)
        self.assertEqual(
            self.calls(), f"engine -validate -config {self.candidate}/waf/coraza.yaml\n"
        )

    # - a release without rules ----------------------------------------------

    def test_without_rules_an_engine_that_never_ran_is_left_alone(self) -> None:
        code, _ = self.run_step("sync_waf_engine 1")

        self.assertEqual(code, 0)
        self.assertNotIn("disable", self.calls())

    def test_without_rules_a_running_engine_is_stopped_and_disabled(self) -> None:
        code, _ = self.run_step("sync_waf_engine 1", ACTIVE="1", ENABLED="1")

        self.assertEqual(code, 0)
        self.assertIn("systemctl disable --now coraza-spoa.service", self.calls())

    # - a release with rules -------------------------------------------------

    def test_the_first_release_with_rules_starts_and_enables_the_engine(self) -> None:
        self.with_rules(self.current)

        code, output = self.run_step("sync_waf_engine 1", LISTEN="1")

        self.assertEqual(code, 0)
        self.assertIn("systemctl enable --now coraza-spoa.service", self.calls())
        self.assertIn("sport = :12345", self.calls())
        self.assertIn("engine listening", output)

    def test_another_process_on_the_port_is_not_the_engine(self) -> None:
        self.with_rules(self.current)

        code, output = self.run_step("sync_waf_engine 1", LISTEN="other")

        self.assertEqual(code, 1)
        self.assertIn("did not start listening", output)

    def test_an_engine_that_never_listens_fails_the_deploy(self) -> None:
        self.with_rules(self.current)

        code, output = self.run_step("sync_waf_engine 1", LISTEN="0")

        self.assertEqual(code, 1)
        self.assertIn("did not start listening", output)

    def test_a_running_engine_takes_new_rules_when_it_says_so(self) -> None:
        self.with_rules(self.current)

        code, output = self.run_step(
            "sync_waf_engine 1",
            ACTIVE="1",
            ENABLED="1",
            REPLY_LINE='{"level":"info","message":"Configuration successfully reloaded"}',
        )

        self.assertEqual(code, 0)
        self.assertIn("systemctl reload coraza-spoa.service", self.calls())
        self.assertIn("took the new rules", output)

    def test_the_answer_is_read_from_the_journal_the_unit_logs_to(self) -> None:
        # Package revision 2 logs into a namespace; revision 1 into the system journal.
        self.with_rules(self.current)
        for namespace, wanted in (("haproxy-waf", "--namespace=haproxy-waf -u"), ("", "-u")):
            with self.subTest(namespace=namespace or "system journal"):
                self.record.unlink(missing_ok=True)
                self.journal.unlink(missing_ok=True)
                code, _ = self.run_step(
                    "sync_waf_engine 1",
                    ACTIVE="1",
                    ENABLED="1",
                    NAMESPACE=namespace,
                    REPLY_LINE='{"level":"info","message":"Configuration successfully reloaded"}',
                )
                reads = [c for c in self.calls().splitlines() if c.startswith("journalctl ")]
                self.assertEqual(code, 0)
                self.assertTrue(reads)
                for read in reads:
                    self.assertTrue(
                        read.startswith(f"journalctl {wanted} coraza-spoa.service"), read
                    )

    def test_an_engine_that_keeps_its_old_rules_fails_the_deploy(self) -> None:
        self.with_rules(self.current)

        code, output = self.run_step(
            "sync_waf_engine 1",
            ACTIVE="1",
            ENABLED="1",
            REPLY_LINE='{"level":"error","message":"Failed to reload configuration, using old configuration"}',
        )

        self.assertEqual(code, 1)
        self.assertIn("kept the previous ones", output)

    def test_an_engine_that_says_nothing_fails_the_deploy(self) -> None:
        self.with_rules(self.current)

        code, output = self.run_step("sync_waf_engine 1", ACTIVE="1", ENABLED="1")

        self.assertEqual(code, 1)
        self.assertIn("did not confirm", output)

    def test_an_unchanged_release_does_not_signal_the_engine(self) -> None:
        self.with_rules(self.current)

        code, _ = self.run_step("sync_waf_engine 0", ACTIVE="1", ENABLED="1")

        self.assertEqual(code, 0)
        self.assertNotIn("reload", self.calls())

    def test_a_running_engine_that_is_not_enabled_is_enabled(self) -> None:
        # A person who started it by hand left a node that loses it at reboot.
        self.with_rules(self.current)

        code, _ = self.run_step("sync_waf_engine 0", ACTIVE="1", ENABLED="0")

        self.assertEqual(code, 0)
        self.assertIn("systemctl enable --quiet coraza-spoa.service", self.calls())


STATUS = Path(__file__).resolve().parents[1] / "install" / "node" / "haproxy-node-status"


class TheStatusReport(unittest.TestCase):
    """What the node tells the manager about its engine (B230, B231)."""

    def report(self, dpkg: tuple[int, str], active: bool) -> dict[str, object]:
        text = STATUS.read_text()
        found = re.search(
            r"^def package_version\(.*?^def read_waf_engine\(.*?(?=^\S)",
            text,
            re.DOTALL | re.MULTILINE,
        )
        assert found, "read_waf_engine is no longer where the test extracts it from"
        namespace: dict[str, Any] = {
            "WAF_PACKAGE": "haproxy-manager-coraza-spoa",
            "WAF_UNIT": "coraza-spoa.service",
            "run": lambda *argv: subprocess.CompletedProcess(argv, dpkg[0], dpkg[1], ""),
            "service_active": lambda name: active,
        }
        exec(found.group(0), namespace)  # noqa: S102 - the script's own function, verbatim
        report: dict[str, object] = namespace["read_waf_engine"]()
        return report

    def test_an_installed_engine_reports_its_package_version(self) -> None:
        self.assertEqual(
            self.report((0, "install ok installed\t0.9.0-1"), True),
            {"version": "0.9.0-1", "active": True},
        )

    def test_a_missing_or_removed_package_reports_no_engine(self) -> None:
        for dpkg in ((1, ""), (0, "deinstall ok config-files\t0.9.0-1")):
            with self.subTest(dpkg=dpkg):
                self.assertEqual(self.report(dpkg, False), {"version": None, "active": False})


class TheOrderInTheDeploy(unittest.TestCase):
    """Where the steps sit decides what a failure leaves behind."""

    def setUp(self) -> None:
        self.text = SCRIPT.read_text()

    def position(self, needle: str) -> int:
        index = self.text.find(needle)
        self.assertNotEqual(index, -1, needle)
        return index

    def test_the_rules_are_compiled_before_the_release_is_written(self) -> None:
        self.assertLess(
            self.position('validate_waf_candidate "$VALIDATE" || exit 1'),
            self.position('RELEASE="${RELEASE_DIR}/'),
        )

    def test_the_engine_takes_the_rules_before_haproxy_reloads(self) -> None:
        self.assertLess(
            self.position("if ! sync_waf_engine 1; then"),
            self.position('log "Reloading HAProxy..."'),
        )

    def test_the_validation_copy_points_the_engine_at_the_candidate(self) -> None:
        self.assertIn('-e "s#/etc/haproxy/waf/#${VALIDATE}/waf/#g"', self.text)
        self.assertIn("--include='*.yaml'", self.text)


if __name__ == "__main__":
    unittest.main()
