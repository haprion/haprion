"""A removed node steps down on reading the release without it (B319), as the shell it is.

The block is extracted from `install/node/haprion-pull-deploy` verbatim and run
with `systemctl` and `hostname` replaced by recording stubs, in a scratch root.
What it proves is the decision: which releases mean "removed", what is stopped,
and that a node added again comes back. That keepalived then lets the address
go is a fact about a real node, measured on the lab.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-pull-deploy"
BLOCK = re.compile(r'^LEFT_MARKER=.*?^    rm -f "\$LEFT_MARKER"\nfi$', re.DOTALL | re.MULTILINE)
MARK = re.compile(r"^KEEPALIVED_MARK=.*$", re.MULTILINE)


def conf(source: str, peers: tuple[str, ...], *, mark: bool = True) -> str:
    head = "# Written by Haprion - a deploy replaces this file.\n" if mark else "# mine\n"
    return (
        head
        + "vrrp_instance lab {\n"
        + f"    unicast_src_ip {source}\n"
        + "    unicast_peer {\n"
        + "".join(f"        {peer}\n" for peer in peers)
        + "    }\n}\n"
    )


class StepDown(unittest.TestCase):
    def setUp(self) -> None:
        text = SCRIPT.read_text()
        block = BLOCK.search(text)
        mark = MARK.search(text)
        assert block and mark, "the block is no longer where the test extracts it from"
        self.block = block.group(0)
        self.mark = mark.group(0)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        bin_ = self.root / "bin"
        bin_.mkdir()
        (bin_ / "systemctl").write_text(
            '#!/bin/sh\necho "systemctl $*" >> "$RECORD"\nexit "${SYSTEMCTL_EXIT:-0}"\n'
        )
        (bin_ / "hostname").write_text('#!/bin/sh\necho "${HOST:-node-b}"\n')
        for stub in bin_.iterdir():
            stub.chmod(0o755)
        self.stage = self.root / "stage"
        (self.stage / "keepalived").mkdir(parents=True)
        (self.root / "etc").mkdir()
        self.installed = self.root / "etc" / "keepalived.conf"
        self.marker = self.root / "etc" / "left-cluster"
        self.record = self.root / "record"
        # node-b, at 192.0.2.12, peering with node-a.
        self.installed.write_text(conf("192.0.2.12", ("192.0.2.11",)))

    def publish(self, *nodes: tuple[str, str]) -> None:
        for name, source in nodes:
            others = tuple(address for other, address in nodes if other != name) or ("127.0.0.1",)
            (self.stage / "keepalived" / f"node-{name}.conf").write_text(conf(source, others))

    def run_block(self, **environment: str) -> tuple[int, str]:
        script = self.root / "block.sh"
        script.write_text(
            "set -Eeuo pipefail\n"
            'log() { echo "$*"; }\n'
            f"{self.mark}\n"
            f'STAGE="{self.stage}"\n'
            f'KEEPALIVED_CONF="{self.installed}"\n'
            + self.block.replace(
                'LEFT_MARKER="/etc/haprion/left-cluster"', f'LEFT_MARKER="{self.marker}"'
            )
            + "\necho carried-on\n"
        )
        finished = subprocess.run(
            ["/bin/bash", str(script)],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.root / 'bin'}:/usr/bin:/bin",
                "RECORD": str(self.record),
                **environment,
            },
            check=False,
        )
        return finished.returncode, finished.stdout + finished.stderr

    def calls(self) -> str:
        return self.record.read_text() if self.record.exists() else ""

    def test_a_release_without_this_node_stops_and_disables_both(self) -> None:
        self.publish(("node-a", "192.0.2.11"))

        code, said = self.run_block()

        self.assertEqual(code, 0, said)
        self.assertNotIn("carried-on", said)
        self.assertIn("removed from the cluster", said)
        self.assertEqual(
            self.calls(),
            "systemctl disable --quiet --now keepalived\nsystemctl disable --quiet --now haproxy\n",
        )
        self.assertTrue(self.marker.exists())

    def test_a_release_with_this_node_goes_on_as_before(self) -> None:
        self.publish(("node-a", "192.0.2.11"), ("node-b", "192.0.2.12"))

        code, said = self.run_block()

        self.assertEqual(code, 0, said)
        self.assertIn("carried-on", said)
        self.assertEqual(self.calls(), "")

    def test_a_renamed_host_is_known_by_its_address(self) -> None:
        # The release names node-b; this machine now calls itself node-x.
        self.publish(("node-a", "192.0.2.11"), ("node-b", "192.0.2.12"))

        code, said = self.run_block(HOST="node-x")

        self.assertIn("carried-on", said, code)
        self.assertEqual(self.calls(), "")

    def test_a_person_s_keepalived_or_a_release_without_the_files_is_left_alone(self) -> None:
        self.publish(("node-a", "192.0.2.11"))
        self.installed.write_text(conf("192.0.2.12", ("192.0.2.11",), mark=False))
        self.assertIn("carried-on", self.run_block()[1])

        self.installed.write_text(conf("192.0.2.12", ("192.0.2.11",)))
        for published in (self.stage / "keepalived").iterdir():
            published.unlink()
        self.assertIn("carried-on", self.run_block()[1])
        self.assertEqual(self.calls(), "")

    def test_a_service_that_does_not_stop_fails_the_deploy(self) -> None:
        self.publish(("node-a", "192.0.2.11"))

        code, said = self.run_block(SYSTEMCTL_EXIT="1")

        self.assertEqual(code, 1)
        self.assertIn("keepalived could not be stopped", said)
        self.assertFalse(self.marker.exists())

    def test_added_again_it_starts_both_and_drops_the_marker(self) -> None:
        self.marker.write_text("")
        self.publish(("node-a", "192.0.2.11"), ("node-b", "192.0.2.12"))

        code, said = self.run_block()

        self.assertEqual(code, 0, said)
        self.assertIn("carried-on", said)
        self.assertEqual(
            self.calls(),
            "systemctl enable --quiet --now haproxy\nsystemctl enable --quiet --now keepalived\n",
        )
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
