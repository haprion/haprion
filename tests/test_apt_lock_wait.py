"""Every apt-get the product runs on a host waits for the package lock (26-10-08).

Ubuntu's unattended upgrades hold the lock for minutes, on a fresh VM's first
boot above all, and node preparation stopped on it once - `Could not get lock
/var/lib/dpkg/lock-frontend` - half-way through. Held to the source, so an
apt-get added later without the wait fails here rather than on a node.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haproxy_mgmt import restore_agent

ROOT = Path(__file__).resolve().parents[1]
SHELL = (ROOT / "install" / "lib.sh", ROOT / "install" / "04-node-prepare")


class EveryAptGetWaits(unittest.TestCase):
    def test_in_the_node_preparation(self) -> None:
        for path in SHELL:
            calls = [
                line
                for line in path.read_text().splitlines()
                if re.search(r"\bapt-get\s", line) and not line.lstrip().startswith("#")
            ]
            with self.subTest(path=path.name):
                self.assertTrue(calls)
                for line in calls:
                    self.assertIn('apt-get "${APT_WAIT[@]}"', line)

    def test_the_shell_wait_is_apts_own_option(self) -> None:
        self.assertIn("APT_WAIT=(-o DPkg::Lock::Timeout=600)", SHELL[0].read_text())

    def test_in_the_restore_agent(self) -> None:
        source = Path(restore_agent.__file__).read_text()
        calls = re.findall(r'\[\s*"apt-get",[^\]]*\]', source)

        self.assertEqual(restore_agent.APT_WAIT, ("-o", "DPkg::Lock::Timeout=600"))
        self.assertTrue(calls)
        for call in calls:
            self.assertIn("*APT_WAIT", call)


if __name__ == "__main__":
    unittest.main()
