"""Every package a node needs comes back when the node is restored (B298).

`docs/install.md` names the packages and where each is installed. A node
restored to a new VM gets what the restore installs from the distribution,
the node package and what it depends on, what 04-node-prepare installs, and
the WAF engine the CLI release carries. A package installed on the nodes by
hand and by nothing else would be missing on every rebuilt node - which is
what the WAF engine was until 2026-10-13: a restore of a node in a cluster
with WAF rules would have stopped at its last step.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion import node_package, restore_plan, waf_engine_package

ROOT = Path(__file__).resolve().parents[1]
ROW = re.compile(r"^\| ((?:`[a-z0-9.+-]+`(?:, )?)+) \| ([^|]+) \|", re.M)
INSTALLED = re.compile(r"apt-get [^\n]*install -y -q ([a-z0-9.+-]+)")


def node_packages() -> set[str]:
    """What install.md says goes on the nodes."""

    found: set[str] = set()
    for packages, where in ROW.findall((ROOT / "docs/install.md").read_text(encoding="utf-8")):
        if "node" in where:
            found |= set(re.findall(r"`([a-z0-9.+-]+)`", packages))
    return found


def carried() -> set[str]:
    """The packages the release carries that the restore actually sends.

    A carrying module counts only where the restore reads it - so taking the
    WAF engine out of the restore makes this test fail, not only taking it out
    of the release.
    """

    restore = (ROOT / "src/haprion/node_restore.py").read_text(encoding="utf-8")
    return {
        module.PACKAGE
        for module in (node_package, waf_engine_package)
        if f"{module.__name__.rsplit('.', 1)[-1]}.release_package" in restore
    }


def restored() -> set[str]:
    """What a restore to a new VM puts on it."""

    prepared = set()
    for script in ("install/04-node-prepare", "install/node-lib.sh"):
        prepared |= set(INSTALLED.findall((ROOT / script).read_text(encoding="utf-8")))
    depends = {part.strip().split()[0] for part in node_package.DEPENDS.split(",")}
    return set(restore_plan.PRODUCT_PACKAGES) | carried() | depends | prepared


class EveryNodePackageComesBack(unittest.TestCase):
    def test_install_md_names_the_node_packages(self) -> None:
        self.assertGreaterEqual(node_packages(), {"haprion-node", "haprion-coraza-spoa"})

    def test_each_is_put_back_by_the_restore(self) -> None:
        self.assertEqual(sorted(node_packages() - restored()), [])

    def test_what_04_node_prepare_installs_is_read(self) -> None:
        self.assertIn("dnsdist", restored())


if __name__ == "__main__":
    unittest.main()
