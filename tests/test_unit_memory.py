"""Each service that reads what a node or a visitor sends has a measured memory limit (B357).

The security review (26-10-22, S2) found web, worker and poller at
`MemoryMax=infinity`: a node that answered without end could take the
manager's memory, and a root helper's process as well as the Python one
reading its answer. Each unit here is held to a limit set from what it was
measured to use, and to `MemorySwapMax=0`, so one that runs away is stopped
rather than swapped until the machine stalls.
"""

from __future__ import annotations

import unittest
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "install" / "platform" / "examples"

#
# The limit each unit carries, against the most it was measured to use
# (26-10-23, in MB): the journal's peaks on the manager since 26-10-09 and,
# for the helpers, what the largest step took.
#
LIMITED = {
    "haprion-web.service.example": ("768M", 177),
    "haprion-worker.service.example": ("768M", 95),
    "haprion-poller.service.example": ("512M", 138 + 45),
    "haprion-traffic-collector.service.example": ("512M", 212),
    "haprion-node-restore-helper@.service.example": ("512M", 84),
    **{
        f"haprion-{name}-helper@.service.example": ("256M", 84)
        for name in (
            "backup-job",
            "cert-export",
            "cert-receiver",
            "ndes-server",
            "node",
            "oidc",
            "probe",
            "resolve",
            "tls",
        )
    },
}


def directives(text: str, name: str) -> list[str]:
    return [line.split("=", 1)[1] for line in text.splitlines() if line.startswith(f"{name}=")]


class EachUnitHasItsMeasuredLimit(unittest.TestCase):
    def test_every_helper_and_every_long_running_service_is_listed(self) -> None:
        units = {path.name for path in EXAMPLES.glob("*.service.example")}
        helpers = {name for name in units if "-helper@" in name}
        self.assertLessEqual(helpers, set(LIMITED))
        self.assertLessEqual(set(LIMITED), units)

    def test_each_limit_is_its_own_with_room_above_what_was_measured(self) -> None:
        for name, (limit, measured) in LIMITED.items():
            with self.subTest(unit=name):
                text = (EXAMPLES / name).read_text()
                self.assertEqual(directives(text, "MemoryMax"), [limit])
                self.assertEqual(directives(text, "MemorySwapMax"), ["0"])
                self.assertGreaterEqual(int(limit.removesuffix("M")), 2 * measured)


if __name__ == "__main__":
    unittest.main()
