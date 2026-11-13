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
# for the helpers, what the largest step took. Web, worker and poller since
# 26-11-06 from the install test's scale run with 10 000 heavy objects
# (`tools/install-test --scenario scale`, which holds the peaks to these).
#
LIMITED = {
    "haprion-web.service.example": ("768M", 236),
    "haprion-worker.service.example": ("768M", 302),
    "haprion-poller.service.example": ("1152M", 524 + 45),
    "haprion-traffic-collector.service.example": ("512M", 212),
    "haprion-node-restore-helper@.service.example": ("512M", 84),
    # A list of 100 000 entries tested with exceptions in four clusters (26-11-11).
    "haprion-blocklist-check-helper@.service.example": ("256M", 90),
    # Two such lists in four clusters, before the deploy it starts (26-11-11).
    "haprion-blocklist-refresh.service.example": ("512M", 145),
    **{
        f"haprion-{name}-helper@.service.example": ("256M", 84)
        for name in (
            "backup-job",
            "block-api",
            "cert-export",
            "cert-receiver",
            "http01-check",
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


class TheRefreshPassIsBoundedAndSandboxed(unittest.TestCase):
    """The timer's pass fetches text from the internet as root (review 2026-11-13, BL03, BL15)."""

    def setUp(self) -> None:
        self.text = (EXAMPLES / "haprion-blocklist-refresh.service.example").read_text()

    def test_a_stalled_pass_is_ended(self) -> None:
        # A oneshot unit has no start timeout of its own.
        self.assertEqual(len(directives(self.text, "TimeoutStartSec")), 1)

    def test_it_is_sandboxed_to_what_a_pass_writes(self) -> None:
        for key, value in {
            "ProtectSystem": "strict",
            "ProtectHome": "read-only",
            "ProtectKernelTunables": "yes",
            "RestrictNamespaces": "yes",
        }.items():
            with self.subTest(key=key):
                self.assertEqual(directives(self.text, key), [value])
        writable = directives(self.text, "ReadWritePaths")[0].split()
        self.assertIn("/var/lib/haprion/blocklists", writable)
        self.assertIn("@POLICY_PATHS@", writable)


#
# The units whose program runs sudo: the worker and the poller for their
# helpers, and the refresh pass through haprion-cert-deploy, which hands its
# request to the root helper with sudo even when root runs it. The install test
# found the refresh unit sandboxed without them (26-11-13): every deploy of a
# changed list ended "sudo: PERM_SUDOERS: setresuid ... Operation not permitted".
#
REACHES_SUDO = (
    "haprion-worker.service.example",
    "haprion-poller.service.example",
    "haprion-blocklist-refresh.service.example",
)


class AUnitThatRunsSudoCanUseIt(unittest.TestCase):
    """sudo changes its user and writes an audit record; a sandbox has to let it."""

    def test_sudo_has_what_it_needs(self) -> None:
        for name in REACHES_SUDO:
            text = (EXAMPLES / name).read_text()
            with self.subTest(unit=name):
                self.assertEqual(directives(text, "NoNewPrivileges"), ["no"])
                bounded = " ".join(directives(text, "CapabilityBoundingSet")).split()
                for capability in ("CAP_SETUID", "CAP_SETGID", "CAP_AUDIT_WRITE"):
                    self.assertIn(capability, bounded)
                self.assertIn("AF_NETLINK", " ".join(directives(text, "RestrictAddressFamilies")))


if __name__ == "__main__":
    unittest.main()
