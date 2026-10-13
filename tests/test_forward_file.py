"""The log forwarding as a component of the release (review 26-10-13, A1).

`haprion-pull-deploy` installs the forwarding after the reload and puts the
previous file back when rsyslog refuses the new one, so a node can run the
target hash with the old receivers. The node measures both files; the manager
decides what that means. Unlike the address list, a release without the file
asks for none - the deploy removes it - so absent on both sides is current.

The node half is extracted from `install/node/haprion-node-status` verbatim and
run against files written here, as `test_node_addresses` does.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion.cluster_status import (
    BEHIND_ADDRESSES,
    BEHIND_FORWARDING,
    BEHIND_IPVS,
    BEHIND_RELEASE,
    behind_part,
    forwarding_current,
    parse_status,
)
from tests.test_status_addresses import envelope, node_status

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READING = re.compile(
    r"^def address_list\(path\):.*?(?=^def runtime_info\()", re.DOTALL | re.MULTILINE
)
FORWARD = 'action(type="omfwd" name="haprion-loki" target="192.0.2.21")\n'
OTHER = 'action(type="omfwd" name="haprion-loki" target="192.0.2.22")\n'
DIGEST = "a1" * 32


def reported(**fields: object) -> dict[str, object]:
    forward: dict[str, object] = {
        "published": True,
        "published_sha256": DIGEST,
        "installed": True,
        "installed_sha256": DIGEST,
    }
    forward.update(fields)
    return {"forward_file": forward}


class WhatTheManagerMakesOfIt(unittest.TestCase):
    def test_the_file_the_release_carries_is_current(self) -> None:
        self.assertIs(forwarding_current(reported()), True)

    def test_the_previous_file_kept_by_rsyslog_is_behind(self) -> None:
        self.assertIs(forwarding_current(reported(installed_sha256="b2" * 32)), False)

    def test_a_file_the_release_carries_and_the_node_lacks_is_behind(self) -> None:
        self.assertIs(forwarding_current(reported(installed=False, installed_sha256=None)), False)

    def test_no_file_on_either_side_is_current(self) -> None:
        self.assertIs(
            forwarding_current(
                reported(
                    published=False,
                    published_sha256=None,
                    installed=False,
                    installed_sha256=None,
                )
            ),
            True,
        )

    def test_a_file_left_behind_by_a_release_that_forwards_nowhere_is_behind(self) -> None:
        # The deploy removes it; until then the node forwards to receivers the
        # release no longer has.
        self.assertIs(forwarding_current(reported(published=False, published_sha256=None)), False)

    def test_what_could_not_be_read_is_not_an_answer(self) -> None:
        for fields in (
            {"published": None, "published_sha256": None},
            {"installed": None, "installed_sha256": None},
            {"installed_sha256": None},
            {"published_sha256": None},
            {"published": False, "published_sha256": None, "installed": None},
        ):
            with self.subTest(fields=fields):
                self.assertIsNone(forwarding_current(reported(**fields)))

    def test_the_deploy_reads_it_from_the_status_it_parsed(self) -> None:
        # The deploy decides on `ClusterStatus.observation()`, not on the status
        # command's own comparison; both must carry the answer.
        status = node_status({"active": True, "state": "MASTER"})
        status.update(reported(installed_sha256="b2" * 32))

        observed = parse_status(envelope(status)).observation().nodes[0]

        self.assertIs(observed.forwarding_current, False)

    def test_a_node_from_before_the_measurement_is_not_held_to_it(self) -> None:
        self.assertIs(forwarding_current({}), True)
        self.assertIs(forwarding_current({"forward_file": None}), True)


class WhichPartIsBehind(unittest.TestCase):
    """Review 26-10-13 r16k, F1: the part a deploy meets first, for CLI and dashboard alike."""

    TARGET = "c3" * 20

    def status(self, **parts: object) -> dict[str, object]:
        status: dict[str, object] = {"release": {"hash": self.TARGET}}
        status.update(parts)
        return status

    def test_another_release_is_the_release(self) -> None:
        stale = self.status(release={"hash": "d4" * 20}, **reported(installed_sha256="b2" * 32))
        self.assertEqual(behind_part(stale, self.TARGET), BEHIND_RELEASE)

    def test_each_file_the_release_activates_is_named(self) -> None:
        listed = {
            "published": True,
            "published_sha256": DIGEST,
            "installed": True,
            "installed_sha256": "b2" * 32,
            "included": True,
        }
        cases = (
            (self.status(keepalived={"addresses": listed}), BEHIND_ADDRESSES),
            (self.status(ipvs=listed), BEHIND_IPVS),
            (self.status(**reported(installed_sha256="b2" * 32)), BEHIND_FORWARDING),
        )
        for status, part in cases:
            with self.subTest(part=part):
                self.assertEqual(behind_part(status, self.TARGET), part)

    def test_a_node_carrying_everything_is_behind_in_nothing(self) -> None:
        self.assertIsNone(behind_part(self.status(**reported()), self.TARGET))

    def test_without_a_target_the_release_is_not_judged(self) -> None:
        self.assertIsNone(behind_part({"release": {"hash": "d4" * 20}}, None))


class WhatTheNodeReports(unittest.TestCase):
    def setUp(self) -> None:
        found = READING.search(SCRIPT.read_text())
        assert found, "the reading is no longer where the test extracts it from"
        self.source = found.group(0)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.published = self.root / "published.conf"
        self.installed = self.root / "installed.conf"

    def namespace(self) -> dict[str, Any]:
        namespace: dict[str, Any] = {
            "Path": Path,
            "hashlib": hashlib,
            "MAX_KEEPALIVED_BYTES": 1024 * 1024,
            "PUBLISHED_FORWARD": self.published,
            "RSYSLOG_FORWARD": self.installed,
        }
        exec(self.source, namespace)  # noqa: S102 - the file under test, read from disk
        return namespace

    def read(self) -> dict[str, Any]:
        forward: dict[str, Any] = self.namespace()["read_forward_file"]()
        return forward

    def summary(self) -> str:
        namespace = self.namespace()
        return str(namespace["forward_file_summary"](namespace["read_forward_file"]()))

    def test_the_same_file_on_both_sides(self) -> None:
        self.published.write_text(FORWARD)
        self.installed.write_text(FORWARD)

        forward = self.read()

        self.assertEqual(forward["published_sha256"], hashlib.sha256(FORWARD.encode()).hexdigest())
        self.assertEqual(forward["published_sha256"], forward["installed_sha256"])
        self.assertIs(forwarding_current({"forward_file": forward}), True)
        self.assertEqual(self.summary(), "installed")

    def test_the_previous_file_kept(self) -> None:
        self.published.write_text(FORWARD)
        self.installed.write_text(OTHER)

        self.assertIs(forwarding_current({"forward_file": self.read()}), False)
        self.assertEqual(self.summary(), "installed file differs from the release")

    def test_published_and_not_installed(self) -> None:
        self.published.write_text(FORWARD)

        forward = self.read()

        self.assertEqual((forward["installed"], forward["installed_sha256"]), (False, None))
        self.assertIs(forwarding_current({"forward_file": forward}), False)
        self.assertEqual(self.summary(), "published, not installed")

    def test_neither(self) -> None:
        forward = self.read()

        self.assertEqual((forward["published"], forward["installed"]), (False, False))
        self.assertIs(forwarding_current({"forward_file": forward}), True)
        self.assertEqual(self.summary(), "none published by this release")

    def test_installed_without_a_release_file(self) -> None:
        self.installed.write_text(FORWARD)

        self.assertIs(forwarding_current({"forward_file": self.read()}), False)
        self.assertEqual(self.summary(), "installed, but this release forwards nowhere")


if __name__ == "__main__":
    unittest.main()
