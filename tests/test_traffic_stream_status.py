"""A node that drops its traffic stream, as the node reads it and as the manager says it.

Review 2026-10-30-igen, R3: a node prepared by this version's step 4 keeps a
traffic line only when it came in on HAProxy's own socket. A release an older
manager published - or one a revert put back - logs to /dev/log, and the node
drops every record until the cluster is published again. The node half is
extracted from `install/node/haprion-node-status` verbatim and run against
files written here, as `test_forward_file` does.
"""

from __future__ import annotations

import os
import re
import socket
import tempfile
import unittest
from pathlib import Path
from stat import S_ISSOCK
from typing import Any

from haprion import traffic_stream
from haprion.cluster_status import traffic_stream_problem

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
READING = re.compile(r"^CURRENT_CONFIG = .*?(?=^def shm_stats_path\()", re.DOTALL | re.MULTILINE)
OLD_LINE = "    log /dev/log len 2048 format local profile mgd-traffic-json local2\n"
NEW_LINE = (
    f"    log {traffic_stream.TRAFFIC_LOG_SOCKET} len 2048 format local profile"
    " mgd-traffic-json local2\n"
)
MARKED = (
    'if ($programname == "haproxy-traffic") then {\n  if ($!haprion!origin == "haproxy") then {'
)


class TheNodeReadsItsRelease(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "current" / "conf.d").mkdir(parents=True)
        (self.root / "current" / "haproxy.cfg").write_text("global\n    daemon\n")
        found = READING.search(SCRIPT.read_text())
        assert found, "the reading is no longer where the test extracts it from"
        self.namespace: dict[str, Any] = {
            "Path": Path,
            "re": re,
            "S_ISSOCK": S_ISSOCK,
            "Any": Any,
            "RSYSLOG_FORWARD": self.root / "forward.conf",
        }
        exec(found.group(0), self.namespace)  # noqa: S102 - the file under test, read from disk
        self.namespace["CURRENT_CONFIG"] = self.root / "current"
        self.namespace["TRAFFIC_RULE"] = self.root / "48-haprion-traffic.conf"
        self.namespace["TRAFFIC_SOCKET"] = self.root / "t.sock"
        self.namespace["TRAFFIC_SOCKET_LINK"] = self.root / "chroot" / "t.sock"

    def release(self, line: str) -> None:
        (self.root / "current" / "conf.d" / "1040-frontends.cfg").write_text(
            "frontend mgd-http\n" + line
        )

    def read(self) -> dict[str, Any] | None:
        result: dict[str, Any] | None = self.namespace["read_traffic_stream"]()
        return result

    def test_a_release_that_logs_no_stream_says_nothing(self) -> None:
        self.release("    log /dev/log local0\n")
        self.assertIsNone(self.read())

    def test_a_release_from_before_on_a_node_prepared_since_is_dropped(self) -> None:
        self.release(OLD_LINE)
        (self.root / "48-haprion-traffic.conf").write_text(MARKED)
        stream = self.read()
        self.assertEqual(stream, {"to_socket": False, "marked_only": True, "socket": False})
        assert stream is not None
        self.assertIn(
            "publish the cluster again", traffic_stream_problem({"traffic_stream": stream}) or ""
        )
        self.assertIn("DROPPED", self.namespace["traffic_stream_summary"](stream))

    def test_the_same_release_on_a_node_not_yet_prepared_arrives(self) -> None:
        self.release(OLD_LINE)
        stream = self.read()
        self.assertEqual(stream, {"to_socket": False, "marked_only": False, "socket": False})
        self.assertIsNone(traffic_stream_problem({"traffic_stream": stream}))

    def test_a_marked_forwarding_rule_counts_as_the_day_files(self) -> None:
        self.release(OLD_LINE)
        (self.root / "forward.conf").write_text('if ($!haprion!origin == "haproxy") then {}\n')
        stream = self.read()
        assert stream is not None
        self.assertTrue(stream["marked_only"])

    def test_a_release_to_the_socket_needs_it_held_for_haproxy_alone(self) -> None:
        self.release(NEW_LINE.replace(traffic_stream.TRAFFIC_LOG_SOCKET, str(self.root / "t.sock")))
        (self.root / "48-haprion-traffic.conf").write_text(MARKED)
        stream = self.read()
        assert stream is not None
        self.assertEqual((stream["to_socket"], stream["socket"]), (True, False))
        self.assertIn(
            "haprion-node-prepare", traffic_stream_problem({"traffic_stream": stream}) or ""
        )
        held = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(held.close)
        held.bind(str(self.root / "t.sock"))
        os.chmod(self.root / "t.sock", 0o660)
        #
        # Held, but by this test's account and not haproxy's.
        #
        stream = self.read()
        assert stream is not None
        self.assertFalse(stream["socket"])

    def test_a_socket_haproxy_alone_may_write_is_not_ready_without_the_chroots_link(self) -> None:
        """Review 2026-10-30-igen2, S5: pull-deploy refuses the same node, so status must say so."""

        class Haproxys(type(Path())):  # type: ignore[misc]
            def owner(self, **_: Any) -> str:
                return "haproxy"

            def group(self, **_: Any) -> str:
                return "haproxy"

        sock = self.root / "t.sock"
        self.release(NEW_LINE.replace(traffic_stream.TRAFFIC_LOG_SOCKET, str(sock)))
        held = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(held.close)
        held.bind(str(sock))
        os.chmod(sock, 0o660)
        self.namespace["TRAFFIC_SOCKET"] = Haproxys(sock)

        stream = self.read()
        assert stream is not None
        self.assertFalse(stream["socket"])

        link = self.root / "chroot" / "t.sock"
        link.parent.mkdir()
        link.symlink_to("../elsewhere")
        stream = self.read()
        assert stream is not None
        self.assertFalse(stream["socket"])

        link.unlink()
        link.symlink_to("../t.sock")
        stream = self.read()
        assert stream is not None
        self.assertTrue(stream["socket"])

    def test_the_node_names_the_socket_the_generator_logs_to(self) -> None:
        text = SCRIPT.read_text()
        self.assertIn(f'TRAFFIC_SOCKET = Path("{traffic_stream.TRAFFIC_LOG_SOCKET}")', text)
        self.assertIn(traffic_stream.TRAFFIC_LOG_PROFILE, text)


class TheManagerSaysIt(unittest.TestCase):
    def test_a_node_that_does_not_report_it_says_nothing(self) -> None:
        self.assertIsNone(traffic_stream_problem({}))
        self.assertIsNone(traffic_stream_problem({"traffic_stream": None}))

    def test_a_stream_that_arrives_says_nothing(self) -> None:
        self.assertIsNone(
            traffic_stream_problem(
                {"traffic_stream": {"to_socket": True, "marked_only": True, "socket": True}}
            )
        )


if __name__ == "__main__":
    unittest.main()
