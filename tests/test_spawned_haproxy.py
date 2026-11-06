"""A port another process holds must stop a test's HAProxy, not be shared with it.

Tests choose a port by binding port 0 and letting it go, so another test
process can take it before HAProxy binds. HAProxy binds with SO_REUSEPORT on
Linux, so without `noreuseport` it starts anyway and the kernel hands each new
connection to one of the two listeners. In a full gate a test's HTTP request
reached another test's peers listener, which answers anything that is not a
peers hello with a bare "501" (26-11-06). With `noreuseport` the second HAProxy
fails to bind, and `tests.spawned` starts the test over on new ports.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import spawned
from tests.test_generate_behaviour import CORE

ROOT = Path(__file__).resolve().parent.parent
HAPROXY = shutil.which("haproxy")


def _configuration(path: Path, port: int, *, noreuseport: bool) -> list[str]:
    path.write_text(
        "global\n" + (spawned.NOREUSEPORT if noreuseport else "") + "defaults\n"
        "    mode http\n"
        "    timeout connect 2s\n"
        "    timeout client 5s\n"
        "    timeout server 5s\n"
        "frontend fe\n"
        f"    bind 127.0.0.1:{port}\n"
        "    http-request return status 200\n"
    )
    return ["-f", str(path)]


class EveryLiveTestRefusesASharedPort(unittest.TestCase):
    """Static: no module starts a HAProxy that may share a port."""

    def test_the_shared_core_and_the_helper_say_it(self) -> None:
        self.assertIn(spawned.NOREUSEPORT.strip(), CORE.split())

    def test_every_module_that_starts_haproxy_has_it(self) -> None:
        #
        # Starting one through `start_haproxy` with a release from
        # `write_release` gets the core file; a module that writes its own
        # `global`, or starts HAProxy by hand (`-db`), must carry the line.
        #
        starters = [
            path
            for directory in (ROOT / "tests", ROOT / "ui" / "tests")
            for path in sorted(directory.glob("test_*.py"))
            if path.name != Path(__file__).name
            and re.search(r"\bstart_haproxy\(|\"-db\"", path.read_text(encoding="utf-8"))
        ]
        self.assertTrue(starters, "found no module that starts HAProxy")
        lacking = []
        for path in starters:
            text = path.read_text(encoding="utf-8")
            own = "noreuseport" in text or "NOREUSEPORT" in text
            core = "write_release(" in text
            if not (own or core):
                lacking.append(path.name)
        self.assertEqual(lacking, [], "these start HAProxy that may share a port")

    def test_a_module_with_its_own_global_has_it_in_each(self) -> None:
        for name in ("test_http3_live.py", "test_dynamic_block_live.py"):
            text = (ROOT / "tests" / name).read_text(encoding="utf-8")
            self.assertIn("noreuseport", text.replace("NOREUSEPORT", "noreuseport"), name)
        stream = (ROOT / "ui" / "tests" / "test_traffic_stream_live.py").read_text()
        self.assertIn("noreuseport", stream)


@unittest.skipUnless(HAPROXY, "haproxy is not installed here")
class AHeldPortStopsTheSecondHaproxy(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def _start(self, name: str, port: int, *, noreuseport: bool) -> subprocess.Popen[bytes]:
        assert HAPROXY is not None
        arguments = _configuration(self.root / f"{name}.cfg", port, noreuseport=noreuseport)
        return spawned.start_haproxy(HAPROXY, arguments, port)

    def test_with_noreuseport_the_second_fails_to_bind(self) -> None:
        port = spawned.free_port()
        first = self._start("first", port, noreuseport=True)
        self.addCleanup(first.wait, 5)
        self.addCleanup(first.terminate)

        with self.assertRaises(spawned.PortTaken):
            self._start("second", port, noreuseport=True)

    def test_without_it_both_start_and_share_the_port(self) -> None:
        #
        # The failure this guards against, measured: both run on one port.
        #
        port = spawned.free_port()
        first = self._start("first", port, noreuseport=False)
        self.addCleanup(first.wait, 5)
        self.addCleanup(first.terminate)
        second = self._start("second", port, noreuseport=False)
        self.addCleanup(second.wait, 5)
        self.addCleanup(second.terminate)

        self.assertIsNone(first.poll())
        self.assertIsNone(second.poll())

    def test_a_python_listener_on_the_port_stops_it_too(self) -> None:
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            held.listen()
            with self.assertRaises(spawned.PortTaken):
                self._start("only", int(held.getsockname()[1]), noreuseport=True)


class ATakenPortIsTriedAgain(unittest.TestCase):
    def test_a_setup_that_met_a_taken_port_runs_again(self) -> None:
        calls = []

        @spawned.retry_on_taken_port
        def setup() -> str:
            calls.append(1)
            if len(calls) < 3:
                raise spawned.PortTaken("held")
            return "up"

        self.assertEqual(setup(), "up")
        self.assertEqual(len(calls), 3)

    def test_it_gives_up_with_the_last_error(self) -> None:
        @spawned.retry_on_taken_port
        def setup() -> None:
            raise spawned.PortTaken("held")

        with self.assertRaises(spawned.PortTaken):
            setup()

    def test_another_error_is_not_retried(self) -> None:
        calls = []

        @spawned.retry_on_taken_port
        def setup() -> None:
            calls.append(1)
            raise AssertionError("a real failure")

        with self.assertRaises(AssertionError):
            setup()
        self.assertEqual(calls, [1])


if __name__ == "__main__":
    unittest.main()
