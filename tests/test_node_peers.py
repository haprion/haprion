"""What a node makes of `show peers` (B270).

Extracted from `install/node/haprion-node-status` verbatim and run against
output captured from HAProxy 3.4.6 with two instances sharing one table
(26-10-10), the way `test_node_runtime_stat` reads `show stat`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "node" / "haprion-node-status"
PARSING = re.compile(r"^PEER_LINE = .*?(?=^def read_peers\()", re.DOTALL | re.MULTILINE)

CONNECTED = """\
0x7334c7e72000: [19/Feb/1970:18:02:26] id=mgd-peers disabled=0 flags=0x100001 resync_timeout=0s task_calls=2
  0x7334c967b6c0: id=node-b(remote,active) addr=192.0.2.2:10000 app_state=RUNNING learn_state=NOTASSIGNED last_status=ESTA last_hdshk=2s
        reconnect=0s heartbeat=<NEVER> confirm=0 tx_hbt=0 rx_hbt=0 no_hbt=0 new_conn=1 proto_err=0 coll=0
        flags=0x100028 appctx:0x7334c8a88000 st0=7 st1=0 task_calls=11 state=EST
        shared tables:
              table:0x7334c9661000 id=f update=0 localupdate=0 refcnt=1
  0x7334c967b600: id=node-a(local,inactive) addr=192.0.2.1:10000 app_state=STOPPED learn_state=NOTASSIGNED last_status=NONE last_hdshk=<NEVER>
"""
DOWN = CONNECTED.replace("(remote,active)", "(remote,inactive)").replace(
    "app_state=RUNNING learn_state=NOTASSIGNED last_status=ESTA",
    "app_state=STOPPED learn_state=NOTASSIGNED last_status=HSHK",
)


# Two seconds after a reload (3.4.7, 26-11-01): connected, tables not yet taught.
RESYNCING = CONNECTED.replace("flags=0x100028 appctx", "flags=0x100020 appctx")


class ReadingShowPeers(unittest.TestCase):
    def setUp(self) -> None:
        found = PARSING.search(SCRIPT.read_text())
        assert found, "the parsing is no longer where the test extracts it from"
        namespace: dict[str, Any] = {"re": re}
        exec(found.group(0), namespace)  # noqa: S102 - the file under test, read from disk
        self.parse = namespace["parse_peers"]

    def test_a_connected_peer(self) -> None:
        self.assertEqual(
            self.parse(CONNECTED),
            [{"name": "node-b", "address": "192.0.2.2:10000", "connected": True, "synced": True}],
        )

    def test_a_peer_that_has_not_taught_its_tables_yet_is_not_synced(self) -> None:
        peer = self.parse(RESYNCING)[0]
        self.assertEqual((peer["connected"], peer["synced"]), (True, False))

    def test_a_peer_that_does_not_answer(self) -> None:
        peer = self.parse(DOWN)[0]
        self.assertEqual((peer["connected"], peer["synced"]), (False, False))

    def test_a_node_that_shares_nothing(self) -> None:
        self.assertEqual(self.parse(""), [])


if __name__ == "__main__":
    unittest.main()
