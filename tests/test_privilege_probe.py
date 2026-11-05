"""tools/privilege-probe expects what the contract's own files say (R2 26-10-27, moment 4).

The probe's lists are written out, as the lab's was, so that it reads on a
manager without the repository; these tests hold them to the files the
installation takes them from.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PROBE = (BASE / "tools" / "privilege-probe").read_text(encoding="utf-8")
EXAMPLES = BASE / "install" / "platform" / "examples"
#
# The socket units name their group by the answer that sets it.
#
SOCKET_ACCOUNTS = {"WEB_USER": "_haprion-web", "WORKER_USER": "_haprion-worker"}


def probe_words(name: str) -> set[str]:
    found = re.search(rf'^{name}="(?P<words>[^"]*)"', PROBE, re.MULTILINE)
    if found is None:
        raise AssertionError(f"privilege-probe has no {name}")
    return set(found["words"].split())


def probe_table(name: str) -> dict[str, str]:
    found = re.search(rf"^declare -A {name}=\(\n(?P<rows>.*?)^\)", PROBE, re.MULTILINE | re.DOTALL)
    if found is None:
        raise AssertionError(f"privilege-probe has no {name}")
    return dict(re.findall(r'^\s*\[(\S+)\]="?([^"\n]*)"?$', found["rows"], re.MULTILINE))


def sudoers_helpers(example: str) -> set[str]:
    text = (EXAMPLES / example).read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return {name for name in re.findall(r"haprion-([a-z-]+)-helper\b", code)}


class TheProbeExpectsTheContract(unittest.TestCase):
    def test_the_helpers_are_the_sudoers_examples(self) -> None:
        self.assertEqual(
            probe_words("WORKER_HELPERS"), sudoers_helpers("haprion-worker.sudoers.example")
        )
        self.assertEqual(
            probe_words("POLLER_HELPERS"), sudoers_helpers("haprion-poller.sudoers.example")
        )

    def test_the_sockets_are_the_socket_units(self) -> None:
        units: dict[str, str] = {}
        for example in sorted(EXAMPLES.glob("*.socket.example")):
            text = example.read_text(encoding="utf-8")
            path = re.search(r"^ListenStream=(\S+)$", text, re.MULTILINE)
            group = re.search(r"^SocketGroup=(\S+)$", text, re.MULTILINE)
            if path and group:
                units[path[1]] = SOCKET_ACCOUNTS.get(group[1], group[1])
        self.assertEqual(probe_table("SOCKET_GROUP"), units)

    def test_the_groups_are_the_sysusers_fragment(self) -> None:
        text = (BASE / "install" / "sysusers" / "haprion.conf").read_text(encoding="utf-8")
        lines = [line.split() for line in text.splitlines() if line and not line.startswith("#")]
        groups = {fields[1]: {fields[1]} for fields in lines if fields[0] == "u"}
        for fields in lines:
            if fields[0] == "m":
                groups[fields[1]].add(fields[2])
        expected = {account: " ".join(sorted(names)) for account, names in groups.items()}
        table = probe_table("GROUPS_EXPECTED")
        self.assertEqual({k: v for k, v in table.items() if k != "www-data"}, expected)
        self.assertEqual(sorted(table), sorted([*expected, "www-data"]))


if __name__ == "__main__":
    unittest.main()
