"""The repository keys the installers ship, held to their fingerprints (B179, B249).

`install/node-lib.sh` writes the key beside it into APT's keyrings without asking a
server, and a shell has no OpenPGP parser to check it with. So the check is
here: the shipped file must be the key whose fingerprint `node-lib.sh` names, and a
key replaced without its fingerprint fails the gate rather than a node.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from haprion.haproxy_repository import fingerprint

INSTALL = Path(__file__).resolve().parents[1] / "install"


class TheDnsdistKeyIsTheOneLibShNames(unittest.TestCase):
    def test_the_shipped_key_has_the_named_fingerprint(self) -> None:
        named = re.search(
            r"fingerprint,\n# ((?:[0-9A-F]{4} {1,2}){9}[0-9A-F]{4})",
            (INSTALL / "node-lib.sh").read_text(),
        )
        assert named is not None, "node-lib.sh names no dnsdist key fingerprint"
        expected = named.group(1).replace(" ", "")

        shipped = fingerprint((INSTALL / "apt-keys" / "powerdns-dnsdist.asc").read_bytes())

        self.assertEqual(shipped, expected)
        self.assertEqual(expected, "9FAAA5577E8FCF62093D036C1B0C6205FD380FBB")


if __name__ == "__main__":
    unittest.main()
