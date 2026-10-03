from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt import crs

SQLI = b"""\
# -=[ libinjection ]=-
SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS "@detectSQLi" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    msg:'SQL Injection Attack Detected via libinjection',\\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\\
    tag:'paranoia-level/1',\\
    severity:'CRITICAL'"

SecRule ARGS "@rx x" \\
    "id:942101,\\
    phase:2,\\
    block,\\
    msg:'It\\'s quoted',\\
    tag:'paranoia-level/2',\\
    severity:'WARNING',\\
    chain"
    SecRule ARGS "@rx y" \\
        "t:none,msg:'the chain is not a rule of its own'"

# SecRule ARGS "@rx z" "id:942999,msg:'commented out'"
"""
PROTOCOL = b"""\
SecRule REQUEST_HEADERS_NAMES "@rx ." \\
    "id:920450,\\
    msg:'HTTP header is restricted by policy (%{MATCHED_VAR})',\\
    severity:'CRITICAL'"
SecAction "id:920000,phase:1,pass,nolog,msg:'Score %{TX.x} now'"
"""


def rule_set(files: dict[str, bytes]) -> crs.RuleSet:
    return crs.RuleSet(version="4.25.1", files={"VERSION": b"4.25.1\n", **files})


class TheCatalogDescribesEachRule(unittest.TestCase):
    """Fas 21 steg 4b: what a rule means, for the WAF page."""

    def test_message_severity_file_and_paranoia_per_rule(self) -> None:
        rules = crs.catalog(
            rule_set(
                {
                    "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": SQLI,
                    "rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf": PROTOCOL,
                    "rules/sql-errors.data": b"id:942555 msg:'not a rule file'\n",
                    "crs-setup.conf": b"SecAction \"id:900000,msg:'setup'\"\n",
                }
            )
        )
        self.assertEqual(sorted(rules), [920000, 920450, 942100, 942101])
        self.assertEqual(
            rules[942100],
            crs.Rule(942100, "SQL Injection Attack Detected via libinjection", "critical", 942, 1),
        )
        self.assertEqual(rules[942101], crs.Rule(942101, "It's quoted", "warning", 942, 2))

    def test_a_message_describes_the_rule_and_not_a_request(self) -> None:
        rules = crs.catalog(rule_set({"rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf": PROTOCOL}))
        self.assertEqual(rules[920450].message, "HTTP header is restricted by policy")
        self.assertEqual(rules[920000].message, "Score … now")
        self.assertEqual((rules[920000].severity, rules[920000].paranoia), ("", 0))

    def test_without_the_package_the_catalog_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(crs.installed_catalog(Path(temporary) / "absent"), {})

    def test_the_catalog_is_read_again_when_the_version_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rules").mkdir()
            (root / "crs-setup.conf.example").write_bytes(b"")
            (root / "VERSION").write_text("4.25.1\n")
            sqli = root / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
            sqli.write_bytes(SQLI)
            self.assertIn(942100, crs.installed_catalog(root))
            sqli.write_bytes(PROTOCOL.replace(b"920450", b"942450"))
            self.assertIn(942100, crs.installed_catalog(root), "one read per version")
            (root / "VERSION").write_text("4.25.2\n")
            rules = crs.installed_catalog(root)
            self.assertNotIn(942100, rules)
            self.assertIn(942450, rules)

    @unittest.skipUnless(crs.ROOT.exists(), "the CRS package is not installed here")
    def test_the_installed_rule_set_reads_whole(self) -> None:
        """Every attack rule the engine can report has a message. The files'
        other rules (`911011` ...) step over paranoia levels and log nothing."""

        rules = crs.installed_catalog()
        attack = [rule for rule in rules.values() if 911 <= rule.file <= 944 and rule.severity]
        self.assertGreater(len(attack), 250)
        self.assertFalse([rule.id for rule in attack if not rule.message])
        self.assertEqual(rules[942100].message, "SQL Injection Attack Detected via libinjection")


class TheManagerSaysWhatItHas(unittest.TestCase):
    def test_the_engine_package_and_the_rule_set_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            query = root / "dpkg-query"
            query.write_text('#!/bin/sh\nprintf "install ok installed\\t0.9.0-2"\n')
            query.chmod(0o755)
            (root / "VERSION").write_text("4.25.1\n")
            self.assertEqual(
                crs.manager_versions(root, str(query)), {"engine": "0.9.0-2", "crs": "4.25.1"}
            )
            query.write_text('#!/bin/sh\nprintf "deinstall ok config-files\\t0.9.0-2"\n')
            (root / "VERSION").write_text("not a version\n")
            self.assertEqual(crs.manager_versions(root, str(query)), {"engine": None, "crs": None})
            self.assertEqual(
                crs.manager_versions(root / "absent", str(root / "absent")),
                {"engine": None, "crs": None},
            )


if __name__ == "__main__":
    unittest.main()
