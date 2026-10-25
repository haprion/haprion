from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from haprion import crs

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
            self.assertEqual(
                crs.installed_catalog(Path(temporary) / "absent"), crs.engine_catalog()
            )

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


class EachRuleAsItIsWritten(unittest.TestCase):
    """B273: what an exception's counter copies - every link, as written."""

    def test_a_rule_and_a_chain_with_its_continuations(self) -> None:
        found = crs.definitions(rule_set({"rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": SQLI}))
        self.assertEqual(sorted(found), [942100, 942101])
        single, chained = found[942100], found[942101]
        self.assertEqual(single.links[0].variables, "REQUEST_COOKIES|ARGS_NAMES|ARGS")
        self.assertEqual(single.links[0].operator, "@detectSQLi")
        self.assertIn(
            "logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'",
            single.links[0].actions,
            "a comma inside quotes is not a separator",
        )
        self.assertEqual((single.phase, single.paranoia), (2, 1))
        self.assertEqual([link.operator for link in chained.links], ["@rx x", "@rx y"])
        self.assertIn("msg:'It\\'s quoted'", chained.links[0].actions)
        self.assertEqual(chained.paranoia, 2)

    def test_only_request_rules_and_never_a_commented_one(self) -> None:
        found = crs.definitions(
            rule_set(
                {
                    "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": SQLI,
                    "rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf": SQLI.replace(b"942", b"951"),
                    "crs-setup.conf": b'SecRule ARGS "@rx a" "id:900990,pass"\n',
                }
            )
        )
        self.assertNotIn(942999, found)
        self.assertEqual(sorted(found), [942100, 942101])

    def test_an_operator_with_an_escaped_quote(self) -> None:
        text = b'SecRule ARGS "@rx a\\"b" "id:941999,phase:1,pass"\n'
        [link] = crs.definitions(rule_set({"rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf": text}))[
            941999
        ].links
        self.assertEqual(link.operator, '@rx a\\"b')
        self.assertEqual(link.actions, ("id:941999", "phase:1", "pass"))

    @unittest.skipUnless(crs.ROOT.is_dir(), "the rule set is not installed here")
    def test_the_installed_rule_set_reads_whole(self) -> None:
        installed = crs.installed()
        assert installed is not None
        found = crs.definitions(installed)
        written = {
            int(rule)
            for name, content in installed.files.items()
            if name.startswith("rules/REQUEST-") and name.endswith(".conf")
            for rule in re.findall(
                r"^SecRule [^\n]*?\bid:([0-9]{6})",
                content.decode().replace("\\\n", " "),
                re.MULTILINE,
            )
        }
        self.assertEqual(written, set(found))
        self.assertTrue(all(link.operator for d in found.values() for link in d.links))


class ADamagedRuleSet(unittest.TestCase):
    def test_is_refused_like_any_configuration_error(self) -> None:
        """Every publish path refuses a ConfigError; a RuleSetError used to escape as a traceback."""

        from haprion.config import ConfigError

        with tempfile.TemporaryDirectory() as raw:
            (Path(raw) / "VERSION").write_text("not a version\n")
            with self.assertRaises(ConfigError):
                crs.installed(Path(raw))

    def test_a_version_s_own_rule_set_is_read_from_its_tree(self) -> None:
        files = {
            "managed/waf/crs/VERSION": b"4.1.0\n",
            "managed/waf/crs/rules/REQUEST-901-INITIALIZATION.conf": b"# rules\n",
            "managed/proxies/shop.yaml": b"name: shop\n",
        }

        rule_set = crs.from_tree(files)

        assert rule_set is not None
        self.assertEqual(rule_set.version, "4.1.0")
        self.assertEqual(set(rule_set.files), {"VERSION", "rules/REQUEST-901-INITIALIZATION.conf"})
        self.assertIsNone(crs.from_tree({"managed/proxies/shop.yaml": b"name: shop\n"}))
