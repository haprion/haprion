"""What the interface accepts as configuration, and what it refuses.

The refusals matter more than the acceptance. A configuration file that is
writable by the account reading it is not configuration; it is state the service
can rewrite, and every value below stops being a decision the deployment made.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from haproxy_ui.config import ConfigError, load

#
# management_writes comes first, and that is not a style choice: a bare key
# written after a table belongs to that table in TOML, so the same three lines
# lower down would silently become listen.management_writes and the flag would
# read as absent. The test below pins the ordering for exactly that reason.
#
VALID = """
management_writes = false

[database]
name = "haproxy_ui"
socket_directory = "/var/run/postgresql"

[listen]
host = "192.0.2.10"
port = 8080
"""


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, text: str, *, mode: int = 0o640) -> Path:
        path = self.root / "ui.toml"
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def load(self, text: str, **kwargs: object):
        return load(self.write(text), require_secure=False, **kwargs)  # type: ignore[arg-type]

    def test_a_complete_file_is_read(self) -> None:
        config = self.load(VALID)
        self.assertEqual(config.database.name, "haproxy_ui")
        self.assertEqual(config.listen.port, 8080)
        self.assertFalse(config.management_writes)
        self.assertFalse(config.demo_fixture)

    def test_the_connection_string_names_no_user_and_no_password(self) -> None:
        config = self.load(VALID)
        self.assertEqual(
            config.database.connection_string,
            "dbname=haproxy_ui host=/var/run/postgresql",
        )
        self.assertNotIn("password", config.database.connection_string)
        self.assertNotIn("user", config.database.connection_string)

    def test_management_writes_defaults_to_off(self) -> None:
        config = self.load(VALID.replace("management_writes = false\n", ""))
        self.assertFalse(config.management_writes)

    def test_demo_fixture_is_explicit_and_cannot_mix_with_real_management(self) -> None:
        config = self.load("demo_fixture = true\n" + VALID)
        self.assertTrue(config.demo_fixture)
        with self.assertRaisesRegex(ConfigError, "management_writes"):
            self.load("demo_fixture = true\n" + VALID.replace("false", "true", 1))
        with self.assertRaisesRegex(ConfigError, "clusters"):
            self.load('demo_fixture = true\nclusters = ["alpha"]\n' + VALID)

    # ------------------------------------------------------------------ refusing

    def test_an_unknown_top_level_key_is_refused_rather_than_ignored(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.load("debug = true\n" + VALID)
        self.assertIn("debug", str(raised.exception))

    def test_a_flag_written_after_a_table_is_caught(self) -> None:
        """The trap TOML sets: a bare key after a table belongs to the table.

        Written below [listen], `management_writes` becomes listen's key. That
        must be an error rather than a flag that silently reads as off - the
        difference between "writes are disabled" and "the line did nothing" is
        the whole value of the flag.
        """

        with self.assertRaises(ConfigError) as raised:
            self.load(
                VALID.replace("management_writes = false\n\n", "") + "\nmanagement_writes = true\n"
            )
        self.assertIn("management_writes", str(raised.exception))

    def test_a_misspelled_key_is_named(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.load(VALID.replace("management_writes", "management_write"))
        self.assertIn("management_write", str(raised.exception))

    def test_a_misspelled_section_key_is_named(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.load(VALID.replace("socket_directory", "socket_dir"))
        self.assertIn("socket_dir", str(raised.exception))

    def test_a_port_outside_the_range_is_refused(self) -> None:
        for port in ("0", "65536", '"8080"', "true"):
            with self.subTest(port=port), self.assertRaises(ConfigError):
                self.load(VALID.replace("port = 8080", f"port = {port}"))

    def test_a_group_writable_file_is_refused(self) -> None:
        path = self.write(VALID, mode=0o660)
        if os.geteuid() == 0:  # pragma: no cover - the suite does not run as root
            self.skipTest("ownership check needs a non-root reader")
        with self.assertRaises(ConfigError) as raised:
            load(path)
        self.assertIn("root-owned", str(raised.exception))

    def test_a_symlink_is_refused(self) -> None:
        target = self.write(VALID)
        link = self.root / "link.toml"
        link.symlink_to(target)
        with self.assertRaises(ConfigError) as raised:
            load(link, require_secure=False)
        self.assertIn("regular non-symlink", str(raised.exception))

    def test_a_missing_file_says_so(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            load(self.root / "absent.toml", require_secure=False)
        self.assertIn("cannot stat", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
