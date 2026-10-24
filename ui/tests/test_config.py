"""What the interface accepts as configuration, and what it refuses.

The refusals matter more than the acceptance. A configuration file that is
writable by the account reading it is not configuration; it is state the service
can rewrite, and every value below stops being a decision the deployment made.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from haprion.status_collect import STATUS_TIMEOUT_SECONDS

from haprion_ui.config import Config, ConfigError, Poller, load

EXAMPLE = (
    Path(__file__).resolve().parents[2] / "install" / "platform" / "examples" / "ui.toml.example"
)

#
# management_writes comes first, and that is not a style choice: a bare key
# written after a table belongs to that table in TOML, so the same three lines
# lower down would silently become database.management_writes and the flag would
# read as absent. The test below pins the ordering for exactly that reason.
#
VALID = """
management_writes = false

[database]
name = "haprion_ui"
socket_directory = "/var/run/postgresql"
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

    def load(self, text: str) -> Config:
        return load(self.write(text), require_secure=False)

    def test_a_complete_file_is_read(self) -> None:
        config = self.load(VALID)
        self.assertEqual(config.database.name, "haprion_ui")
        self.assertFalse(config.management_writes)
        self.assertFalse(config.demo_fixture)

    def test_the_connection_string_names_no_user_and_no_password(self) -> None:
        config = self.load(VALID)
        self.assertEqual(
            config.database.connection_string,
            "dbname=haprion_ui host=/var/run/postgresql",
        )
        self.assertNotIn("password", config.database.connection_string)
        self.assertNotIn("user", config.database.connection_string)

    def test_a_provider_session_is_capped_at_ten_hours_unless_set(self) -> None:
        # B203: a group taken away at the provider counts here until the next
        # sign-in through it, so those sessions have a cap of their own.
        self.assertEqual(self.load(VALID).session.oidc_absolute_hours, 10)
        config = self.load(VALID + "\n[session]\noidc_absolute_hours = 4\n")
        self.assertEqual(config.session.oidc_absolute_hours, 4)
        with self.assertRaises(ConfigError):
            self.load(VALID + "\n[session]\noidc_absolute_hours = 0\n")

    def test_where_the_web_listened_is_still_read_and_used_for_nothing(self) -> None:
        """Review 2026-10-22, 5-8: the web takes its connections on a socket.

        An installation's file still says where it listened, and a release
        before the socket needs it to roll back to, so it is read as it always
        was - and refused as it always was when it is wrong.
        """

        listened = VALID + '\n[listen]\nhost = "127.0.0.1"\nport = 8080\n'
        self.assertFalse(hasattr(self.load(listened), "listen"))
        for wrong in (
            "port = 0",
            'port = "8080"',
            'host = ""\nport = 8080',
            "port = 8080\nextra = 1",
        ):
            with self.subTest(wrong=wrong), self.assertRaises(ConfigError):
                self.load(
                    VALID
                    + "\n[listen]\n"
                    + ('host = "127.0.0.1"\n' if "host" not in wrong else "")
                    + wrong
                    + "\n"
                )

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

        Written below [database], `management_writes` becomes database's key. That
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

    def test_the_dns_profile_public_key_is_optional_and_an_absolute_path(self) -> None:
        self.assertIsNone(self.load(VALID).dns_profiles_public_key)
        config = self.load(
            VALID + '\n[dns_profiles]\npublic_key = "/srv/example/config/dns-profile-keys/a.pub"\n'
        )
        self.assertEqual(
            config.dns_profiles_public_key, Path("/srv/example/config/dns-profile-keys/a.pub")
        )
        for bad in (
            '[dns_profiles]\npublic_key = "relative.pub"\n',
            '[dns_profiles]\npublic_key = "/srv/../a.pub"\n',
            '[dns_profiles]\npublic_key = ""\n',
            '[dns_profiles]\nprivate_key = "/srv/example/a.key"\n',
        ):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                self.load(VALID + "\n" + bad)

    def test_a_cluster_is_named_by_the_engines_id(self) -> None:
        """Up to 63 characters with hyphens, as the engine makes them; until 2026-10-22, 32."""

        longest = "a" + "b" * 62
        config = self.load(f'clusters = ["edge-a", "{longest}"]\n' + VALID)
        self.assertEqual(config.clusters, ("edge-a", longest))
        for refused in ("al_pha", "1alpha", "alpha\\n", longest + "c"):
            with self.subTest(cluster=refused), self.assertRaisesRegex(ConfigError, "cluster id"):
                self.load(f'clusters = ["{refused}"]\n' + VALID)

    def test_a_port_outside_the_range_is_refused(self) -> None:
        for port in ("0", "65536", '"8080"', "true"):
            with self.subTest(port=port), self.assertRaises(ConfigError):
                self.load(VALID + f'\n[listen]\nhost = "127.0.0.1"\nport = {port}\n')

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


class TheExampleAndTheDefaultsAgree(unittest.TestCase):
    """The shipped example is what a new installation gets; the defaults are
    what one that deleted a line gets. Two numbers for one setting is how two
    installations end up behaving differently for a reason neither file shows.

    Only the values that have a default are compared. A key the example leaves
    for the installation to fill in - the clusters, the database name - has no
    default to disagree with.
    """

    def test_the_example_turns_writes_on_and_a_missing_line_does_not(self) -> None:
        #
        # The one deliberate difference: an installation made from the example
        # writes (2026-09-29), while a file that lost the line reads - the
        # safer way to be wrong. The line comes before the first table, or it
        # would belong to that table and read as absent.
        #
        lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
        first_table = next(index for index, line in enumerate(lines) if line.startswith("["))

        self.assertIn("management_writes = true", lines[:first_table])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ui.toml"
            path.write_text(VALID.replace("management_writes = false\n", ""), encoding="utf-8")
            path.chmod(0o600)
            self.assertFalse(load(path, require_secure=False).management_writes)

    def test_the_poller_interval_is_the_same_number_in_both(self) -> None:
        written = [
            line
            for line in EXAMPLE.read_text(encoding="utf-8").splitlines()
            if line.startswith("interval_seconds")
        ]

        self.assertEqual(len(written), 1)
        example = int(written[0].split("=")[1])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ui.toml"
            path.write_text(VALID, encoding="utf-8")
            path.chmod(0o600)
            config = load(path, require_secure=False)

        self.assertEqual(config.poller.interval_seconds, example)


class StalenessAllowsForTheSlowestReading(unittest.TestCase):
    """Review 26-10-24, 02-09: one node that never answered made every other cluster stale."""

    def test_two_rounds_and_the_status_timeout(self) -> None:
        self.assertEqual(
            Poller(interval_seconds=30).stale_after,
            timedelta(seconds=60 + STATUS_TIMEOUT_SECONDS),
        )

    def test_it_is_said_in_one_place(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src" / "haprion_ui"
        copies = [
            f"{path.name}:{number}"
            for path in sorted(source.rglob("*.py"))
            for number, line in enumerate(path.read_text().splitlines(), start=1)
            if "stale_after" in line and "interval_seconds" in line
        ]
        self.assertEqual(copies, [])
