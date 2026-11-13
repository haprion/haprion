"""A blocklist on the manager: the sealed secret, the definition root keeps, the state (B500)."""

from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import blocklist_store, blocklists, dns_profile_keys
from haprion.blocklist_store import ListState, Stored, StoreError

SECRET = "tok"  # noqa: S105 - a test value, sealed and opened in memory


def _stored(revision: int = 1, **fields: object) -> Stored:
    base: dict[str, object] = {
        "name": "crowdsec",
        "url": "https://example.com/list.txt",
        "every_hours": 24,
        "authorization": "basic",
        "username": "admin",
        "excepts": ["192.0.2.10", "partner-sites"],
    }
    item = blocklists.definition(**{**base, **fields})  # type: ignore[arg-type]
    return Stored(definition=item, secret=SECRET, revision=revision)


def _item(**fields: Any) -> blocklists.Definition:
    return _stored(**fields).definition


class TheSecretIsBoundToItsList(unittest.TestCase):
    def setUp(self) -> None:
        self.private, self.public = dns_profile_keys.generate()

    def seal(self, revision: int = 3, **fields: Any) -> bytes:
        return blocklist_store.seal_secret(
            self.public, definition=_item(**fields), revision=revision, secret=SECRET
        )

    def test_it_opens_for_its_own_list(self) -> None:
        self.assertEqual(
            blocklist_store.open_secret(self.private, self.seal(), definition=_item(), revision=3),
            SECRET,
        )

    def test_a_box_sealed_for_another_list_is_refused(self) -> None:
        with self.assertRaisesRegex(StoreError, "another blocklist"):
            blocklist_store.open_secret(
                self.private, self.seal(name="other"), definition=_item(), revision=3
            )

    def test_a_box_sealed_for_another_source_is_refused(self) -> None:
        box = self.seal()
        for fields in (
            {"url": "https://attacker.example.net/list.txt"},
            {"authorization": "bearer", "username": ""},
            {"username": "other"},
        ):
            with (
                self.subTest(fields=fields),
                self.assertRaisesRegex(StoreError, "type it again"),
            ):
                blocklist_store.open_secret(
                    self.private, box, definition=_item(**fields), revision=3
                )

    def test_a_changed_exception_or_interval_is_the_same_source(self) -> None:
        self.assertEqual(
            blocklist_store.open_secret(
                self.private,
                self.seal(),
                definition=_item(excepts=["198.51.100.7"], every_hours=6),
                revision=3,
            ),
            SECRET,
        )

    def test_an_older_revision_is_refused_and_a_newer_one_opens(self) -> None:
        box = self.seal(revision=2)
        with self.assertRaisesRegex(StoreError, "older revision"):
            blocklist_store.open_secret(self.private, box, definition=_item(), revision=3)
        self.assertEqual(
            blocklist_store.open_secret(self.private, box, definition=_item(), revision=1), SECRET
        )

    def test_a_box_sealed_before_it_was_bound_to_its_source_says_to_type_it_again(self) -> None:
        old = {
            "schema_version": 1,
            "blocklist": "crowdsec",
            "key_id": self.public.key_id,
            "revision": 1,
            "secret": SECRET,
        }
        box = dns_profile_keys.seal(self.public, json.dumps(old).encode())
        with self.assertRaisesRegex(StoreError, "before it was bound to its source"):
            blocklist_store.open_secret(self.private, box, definition=_item(), revision=1)

    def test_another_key_is_refused(self) -> None:
        other, _ = dns_profile_keys.generate()
        with self.assertRaisesRegex(StoreError, "not sealed against key"):
            blocklist_store.open_secret(other, self.seal(1), definition=_item(), revision=1)

    def test_a_line_break_is_not_sealed(self) -> None:
        with self.assertRaises(StoreError):
            blocklist_store.seal_secret(
                self.public,
                definition=_item(),
                revision=1,
                secret="a\nb",  # noqa: S106 - a line break, which is what is refused
            )

    def test_the_source_key_follows_what_a_fetch_depends_on(self) -> None:
        base = blocklist_store.source_key(_item(), 1)
        self.assertEqual(base, blocklist_store.source_key(_item(excepts=[], every_hours=6), 1))
        for other in (
            blocklist_store.source_key(_item(url="https://example.com/other.txt"), 1),
            blocklist_store.source_key(_item(username="other"), 1),
            blocklist_store.source_key(_item(), 2),
        ):
            self.assertNotEqual(base, other)


class TheDefinitionIsRootOnly(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "blocklists"
        self.directory.mkdir(mode=0o700)

    def _write(self, stored: Stored) -> Path:
        return blocklist_store.write(stored, directory=self.directory, require_secure=False)

    def test_it_is_written_and_read_back(self) -> None:
        path = self._write(_stored())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(blocklist_store.read_all(directory=self.directory), (_stored(),))

    def test_an_older_revision_does_not_replace_a_newer_one(self) -> None:
        self._write(_stored(revision=4))
        with self.assertRaisesRegex(StoreError, "older"):
            self._write(_stored(revision=3))
        self._write(_stored(revision=4, every_hours=6))
        (stored,) = blocklist_store.read_all(directory=self.directory)
        self.assertEqual(stored.definition.every_hours, 6)

    def test_the_directory_must_be_root_0700(self) -> None:
        with self.assertRaisesRegex(StoreError, "root, mode 0700"):
            blocklist_store.write(_stored(), directory=self.directory)

    def test_a_file_under_another_name_is_refused(self) -> None:
        path = self._write(_stored())
        path.rename(self.directory / "other.json")
        with self.assertRaisesRegex(StoreError, "holds the blocklist crowdsec"):
            blocklist_store.read_all(directory=self.directory)

    def test_a_definition_the_rules_refuse_is_refused_on_read(self) -> None:
        path = self._write(_stored())
        document = json.loads(path.read_text())
        document["url"] = "http://example.com/"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(StoreError, "https"):
            blocklist_store.read_all(directory=self.directory)

    def test_remove_says_whether_there_was_one(self) -> None:
        self._write(_stored())
        remove = blocklist_store.remove
        self.assertTrue(remove("crowdsec", directory=self.directory, require_secure=False))
        self.assertFalse(remove("crowdsec", directory=self.directory, require_secure=False))
        self.assertEqual(blocklist_store.read_all(directory=self.directory), ())

    def test_a_missing_directory_holds_none(self) -> None:
        self.assertEqual(blocklist_store.read_all(directory=self.directory / "absent"), ())


class TheStateAndTheLastGoodList(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def test_the_last_good_list_comes_back(self) -> None:
        self.assertIsNone(blocklist_store.kept("crowdsec", directory=self.directory))
        networks = blocklists.parse(b"192.0.2.0/24\n198.51.100.7\n").networks
        blocklist_store.keep("crowdsec", networks, directory=self.directory)
        self.assertEqual(blocklist_store.kept("crowdsec", directory=self.directory), networks)

    def test_the_state_comes_back(self) -> None:
        self.assertEqual(blocklist_store.read_state(directory=self.directory), {})
        states = {
            "crowdsec": ListState(fetched_at="2026-11-10T06:00:00+00:00", entries=3),
            "drop": ListState(failed_at="2026-11-10T06:00:00+00:00", error="refused"),
        }
        blocklist_store.write_state(states, directory=self.directory)
        self.assertEqual(blocklist_store.read_state(directory=self.directory), states)

    def test_a_state_of_another_shape_is_refused(self) -> None:
        (self.directory / "state.json").write_text('{"lists": {"crowdsec": {"x": 1}}}')
        with self.assertRaises(StoreError):
            blocklist_store.read_state(directory=self.directory)

    def test_forgetting_a_list_removes_its_file_and_its_state_and_no_other(self) -> None:
        networks = blocklists.parse(b"192.0.2.0/24\n").networks
        blocklist_store.keep("crowdsec", networks, directory=self.directory)
        blocklist_store.write_state(
            {"crowdsec": ListState(entries=3), "drop": ListState(entries=4)},
            directory=self.directory,
        )

        blocklist_store.forget("crowdsec", directory=self.directory)
        blocklist_store.forget("crowdsec", directory=self.directory)

        self.assertIsNone(blocklist_store.kept("crowdsec", directory=self.directory))
        self.assertEqual(list(blocklist_store.read_state(directory=self.directory)), ["drop"])

    def test_forgetting_a_list_with_no_state_file_makes_none(self) -> None:
        blocklist_store.forget("crowdsec", directory=self.directory)

        self.assertFalse((self.directory / "state.json").exists())


if __name__ == "__main__":
    unittest.main()
