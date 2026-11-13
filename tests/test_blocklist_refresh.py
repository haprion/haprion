"""The refresh pass: what is fetched, what is kept, what each cluster gets (B500)."""

from __future__ import annotations

import datetime as dt
import os
import stat
import tempfile
import unittest
from pathlib import Path

from haprion import blocklist_refresh, blocklist_store, blocklists
from haprion.blocklist_refresh import ClusterTarget
from haprion.blocklist_store import ListState, Stored

NOW = dt.datetime(2026, 11, 10, 6, 0, tzinfo=dt.UTC)


def _stored(
    name: str = "crowdsec",
    every: int = 24,
    excepts: tuple[str, ...] = (),
    url: str = "https://example.com/list.txt",
    secret_revision: int = 1,
    revision: int = 1,
) -> Stored:
    item = blocklists.definition(name=name, url=url, every_hours=every, excepts=excepts)
    return Stored(definition=item, secret="", revision=revision, secret_revision=secret_revision)


class Source:
    def __init__(self, body: bytes = b"192.0.2.0/24\n198.51.100.7\n") -> None:
        self.body = body
        self.error: Exception | None = None
        self.asked: list[str] = []

    def __call__(self, item: blocklists.Definition, secret: str) -> bytes:
        self.asked.append(item.name)
        if self.error is not None:
            raise self.error
        return self.body


class WhenAListIsDue(unittest.TestCase):
    def test_never_fetched_is_due(self) -> None:
        self.assertTrue(blocklist_refresh.due(_stored(), None, NOW))

    def test_a_good_list_waits_its_interval(self) -> None:
        then = (NOW - dt.timedelta(hours=5)).isoformat()
        state = ListState(fetched_at=then, attempted_at=then, source=_stored().source)
        self.assertFalse(blocklist_refresh.due(_stored(every=6), state, NOW))
        self.assertTrue(blocklist_refresh.due(_stored(every=1), state, NOW))

    def test_a_new_source_is_due_whatever_the_interval_says(self) -> None:
        then = (NOW - dt.timedelta(minutes=5)).isoformat()
        state = ListState(fetched_at=then, attempted_at=then, source=_stored().source)
        self.assertFalse(
            blocklist_refresh.due(_stored(excepts=("192.0.2.9",), revision=2), state, NOW)
        )
        for changed in (
            _stored(url="https://example.com/other.txt", revision=2),
            _stored(secret_revision=2, revision=2),
        ):
            self.assertTrue(blocklist_refresh.due(changed, state, NOW))

    def test_a_failed_list_is_tried_again_after_an_hour(self) -> None:
        then = (NOW - dt.timedelta(minutes=61)).isoformat()
        source = _stored().source
        state = ListState(attempted_at=then, failed_at=then, error="refused", source=source)
        self.assertTrue(blocklist_refresh.due(_stored(every=24), state, NOW))
        soon = (NOW - dt.timedelta(minutes=30)).isoformat()
        state = ListState(attempted_at=soon, failed_at=soon, error="refused", source=source)
        self.assertFalse(blocklist_refresh.due(_stored(every=24), state, NOW))


class APass(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state = root / "state"
        self.state.mkdir()
        self.targets = []
        for cluster, groups in (("alpha", {"partner-sites": ("198.51.100.0/24",)}), ("beta", {})):
            directory = root / "certdist" / cluster
            directory.mkdir(parents=True, mode=0o750)
            self.targets.append(
                ClusterTarget(
                    cluster=cluster,
                    directory=directory,
                    groups=groups,
                    uid=os.getuid(),
                    gid=os.getgid(),
                    mode=0o640,
                )
            )
        self.source = Source()

    def _run(self, *stored: Stored, now: dt.datetime = NOW) -> blocklist_refresh.Pass:
        return blocklist_refresh.run(
            stored, self.targets, now, fetch=self.source, state_directory=self.state
        )

    def _file(self, cluster: str, name: str = "crowdsec") -> bytes:
        return (
            self.targets[0].directory.parent / cluster / "blocklists" / f"{name}.lst"
        ).read_bytes()

    def test_each_cluster_gets_the_list_with_its_own_exceptions(self) -> None:
        result = self._run(_stored(excepts=("partner-sites", "192.0.2.128/25")))
        self.assertEqual(self._file("alpha"), b"192.0.2.0/25\n")
        self.assertEqual(self._file("beta"), b"192.0.2.0/25\n198.51.100.7\n")
        self.assertEqual(result.changed_clusters(), {"alpha": ("crowdsec",), "beta": ("crowdsec",)})
        (beta,) = [w for w in result.written if w.cluster == "beta"]
        self.assertEqual(beta.unknown_groups, ("partner-sites",))
        path = self.targets[0].directory / "blocklists" / "crowdsec.lst"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_an_unchanged_list_moves_nothing(self) -> None:
        self._run(_stored(every=1))
        later = NOW + dt.timedelta(hours=2)
        self.assertEqual(self._run(_stored(every=1), now=later).changed_clusters(), {})
        self.assertEqual(self.source.asked, ["crowdsec", "crowdsec"])

    def test_an_exception_takes_effect_without_a_fetch(self) -> None:
        self._run(_stored())
        result = self._run(_stored(excepts=("198.51.100.7",)), now=NOW + dt.timedelta(minutes=5))
        self.assertEqual(self.source.asked, ["crowdsec"])
        self.assertEqual(self._file("beta"), b"192.0.2.0/24\n")
        self.assertEqual(set(result.changed_clusters()), {"alpha", "beta"})

    def test_a_changed_url_is_fetched_in_the_same_pass_and_a_changed_token_too(self) -> None:
        self._run(_stored())
        soon = NOW + dt.timedelta(minutes=5)
        self._run(_stored(url="https://example.com/other.txt", revision=2), now=soon)
        self._run(
            _stored(url="https://example.com/other.txt", revision=3, secret_revision=3), now=soon
        )
        self.assertEqual(self.source.asked, ["crowdsec"] * 3)

    def test_a_failed_first_fetch_from_a_new_source_keeps_and_serves_the_old_list(self) -> None:
        # Dropping the file would make the generator refuse every object naming the list.
        self._run(_stored())
        self.source.error = blocklists.BlocklistError("refused", "example.com answered 503")
        moved = _stored(url="https://example.com/other.txt", revision=2)

        result = self._run(moved, now=NOW + dt.timedelta(minutes=5))

        state = result.states["crowdsec"]
        self.assertEqual((state.fetched_at, state.entries), (NOW.isoformat(), 2))
        self.assertIn("example.com answered 503", state.error)
        self.assertIn("the list kept is from the previous source", state.error)
        for target in self.targets:
            self.assertEqual(
                (target.directory / "blocklists" / "crowdsec.lst").read_bytes(),
                b"192.0.2.0/24\n198.51.100.7\n",
            )
        later = self._run(moved, now=NOW + dt.timedelta(hours=2)).states["crowdsec"]
        self.assertIn("the list kept is from the previous source", later.error)

        self.source.error = None
        self.source.body = b"203.0.113.0/24\n"
        fresh = self._run(moved, now=NOW + dt.timedelta(hours=4)).states["crowdsec"]
        self.assertEqual((fresh.error, fresh.entries), ("", 1))

    def test_a_list_made_again_under_a_removed_name_does_not_inherit_the_old_one(self) -> None:
        self._run(_stored())
        self._run(now=NOW + dt.timedelta(minutes=1))
        self.assertIsNone(blocklist_store.kept("crowdsec", directory=self.state))
        self.source.error = blocklists.BlocklistError("refused", "example.com answered 503")

        result = self._run(_stored(), now=NOW + dt.timedelta(minutes=2))

        self.assertEqual(result.written, ())
        for target in self.targets:
            self.assertFalse((target.directory / "blocklists" / "crowdsec.lst").exists())

    def test_a_failed_fetch_keeps_the_last_good_list(self) -> None:
        self._run(_stored(every=1))
        self.source.error = blocklists.BlocklistError("refused", "example.com answered 503")
        later = NOW + dt.timedelta(hours=1)
        result = self._run(_stored(every=1), now=later)
        state = result.states["crowdsec"]
        self.assertEqual(state.fetched_at, NOW.isoformat())
        self.assertEqual(state.failed_at, later.isoformat())
        self.assertEqual(state.error, "example.com answered 503")
        self.assertEqual(state.entries, 2)
        self.assertEqual(self._file("beta"), b"192.0.2.0/24\n198.51.100.7\n")

    def test_an_empty_answer_is_a_failure_not_an_empty_list(self) -> None:
        self._run(_stored(every=1))
        self.source.body = b""
        result = self._run(_stored(every=1), now=NOW + dt.timedelta(hours=1))
        self.assertEqual(result.states["crowdsec"].error, "the list holds no address")
        self.assertEqual(self._file("beta"), b"192.0.2.0/24\n198.51.100.7\n")

    def test_a_list_never_fetched_well_writes_no_file(self) -> None:
        self.source.error = blocklists.BlocklistError(
            "unreachable", "example.com could not be reached"
        )
        result = self._run(_stored())
        self.assertEqual(result.written, ())
        self.assertFalse((self.targets[0].directory / "blocklists" / "crowdsec.lst").exists())

    def test_the_state_of_a_removed_definition_goes(self) -> None:
        self._run(_stored(), _stored(name="drop"))
        result = self._run(_stored(), now=NOW + dt.timedelta(minutes=1))
        self.assertEqual(set(result.states), {"crowdsec"})
        self.assertEqual(set(blocklist_store.read_state(directory=self.state)), {"crowdsec"})

    def test_a_removed_list_leaves_every_clusters_directory(self) -> None:
        self._run(_stored(), _stored(name="drop"))
        self._run(_stored(), now=NOW + dt.timedelta(minutes=1))
        for target in self.targets:
            self.assertEqual(
                sorted(p.name for p in (target.directory / "blocklists").iterdir()),
                ["crowdsec.lst"],
            )

    def test_only_fetches_the_named_list_now(self) -> None:
        self._run(_stored(), _stored(name="drop"))
        blocklist_refresh.run(
            (_stored(), _stored(name="drop")),
            self.targets,
            NOW + dt.timedelta(minutes=1),
            fetch=self.source,
            state_directory=self.state,
            only=("drop",),
        )
        self.assertEqual(self.source.asked, ["crowdsec", "drop", "drop"])

    def test_a_time_without_a_zone_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._run(_stored(), now=NOW.replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main()
