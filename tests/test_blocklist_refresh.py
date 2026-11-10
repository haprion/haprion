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


def _stored(name: str = "crowdsec", every: int = 24, excepts: tuple[str, ...] = ()) -> Stored:
    item = blocklists.definition(
        name=name, url="https://example.com/list.txt", every_hours=every, excepts=excepts
    )
    return Stored(definition=item, secret="", revision=1)


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
        self.assertTrue(blocklist_refresh.due(_stored().definition, None, NOW))

    def test_a_good_list_waits_its_interval(self) -> None:
        then = (NOW - dt.timedelta(hours=5)).isoformat()
        state = ListState(fetched_at=then, attempted_at=then)
        self.assertFalse(blocklist_refresh.due(_stored(every=6).definition, state, NOW))
        self.assertTrue(blocklist_refresh.due(_stored(every=1).definition, state, NOW))

    def test_a_failed_list_is_tried_again_after_an_hour(self) -> None:
        then = (NOW - dt.timedelta(minutes=61)).isoformat()
        state = ListState(attempted_at=then, failed_at=then, error="refused")
        self.assertTrue(blocklist_refresh.due(_stored(every=24).definition, state, NOW))
        soon = (NOW - dt.timedelta(minutes=30)).isoformat()
        state = ListState(attempted_at=soon, failed_at=soon, error="refused")
        self.assertFalse(blocklist_refresh.due(_stored(every=24).definition, state, NOW))


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
