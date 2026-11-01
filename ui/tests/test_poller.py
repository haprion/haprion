"""What the poller does with every kind of answer, including the bad ones.

The distinction these tests exist to protect: `poll_error` means this process
could not get an answer, while an outcome of failed or partial means the cluster
answered and the answer is bad news. Collapsing the two would leave an operator
unable to tell a broken sudoers rule from a broken cluster.
"""

from __future__ import annotations

import contextlib
import inspect
import json
import subprocess
import unittest
import unittest.mock
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import psycopg
from haprion.version_history import MAX_LIST_LIMIT

from haprion_ui import config, db, poller, service


def completed(stdout: str, *, returncode: int = 0, stderr: str = "") -> Any:
    return subprocess.CompletedProcess(
        args=["helper"], returncode=returncode, stdout=stdout, stderr=stderr
    )


#
# Every request the poller makes carries this ID, so an answer can echo it:
# the poller only accepts its own request's envelope (review 26-10-13, K3).
#
REQUEST = "00000000-0000-4000-8000-000000000001"
_FIXED_REQUEST = unittest.mock.patch.object(poller, "new_request_id", return_value=REQUEST)


def poll_once(
    pool: Any,
    config: Any,
    sources: tuple[poller.Source, ...] = poller.SOURCES,
    *,
    clusters: tuple[str, ...] | None = None,
) -> int:
    """Every listed cluster's sources once, in order; how many answered well."""

    listed = tuple(clusters if clusters is not None else config.clusters)
    return sum(
        1 for cluster in listed if poller._poll_cluster_sources(pool, cluster, sources) == "done"
    )


def setUpModule() -> None:
    _FIXED_REQUEST.start()


def tearDownModule() -> None:
    _FIXED_REQUEST.stop()


def document(
    operation: str, outcome: str = "done", result: Any = None, **extra: Any
) -> dict[str, Any]:
    """A v1 envelope as a helper writes it, answering REQUEST."""

    body: dict[str, Any] = {
        "schema_version": 1,
        "ok": outcome == "done",
        "operation": operation,
        "outcome": outcome,
        "cluster": "alpha",
        "request_id": REQUEST,
        "result": result if outcome in {"done", "partial"} else None,
        "warnings": (
            [{"code": "synthetic_warning", "message": "synthetic warning"}]
            if outcome == "partial"
            else []
        ),
        "error": (
            None
            if outcome in {"done", "partial"}
            else {"code": "synthetic_failure", "message": "synthetic failure"}
        ),
    }
    body.update(extra)
    return body


def envelope(outcome: str = "done", **extra: Any) -> str:
    return json.dumps(
        document("status", outcome, {"summary": {"release_state": "current"}}, **extra)
    )


def inventory_envelope(outcome: str = "done", operation: str = "inventory", **extra: Any) -> str:
    return json.dumps(document(operation, outcome, {"proxies": []}, **extra))


class GoodAnswers(unittest.TestCase):
    def test_a_joining_node_is_marked_in_the_reading_it_stores(self) -> None:
        """B329: the helper only sees a failed connection; the poller knows it never answered."""

        result = {"nodes": [{"name": "node-a", "reachable": True}, {"name": "node-b"}]}
        marked = poller.with_joining(result, frozenset({"node-b"}))
        self.assertEqual(marked["nodes"][1], {"name": "node-b", "joining": True})
        self.assertNotIn("joining", marked["nodes"][0])
        self.assertIs(poller.with_joining(result, frozenset()), result)

    def test_what_a_node_said_about_its_failure_is_redacted_before_it_is_stored(self) -> None:
        """Review 2026-10-30, E3."""

        said = "ERROR: failed\napi_token = hunter2"
        body = json.loads(envelope("partial"))
        body["result"]["nodes"] = [
            {
                "name": "n1",
                "error": {
                    "code": "node_status_invalid",
                    "message": "failed: api_token = hunter2",
                    "node": "n1",
                    "details": {"stderr": said},
                },
            }
        ]
        reading = poller.poll_cluster("alpha", lambda *_: completed(json.dumps(body)))
        stored = json.dumps(reading["result"])
        self.assertNotIn("hunter2", stored)
        self.assertIn("ERROR: failed", stored)

    def test_a_healthy_cluster_is_recorded_with_its_result(self) -> None:
        reading = poller.poll_cluster("alpha", lambda *_: completed(envelope()))
        self.assertEqual(reading["outcome"], "done")
        self.assertEqual(reading["result"]["summary"]["release_state"], "current")
        self.assertIsNone(reading["poll_error"])

    def test_partial_and_failed_are_answers_not_errors(self) -> None:
        #
        # A cluster that answers 'failed' has been reached. Recording that as a
        # poll error would send somebody to look at sudoers instead of at the
        # cluster.
        #
        for outcome in ("partial", "failed"):
            reading = poller.poll_cluster("alpha", lambda *_, o=outcome: completed(envelope(o)))
            self.assertEqual(reading["outcome"], outcome)
            self.assertIsNone(reading["poll_error"])

    def test_warnings_and_errors_are_carried_through_untouched(self) -> None:
        warned = [{"code": "vip_unknown", "message": "the VIP owner is not known"}]
        payload = envelope("partial", warnings=warned, error=None)
        reading = poller.poll_cluster("alpha", lambda *_: completed(payload))
        self.assertEqual(reading["warnings"], warned)

    def test_inventory_accepts_only_its_own_done_or_failed_outcomes(self) -> None:
        reading = poller.poll_cluster(
            "alpha", lambda *_: completed(inventory_envelope()), operation="inventory"
        )
        self.assertEqual(reading["outcome"], "done")
        wrong = poller.poll_cluster(
            "alpha", lambda *_: completed(envelope()), operation="inventory"
        )
        self.assertEqual(wrong["outcome"], "unavailable")


class BadAnswers(unittest.TestCase):
    def test_a_helper_that_cannot_be_run_is_a_poll_error(self) -> None:
        def explode(*_: object) -> Any:
            raise OSError("sudo: a password is required")

        reading = poller.poll_cluster("alpha", explode)
        self.assertEqual(reading["outcome"], "unavailable")
        self.assertIn("could not run the status helper", reading["poll_error"])

    def test_output_that_is_not_json_keeps_the_exit_code_and_stderr(self) -> None:
        reading = poller.poll_cluster(
            "alpha",
            lambda *_: completed("sudo: no rule", returncode=1, stderr="not allowed"),
        )
        self.assertEqual(reading["outcome"], "unavailable")
        self.assertIn("exit 1", reading["poll_error"])
        self.assertIn("not allowed", reading["poll_error"])

    def test_json_that_is_not_an_envelope_is_refused(self) -> None:
        reading = poller.poll_cluster("alpha", lambda *_: completed('["a", "list"]'))
        self.assertEqual(reading["outcome"], "unavailable")
        self.assertIn("valid status envelope", reading["poll_error"])

    def test_an_unknown_outcome_is_not_written_as_if_it_were_understood(self) -> None:
        #
        # The column has a CHECK, so an unrecognised outcome would fail the
        # insert and lose the row entirely. Caught here instead, and recorded as
        # something a person can read.
        #
        reading = poller.poll_cluster("alpha", lambda *_: completed(envelope("splendid")))
        self.assertEqual(reading["outcome"], "unavailable")
        self.assertIn("valid status envelope", reading["poll_error"])

    def test_an_answer_to_another_request_is_not_this_reading(self) -> None:
        # Review 26-10-13, K3: accepted on operation and outcome alone.
        wrongs: tuple[tuple[str, object], ...] = (
            ("cluster", "beta"),
            ("request_id", "wrong"),
            ("schema_version", 999),
            ("ok", False),
        )
        for field, wrong in wrongs:
            with self.subTest(field=field):
                payload = json.dumps({**json.loads(envelope()), field: wrong})
                reading = poller.poll_cluster("alpha", lambda *_, p=payload: completed(p))
                self.assertEqual(reading["outcome"], "unavailable")
                self.assertIsNotNone(reading["poll_error"])

    def test_done_from_a_process_that_failed_is_not_done(self) -> None:
        reading = poller.poll_cluster("alpha", lambda *_: completed(envelope(), returncode=70))
        self.assertEqual(reading["outcome"], "unavailable")
        self.assertIn("exited 70", reading["poll_error"])

    def test_an_enormous_stderr_is_truncated(self) -> None:
        reading = poller.poll_cluster(
            "alpha", lambda *_: completed("", returncode=1, stderr="x" * 50_000)
        )
        self.assertLess(len(reading["poll_error"]), poller.MAX_ERROR_BYTES + 200)
        self.assertTrue(reading["poll_error"].endswith("[…]"))


class WhatAFailedReadingStoresIsRedacted(unittest.TestCase):
    """Review 26-10-24, 08-02: a helper's stderr was stored as it came and shown on /network."""

    def test_stderr_is_masked_before_it_is_kept(self) -> None:
        said = "reading /root/.ssh/id_x failed; " + "pass" + "word=synthetic-password-value\x00"
        reading = poller.poll_cluster("alpha", lambda *_: completed("", returncode=1, stderr=said))
        self.assertIn("[REDACTED]", reading["poll_error"])
        self.assertNotIn("/root/.ssh", reading["poll_error"])
        self.assertNotIn("synthetic-password-value", reading["poll_error"])
        self.assertNotIn("\x00", reading["poll_error"])

    def test_a_helper_that_could_not_be_run_is_masked_too(self) -> None:
        def explode(*_: object) -> Any:
            raise OSError("cannot open /root/.ssh/id_x")

        reading = poller.poll_cluster("alpha", explode)
        self.assertNotIn("/root/.ssh", reading["poll_error"])


class Passes(unittest.TestCase):
    def test_one_bad_cluster_does_not_stop_the_others_being_recorded(self) -> None:
        #
        # The property that matters when something is broken: the clusters that
        # are fine are usually what somebody is waiting to hear about.
        #
        written: list[tuple[str, str]] = []

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        def record(_c: object, **kwargs: Any) -> None:
            written.append((kwargs["cluster"], kwargs["outcome"]))

        def helper(cluster: str, _request: str) -> Any:
            if cluster == "beta":
                raise OSError("unreachable")
            return completed(envelope(cluster=cluster))

        def inventory_helper(cluster: str, _request: str) -> Any:
            if cluster == "beta":
                return completed(inventory_envelope("failed", cluster=cluster))
            return completed(inventory_envelope(cluster=cluster))

        def list_helper(cluster: str, _request: str) -> Any:
            if cluster == "beta":
                return completed(inventory_envelope("failed", operation="list", cluster=cluster))
            return completed(inventory_envelope(operation="list", cluster=cluster))

        from haprion_ui.config import Config, Database, Poller, Throttle
        from haprion_ui.config import Session as SessionPolicy

        config = Config(
            database=Database(name="x", socket_directory="/tmp"),  # noqa: S108
            management_writes=False,
            demo_fixture=False,
            session=SessionPolicy(inactivity_minutes=600, absolute_hours=168, cookie_secure=True),
            throttle=Throttle(max_failures=10, window_minutes=15),
            clusters=("alpha", "beta", "gamma"),
            poller=Poller(interval_seconds=60),
        )
        #
        # The recorders are passed in rather than patched onto the module: the
        # source table binds them when it is built, so a patch applied later
        # would be written past rather than through.
        #
        sources = (
            poller.Source("status", helper, record, partial_ok=True),
            poller.Source("inventory", inventory_helper, record),
            poller.Source("list", list_helper, record),
        )
        healthy = poll_once(Pool(), config, sources)

        self.assertEqual(healthy, 2)
        # The clusters are read at once, so only each cluster's own order is
        # promised; a stable sort by cluster keeps it.
        self.assertEqual(
            sorted(written, key=lambda row: row[0]),
            [
                ("alpha", "done"),
                ("alpha", "done"),
                ("alpha", "done"),
                ("beta", "unavailable"),
                ("beta", "failed"),
                ("beta", "failed"),
                ("gamma", "done"),
                ("gamma", "done"),
                ("gamma", "done"),
            ],
        )

    def test_a_reading_that_cannot_be_stored_costs_that_reading_alone(self) -> None:
        """B335: a failing record raised through the cluster threads and ended the pass."""

        written: list[tuple[str, str]] = []

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        def record(_c: object, **kwargs: Any) -> None:
            if kwargs["cluster"] == "beta":
                raise ValueError("a column too long")
            written.append((kwargs["cluster"], kwargs["outcome"]))

        def helper(cluster: str, _request: str) -> Any:
            return completed(envelope(cluster=cluster))

        from haprion_ui.config import Config, Database, Poller, Throttle
        from haprion_ui.config import Session as SessionPolicy

        config = Config(
            database=Database(name="x", socket_directory="/tmp"),  # noqa: S108
            management_writes=False,
            demo_fixture=False,
            session=SessionPolicy(inactivity_minutes=600, absolute_hours=168, cookie_secure=True),
            throttle=Throttle(max_failures=10, window_minutes=15),
            clusters=("alpha", "beta", "gamma"),
            poller=Poller(interval_seconds=60),
        )
        with self.assertLogs("haprion_ui.poller", "ERROR") as logged:
            healthy = poll_once(
                Pool(), config, (poller.Source("status", helper, record, partial_ok=True),)
            )

        self.assertEqual(healthy, 2)
        self.assertEqual(sorted(written), [("alpha", "done"), ("gamma", "done")])
        self.assertIn("cluster beta status: the reading was not stored", logged.output[0])

    def test_a_pass_is_marked_begun_before_its_readings_and_settled_after_them(self) -> None:
        #
        # 0068: a page waits for a pass begun after its job ended to be
        # recorded whole. Marked any later, a reading taken before the job's
        # change would count; settled any earlier, a page would redraw between
        # the status and the objects it counts its buttons from.
        #
        order: list[str] = []

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        def record(_c: object, **kwargs: Any) -> None:
            order.append(f"record {kwargs['cluster']}")

        sources = (
            poller.Source("status", lambda *_: completed(envelope()), record, partial_ok=True),
            poller.Source("inventory", lambda *_: completed(inventory_envelope()), record),
        )
        with (
            unittest.mock.patch(
                "haprion_ui.db.begin_cluster_pass",
                side_effect=lambda _c, cluster: order.append(f"begin {cluster}"),
            ),
            unittest.mock.patch(
                "haprion_ui.db.settle_cluster_pass",
                side_effect=lambda _c, cluster: order.append(f"settle {cluster}"),
            ),
        ):
            poll_once(Pool(), None, sources, clusters=("alpha",))

        self.assertEqual(order, ["begin alpha", "record alpha", "record alpha", "settle alpha"])

    def test_a_pass_that_cannot_be_marked_is_still_read(self) -> None:
        #
        # The mark is a hint for the pages. Without it they wait two intervals
        # at most; without the readings every page would be wrong.
        #
        written: list[str] = []

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        sources = (
            poller.Source(
                "status",
                lambda *_: completed(envelope()),
                lambda _c, **kwargs: written.append(kwargs["cluster"]),
                partial_ok=True,
            ),
        )
        refused = psycopg.errors.InsufficientPrivilege("no grant")
        with (
            unittest.mock.patch("haprion_ui.db.begin_cluster_pass", side_effect=refused),
            unittest.mock.patch("haprion_ui.db.settle_cluster_pass", side_effect=refused),
            self.assertLogs("haprion_ui.poller", level="WARNING") as logged,
        ):
            healthy = poll_once(Pool(), None, sources, clusters=("alpha",))

        self.assertEqual((healthy, written), (1, ["alpha"]))
        self.assertEqual(len([line for line in logged.output if "pass not marked" in line]), 2)

    def test_the_shipped_source_table_covers_every_polled_read(self) -> None:
        #
        # The table is what a new source has to be added to. This states which
        # reads the poller is expected to make, so adding a helper without
        # wiring it up fails here rather than being noticed as a view that
        # never has data.
        #
        self.assertEqual(
            [source.operation for source in poller.SOURCES],
            [
                "status",
                "inventory",
                "list",
                "list_backups",
                "cert_list",
                "network",
                "cluster_settings",
                "objects",
            ],
        )
        #
        # Partial is allowed only where the read has more than one place to
        # fail: status reaches two nodes, and a backup listing reads one
        # directory per node. The other six are each one read of one place.
        #
        self.assertEqual(
            [source.partial_ok for source in poller.SOURCES],
            [True, False, False, True, False, False, False, False],
        )

    def test_the_backup_source_asks_for_every_retained_archive(self) -> None:
        #
        # The page pages the list and a restore is chosen from it. The command
        # line's default of fourteen per node would leave the rest of a longer
        # retention on disk and off the page.
        #
        source = next(item for item in poller.SOURCES if item.operation == "list_backups")
        if source.reading is None:
            raise AssertionError("the backup listing is not a manager-local reading")

        self.assertEqual(source.reading({}), {"limit": None, "node": None})

    def test_the_six_manager_local_readings_are_one_call(self) -> None:
        """N2 (2026-10-08): one sudo call for what touches only the manager."""

        local = [source.operation for source in poller.SOURCES if source.run is None]

        self.assertEqual(
            local, ["list", "list_backups", "cert_list", "network", "cluster_settings", "objects"]
        )
        self.assertTrue(all(source.reading is not None for source in poller.SOURCES[2:]))

    def test_the_objects_source_reads_the_source_and_not_the_published_config(self) -> None:
        #
        # The two are easy to confuse and answer different questions:
        # `inventory` parses what a node is serving, `objects` reads the
        # documents an edit is made against. Wiring the objects row to the
        # inventory recorder would leave the editor loading generated
        # configuration and would look like working software.
        #
        source = next(item for item in poller.SOURCES if item.operation == "objects")

        self.assertIs(source.record, poller.record_objects)
        self.assertIsNot(source.record, db.record_cluster_inventory)


class TheSingletonLockSession(unittest.TestCase):
    """The lock is only worth having if it outlives the first ten seconds.

    Found on 2026-08-31 by stopping the platform and watching `pg_locks`: the
    lock was taken at startup and gone ten seconds later, while the poller kept
    polling. The cause was a lock taken in transaction mode - the roles carry
    `idle_in_transaction_session_timeout = 10s`, so the server closed the idle
    session and the session-scoped lock went with it.

    Autocommit is therefore not a style choice here, and this test states it as
    the requirement it is. It is checked at the connection rather than against a
    live server because the failure is silent by nature: a second poller starting
    is what makes it visible, and by then two of them are writing.
    """

    def test_the_lock_is_taken_on_an_autocommit_connection(self) -> None:
        recorded: dict[str, Any] = {}

        def fake_connect(conninfo: str, **kwargs: Any) -> object:
            recorded["conninfo"] = conninfo
            recorded.update(kwargs)
            return object()

        database = config.Database(name="haprion_ui", socket_directory="/var/run/postgresql")
        with unittest.mock.patch.object(psycopg, "connect", fake_connect):
            db.lock_session(database)

        self.assertTrue(recorded.get("autocommit"), "the lock session must not open a transaction")
        self.assertEqual(recorded["conninfo"], database.connection_string)

    def test_the_lock_session_is_not_taken_from_a_pool(self) -> None:
        source = inspect.getsource(poller.main)
        self.assertIn("db.lock_session(", source)
        self.assertNotIn("lock_pool", source)


class NoClusterYet(unittest.TestCase):
    """A new installation has no cluster (B302); the poller runs, it does not exit."""

    def run_main(
        self,
        *,
        holds: Any = True,
        notified: bool = False,
        turns: int = 1,
        listed: tuple[str, ...] | None = (),
        configured: tuple[str, ...] = (),
    ) -> tuple[int, list[tuple[str, ...]], list[tuple[str, ...]]]:
        """`turns` passes of `main` against nothing, with the lock held or lost before them."""

        recorded: list[tuple[str, ...]] = []
        passes: list[tuple[str, ...]] = []
        self.calls: list[str] = []
        self.touched: list[tuple[str, ...]] = []

        class Passes:
            def __init__(self, **_kwargs: Any) -> None:
                self.asked = 0

            def requested(self) -> bool:
                self.asked += 1
                return self.asked > turns

        @contextlib.contextmanager
        def session(_database: Any) -> Any:
            yield object()

        self.woken = 0
        self.stopped = False
        test = self

        class Readers:
            def __init__(self, _pool: Any, **_kwargs: Any) -> None:
                self.stopped = False

            def follow(self, clusters: tuple[str, ...]) -> None:
                test.calls.append("follow")
                passes.append(clusters)

            def wake(self) -> None:
                test.calls.append("wake")
                test.woken += 1

            def stop(self) -> list[str]:
                test.stopped = True
                return []

        pool = unittest.mock.MagicMock()
        self.manager = unittest.mock.Mock()
        self.packages = unittest.mock.MagicMock()
        patches = {
            "poll_manager": self.manager,
            "PackageWatch": unittest.mock.MagicMock(return_value=self.packages),
            "read_cluster_list": unittest.mock.Mock(side_effect=self.list_read(listed)),
            "load_config": unittest.mock.Mock(
                return_value=unittest.mock.Mock(
                    clusters=configured, poller=config.Poller(interval_seconds=20)
                )
            ),
            "index_cluster_list": unittest.mock.Mock(),
            "ClusterReaders": Readers,
            "StopRequest": Passes,
        }
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(unittest.mock.patch.object(poller, name, value))
            stack.enter_context(unittest.mock.patch.object(db, "pool", return_value=pool))
            stack.enter_context(
                unittest.mock.patch.object(db, "listener", return_value=unittest.mock.Mock())
            )
            stack.enter_context(unittest.mock.patch.object(db, "lock_session", session))
            stack.enter_context(
                unittest.mock.patch.object(
                    db, "connected_identity", return_value=("app_poller", "haprion")
                )
            )
            stack.enter_context(
                unittest.mock.patch.object(db, "try_singleton_lock", return_value=True)
            )
            stack.enter_context(
                unittest.mock.patch.object(
                    db,
                    "holds_singleton_lock",
                    **({"side_effect": holds} if callable(holds) else {"return_value": holds}),
                )
            )
            stack.enter_context(
                unittest.mock.patch.object(
                    db,
                    "record_cluster_list",
                    lambda _connection, clusters: recorded.append(tuple(clusters)),
                )
            )
            stack.enter_context(
                unittest.mock.patch.object(
                    db,
                    "touch_cluster_list",
                    lambda _connection, fallback: self.touched.append(tuple(fallback)),
                )
            )
            stack.enter_context(
                unittest.mock.patch.object(service, "sleep_until_notified", return_value=notified)
            )
            code = poller.main([])
        return code, recorded, passes

    def list_read(self, listed: tuple[str, ...] | None) -> Any:
        def read() -> tuple[str, ...] | None:
            self.calls.append("list")
            return listed

        return read

    def test_the_poller_records_that_there_is_none_and_keeps_polling(self) -> None:
        self.assertEqual(self.run_main(), (0, [()], [()]))

    def test_a_lost_lock_ends_the_poller_before_the_pass_writes_anything(self) -> None:
        """Review 2026-10-18, A1: the lock session ended while the pool worked on."""

        with self.assertLogs("haprion_ui", "ERROR"):
            self.assertEqual(self.run_main(holds=False), (75, [], []))
        self.assertTrue(self.stopped)

    def test_the_heartbeat_is_written_when_the_list_cannot_be_read(self) -> None:
        """The row's age says the cycle runs; an unreadable list helper does not stop it."""

        _code, recorded, followed = self.run_main(listed=None, configured=("alpha",), turns=2)

        self.assertEqual((recorded, self.touched), ([], [("alpha",), ("alpha",)]))
        self.assertEqual(followed, [("alpha",), ("alpha",)])

    def test_an_unread_list_does_not_overwrite_the_stored_one(self) -> None:
        """Review 26-11-01, omvända 3 P2-1: at a start with the list helper unread and
        no list in `ui.toml`, the heartbeat wrote an empty list - "no cluster" to every
        page. Only the time may move."""

        _code, recorded, _ = self.run_main(listed=None, configured=(), turns=1)

        self.assertEqual((recorded, self.touched), ([], [()]))

    def test_a_lock_lost_during_the_cycle_stops_the_managers_own_writes(self) -> None:
        """The helpers of the cycle take time: the lock is looked at before each write."""

        for held_for, written, manager, packages in ((0, 0, 0, 0), (1, 1, 0, 0), (2, 1, 1, 0)):
            looks = 0

            def holds(*_a: object, _until: int = held_for) -> bool:
                nonlocal looks
                looks += 1
                return looks <= _until

            with self.subTest(held_for=held_for), self.assertLogs("haprion_ui", "ERROR"):
                code, recorded, _ = self.run_main(holds=holds, listed=("alpha",))
                self.assertEqual(code, 75)
                self.assertEqual(
                    (len(recorded), self.manager.call_count, self.packages.poll.call_count),
                    (written, manager, packages),
                )

    def test_a_finished_job_wakes_the_clusters_and_the_clock_does_not(self) -> None:
        self.run_main(notified=True, turns=2)
        self.assertEqual(self.woken, 1)
        self.run_main(notified=False, turns=2)
        self.assertEqual(self.woken, 0)

    def test_the_list_is_read_again_before_the_clusters_are_woken(self) -> None:
        """A removal's notification must not wake the reader of the cluster it removed."""

        self.run_main(notified=True, turns=2)

        self.assertEqual(self.calls, ["list", "list", "follow", "list", "follow", "wake"])

    def test_the_clusters_read_are_the_listed_ones_not_the_configured_ones(self) -> None:
        """B206: the cluster file decides; `ui.toml` is the fallback only."""

        _code, recorded, followed = self.run_main(listed=("gamma",), configured=("alpha",))

        self.assertEqual(followed, [("gamma",)])
        self.assertEqual(recorded, [("gamma",)])


class TheClusterList(unittest.TestCase):
    """Which clusters exist is read from the cluster file on every pass (B206/B211)."""

    def answer(self, *ids: str, outcome: str = "done") -> Any:
        listed = [{"id": name, "display_name": name.title(), "nodes": 2} for name in ids]
        return completed(
            json.dumps(document("cluster_list", outcome, {"clusters": listed}, cluster=None))
        )

    def test_the_file_s_order_is_kept(self) -> None:
        listed = poller.read_cluster_list(lambda request: self.answer("beta", "alpha"))
        self.assertEqual(listed, ("beta", "alpha"))

    def test_anything_short_of_a_list_is_not_known_rather_than_empty(self) -> None:
        def broken(_request: str) -> Any:
            raise OSError("sudo: a password is required")

        for run in (
            broken,
            lambda _request: completed("not json"),
            lambda _request: self.answer("alpha", outcome="failed"),
            lambda _request: completed(envelope()),
            lambda _request: completed(
                json.dumps(
                    document("cluster_list", "done", {"clusters": [{"name": "x"}]}, cluster=None)
                )
            ),
        ):
            with self.subTest(run=run):
                self.assertIsNone(poller.read_cluster_list(run))

    def test_no_cluster_is_an_answer_not_an_unknown(self) -> None:
        """B302: a new installation, or the last cluster removed (Fas 18, 26-10-13)."""

        self.assertEqual(poller.read_cluster_list(lambda _request: self.answer()), ())

    def test_the_pages_take_an_empty_list_for_what_it_says(self) -> None:
        """Not ui.toml's list instead: that would show a removed cluster on every page."""

        from haprion_ui import reading, settings_tool

        settings = unittest.mock.Mock(clusters=("alpha",))
        pool = unittest.mock.MagicMock()
        request = unittest.mock.Mock()
        request.app.state.pool = pool
        for recorded, expected in (((), ((), True)), (None, (("alpha",), False))):
            with (
                self.subTest(recorded=recorded),
                unittest.mock.patch.object(db, "cluster_list", return_value=recorded),
            ):
                self.assertEqual(settings_tool.known_clusters(object(), settings), expected)
                self.assertEqual(reading._cluster_list(request, settings), expected)

    def test_a_source_s_extra_request_is_built_from_what_is_kept(self) -> None:
        """The listing asks for the diffs it has not kept yet (B220); a failure there costs only that."""

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        calls: list[dict[str, Any]] = []

        def helper(_cluster: str, _request: str, **extra: Any) -> Any:
            calls.append(extra)
            return completed(envelope())

        def broken(_connection: Any, _cluster: str) -> dict[str, Any]:
            raise RuntimeError("no database")

        for asks, expected in (
            (lambda _connection, cluster: {"diffs": (cluster * 40,)}, {"diffs": ("a" * 40,)}),
            (broken, {}),
        ):
            calls.clear()
            source = poller.Source("status", helper, lambda _c, **_k: None, asks=asks)
            with (
                self.assertLogs("haprion_ui.poller", level="WARNING")
                if asks is broken
                else contextlib.nullcontext()
            ):
                poller._poll_cluster_sources(Pool(), "a", (source,))
            self.assertEqual(calls, [expected])


class TheSearchIndexIsKeptBesideTheReadings(unittest.TestCase):
    """B222: each reading replaces its own rows, and only a reading that answered."""

    class Pool:
        def connection(self) -> Any:
            return self

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def commit(self) -> None:
            return None

    def index(self, operation: str, reading: dict[str, Any]) -> list[dict[str, Any]]:
        written: list[dict[str, Any]] = []
        source = poller.Source(operation, lambda *_: None, lambda *_a, **_k: None)
        with unittest.mock.patch(
            "haprion_ui.db.replace_search_entries",
            side_effect=lambda _c, **kwargs: written.append(kwargs),
        ):
            poller._index(self.Pool(), source, cluster="alpha", reading=reading)
        return written

    def test_an_answered_reading_replaces_its_rows(self) -> None:
        result = {"objects": [{"name": "shop", "hostnames": ["shop.example.com"]}]}

        written = self.index("objects", {"outcome": "done", "result": result})

        self.assertEqual([(w["cluster"], w["source"]) for w in written], [("alpha", "objects")])
        self.assertEqual({e.value for e in written[0]["entries"]}, {"shop", "shop.example.com"})

    def test_a_failed_reading_leaves_the_last_rows_alone(self) -> None:
        self.assertEqual(self.index("objects", {"outcome": "failed", "result": {}}), [])
        self.assertEqual(self.index("objects", {"outcome": "unavailable", "result": {}}), [])

    def test_a_reading_the_search_does_not_cover_writes_nothing(self) -> None:
        self.assertEqual(self.index("list", {"outcome": "done", "result": {"versions": []}}), [])

    def test_a_failure_to_write_is_a_log_line_not_a_failed_pass(self) -> None:
        source = poller.Source("objects", lambda *_: None, lambda *_a, **_k: None)
        with (
            unittest.mock.patch(
                "haprion_ui.db.replace_search_entries", side_effect=RuntimeError("down")
            ),
            self.assertLogs("haprion_ui.poller", level="WARNING"),
        ):
            poller._index(
                self.Pool(),
                source,
                cluster="alpha",
                reading={"outcome": "done", "result": {"objects": []}},
            )


class TheObjectsReadingSendsWhatItHolds(unittest.TestCase):
    """B222: the fingerprint of the cached listing goes to the helper, and an unchanged answer stops there."""

    def source(self) -> poller.Source:
        return next(source for source in poller.SOURCES if source.operation == "objects")

    def test_the_held_fingerprint_is_asked_with(self) -> None:
        asks = self.source().asks
        if asks is None:
            raise AssertionError("the objects source asks nothing")
        with unittest.mock.patch("haprion_ui.db.objects_fingerprint", return_value="f" * 64):
            self.assertEqual(asks(object(), "alpha"), {"unchanged_since": "f" * 64})
        with unittest.mock.patch("haprion_ui.db.objects_fingerprint", return_value=None):
            self.assertEqual(asks(object(), "alpha"), {})

    def test_an_unchanged_answer_leaves_the_search_alone(self) -> None:
        with unittest.mock.patch("haprion_ui.db.replace_search_entries") as replace:
            poller._index(
                TheSearchIndexIsKeptBesideTheReadings.Pool(),
                self.source(),
                cluster="alpha",
                reading={"outcome": "done", "result": {"unchanged": True, "objects": []}},
            )
        replace.assert_not_called()


class TheManagerIsReadWithoutACluster(unittest.TestCase):
    """B304: what the manager holds is read every pass, before any cluster exists."""

    class Pool:
        def connection(self) -> Any:
            return contextlib.nullcontext(unittest.mock.Mock())

    def test_the_reading_is_recorded_and_its_certificates_searched_with_no_cluster(self) -> None:
        asked: list[tuple[str | None, Mapping[str, Any]]] = []
        registry: dict[str, list[str]] = {"certificates": [], "receivers": []}

        def readings(cluster: str | None, request_id: str, reads: Mapping[str, Any]) -> Any:
            asked.append((cluster, reads))
            inner = document(
                "cert_list",
                result={"interface_served": None, "registry": registry},
                cluster=None,
                request_id=request_id,
            )
            outer = document(
                "readings",
                result={"reads": {"cert_list": {"exit_code": 0, "envelope": inner, "stderr": ""}}},
                cluster=None,
                request_id=request_id,
            )
            return subprocess.CompletedProcess([], 0, json.dumps(outer), "")

        with (
            unittest.mock.patch("haprion_ui.db.record_manager_certificates") as recorded,
            unittest.mock.patch("haprion_ui.db.replace_search_entries") as searched,
        ):
            self.assertTrue(poller.poll_manager(self.Pool(), readings))

        self.assertEqual(asked, [(None, {"cert_list": {}})])
        self.assertEqual(recorded.call_args.kwargs["outcome"], "done")
        self.assertEqual(recorded.call_args.kwargs["result"]["registry"], registry)
        self.assertEqual(
            (searched.call_args.kwargs["cluster"], searched.call_args.kwargs["source"]),
            (None, "manager"),
        )

    def test_a_failed_reading_is_recorded_and_searched_for_nothing(self) -> None:
        def readings(*_args: Any) -> Any:
            return subprocess.CompletedProcess([], 1, "", "sudo: a password is required")

        with (
            unittest.mock.patch("haprion_ui.db.record_manager_certificates") as recorded,
            unittest.mock.patch("haprion_ui.db.replace_search_entries") as searched,
        ):
            self.assertFalse(poller.poll_manager(self.Pool(), readings))

        self.assertEqual(recorded.call_args.kwargs["outcome"], "unavailable")
        searched.assert_not_called()

    def test_a_helper_that_could_not_be_run_is_masked_as_a_cluster_s_is(self) -> None:
        """Review 26-10-25, 08-02: the manager's reading wrote the exception as it came."""

        def readings(*_args: Any) -> Any:
            raise OSError("cannot open /root/.ssh/id_x")

        with (
            unittest.mock.patch("haprion_ui.db.record_manager_certificates") as recorded,
            unittest.mock.patch("haprion_ui.db.replace_search_entries"),
        ):
            self.assertFalse(poller.poll_manager(self.Pool(), readings))

        self.assertNotIn("/root/.ssh", recorded.call_args.kwargs["poll_error"])


class TheLocalReadingsComeFromOneCall(unittest.TestCase):
    """`_local_readings`: one `haprion-readings-helper` call, each answer as its own reading (N2)."""

    class Pool:
        def connection(self) -> Any:
            return contextlib.nullcontext(object())

    def sources(self) -> list[poller.Source]:
        return [source for source in poller.SOURCES if source.run is None]

    def test_each_reading_gets_its_own_envelope_and_the_list_its_diffs(self) -> None:
        asked: list[tuple[str | None, Mapping[str, Any]]] = []

        def readings(cluster: str | None, _request_id: str, reads: Mapping[str, Any]) -> Any:
            asked.append((cluster, reads))
            answers = {
                name: {"exit_code": 0, "envelope": document(name, result={"n": name}), "stderr": ""}
                for name in reads
            }
            return subprocess.CompletedProcess(
                [], 0, json.dumps(document("readings", result={"reads": answers})), ""
            )

        with (
            unittest.mock.patch("haprion_ui.db.versions_without_diff", return_value=["a" * 40]),
            unittest.mock.patch("haprion_ui.db.objects_fingerprint", return_value=None),
        ):
            asked_id, runs = poller._local_readings(self.Pool(), "alpha", self.sources(), readings)

        ((cluster, reads),) = asked
        self.assertEqual(cluster, "alpha")
        self.assertEqual(reads["list"], {"limit": MAX_LIST_LIMIT, "diffs": ["a" * 40]})
        self.assertEqual(reads["objects"], {})
        reading = poller.poll_cluster(
            "alpha", runs["network"], operation="network", request_id=asked_id
        )
        self.assertEqual((reading["outcome"], reading["result"]), ("done", {"n": "network"}))

    def test_a_failed_call_is_a_poll_error_on_every_reading_it_carried(self) -> None:
        def readings(*_args: Any) -> Any:
            return subprocess.CompletedProcess([], 1, "", "sudo: a password is required")

        with (
            unittest.mock.patch("haprion_ui.db.versions_without_diff", return_value=[]),
            unittest.mock.patch("haprion_ui.db.objects_fingerprint", return_value=None),
        ):
            asked_id, runs = poller._local_readings(self.Pool(), "alpha", self.sources(), readings)

        for name, run in runs.items():
            reading = poller.poll_cluster("alpha", run, operation=name, request_id=asked_id)
            self.assertEqual(reading["outcome"], "unavailable")
            self.assertIn("readings helper gave no answer", reading["poll_error"])

    def test_a_reading_whose_helper_failed_keeps_its_own_words(self) -> None:
        def readings(_cluster: str | None, _request_id: str, reads: Mapping[str, Any]) -> Any:
            answers = {
                name: {"exit_code": 78, "envelope": None, "stderr": "ERROR: no policy"}
                for name in reads
            }
            return subprocess.CompletedProcess(
                [], 0, json.dumps(document("readings", result={"reads": answers})), ""
            )

        with (
            unittest.mock.patch("haprion_ui.db.versions_without_diff", return_value=[]),
            unittest.mock.patch("haprion_ui.db.objects_fingerprint", return_value=None),
        ):
            asked_id, runs = poller._local_readings(self.Pool(), "alpha", self.sources(), readings)

        reading = poller.poll_cluster(
            "alpha", runs["cert_list"], operation="cert_list", request_id=asked_id
        )
        self.assertIn("ERROR: no policy", reading["poll_error"])


class ThePackagesWaitingAreKeptWhenTheyChange(unittest.TestCase):
    """0088, B357: what dpkg has installed against what apt's lists offer, on this host."""

    class Pool:
        def connection(self) -> Any:
            return contextlib.nullcontext(unittest.mock.Mock())

    class Reader:
        def __init__(self) -> None:
            self.answers: list[Any] = []

        def read(self) -> Any:
            answer = self.answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

    def test_written_on_the_first_pass_and_again_only_when_it_changed(self) -> None:
        from haprion.package_inventory import Behind

        reader = self.Reader()
        waiting = [Behind("haprion-cli", "0.99.0", "0.99.1")]
        reader.answers = [[], [], waiting, waiting, OSError("unreadable"), []]
        watch = poller.PackageWatch(reader)  # type: ignore[arg-type]
        with unittest.mock.patch("haprion_ui.db.replace_package_waiting") as replaced:
            for _ in range(6):
                watch.poll(self.Pool())
        self.assertEqual(
            [call.args[1] for call in replaced.call_args_list],
            [(), (("haprion-cli", "0.99.0", "0.99.1"),), ()],
        )

    def test_a_database_that_refuses_is_tried_again_next_pass(self) -> None:
        reader = self.Reader()
        reader.answers = [[], []]
        watch = poller.PackageWatch(reader)  # type: ignore[arg-type]
        with unittest.mock.patch(
            "haprion_ui.db.replace_package_waiting", side_effect=[RuntimeError("down"), None]
        ) as replaced:
            watch.poll(self.Pool())
            watch.poll(self.Pool())
        self.assertEqual(replaced.call_count, 2)


def _answering(outcome: str) -> Any:
    def helper(cluster: str, _request: str) -> Any:
        return completed(envelope(outcome, cluster=cluster))

    return helper


class EachClusterIsReadAtItsOwnPace(unittest.TestCase):
    """2026-11-01: a cluster that stops answering delays itself and nobody else."""

    class Pool:
        def connection(self) -> Any:
            return self

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def commit(self) -> None:
            return None

    def setUp(self) -> None:
        patches = [
            unittest.mock.patch.object(db, name, lambda _c, _n: None)
            for name in ("begin_cluster_pass", "settle_cluster_pass")
        ]
        patches.append(unittest.mock.patch.object(poller, "_index", lambda *_a, **_k: None))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def readers(
        self,
        helper: Any,
        *,
        interval: int = 1,
        limit: int | None = None,
        partial: bool = False,
        stop_requested: Any = lambda: False,
    ) -> tuple[poller.ClusterReaders, list[tuple[str, float]]]:
        import time

        recorded: list[tuple[str, float]] = []

        def record(_c: object, **kwargs: Any) -> None:
            recorded.append((kwargs["cluster"], time.monotonic()))

        source = poller.Source("status", helper, record, partial_ok=partial)
        return (
            poller.ClusterReaders(
                self.Pool(),
                interval_seconds=interval,
                sources=(source,),
                limit=limit,
                stop_requested=stop_requested,
            ),
            recorded,
        )

    @staticmethod
    def until(condition: Any, seconds: float = 10.0) -> bool:
        import time

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.02)
        return bool(condition())

    def test_a_hung_cluster_does_not_hold_back_the_other(self) -> None:
        import threading
        import time

        release = threading.Event()
        entered = threading.Event()

        def helper(cluster: str, _request: str) -> Any:
            if cluster == "external":
                entered.set()
                release.wait(30)
            return completed(envelope(cluster=cluster))

        readers, recorded = self.readers(helper)
        started = time.monotonic()
        try:
            readers.follow(("external", "internal"))
            self.assertTrue(entered.wait(5))
            self.assertTrue(
                self.until(lambda: sum(1 for c, _ in recorded if c == "internal") >= 4, 15)
            )
            elapsed = time.monotonic() - started
            internal = [at for c, at in recorded if c == "internal"]
            gaps = [b - a for a, b in zip(internal, internal[1:], strict=False)]
            self.assertEqual([c for c, _ in recorded if c == "external"], [])
            # One interval of one second plus its own (instant) read.
            self.assertLess(max(gaps), 1.8)
            stale_after = config.Poller(interval_seconds=1).stale_after.total_seconds()
            self.assertLess(time.monotonic() - internal[-1], stale_after)
            print(
                f"\n[timing] internal read {len(internal)} times in {elapsed:.2f}s with "
                f"external hung; largest gap {max(gaps):.2f}s (interval 1s)"
            )
        finally:
            release.set()
            readers.stop(5)

    def test_never_more_readings_at_once_than_the_limit(self) -> None:
        import threading
        import time

        now = 0
        most = 0
        guard = threading.Lock()

        def helper(cluster: str, _request: str) -> Any:
            nonlocal now, most
            with guard:
                now += 1
                most = max(most, now)
            time.sleep(0.15)
            with guard:
                now -= 1
            return completed(envelope(cluster=cluster))

        readers, recorded = self.readers(helper, limit=3)
        try:
            names = tuple(f"c{n}" for n in range(8))
            readers.follow(names)
            self.assertTrue(self.until(lambda: len({c for c, _ in recorded}) == len(names)))
        finally:
            readers.stop(5)
        self.assertEqual(most, 3)

    def test_the_default_limit_is_the_module_s(self) -> None:
        readers, _ = self.readers(lambda c, r: completed(envelope(cluster=c)))
        for _ in range(poller.MAX_PARALLEL_CLUSTERS):
            self.assertTrue(readers._slots.acquire(blocking=False))
        self.assertFalse(readers._slots.acquire(blocking=False))

    def test_a_cluster_added_is_read_and_one_removed_is_let_go(self) -> None:
        def helper(cluster: str, _request: str) -> Any:
            return completed(envelope(cluster=cluster))

        readers, recorded = self.readers(helper)
        try:
            readers.follow(("alpha",))
            self.assertTrue(self.until(lambda: {c for c, _ in recorded} == {"alpha"}))
            readers.follow(("alpha", "beta"))
            self.assertTrue(self.until(lambda: {c for c, _ in recorded} == {"alpha", "beta"}))
            readers.follow(("beta",))
            self.assertTrue(self.until(lambda: "alpha" not in readers._readers))
            seen = sum(1 for c, _ in recorded if c == "alpha")
            beta = sum(1 for c, _ in recorded if c == "beta")
            self.assertTrue(self.until(lambda: sum(1 for c, _ in recorded if c == "beta") > beta))
            self.assertEqual(sum(1 for c, _ in recorded if c == "alpha"), seen)
        finally:
            readers.stop(5)

    def test_a_removed_cluster_is_let_go_at_once_not_after_its_interval(self) -> None:
        readers, recorded = self.readers(lambda c, r: completed(envelope(cluster=c)), interval=60)
        try:
            readers.follow(("alpha",))
            self.assertTrue(self.until(lambda: len(recorded) == 1))
            readers.follow(())
            self.assertTrue(self.until(lambda: not readers._readers, 5))
        finally:
            readers.stop(5)

    def test_a_removed_cluster_finishes_the_reading_in_flight(self) -> None:
        import threading

        release = threading.Event()
        entered = threading.Event()

        def helper(cluster: str, _request: str) -> Any:
            entered.set()
            release.wait(10)
            return completed(envelope(cluster=cluster))

        readers, recorded = self.readers(helper)
        try:
            readers.follow(("alpha",))
            self.assertTrue(entered.wait(5))
            readers.follow(())
            self.assertEqual(recorded, [])
            release.set()
            self.assertTrue(self.until(lambda: len(recorded) == 1))
            self.assertTrue(self.until(lambda: not readers._readers))
            self.assertEqual(len(recorded), 1)
        finally:
            release.set()
            readers.stop(5)

    def stopped_in_flight(self, answer: Any) -> tuple[list[tuple[str, float]], list[str]]:
        """Stop while a reading is in flight, then let its helper end with `answer`."""

        import threading
        import time

        release = threading.Event()
        entered = threading.Event()

        def helper(cluster: str, _request: str) -> Any:
            entered.set()
            release.wait(10)
            return answer(cluster)

        readers, recorded = self.readers(helper)
        readers.follow(("alpha",))
        self.assertTrue(entered.wait(5))
        done: list[list[str]] = []
        stopper = threading.Thread(target=lambda: done.append(readers.stop(10)))
        stopper.start()
        time.sleep(0.3)
        self.assertEqual(done, [])  # still waiting for the reading in flight
        release.set()
        stopper.join(5)
        self.assertEqual(done, [[]])
        readers.follow(("alpha", "beta"))  # nothing starts after a stop
        time.sleep(0.3)
        self.assertEqual(readers._readers, {})
        return recorded, done[0]

    def test_a_reading_the_stop_cut_short_is_not_written(self) -> None:
        """systemd signals the helpers with the poller: exit -15 and nothing to read."""

        with self.assertLogs("haprion_ui.poller", "INFO") as logged:
            recorded, _ = self.stopped_in_flight(lambda _c: completed("", returncode=-15))

        self.assertEqual(recorded, [])
        self.assertTrue(any("is leaving" in line for line in logged.output))

    def test_a_stop_requested_by_the_signal_cuts_the_reading_before_stop_is_reached(self) -> None:
        """The real order: SIGTERM reaches the helper at once; `stop()` a second later."""

        import signal
        import threading

        from haprion_ui.service import StopRequest

        for number in (signal.SIGTERM, signal.SIGINT):
            self.addCleanup(signal.signal, number, signal.getsignal(number))
        stopping = StopRequest(what="test")
        release = threading.Event()
        entered = threading.Event()

        def helper(_cluster: str, _request: str) -> Any:
            entered.set()
            release.wait(10)
            return completed("", returncode=-15)

        readers, recorded = self.readers(helper, stop_requested=stopping.requested)
        try:
            readers.follow(("alpha",))
            self.assertTrue(entered.wait(5))
            signal.raise_signal(signal.SIGTERM)  # the handler sets the request; no stop() yet
            self.assertTrue(stopping.requested())
            release.set()
            self.assertTrue(self.until(lambda: not readers._readers))
            self.assertEqual(recorded, [])
        finally:
            release.set()
            readers.stop(5)

    def test_a_reading_that_ends_after_the_stop_is_not_written_either(self) -> None:
        recorded, _ = self.stopped_in_flight(lambda c: completed(envelope(cluster=c)))

        self.assertEqual(recorded, [])

    def test_a_dropped_reading_is_not_noted_as_unread(self) -> None:
        import logging

        with self.assertNoLogs("haprion_ui.poller", logging.WARNING):
            self.stopped_in_flight(lambda _c: completed("", returncode=-15))

    def test_a_reading_made_before_the_stop_is_written(self) -> None:
        readers, recorded = self.readers(lambda c, r: completed(envelope(cluster=c)), interval=30)
        readers.follow(("alpha",))
        self.assertTrue(self.until(lambda: len(recorded) == 1))
        readers.stop(5)

        self.assertEqual(len(recorded), 1)

    def test_a_status_that_is_partial_or_failed_was_read(self) -> None:
        for outcome, expected in (("partial", "partial"), ("failed", "failed")):
            with self.subTest(outcome):
                source = poller.Source(
                    "status",
                    _answering(outcome),
                    lambda *a, **k: None,
                    partial_ok=True,
                )
                self.assertEqual(
                    poller._poll_cluster_sources(self.Pool(), "alpha", (source,)), expected
                )
        source = poller.Source(
            "status", lambda c, r: completed("", returncode=1), lambda *a, **k: None
        )
        self.assertEqual(
            poller._poll_cluster_sources(self.Pool(), "alpha", (source,)), "unavailable"
        )

    def test_a_cluster_with_a_node_down_is_not_logged_as_unread(self) -> None:
        import logging

        readers, recorded = self.readers(
            lambda c, r: completed(envelope("partial", cluster=c)), interval=30, partial=True
        )
        with self.assertLogs("haprion_ui.poller", logging.WARNING) as logged:
            readers.follow(("alpha",))
            self.assertTrue(self.until(lambda: len(recorded) == 1))
            readers.stop(5)

        self.assertFalse(any("is not being read" in line for line in logged.output))

    def test_a_cluster_that_gives_no_answer_is_logged_as_unread(self) -> None:
        readers, recorded = self.readers(lambda c, r: completed("", returncode=1), interval=30)
        with self.assertLogs("haprion_ui.poller", "WARNING") as logged:
            readers.follow(("alpha",))
            self.assertTrue(self.until(lambda: len(recorded) == 1))
            self.assertTrue(self.until(lambda: readers._readers["alpha"].last_read is False))
            readers.stop(5)

        self.assertTrue(any("is not being read" in line for line in logged.output))

    def test_a_reader_thread_that_died_is_started_again(self) -> None:
        import threading

        readers, recorded = self.readers(lambda c, r: completed(envelope(cluster=c)), interval=30)
        real = poller.ClusterReaders._noted
        broke: list[str] = []

        def noted(name: str, reader: Any, read: bool) -> None:
            if not broke:
                broke.append(name)
                raise RuntimeError("the reader's own code failed")
            real(name, reader, read)

        try:
            with (
                unittest.mock.patch.object(threading, "excepthook", lambda _args: None),
                unittest.mock.patch.object(poller.ClusterReaders, "_noted", staticmethod(noted)),
            ):
                readers.follow(("alpha",))
                self.assertTrue(self.until(lambda: len(recorded) == 1))
                thread = readers._readers["alpha"].thread
                self.assertTrue(self.until(lambda: thread is not None and not thread.is_alive()))
                with self.assertLogs("haprion_ui.poller", "ERROR"):
                    readers.follow(("alpha",))
                self.assertTrue(self.until(lambda: len(recorded) == 2))
        finally:
            readers.stop(5)

    def test_a_cluster_put_back_before_its_thread_left_is_read_by_the_same_thread(self) -> None:
        import threading

        release = threading.Event()
        entered = threading.Event()

        def helper(cluster: str, _request: str) -> Any:
            entered.set()
            release.wait(10)
            return completed(envelope(cluster=cluster))

        readers, recorded = self.readers(helper, interval=1)
        try:
            readers.follow(("alpha",))
            self.assertTrue(entered.wait(5))
            thread = readers._readers["alpha"].thread
            readers.follow(())
            readers.follow(("alpha",))
            release.set()
            self.assertTrue(self.until(lambda: len(recorded) >= 2, 10))
            self.assertIs(readers._readers["alpha"].thread, thread)
            self.assertTrue(thread is not None and thread.is_alive())
        finally:
            release.set()
            readers.stop(5)

    def test_a_reading_that_raises_costs_that_reading_and_frees_its_slot(self) -> None:
        readers, _ = self.readers(lambda c, r: completed(envelope(cluster=c)), limit=1)
        calls: list[str] = []

        def poll(pool: Any, cluster: str, sources: Any, **kwargs: Any) -> str:
            calls.append(cluster)
            if cluster == "broken":
                raise RuntimeError("the reading blew up")
            return "done"

        try:
            with (
                unittest.mock.patch.object(poller, "_poll_cluster_sources", poll),
                self.assertLogs("haprion_ui.poller", "ERROR") as logged,
            ):
                readers.follow(("broken", "alpha"))
                # One slot: alpha is read only when the broken reading let go of it.
                self.assertTrue(self.until(lambda: "alpha" in calls))
                self.assertTrue(self.until(lambda: calls.count("broken") >= 2, 10))
        finally:
            readers.stop(5)
        self.assertTrue(any("the reading failed" in line for line in logged.output))

    def test_stop_leaves_within_its_grace_when_a_cluster_hangs(self) -> None:
        import threading
        import time

        release = threading.Event()
        entered = threading.Event()

        def helper(cluster: str, _request: str) -> Any:
            entered.set()
            release.wait(30)
            return completed(envelope(cluster=cluster))

        readers, _ = self.readers(helper)
        readers.follow(("alpha",))
        self.assertTrue(entered.wait(5))
        began = time.monotonic()
        try:
            with self.assertLogs("haprion_ui.poller", "WARNING"):
                still = readers.stop(0.5)
            took = time.monotonic() - began
            self.assertEqual(still, ["alpha"])
            self.assertLess(took, 2.0)
        finally:
            release.set()

    def test_a_finished_job_reads_the_cluster_again_at_once(self) -> None:
        import time

        readers, recorded = self.readers(lambda c, r: completed(envelope(cluster=c)), interval=30)
        try:
            readers.follow(("alpha",))
            self.assertTrue(self.until(lambda: len(recorded) == 1))
            began = time.monotonic()
            readers.wake()
            self.assertTrue(self.until(lambda: len(recorded) == 2, 5))
            self.assertLess(time.monotonic() - began, 5)
        finally:
            readers.stop(5)

    def test_a_change_between_read_and_not_read_is_logged_once(self) -> None:
        reader = poller._Reader()
        with self.assertLogs("haprion_ui.poller", "INFO") as logged:
            for outcome in (True, True, False, False, True, True):
                poller.ClusterReaders._noted("alpha", reader, outcome)
        self.assertEqual([line.split(":", 2)[0] for line in logged.output], ["WARNING", "INFO"])


class EachReadingAcceptsWhatItsSchemaAllows(unittest.TestCase):
    """`partial_ok` against the contract (review 2026-10-22, 6-6).

    A reading that refuses `partial` its schema allows throws away a usable
    answer; one that accepts it where the schema has none takes as a reading
    what is not one. Nothing held the two together.
    """

    def outcomes(self) -> dict[str, set[str]]:
        schemas = Path(__file__).resolve().parents[2] / "schemas" / "v1"
        declared: dict[str, set[str]] = {}
        for path in sorted(schemas.glob("haprion-*.schema.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            for branch in (document, *document.get("allOf", ())):
                properties = branch.get("properties", {})
                if "operation" in properties and "outcome" in properties:
                    named = properties["operation"]
                    for name in named.get("enum") or [named["const"]]:
                        declared[name] = set(properties["outcome"]["enum"])
        return declared

    def test_partial_is_accepted_exactly_where_the_schema_has_it(self) -> None:
        declared = self.outcomes()
        for source in poller.SOURCES:
            with self.subTest(reading=source.operation):
                self.assertIn(source.operation, declared)
                self.assertEqual(source.partial_ok, "partial" in declared[source.operation])


class MainWithTheRealReaders(unittest.TestCase):
    """`main` against the real `ClusterReaders`; only helpers and the database are doubles."""

    class Pool:
        def connection(self) -> Any:
            return self

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def commit(self) -> None:
            return None

        def open(self, **_kwargs: Any) -> None:
            return None

        def close(self) -> None:
            return None

    def run_main(
        self,
        *,
        lists: list[tuple[str, ...]],
        helper: Any,
        holds: Any = True,
        sleeps: Any = None,
        interval: int = 1,
    ) -> tuple[int, list[tuple[str, str]]]:
        """`main` over `lists` (one per turn); the cluster and outcome of each recorded reading."""

        import functools
        import threading

        recorded: list[tuple[str, str]] = []
        guard = threading.Lock()

        def record(_c: object, **kwargs: Any) -> None:
            with guard:
                recorded.append((kwargs["cluster"], kwargs["outcome"]))

        source = poller.Source("status", helper, record, partial_ok=True)
        turns = iter(lists)
        asked = 0

        class Turns:
            def __init__(self, **_kwargs: Any) -> None:
                pass

            def requested(self) -> bool:
                nonlocal asked
                if threading.current_thread() is not threading.main_thread():
                    return False  # the readers ask too; only the loop's asks count turns
                asked += 1
                return asked > len(lists)

        @contextlib.contextmanager
        def session(_database: Any) -> Any:
            yield object()

        patches: list[Any] = [
            unittest.mock.patch.object(poller, "read_cluster_list", lambda: next(turns, lists[-1])),
            unittest.mock.patch.object(
                poller,
                "load_config",
                unittest.mock.Mock(
                    return_value=unittest.mock.Mock(
                        clusters=(), poller=config.Poller(interval_seconds=interval)
                    )
                ),
            ),
            unittest.mock.patch.object(poller, "index_cluster_list", unittest.mock.Mock()),
            unittest.mock.patch.object(poller, "poll_manager", unittest.mock.Mock()),
            unittest.mock.patch.object(poller, "PackageWatch", unittest.mock.MagicMock()),
            unittest.mock.patch("haprion_ui.update_check.Asker", unittest.mock.MagicMock()),
            unittest.mock.patch.object(
                poller,
                "ClusterReaders",
                functools.partial(poller.ClusterReaders, sources=(source,)),
            ),
            unittest.mock.patch.object(poller, "StopRequest", Turns),
            unittest.mock.patch.object(db, "pool", return_value=self.Pool()),
            unittest.mock.patch.object(db, "listener", return_value=unittest.mock.Mock()),
            unittest.mock.patch.object(db, "lock_session", session),
            unittest.mock.patch.object(
                db, "connected_identity", return_value=("app_poller", "haprion")
            ),
            unittest.mock.patch.object(db, "try_singleton_lock", return_value=True),
            unittest.mock.patch.object(db, "holds_singleton_lock", side_effect=holds),
            unittest.mock.patch.object(db, "record_cluster_list", lambda _c, _l: None),
            unittest.mock.patch.object(db, "begin_cluster_pass", lambda _c, _n: None),
            unittest.mock.patch.object(db, "settle_cluster_pass", lambda _c, _n: None),
            unittest.mock.patch.object(poller, "_index", lambda *_a, **_k: None),
            unittest.mock.patch.object(service, "sleep_until_notified", sleeps),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            code = poller.main([])
        return code, recorded

    @staticmethod
    def until(condition: Any, seconds: float = 10.0) -> bool:
        return EachClusterIsReadAtItsOwnPace.until(condition, seconds)

    def test_clusters_are_read_let_go_and_woken_through_the_real_readers(self) -> None:
        import threading

        readings: list[str] = []
        guard = threading.Lock()

        def helper(cluster: str, _request: str) -> Any:
            with guard:
                readings.append(cluster)
            return completed(envelope(cluster=cluster))

        turn = 0
        seen: dict[str, int] = {}

        def count(cluster: str) -> int:
            with guard:
                return readings.count(cluster)

        def sleeps(_stopping: Any, _listener: Any, _seconds: int) -> bool:
            nonlocal turn
            turn += 1
            if turn == 1:
                self.assertTrue(self.until(lambda: count("alpha") and count("gamma")))
            if turn == 2:
                # A removal job ended: the notification comes, gamma is gone from the list.
                seen["alpha"], seen["gamma"] = count("alpha"), count("gamma")
                return True
            if turn == 3:
                # The interval is 30 s, so only the wake can make this reading.
                self.assertTrue(self.until(lambda: count("alpha") > seen["alpha"]))
            return False

        code, _recorded = self.run_main(
            lists=[("alpha", "gamma"), ("alpha", "gamma"), ("alpha",), ("alpha",)],
            helper=helper,
            holds=lambda *_: True,
            sleeps=sleeps,
            interval=30,
        )

        self.assertEqual(code, 0)
        self.assertEqual(count("gamma"), seen["gamma"])  # not read once more after its removal
        self.assertEqual([t.name for t in threading.enumerate() if t.name.startswith("read-")], [])

    def test_a_lost_lock_drops_the_readings_in_flight(self) -> None:
        import threading

        release = threading.Event()
        entered = threading.Event()

        def helper(cluster: str, _request: str) -> Any:
            entered.set()
            release.wait(10)
            return completed(envelope(cluster=cluster))

        checks = 0

        def holds(*_: object) -> bool:
            nonlocal checks
            checks += 1
            if checks <= 3:  # the three looks of the first cycle
                return True
            # The second look finds the lock gone while alpha's reading is out.
            threading.Timer(0.3, release.set).start()
            return False

        def sleeps(_stopping: Any, _listener: Any, _seconds: int) -> bool:
            self.assertTrue(entered.wait(5))
            return False

        try:
            with self.assertLogs("haprion_ui.poller", "INFO"):
                code, recorded = self.run_main(
                    lists=[("alpha",), ("alpha",)], helper=helper, holds=holds, sleeps=sleeps
                )
        finally:
            release.set()

        self.assertEqual(code, 75)
        self.assertEqual(recorded, [])


if __name__ == "__main__":
    unittest.main()
