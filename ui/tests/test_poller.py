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

        from haprion_ui.config import Config, Database, Listen, Poller, Throttle
        from haprion_ui.config import Session as SessionPolicy

        config = Config(
            database=Database(name="x", socket_directory="/tmp"),  # noqa: S108
            listen=Listen(host="127.0.0.1", port=8080),
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
        healthy = poller.poll_once(Pool(), config, sources)

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

        from haprion_ui.config import Config, Database, Listen, Poller, Throttle
        from haprion_ui.config import Session as SessionPolicy

        config = Config(
            database=Database(name="x", socket_directory="/tmp"),  # noqa: S108
            listen=Listen(host="127.0.0.1", port=8080),
            management_writes=False,
            demo_fixture=False,
            session=SessionPolicy(inactivity_minutes=600, absolute_hours=168, cookie_secure=True),
            throttle=Throttle(max_failures=10, window_minutes=15),
            clusters=("alpha", "beta", "gamma"),
            poller=Poller(interval_seconds=60),
        )
        with self.assertLogs("haprion_ui.poller", "ERROR") as logged:
            healthy = poller.poll_once(
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
            poller.poll_once(Pool(), None, sources, clusters=("alpha",))  # type: ignore[arg-type]

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
            healthy = poller.poll_once(Pool(), None, sources, clusters=("alpha",))  # type: ignore[arg-type]

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

        self.assertIs(source.record, db.record_cluster_objects)
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
        self, *, holds: bool = True
    ) -> tuple[int, list[tuple[str, ...]], list[tuple[str, ...]]]:
        """One pass of `main` against nothing, with the lock held or lost before it."""

        recorded: list[tuple[str, ...]] = []
        passes: list[tuple[str, ...]] = []

        class OnePass:
            def __init__(self, **_kwargs: Any) -> None:
                self.asked = 0

            def requested(self) -> bool:
                self.asked += 1
                return self.asked > 1

        @contextlib.contextmanager
        def session(_database: Any) -> Any:
            yield object()

        def record_pass(_pool: Any, _config: Any, *, clusters: tuple[str, ...]) -> int:
            passes.append(clusters)
            return 0

        pool = unittest.mock.MagicMock()
        patches = {
            "read_cluster_list": unittest.mock.Mock(return_value=()),
            "load_config": unittest.mock.Mock(
                return_value=unittest.mock.Mock(
                    clusters=(), poller=config.Poller(interval_seconds=20)
                )
            ),
            "index_cluster_list": unittest.mock.Mock(),
            "poll_once": record_pass,
            "StopRequest": OnePass,
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
                unittest.mock.patch.object(db, "holds_singleton_lock", return_value=holds)
            )
            stack.enter_context(
                unittest.mock.patch.object(
                    db,
                    "record_cluster_list",
                    lambda _connection, clusters: recorded.append(tuple(clusters)),
                )
            )
            stack.enter_context(unittest.mock.patch.object(service, "sleep_until_notified"))
            code = poller.main([])
        return code, recorded, passes

    def test_the_poller_records_that_there_is_none_and_keeps_polling(self) -> None:
        self.assertEqual(self.run_main(), (0, [()], [()]))

    def test_a_lost_lock_ends_the_poller_before_the_pass_writes_anything(self) -> None:
        """Review 2026-10-18, A1: the lock session ended while the pool worked on."""

        with self.assertLogs("haprion_ui", "ERROR"):
            self.assertEqual(self.run_main(holds=False), (75, [], []))


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

        from haprion_ui import settings_tool, views

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
                self.assertEqual(views._cluster_list(request, settings), expected)

    def test_a_pass_goes_over_the_listed_clusters_not_the_configured_ones(self) -> None:
        asked: list[str] = []

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        def helper(cluster: str, _request: str) -> Any:
            asked.append(cluster)
            return completed(envelope())

        from haprion_ui.config import Config, Database, Listen, Poller, Throttle
        from haprion_ui.config import Session as SessionPolicy

        configured = Config(
            database=Database(name="x", socket_directory="/tmp"),  # noqa: S108
            listen=Listen(host="127.0.0.1", port=8080),
            management_writes=False,
            demo_fixture=False,
            session=SessionPolicy(inactivity_minutes=600, absolute_hours=168, cookie_secure=True),
            throttle=Throttle(max_failures=10, window_minutes=15),
            clusters=("alpha",),
            poller=Poller(interval_seconds=60),
        )
        source = poller.Source("status", helper, lambda _c, **_k: None)

        poller.poll_once(Pool(), configured, (source,), clusters=("gamma", "delta"))

        self.assertCountEqual(asked, ["gamma", "delta"])

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

    def test_the_clusters_are_read_at_once(self) -> None:
        """Fas 16 punkt 1: a pass takes as long as its slowest cluster, not their sum."""

        import threading

        clusters = ("alpha", "beta", "gamma")
        # Each helper waits until all three clusters are being read; in series
        # the first would wait alone and the barrier would break.
        together = threading.Barrier(len(clusters), timeout=5)

        class Pool:
            def connection(self) -> Any:
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def commit(self) -> None:
                return None

        def helper(cluster: str, _request: str) -> Any:
            together.wait()
            return completed(envelope(cluster=cluster))

        source = poller.Source("status", helper, lambda _c, **_k: None)
        healthy = poller.poll_once(Pool(), None, (source,), clusters=clusters)  # type: ignore[arg-type]

        self.assertEqual(healthy, 3)


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


if __name__ == "__main__":
    unittest.main()


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
