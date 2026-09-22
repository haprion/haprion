"""What the poller does with every kind of answer, including the bad ones.

The distinction these tests exist to protect: `poll_error` means this process
could not get an answer, while an outcome of failed or partial means the cluster
answered and the answer is bad news. Collapsing the two would leave an operator
unable to tell a broken sudoers rule from a broken cluster.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import unittest
import unittest.mock
from typing import Any

from haproxy_ui import config, db, poller


def completed(stdout: str, *, returncode: int = 0, stderr: str = "") -> Any:
    return subprocess.CompletedProcess(
        args=["helper"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def envelope(outcome: str = "done", **extra: Any) -> str:
    document: dict[str, Any] = {
        "schema_version": 1,
        "operation": "status",
        "outcome": outcome,
        "cluster": "alpha",
        "result": {"summary": {"release_state": "current"}},
    }
    document.update(extra)
    return json.dumps(document)


def inventory_envelope(outcome: str = "done", **extra: Any) -> str:
    document: dict[str, Any] = {
        "schema_version": 1,
        "operation": "inventory",
        "outcome": outcome,
        "cluster": "alpha",
        "result": {"proxies": []},
    }
    document.update(extra)
    return json.dumps(document)


class GoodAnswers(unittest.TestCase):
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
        payload = envelope("partial", warnings=[{"code": "vip_unknown"}], error=None)
        reading = poller.poll_cluster("alpha", lambda *_: completed(payload))
        self.assertEqual(reading["warnings"], [{"code": "vip_unknown"}])

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
        self.assertIn("not a result envelope", reading["poll_error"])

    def test_an_unknown_outcome_is_not_written_as_if_it_were_understood(self) -> None:
        #
        # The column has a CHECK, so an unrecognised outcome would fail the
        # insert and lose the row entirely. Caught here instead, and recorded as
        # something a person can read.
        #
        reading = poller.poll_cluster("alpha", lambda *_: completed(envelope("splendid")))
        self.assertEqual(reading["outcome"], "unavailable")
        self.assertIn("unknown outcome", reading["poll_error"])

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
            return completed(envelope())

        def inventory_helper(cluster: str, _request: str) -> Any:
            if cluster == "beta":
                return completed(inventory_envelope("failed"))
            return completed(inventory_envelope())

        def list_helper(cluster: str, _request: str) -> Any:
            if cluster == "beta":
                return completed(inventory_envelope("failed", operation="list"))
            return completed(inventory_envelope(operation="list"))

        from haproxy_ui.config import Config, Database, Listen, Poller, Throttle
        from haproxy_ui.config import Session as SessionPolicy

        config = Config(
            database=Database(name="x", socket_directory="/tmp"),  # noqa: S108
            listen=Listen(host="127.0.0.1", port=8080),
            management_writes=False,
            demo_fixture=False,
            production_snapshot=False,
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
        self.assertEqual(
            written,
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

    def test_the_shipped_source_table_covers_every_polled_read(self) -> None:
        #
        # The table is what a new source has to be added to. This states which
        # reads the poller is expected to make, so adding a helper without
        # wiring it up fails here rather than being noticed as a view that
        # never has data.
        #
        self.assertEqual(
            [source.operation for source in poller.SOURCES],
            ["status", "inventory", "list", "list_backups", "cert_list", "network", "objects"],
        )
        #
        # Partial is allowed only where the read has more than one place to
        # fail: status reaches two nodes, and a backup listing reads one
        # directory per node. The other five are each one read of one place.
        #
        self.assertEqual(
            [source.partial_ok for source in poller.SOURCES],
            [True, False, False, True, False, False, False],
        )

    def test_the_backup_source_asks_for_every_retained_archive(self) -> None:
        #
        # The page pages the list and a restore is chosen from it. The command
        # line's default of fourteen per node would leave the rest of a longer
        # retention on disk and off the page.
        #
        source = next(item for item in poller.SOURCES if item.operation == "list_backups")
        with unittest.mock.patch.object(poller, "run_list_backups_helper") as helper:
            source.run("alpha", "request-1")

        helper.assert_called_once_with("alpha", "request-1", None)

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


if __name__ == "__main__":
    unittest.main()


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

        database = config.Database(name="haproxy_ui", socket_directory="/var/run/postgresql")
        with unittest.mock.patch.object(db.psycopg, "connect", fake_connect):
            db.lock_session(database)

        self.assertTrue(recorded.get("autocommit"), "the lock session must not open a transaction")
        self.assertEqual(recorded["conninfo"], database.connection_string)

    def test_the_lock_session_is_not_taken_from_a_pool(self) -> None:
        source = inspect.getsource(poller.main)
        self.assertIn("db.lock_session(", source)
        self.assertNotIn("lock_pool", source)
