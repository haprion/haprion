"""Checks that need PostgreSQL rather than an imitation of its cursor."""

from __future__ import annotations

import importlib.util
import os
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg

from haproxy_ui import db

DSN = os.environ.get("HAPROXY_UI_TEST_DATABASE_DSN", "")


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class ARealDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def test_every_migration_reaches_the_declared_head(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select version_num from alembic_version")
            self.assertEqual(cursor.fetchone(), ("0028",))

    def test_runtime_accounts_inherit_exactly_one_contract_role(self) -> None:
        expected = {
            "HAPROXY_UI_TEST_WEB_ROLE": "app_web",
            "HAPROXY_UI_TEST_WORKER_ROLE": "app_worker",
            "HAPROXY_UI_TEST_POLLER_ROLE": "app_poller",
        }
        with self.connect() as connection, connection.cursor() as cursor:
            for variable, contract in expected.items():
                cursor.execute(
                    "select parent.rolname from pg_auth_members membership "
                    "join pg_roles member on member.oid = membership.member "
                    "join pg_roles parent on parent.oid = membership.roleid "
                    "where member.rolname = %s order by parent.rolname",
                    (os.environ[variable],),
                )
                self.assertEqual(cursor.fetchall(), [(contract,)])

    def test_web_can_read_status_but_cannot_write_it(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select cluster from cluster_status limit 0")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute(
                    "insert into cluster_status (cluster, outcome) values ('alpha', 'done')"
                )

    def test_worker_can_read_jobs_but_not_accounts(self) -> None:
        with (
            self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("select id from job limit 0")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cursor.execute("select id from app_user limit 0")

    def test_poller_can_write_metrics_but_cannot_read_jobs(self) -> None:
        now = datetime.now(UTC)
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (now.date(),))
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_frontend "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('alpha', 'node-a', 'mgd-main-http', true, 60, 1)"
            )
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select id from job limit 0")

    def test_frontend_buckets_never_mix_two_nodes_uptime(self) -> None:
        #
        # Pinned to the start of a ten-minute bucket rather than placed relative
        # to now. `date_bin` bins against a fixed origin, so rows laid out at
        # `now - 20 min` and `+2 min` straddled a bucket boundary whenever that
        # minute ended in 8 or 9 - the test then failed about one run in five
        # while describing nothing but the clock.
        #
        now = datetime.now(UTC)
        start = now.replace(minute=now.minute // 10 * 10, second=0, microsecond=0) - timedelta(
            minutes=20
        )
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (start.date(),))
            cursor.executemany(
                "insert into metric_frontend "
                "(cluster, node, frontend, observed_at, owns_vip, uptime_sec, req_tot) "
                "values (%s, %s, %s, %s, true, %s, %s)",
                [
                    ("alpha", "node-a", "mgd-main-http", start, 5000, 5_000_000),
                    ("alpha", "node-b", "mgd-main-http", start + timedelta(minutes=1), 10, 100),
                    (
                        "alpha",
                        "node-a",
                        "mgd-main-http",
                        start + timedelta(minutes=2),
                        5120,
                        5_000_400,
                    ),
                ],
            )
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            samples = db.read_frontend_samples(
                connection,
                cluster="alpha",
                frontend="mgd-main-http",
                since=start,
                until=start + timedelta(minutes=9),
                width=timedelta(minutes=10),
            )
        by_node = {sample.node: sample for sample in samples}
        self.assertEqual(set(by_node), {"node-a", "node-b"})
        self.assertEqual(by_node["node-a"].floor_uptime_sec, 5000)
        self.assertEqual(by_node["node-b"].floor_uptime_sec, 10)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheMetricTablesUnderTheirNewNames(unittest.TestCase):
    """Migration 0023 renamed the metric tables and left the old names as views.

    The views are what let the UI release before the rename accept this
    revision: it reads and writes `metric_listener` during the minutes between
    migration and activation, and again if the rename is rolled back. So the
    old names must carry exactly the old grants, and a row written through one
    name must be the row read through the other.
    """

    MIGRATION = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "0023_metric_table_names.py"
    )

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def test_the_old_names_are_views_over_the_new_tables(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "select relname, relkind from pg_class where relname in "
                "('metric_frontend', 'metric_backend_member', 'metric_backend_hour', "
                " 'metric_listener', 'metric_pool_member', 'metric_pool_hour') order by 1"
            )
            self.assertEqual(
                cursor.fetchall(),
                [
                    ("metric_backend_hour", "p"),
                    ("metric_backend_member", "p"),
                    ("metric_frontend", "p"),
                    ("metric_listener", "v"),
                    ("metric_pool_hour", "v"),
                    ("metric_pool_member", "v"),
                ],
            )

    def test_the_poller_writes_the_old_name_and_the_web_reads_the_new(self) -> None:
        day = datetime.now(UTC).date()
        with self.connect() as connection, connection.cursor() as cursor:
            #
            # Asked for under the old name, as the retention command installed
            # beside the previous release still does; made under the new one.
            #
            cursor.execute("select metric_partition('metric_listener', %s::date)", (day,))
            self.assertEqual(cursor.fetchone(), (f"metric_frontend_{day:%Y%m%d}",))
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "insert into metric_listener "
                "(cluster, node, frontend, owns_vip, uptime_sec, req_tot) "
                "values ('bridge', 'node-a', 'mgd-old-name', true, 60, 7)"
            )
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute(
                "select req_tot, observed_at is not null from metric_frontend "
                "where cluster = 'bridge' and frontend = 'mgd-old-name'"
            )
            self.assertEqual(cursor.fetchall(), [(7, True)])

    def test_the_rollup_boundary_moved_with_the_table(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection, connection.cursor() as cursor:
            cursor.execute("select rollup_name from metric_rollup_state order by 1")
            self.assertEqual(cursor.fetchall(), [("backend_hour",)])

    def test_partitions_and_their_indexes_are_renamed_with_the_parent(self) -> None:
        """The rename loop, exercised against a partition it has to carry along.

        The harness migrates an empty database, so no partition existed when
        0023 ran. This makes one, runs the migration's own downgrade and upgrade
        through the same statements alembic would, and checks the partition, its
        primary key, the read index and the check constraint changed prefix each
        way - because the retention command finds partitions by prefix, and one
        left behind would never be dropped.
        """

        day = datetime.now(UTC).date() + timedelta(days=200)
        suffix = f"{day:%Y%m%d}"
        migration = self.load_migration()

        def names(cursor: psycopg.Cursor, prefix: str) -> set[str]:
            cursor.execute(
                "select relname from pg_class where relname like %s "
                "union select conname from pg_constraint where conname like %s",
                (prefix + "%", prefix + "%"),
            )
            return {row[0] for row in cursor.fetchall()}

        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("select metric_partition('metric_frontend', %s::date)", (day,))
            migration.op = _Executes(cursor)
            migration.downgrade()
            old = names(cursor, "metric_listener")
            self.assertIn(f"metric_listener_{suffix}", old)
            self.assertIn(f"metric_listener_{suffix}_pkey", old)
            self.assertIn("metric_listener_read", old)
            self.assertIn("metric_listener_cluster_shape", old)
            self.assertFalse(names(cursor, "metric_frontend"))
            migration.upgrade()
            new = names(cursor, "metric_frontend")
            self.assertIn(f"metric_frontend_{suffix}", new)
            self.assertIn(f"metric_frontend_{suffix}_pkey", new)
            self.assertIn("metric_frontend_read", new)
            self.assertIn("metric_frontend_cluster_shape", new)
            self.assertEqual(names(cursor, "metric_listener"), {"metric_listener"})

    def load_migration(self) -> Any:
        spec = importlib.util.spec_from_file_location("migration_0023", self.MIGRATION)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {self.MIGRATION}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class _Executes:
    """What the migration needs of alembic's `op`: `execute`, on our cursor."""

    def __init__(self, cursor: psycopg.Cursor) -> None:
        self.cursor = cursor

    def execute(self, sql: str) -> None:
        self.cursor.execute(sql)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheQueueCarriesCertificateJobs(unittest.TestCase):
    """Migration 0024: a job whose scope is a certificate rather than a cluster.

    The constraints are the point. A cluster operation without a cluster and a
    certificate operation with one are both refused by the database, so a
    process that has been talked into queueing a job whose cluster column means
    nothing fails before a worker ever claims the row.
    """

    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def setUp(self) -> None:
        self.connection = self.connect()
        self.addCleanup(self.connection.close)
        with self.connection.cursor() as cursor:
            cursor.execute("delete from job")
        self.connection.commit()

    def queue(self, operation: str, cluster: str | None, **payload: Any) -> db.Job:
        return db.queue_job(
            self.connection,
            operation=operation,
            cluster=cluster,
            payload=payload,
            idempotency_key=uuid4(),
        )

    def test_a_certificate_job_is_queued_with_no_cluster(self) -> None:
        job = self.queue("cert_publish", None, certificates=["example.com"])

        self.assertIsNone(job.cluster)
        self.assertEqual(job.operation, "cert_publish")

    def test_a_certificate_job_carrying_a_cluster_is_refused(self) -> None:
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue("cert_publish", "alpha")

    def test_a_cluster_job_without_a_cluster_is_refused(self) -> None:
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.queue("deploy", None)

    def test_only_one_certificate_job_may_be_in_flight_at_a_time(self) -> None:
        """The queue agreeing with the publisher, which takes one lock for all of them."""

        self.queue("cert_publish", None, certificates=["example.com"])

        with self.assertRaises(db.CertificateBusy):
            self.queue("cert_issue", None, domain="new.example")

    def test_a_certificate_job_does_not_make_a_cluster_busy(self) -> None:
        """It holds no cluster's slot, so a deploy may still be queued beside it."""

        self.queue("cert_publish", None, certificates=["example.com"])

        job = self.queue("deploy", "alpha")

        self.assertEqual(job.cluster, "alpha")

    def test_a_retry_of_a_certificate_job_is_the_job_it_already_queued(self) -> None:
        """`null = null` is null, so the retry lookup has to compare the absence too."""

        key = uuid4()
        payload = {"certificates": ["example.com"]}
        first = db.queue_job(
            self.connection,
            operation="cert_publish",
            cluster=None,
            payload=payload,
            idempotency_key=key,
        )

        second = db.queue_job(
            self.connection,
            operation="cert_publish",
            cluster=None,
            payload=payload,
            idempotency_key=key,
        )

        self.assertEqual(second.id, first.id)


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class TheProfileTableHoldsABoxNobodyHereCanOpen(unittest.TestCase):
    """Migration 0025: sealed DNS provider profiles and the job that applies them.

    The grants are the point. The web writes boxes and reads metadata; the
    worker reads a box to hand it to root; the poller sees nothing. Whether
    the box can be opened is not a question this database can answer, which
    is the whole design.
    """

    def connect(self, role_variable: str) -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def setUp(self) -> None:
        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                cursor.execute("delete from job")
                cursor.execute("delete from dns_provider_profile")
            connection.commit()

    def test_the_web_creates_replaces_and_lists_without_seeing_the_box(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            created = db.create_dns_profile(
                connection,
                profile_id="cf-main",
                name="Cloudflare main",
                provider_id="cloudflare",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="operator",
            )
            self.assertEqual(created.revision, 1)
            with self.assertRaises(db.ProfileExists):
                db.create_dns_profile(
                    connection,
                    profile_id="cf-main",
                    name="again",
                    provider_id="cloudflare",
                    key_id="0123456789abcdef",
                    ciphertext=b"y" * 48,
                    actor="operator",
                )
            replaced = db.replace_dns_profile(
                connection,
                profile_id="cf-main",
                revision=2,
                key_id="fedcba9876543210",
                ciphertext=b"z" * 48,
                actor="admin",
                name=None,
            )
            self.assertEqual(
                (replaced.revision, replaced.key_id, replaced.name),
                (2, "fedcba9876543210", "Cloudflare main"),
            )
            self.assertEqual(replaced.updated_by, "admin")
            with self.assertRaises(db.ProfileMissing):
                db.replace_dns_profile(
                    connection,
                    profile_id="cf-main",
                    revision=2,
                    key_id="fedcba9876543210",
                    ciphertext=b"w" * 48,
                    actor="admin",
                )
            self.assertEqual([row.id for row in db.dns_profiles(connection)], ["cf-main"])
            self.assertIsNone(db.dns_profile(connection, "missing"))
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select ciphertext from dns_provider_profile")
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("update dns_provider_profile set provider_id = 'hetzner'")
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("delete from dns_provider_profile")
            connection.rollback()

    def test_the_worker_reads_the_box_and_the_poller_reads_nothing(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            db.create_dns_profile(
                connection,
                profile_id="cf-main",
                name="Cloudflare main",
                provider_id="cloudflare",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="operator",
            )
            connection.commit()
        with self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection:
            sealed = db.sealed_profile(connection, "cf-main")
            self.assertIsNotNone(sealed)
            self.assertEqual(bytes(sealed.ciphertext if sealed else b""), b"x" * 48)
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select created_by from dns_provider_profile")
            connection.rollback()
            self.assertTrue(db.delete_dns_profile(connection, "cf-main", 1))
            self.assertFalse(db.delete_dns_profile(connection, "cf-main", 1))
            connection.commit()
        with (
            self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection,
            connection.cursor() as cursor,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            cursor.execute("select id from dns_provider_profile")

    def test_the_apply_job_is_a_certificate_job(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="dns_profile_apply",
                cluster=None,
                payload={"profile": "cf-main", "revision": 1},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="cert_issue",
                    cluster=None,
                    payload={"domain": "example.com"},
                    idempotency_key=uuid4(),
                )
            connection.rollback()
            with self.assertRaises(psycopg.errors.CheckViolation):
                db.queue_job(
                    connection,
                    operation="dns_profile_apply",
                    cluster="alpha",
                    payload={},
                    idempotency_key=uuid4(),
                )

    def test_the_migration_downgrades_and_upgrades_cleanly_on_an_empty_queue(self) -> None:
        """The whitelist narrows and widens with the table, both ways, in one transaction."""

        migration_path = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "versions"
            / "0025_dns_provider_profiles.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0025", migration_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {migration_path}")
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute("select to_regclass('dns_provider_profile')")
                self.assertEqual(cursor.fetchone(), (None,))
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertNotIn("dns_profile_apply", cursor.fetchone()[0])
                migration.upgrade()
                cursor.execute("select to_regclass('dns_provider_profile')")
                self.assertEqual(cursor.fetchone(), ("dns_provider_profile",))
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class CertificateDeletion(unittest.TestCase):
    """Migration 0026: the queue may carry `cert_delete`, in the certificate slot."""

    def connect(self, role_variable: str) -> psycopg.Connection:
        role = os.environ[role_variable]
        return psycopg.connect(f"{DSN} user={role}")

    def setUp(self) -> None:
        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                cursor.execute("delete from job")
            connection.commit()

    def test_the_delete_job_is_a_clusterless_certificate_job(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="cert_delete",
                cluster=None,
                payload={"certificates": ["old.example.com"]},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="cert_publish",
                    cluster=None,
                    payload={},
                    idempotency_key=uuid4(),
                )
            connection.rollback()
            with self.assertRaises(psycopg.errors.CheckViolation):
                db.queue_job(
                    connection,
                    operation="cert_delete",
                    cluster="alpha",
                    payload={},
                    idempotency_key=uuid4(),
                )

    def test_the_worker_cannot_read_drafts_so_the_draft_check_is_the_web_s(self) -> None:
        """What took the worker down on 2026-09-13: the run-time draft check.

        The grant is the design, not the bug. The worker publishes from the
        payload and never from the table, so the last look at the drafts is
        the moment the web queues the job; `db.live_drafts` is a web-only
        read and must fail here.
        """

        with (
            self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection,
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
        ):
            db.live_drafts(connection)
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            self.assertEqual(db.live_drafts(connection), [])

    def test_the_migration_downgrades_and_upgrades_cleanly_on_an_empty_queue(self) -> None:
        migration_path = (
            Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0026_cert_delete.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0026", migration_path)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {migration_path}")
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        with self.connect("HAPROXY_UI_TEST_MIGRATION_ROLE") as connection:
            with connection.cursor() as cursor:
                migration.op = _Executes(cursor)
                migration.downgrade()
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertNotIn("cert_delete", cursor.fetchone()[0])
                migration.upgrade()
                cursor.execute(
                    "select pg_get_constraintdef(oid) from pg_constraint "
                    "where conname = 'job_operation_allowed'"
                )
                self.assertIn("cert_delete", cursor.fetchone()[0])
            connection.rollback()


@unittest.skipUnless(DSN, "run through ui/tools/test-database")
class NdesDatabase(unittest.TestCase):
    def connect(self, role_variable: str = "HAPROXY_UI_TEST_MIGRATION_ROLE") -> psycopg.Connection:
        return psycopg.connect(f"{DSN} user={os.environ[role_variable]}")

    def setUp(self) -> None:
        with self.connect() as connection, connection.cursor() as cursor:
            cursor.execute("delete from job")
            cursor.execute("delete from ndes_provider_profile")
            connection.commit()

    def create(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            db.create_ndes_profile(
                connection,
                profile_id="internal-ca",
                name="internal-ca",
                provider_id="ndes",
                key_id="0123456789abcdef",
                ciphertext=b"x" * 48,
                actor="admin",
                endpoint="https://ca.example.com/certsrv/mscep/mscep.dll",
            )
            connection.commit()

    def test_web_can_write_list_and_replace_but_cannot_read_ciphertext(self) -> None:
        self.create()
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            listed = db.ndes_profiles(connection)[0]
            self.assertEqual(listed.id, "internal-ca")
            self.assertEqual(listed.endpoint, "https://ca.example.com/certsrv/mscep/mscep.dll")
            self.assertIsNotNone(db.ndes_profile(connection, "internal-ca"))
            replaced = db.replace_ndes_profile(
                connection,
                profile_id="internal-ca",
                revision=2,
                key_id="0123456789abcdef",
                ciphertext=b"y" * 48,
                actor="admin",
                endpoint="https://ca2.example.com/certsrv/mscep/mscep.dll",
            )
            self.assertEqual(replaced.revision, 2)
            self.assertEqual(replaced.endpoint, "https://ca2.example.com/certsrv/mscep/mscep.dll")
            connection.commit()
            with self.assertRaises(db.ProfileMissing):
                db.replace_ndes_profile(
                    connection,
                    profile_id="internal-ca",
                    revision=2,
                    key_id="0123456789abcdef",
                    ciphertext=b"z" * 48,
                    actor="admin",
                    endpoint="https://ca.example.com/certsrv/mscep/mscep.dll",
                )
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.CheckViolation),
            ):
                cursor.execute("update ndes_provider_profile set endpoint = 'http://plain'")
            connection.rollback()
            for sql in (
                "select ciphertext from ndes_provider_profile",
                "delete from ndes_provider_profile",
                "update ndes_provider_profile set provider_id = 'cloudflare'",
            ):
                with (
                    connection.cursor() as cursor,
                    self.assertRaises(psycopg.errors.InsufficientPrivilege),
                ):
                    cursor.execute(sql)
                connection.rollback()

    def test_worker_reads_only_sealed_binding_and_poller_has_no_access(self) -> None:
        self.create()
        with self.connect("HAPROXY_UI_TEST_WORKER_ROLE") as connection:
            row = db.sealed_ndes_profile(connection, "internal-ca")
            self.assertIsNotNone(row)
            self.assertEqual(row.ciphertext if row else None, b"x" * 48)
            # The removal job's last step: exactly the fenced row, nothing else.
            self.assertFalse(db.delete_ndes_profile(connection, "internal-ca", 7))
            self.assertTrue(db.delete_ndes_profile(connection, "internal-ca", 1))
            connection.rollback()
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select created_by from ndes_provider_profile")
            connection.rollback()
        with self.connect("HAPROXY_UI_TEST_POLLER_ROLE") as connection:
            with (
                connection.cursor() as cursor,
                self.assertRaises(psycopg.errors.InsufficientPrivilege),
            ):
                cursor.execute("select id from ndes_provider_profile")
            connection.rollback()

    def test_ndes_apply_uses_the_shared_certificate_slot(self) -> None:
        with self.connect("HAPROXY_UI_TEST_WEB_ROLE") as connection:
            job = db.queue_job(
                connection,
                operation="ndes_profile_apply",
                cluster=None,
                payload={"profile": "internal-ca", "revision": 1},
                idempotency_key=uuid4(),
            )
            self.assertIsNone(job.cluster)
            with self.assertRaises(db.CertificateBusy):
                db.queue_job(
                    connection,
                    operation="cert_publish",
                    cluster=None,
                    payload={},
                    idempotency_key=uuid4(),
                )
            connection.rollback()
