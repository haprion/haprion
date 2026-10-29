"""What needs doing, on the dashboard and for a monitor (B274)."""

from __future__ import annotations

import json
import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haprion import address_ranges

from haprion_ui import attention, auth, dashboard, db, health, jobs, operations
from haprion_ui.db import StatusAccess
from tests.test_job_page import job
from tests.test_login import LoginTestCase, configuration

NOW = datetime(2026, 10, 11, 18, 40, 2, tzinfo=UTC)


def cluster(name: str = "alpha", **fields: Any) -> Any:
    values: dict[str, Any] = {
        "cluster": name,
        "configured": True,
        "stale": False,
        "behind": False,
        "age_label": "15 s ago",
        "observed_at": NOW - timedelta(seconds=15),
        "nodes": (),
        "label": "Healthy",
        "tone": "healthy",
        "detail": "",
    }
    values.update(fields)
    return SimpleNamespace(**values)


def node(
    name: str,
    tone: str,
    label: str = "Down",
    detail: str = "",
    *,
    prepare_pending: bool = False,
    package_message: str | None = None,
) -> Any:
    return SimpleNamespace(
        name=name,
        tone=tone,
        label=label,
        detail=detail,
        prepare_pending=prepare_pending,
        package_message=package_message,
    )


class EachKindComesAndGoes(unittest.TestCase):
    def test_a_failed_job_stands_until_the_same_operation_works(self) -> None:
        failed = job(state="failed", outcome="failed", operation="deploy")
        failed = replace(failed, id=1, created_at=NOW - timedelta(hours=2))
        other = replace(
            job(state="done", outcome="done", operation="cert_deploy"),
            id=2,
            created_at=NOW - timedelta(hours=1),
        )
        fixed = replace(
            job(state="done", outcome="done", operation="deploy"),
            id=3,
            created_at=NOW - timedelta(minutes=5),
        )

        self.assertEqual([item.subject for item in attention.from_jobs([failed, other])], ["job 1"])
        self.assertEqual(attention.from_jobs([failed, other, fixed]), [])

    def test_a_certificate_that_works_does_not_end_another_s_failure(self) -> None:
        """Review 26-10-24, 02-02: issuing Y hid that issuing X had failed."""

        def issue(job_id: int, domain: str, state: str, minutes: int) -> Any:
            row = job(state=state, outcome=state, operation="cert_issue", cluster=None)
            return replace(
                row,
                id=job_id,
                payload={"domain": domain},
                created_at=NOW - timedelta(minutes=minutes),
            )

        failed_x = issue(1, "x.example.com", "failed", 30)
        done_y = issue(2, "y.example.com", "done", 20)
        self.assertEqual(
            [item.subject for item in attention.from_jobs([failed_x, done_y])], ["job 1"]
        )
        done_x = issue(3, "x.example.com", "done", 10)
        self.assertEqual(attention.from_jobs([failed_x, done_y, done_x]), [])

    def test_a_certificate_that_was_issued_and_not_distributed_says_so(self) -> None:
        """Review 26-10-29, O02: it read *Certificate issue failed* until a second issue."""

        def ended(job_id: int, operation: str, minutes: int, **fields: Any) -> Any:
            row = job(state=fields.pop("state", "done"), operation=operation, cluster=None)
            return replace(
                row,
                id=job_id,
                outcome=row.state,
                created_at=NOW - timedelta(minutes=minutes),
                **fields,
            )

        def distribution(deployed: dict[str, int], failed: bool = False) -> dict[str, Any]:
            return {
                "certificates": [
                    {"id": "example.com", "status": "failed" if failed else "published"}
                ],
                "changed_clusters": list(deployed),
                "deployments": [
                    {"cluster": name, "exit_code": code} for name, code in deployed.items()
                ],
            }

        for operation, payload, body in (
            ("cert_issue", {"domain": "example.com"}, {"id": "example.com"}),
            ("cert_import", {"id": "example.com"}, {"certificate": "example.com"}),
        ):
            with self.subTest(operation):

                def undistributed(
                    operation: str = operation,
                    payload: dict[str, Any] = payload,
                    body: dict[str, Any] = body,
                    **publish: Any,
                ) -> Any:
                    return ended(
                        1,
                        operation,
                        30,
                        state="failed",
                        payload=payload,
                        result={
                            "outcome": "failed",
                            "result": {**body, "publish": distribution(**publish)},
                            "error": {"code": "publish_failed", "message": "not deployed: alpha"},
                        },
                    )

                failed = undistributed(deployed={"alpha": 1})
                verb = "issued" if operation == "cert_issue" else "imported"
                [item] = attention.from_jobs([failed])
                self.assertEqual(item.message, f"Certificate {verb}; distribution failed")
                self.assertEqual(jobs.failure_label(failed), item.message)
                self.assertIn("Certificates", jobs.build_job_overview([failed]).jobs[0].note or "")

                published = ended(2, "cert_publish", 20, payload={"certificates": ["example.com"]})
                self.assertEqual(attention.from_jobs([failed, published]), [])
                deployed = replace(
                    ended(3, "cert_deploy", 20, payload={"allow_vip_unknown": False}),
                    cluster="alpha",
                )
                self.assertEqual(attention.from_jobs([failed, deployed]), [])
                elsewhere = replace(deployed, cluster="beta")
                self.assertEqual(len(attention.from_jobs([failed, elsewhere])), 1)

                # A file not written is not mended by a rollout of the cluster.
                unwritten = undistributed(deployed={}, failed=True)
                self.assertEqual(len(attention.from_jobs([unwritten, deployed])), 1)
                self.assertEqual(attention.from_jobs([unwritten, published]), [])

                # Published again before it: still the job to open.
                earlier = replace(published, created_at=NOW - timedelta(minutes=40))
                self.assertEqual(len(attention.from_jobs([failed, earlier])), 1)

    def test_a_server_state_on_one_object_does_not_end_another_s_failure(self) -> None:
        def state(job_id: int, name: str, outcome: str, minutes: int) -> Any:
            row = job(state=outcome, outcome=outcome, operation="server_state")
            return replace(
                row,
                id=job_id,
                payload={"object": name, "servers": ["s1"], "state": "drain"},
                created_at=NOW - timedelta(minutes=minutes),
            )

        failed = state(1, "web", "failed", 30)
        other = state(2, "api", "done", 20)
        self.assertEqual([item.subject for item in attention.from_jobs([failed, other])], ["job 1"])
        self.assertEqual(attention.from_jobs([failed, other, state(3, "web", "done", 10)]), [])

    def test_a_list_of_certificates_is_settled_one_certificate_at_a_time(self) -> None:
        """Review 26-10-25, 2-02: a, b, c with c refused was never settled by c alone."""

        def delete(job_id: int, names: list[str], state: str, minutes: int, **body: Any) -> Any:
            row = job(state=state, outcome=state, operation="cert_delete", cluster=None)
            return replace(
                row,
                id=job_id,
                payload={"certificates": names},
                result={"outcome": state, "result": body} if body else None,
                created_at=NOW - timedelta(minutes=minutes),
            )

        refused_c = delete(1, ["a", "b", "c"], "partial", 30, refused=["c"])
        self.assertEqual([item.subject for item in attention.from_jobs([refused_c])], ["job 1"])
        done_c = delete(2, ["c"], "done", 20)
        self.assertEqual(attention.from_jobs([refused_c, done_c]), [])

        # An answer that names no certificate leaves the whole list as it ended.
        failed = delete(3, ["d", "e"], "failed", 15)
        done_d = delete(4, ["d"], "done", 10)
        self.assertEqual(
            [item.subject for item in attention.from_jobs([failed, done_d])], ["job 3"]
        )

    def test_one_profile_that_applies_does_not_end_another_s_failure(self) -> None:
        def apply(job_id: int, profile: str, state: str, minutes: int) -> Any:
            row = job(state=state, outcome=state, operation="dns_profile_apply", cluster=None)
            return replace(
                row,
                id=job_id,
                payload={"profile": profile, "revision": 1},
                created_at=NOW - timedelta(minutes=minutes),
            )

        rows = [apply(1, "p-a", "failed", 30), apply(2, "p-b", "done", 20)]

        self.assertEqual([item.subject for item in attention.from_jobs(rows)], ["job 1"])

    def test_only_operations_the_queue_takes_name_a_subject(self) -> None:
        self.assertLessEqual(set(jobs.SUBJECT_FIELDS), operations.OPERATIONS)

    def test_a_running_job_does_not_settle_anything(self) -> None:
        failed = replace(job(state="failed", outcome="failed"), id=1, created_at=NOW)
        running = replace(job(state="running"), id=2, created_at=NOW + timedelta(minutes=1))

        self.assertEqual(len(attention.from_jobs([failed, running])), 1)

    def test_a_wait_is_a_warning_and_a_discarded_job_is_not_listed(self) -> None:
        """Review 26-10-24, 02-08: both were a critical '... failed'."""

        for operation, code, message in (
            ("cert_scep", "request_pending", "Certificate enrollment waits for the CA"),
            (
                "cert_publish",
                "source_missing",
                "Certificate distribution waits for imported material",
            ),
        ):
            with self.subTest(code=code):
                result = {"warnings": [{"code": code, "message": "m"}]}
                waiting = job(
                    state="partial", outcome="partial", result=result, operation=operation
                )
                [item] = attention.from_jobs([replace(waiting, cluster=None)])
                self.assertEqual((item.severity, item.message), ("warning", message))
        mixed = {"warnings": [{"code": "source_missing"}, {"code": "write_failed"}]}
        partial = job(state="partial", outcome="partial", result=mixed, operation="cert_publish")
        self.assertEqual(attention.from_jobs([partial])[0].severity, "critical")

        failed = replace(job(state="failed", outcome="failed"), id=1, created_at=NOW)
        discarded = replace(
            job(state="blocked", outcome="blocked", result={"error": {"code": "held_discarded"}}),
            id=2,
            created_at=NOW + timedelta(minutes=1),
        )
        self.assertEqual(attention.from_jobs([discarded]), [])
        self.assertEqual(
            [item.subject for item in attention.from_jobs([failed, discarded])], ["job 1"]
        )
        self.assertEqual(jobs.last_failure([discarded]), {})
        self.assertEqual(jobs.last_failure([discarded, failed])["alpha"].label, "Deploy failed")

    def test_a_down_node_and_a_stale_reading_are_listed_and_a_drain_is_not(self) -> None:
        items = attention.from_dashboard(
            [
                cluster("alpha", nodes=(node("node-a", "critical"), node("node-b", "healthy"))),
                cluster("beta", stale=True, age_label="9 min ago"),
            ],
            drift_label="Behind",
        )

        self.assertEqual(
            [(item.kind, item.subject, item.link) for item in items],
            [("node", "node-a", "/#cluster-alpha"), ("reading", "beta", "/#cluster-beta")],
        )

    def test_a_node_whose_step_four_changed_is_its_own_row(self) -> None:
        """B363: a node upgraded unattended said nothing anywhere a person looks."""

        items = attention.from_dashboard(
            [
                cluster(
                    "alpha",
                    nodes=(
                        node("node-a", "healthy", "Online", prepare_pending=True),
                        node("node-b", "critical", prepare_pending=True),
                    ),
                )
            ],
            drift_label="Behind",
        )
        self.assertEqual(
            [(item.kind, item.subject, item.severity) for item in items],
            [
                ("preparation", "node-a", "warning"),
                ("preparation", "node-b", "warning"),
                ("node", "node-b", "critical"),
            ],
        )
        self.assertIn("sudo haprion-node-prepare", items[0].message)
        self.assertEqual(items[0].link, "/#cluster-alpha")
        self.assertNotEqual(items[1].key, items[2].key)

    def test_a_node_on_another_node_package_than_the_managers_is_its_own_row(self) -> None:
        """26-10-29: which nodes an upgrade round has not reached yet."""

        said = "haprion-node 0.99.5 (49d2aeb2) is installed; the manager's is 0.99.6 (0123abcd)"
        items = attention.from_dashboard(
            [
                cluster(
                    "alpha",
                    nodes=(
                        node("node-a", "healthy", "Online"),
                        node("node-b", "healthy", "Online", package_message=said),
                    ),
                )
            ],
            drift_label="Behind",
        )
        self.assertEqual(
            [(item.kind, item.subject, item.severity, item.message) for item in items],
            [("node_package", "node-b", "warning", said)],
        )
        self.assertEqual(items[0].link, "/#cluster-alpha")
        self.assertEqual(items[0].page, "Dashboard")

    def test_a_node_waiting_for_its_deploy_is_not_listed(self) -> None:
        items = attention.from_dashboard(
            [
                cluster(
                    behind=True,
                    nodes=(
                        node("node-a", "warning", "Behind"),
                        node("node-b", "warning", "Behind"),
                    ),
                )
            ],
            drift_label="Behind",
        )

        self.assertEqual(items, [])

    def test_a_certificate_running_out_is_listed_once(self) -> None:
        row = SimpleNamespace(
            identifier="shop.example.com",
            tone="critical",
            state_tone="healthy",
            expiry_label="4 days left",
            state_label="On all 2 nodes",
            interface=False,
            placeholder=False,
        )
        registry = SimpleNamespace(certificates=(row,), interface=None, served=None)

        items = attention.from_certificates(registry, ())

        self.assertEqual(
            [(item.subject, item.message) for item in items], [("shop.example.com", "4 days left")]
        )

    def test_the_interface_certificate_counts_only_by_its_expiry(self) -> None:
        row = SimpleNamespace(
            identifier="mgr.example.com",
            tone="healthy",
            state_tone="warning",
            expiry_label="in 300 days",
            state_label="No targets",
            interface=True,
            placeholder=False,
        )
        registry = SimpleNamespace(certificates=(), interface=row, served=None)

        self.assertEqual(attention.from_certificates(registry, ()), [])

    def test_the_worst_comes_first_and_the_counts_add_up(self) -> None:
        warning = attention.Item("waf", "warning", "alpha", "shop", "x", NOW, "/waf")
        critical = attention.Item("job", "critical", "alpha", "job 1", "y", NOW, "/jobs")

        built = attention.build_attention(
            [warning, critical], status_age={"alpha": 10}, stale_after_seconds=40, now=NOW
        )

        self.assertEqual([item.kind for item in built.items], ["job", "waf"])
        self.assertEqual(built.counts(), {"critical": 1, "warning": 1})
        self.assertTrue(built.fresh)


class EveryClusterTheDashboardPaintsIsListed(unittest.TestCase):
    """Review 26-10-22, 2-1 and 8-2: the list is the installation's one alarm outward
    (`/status/attention.json`), and a VIP in split brain or a reading that failed
    was red on the card and absent from it. Built through the dashboard's own code,
    so a new red state without a row is a failing test rather than a quiet monitor.
    """

    def board(self) -> Any:
        from tests.test_dashboard import reading as status_reading

        healthy = status_reading("done-single-owner.json")

        def named(name: str, base: Any = healthy, **result: Any) -> Any:
            return replace(base, cluster=name, result={**base.result, **result})

        split = named("split", summary={**healthy.result["summary"], "vip_state": "split_brain"})
        orphaned = named("orphaned", summary={**healthy.result["summary"], "vip_state": "no_owner"})
        # As the poller writes a failed collection: no result, the error beside it.
        failed = replace(healthy, cluster="failed", result={}, poll_error="sudo refused")
        empty = named("empty", nodes=[])
        down = replace(status_reading("partial-unreachable.json"), cluster="down")
        readings = (named("fine"), split, orphaned, failed, empty, down)
        return dashboard.build_dashboard(
            [reading.cluster for reading in readings],
            readings,
            now=status_reading("done-single-owner.json").observed_at,
            stale_after=timedelta(seconds=120),
        )

    def test_every_red_or_amber_cluster_has_a_row(self) -> None:
        board = self.board()
        items = attention.from_dashboard(
            board.clusters,
            drift_label=dashboard.VERSION_DRIFT,
            cluster_faults=dashboard.CLUSTER_FAULTS,
        )
        listed = {item.cluster for item in items}
        painted = {
            view.cluster
            for view in board.clusters
            if view.tone in ("critical", "warning") and not view.behind
        }

        self.assertEqual(
            painted,
            {"split", "orphaned", "failed", "empty", "down"},
            [v.label for v in board.clusters],
        )
        self.assertEqual(painted - listed, set())
        faults = {item.cluster: item.message for item in items if item.kind == "cluster"}
        self.assertTrue(faults["split"].startswith("VIP fault"))
        self.assertTrue(faults["failed"].startswith("Collection unavailable"))

    def test_the_nodes_card_counts_a_cluster_it_cannot_read(self) -> None:
        board = self.board()

        self.assertEqual(board.unread_clusters, 2)
        self.assertEqual(board.node_tone, "critical")


class TheLogsComeOnlyWhenSomebodyIsWanted(unittest.TestCase):
    """26-10-12: the log page's warning on the list, less what heals itself."""

    NOW = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)

    def freshness(self, **fields: Any) -> Any:
        from haprion_ui.traffic_logs import Freshness

        base: dict[str, Any] = {
            "cluster": "alpha",
            "node": "node-a",
            "last_attempt": self.NOW,
            "last_success": self.NOW,
            "outcome": "ok",
        }
        return Freshness(**{**base, **fields})

    def messages(self, *nodes: Any) -> list[str]:
        return [item.message for item in attention.from_traffic_logs(nodes, now=self.NOW)]

    def test_a_current_node_and_a_burst_being_caught_up_are_not_listed(self) -> None:
        self.assertEqual(
            self.messages(
                self.freshness(),
                self.freshness(node="node-b", current_complete=False, behind_runs=2),
            ),
            [],
        )

    def test_what_wants_somebody_is_listed(self) -> None:
        old = self.NOW - timedelta(minutes=12)
        self.assertEqual(
            self.messages(
                self.freshness(outcome="unreachable", last_success=old),
                self.freshness(node="node-b", last_attempt=None, last_success=None),
                self.freshness(node="node-c", last_attempt=old, last_success=old),
                self.freshness(node="node-d", current_complete=False, behind_runs=5),
                self.freshness(node="node-e", pending_days=2),
                self.freshness(node="node-f", outcome="budget", last_success=old),
            ),
            [
                "log collection failed (unreachable)",
                "log collection has never reached the node",
                "log collection last succeeded 12 min ago",
                "log collection behind for 5 runs",
                "log collection behind · 2 older days waiting",
                "log collection paused: the manager's copy is over its space budget",
            ],
        )

    def test_a_node_being_joined_is_not_listed_until_the_join_has_had_its_time(self) -> None:
        from haprion_ui.traffic_logs import JOINING_SECONDS

        joining = {"outcome": "ssh", "last_success": None}
        self.assertEqual(
            self.messages(
                self.freshness(**joining, first_attempt=self.NOW - timedelta(seconds=30)),
            ),
            [],
        )
        self.assertEqual(
            self.messages(
                self.freshness(
                    **joining, first_attempt=self.NOW - timedelta(seconds=JOINING_SECONDS)
                ),
            ),
            ["log collection failed (ssh)"],
        )

    def test_a_receiver_that_dropped_lines_is_critical(self) -> None:
        row = SimpleNamespace(
            cluster="alpha",
            result={
                "nodes": [
                    {
                        "name": "node-a",
                        "status_ok": True,
                        "status": {
                            "log_forwarding": {
                                "stats_age_sec": 40,
                                "receivers": [
                                    {"name": "graylog", "queued": 12, "dropped_last_hour": 0},
                                    {"name": "loki", "queued": 20000, "dropped_last_hour": 7},
                                ],
                            }
                        },
                    },
                    {"name": "node-b", "status_ok": True, "status": {"log_forwarding": None}},
                ]
            },
        )

        items = attention.from_log_forwarding([row], now=self.NOW)

        self.assertEqual(
            [(item.severity, item.subject, item.message) for item in items],
            [
                ("critical", "node-a", "traffic log to loki: 7 lines dropped in the last hour"),
                ("warning", "node-a", "traffic log to loki: 20 000 lines queued"),
            ],
        )


class AQueueThatIsNotEmptied(unittest.TestCase):
    """26-10-12: on a quiet cluster a receiver out of reach is a few lines that never leave."""

    NOW = datetime(2026, 10, 12, 10, 30, tzinfo=UTC)

    def reading(
        self, queued: int, since: datetime | None, reason: str = "", before: int | None = None
    ) -> Any:
        from haprion_ui.db import _with_forward_waiting

        receiver: dict[str, Any] = {"name": "graylog", "queued": queued, "dropped_last_hour": 0}
        if reason:
            receiver["last_error"] = {"reason": reason, "age_sec": 30}
        node = {
            "name": "node-a",
            "status_ok": True,
            "status": {"log_forwarding": {"stats_age_sec": 20, "receivers": [receiver]}},
        }
        previous: Any = None
        if since is not None:
            earlier: dict[str, Any] = {
                "name": "node-a",
                "forward_waiting_since": {"graylog": since.isoformat()},
            }
            if before is not None:
                earlier["status"] = {
                    "log_forwarding": {
                        "receivers": [{"name": "graylog", "queued": before, "dropped_last_hour": 0}]
                    }
                }
            previous = {"nodes": [earlier]}
        return _with_forward_waiting({"nodes": [node]}, previous, self.NOW)

    def items(self, result: Any) -> list[Any]:
        row = SimpleNamespace(cluster="external", result=result)
        return attention.from_log_forwarding([row], now=self.NOW)

    def test_the_poller_carries_when_the_queue_last_was_empty(self) -> None:
        first = self.reading(3, None)
        self.assertEqual(
            first["nodes"][0]["forward_waiting_since"], {"graylog": self.NOW.isoformat()}
        )
        earlier = self.NOW - timedelta(minutes=7)
        self.assertEqual(
            self.reading(3, earlier)["nodes"][0]["forward_waiting_since"],
            {"graylog": earlier.isoformat()},
        )
        self.assertEqual(self.reading(0, earlier)["nodes"][0]["forward_waiting_since"], {})

    def test_a_queue_that_shrank_is_a_receiver_reached(self) -> None:
        """A far receiver always has lines on their way (review 26-10-12 F3)."""

        earlier = self.NOW - timedelta(minutes=7)

        def since(queued: int, before: int) -> Any:
            return self.reading(queued, earlier, before=before)["nodes"][0]["forward_waiting_since"]

        self.assertEqual(since(3, 5), {"graylog": self.NOW.isoformat()})
        self.assertEqual(since(3, 3), {"graylog": earlier.isoformat()})
        self.assertEqual(since(4, 3), {"graylog": earlier.isoformat()})

    def test_three_minutes_without_emptying_is_listed(self) -> None:
        self.assertEqual(self.items(self.reading(3, self.NOW - timedelta(minutes=2))), [])
        listed = self.items(self.reading(3, self.NOW - timedelta(minutes=7)))
        self.assertEqual(
            [(item.severity, item.subject, item.message) for item in listed],
            [("warning", "node-a", "traffic log to graylog: 3 lines not delivered")],
        )
        self.assertEqual(listed[0].since, self.NOW - timedelta(minutes=7))

    def test_the_row_says_why_and_leads_to_the_clusters_receivers(self) -> None:
        listed = self.items(
            self.reading(3, self.NOW - timedelta(minutes=7), reason="Connection timed out")
        )
        self.assertEqual(
            [(item.message, item.link) for item in listed],
            [
                (
                    "traffic log to graylog: 3 lines not delivered (Connection timed out)",
                    "/settings/clusters/external#delivery",
                )
            ],
        )

    def test_a_long_queue_is_said_once(self) -> None:
        listed = self.items(self.reading(20000, self.NOW - timedelta(minutes=30)))
        self.assertEqual(
            [item.message for item in listed], ["traffic log to graylog: 20 000 lines queued"]
        )


class EveryKindHasALabel(unittest.TestCase):
    def test_every_kind_names_the_page_its_row_goes_to(self) -> None:
        #
        # One list since 26-10-12: the template read its own copy, and a kind
        # missing there would have failed the dashboard.
        #
        self.assertEqual(set(attention.PAGES), set(attention.KINDS))
        self.assertTrue(all(attention.PAGES.values()))
        for kind in attention.KINDS:
            item = attention.Item(kind, "warning", "alpha", "x", "y", None, "/")
            self.assertEqual(item.page, attention.PAGES[kind])


class AServiceThatIsNotServed(unittest.TestCase):
    """An object's *Proxies* lamp, lifted to the list (26-10-12)."""

    def lamp(self, tone: str, label: str, detail: str) -> Any:
        return health.ObjectHealth(tone, label, detail, 0, 2)

    def test_red_and_amber_are_listed_and_lead_to_the_servers(self) -> None:
        items = attention.from_services(
            {
                "alpha": {
                    "shop": self.lamp("critical", "0/2 up", "No servers reachable"),
                    "api": self.lamp("warning", "1/2 up", "1 of 2 servers not up everywhere"),
                    "web": self.lamp("healthy", "2/2 up", "Every server is up"),
                }
            },
            held_label=health.HELD_LABEL,
        )

        self.assertEqual(
            [(item.kind, item.severity, item.subject, item.message, item.link) for item in items],
            [
                (
                    "service",
                    "warning",
                    "api",
                    "1/2 up · 1 of 2 servers not up everywhere",
                    "/proxies/alpha/api#servers",
                ),
                (
                    "service",
                    "critical",
                    "shop",
                    "0/2 up · No servers reachable",
                    "/proxies/alpha/shop#servers",
                ),
            ],
        )

    def test_a_choice_and_what_nobody_checks_are_not_listed(self) -> None:
        items = attention.from_services(
            {
                "alpha": {
                    "held": self.lamp(
                        "warning", health.HELD_LABEL, "Every server is drained or in maintenance"
                    ),
                    "unchecked": self.lamp("unknown", "", "This proxy defines no health check"),
                }
            },
            held_label=health.HELD_LABEL,
        )

        self.assertEqual(items, [])

    def test_the_lamp_and_the_list_agree_on_a_reading(self) -> None:
        reading = SimpleNamespace(
            cluster="alpha",
            observed_at=NOW,
            result={
                "nodes": [
                    {
                        "name": "node-a",
                        "status": {
                            "servers": [
                                {"backend": "shop", "server": "s1", "status": "DOWN"},
                                {"backend": "shop", "server": "s2", "status": "DOWN"},
                                {"backend": "web", "server": "s1", "status": "UP"},
                            ]
                        },
                    }
                ]
            },
        )
        lamps = health.object_healths(
            [reading],
            cluster="alpha",
            objects={"shop": (True, False), "web": (True, False)},
            owners={"shop": "shop", "web": "web"},
        )

        items = attention.from_services({"alpha": lamps}, held_label=health.HELD_LABEL)

        self.assertEqual([(item.subject, item.severity) for item in items], [("shop", "critical")])


class TheTwoForms(unittest.TestCase):
    def built(self, ages: dict[str, int | None]) -> attention.Attention:
        item = attention.Item("job", "critical", "alpha", "job 1", "Deploy failed", NOW, "/jobs")
        return attention.build_attention([item], status_age=ages, stale_after_seconds=40, now=NOW)

    def test_the_json_names_what_a_monitor_asks(self) -> None:
        document = json.loads(self.built({"alpha": 10}).as_json())

        self.assertEqual(document["counts"], {"critical": 1, "warning": 0})
        self.assertTrue(document["fresh"])
        self.assertEqual(document["generated_at"], "2026-10-11T18:40:02Z")
        self.assertEqual(document["items"][0]["kind"], "job")

    def test_a_reading_that_stopped_is_not_fresh(self) -> None:
        self.assertFalse(self.built({"alpha": 300}).fresh)
        self.assertFalse(self.built({"alpha": None}).fresh)

    def test_no_cluster_is_fresh_while_the_cluster_list_is_read(self) -> None:
        # A new installation is not down until its first cluster (26-10-24);
        # a poller that stopped reading even the list still is.
        item = attention.Item("job", "critical", None, "job 1", "Deploy failed", NOW, "/jobs")

        def built(list_age: int | None) -> bool:
            return attention.build_attention(
                [item], status_age={}, stale_after_seconds=40, list_age=list_age, now=NOW
            ).fresh

        self.assertTrue(built(10))
        self.assertFalse(built(300))
        self.assertFalse(built(None))

    def test_the_metrics_carry_every_kind_and_each_clusters_age(self) -> None:
        text = self.built({"alpha": 10}).as_metrics()

        self.assertIn('haprion_attention_items{kind="job",severity="critical"} 1', text)
        self.assertIn('haprion_attention_items{kind="certificate",severity="warning"} 0', text)
        self.assertIn('haprion_status_age_seconds{cluster="alpha"} 10', text)


class TheAccessList(unittest.TestCase):
    def test_addresses_and_networks_one_per_line(self) -> None:
        self.assertEqual(
            attention.access_list("192.0.2.10\n198.51.100.0/24\n\n192.0.2.10\n"),
            ("192.0.2.10/32", "198.51.100.0/24"),
        )

    def test_a_network_with_host_bits_is_a_typo(self) -> None:
        # Refused in the engine's words, as every list of ranges (review 26-10-24, 15-06).
        with self.assertRaisesRegex(ValueError, re.escape(address_ranges.HOST_BITS)):
            attention.access_list("192.0.2.1/24")
        with self.assertRaises(ValueError):
            attention.access_list("monitor.example.com")


class TheEndpoint(LoginTestCase):
    def ask(self, path: str, *, allowed: list[StatusAccess], address: str) -> Any:
        client = self.client()
        with mock.patch("haprion_ui.db.status_access", return_value=allowed):
            return client.get(path, headers={"X-Forwarded-For": address})

    def test_nobody_may_ask_while_the_list_is_empty(self) -> None:
        response = self.ask("/status/attention.json", allowed=[], address="192.0.2.10")

        self.assertEqual(response.status_code, 404)

    def test_an_address_on_the_list_is_answered_without_a_sign_in(self) -> None:
        listed = [StatusAccess("192.0.2.0/24", "admin", NOW)]

        answer = self.ask("/status/attention.json", allowed=listed, address="192.0.2.10")
        metrics = self.ask("/status/metrics", allowed=listed, address="192.0.2.10")
        refused = self.ask("/status/metrics", allowed=listed, address="198.51.100.7")

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(json.loads(answer.text)["counts"], {"critical": 0, "warning": 0})
        self.assertEqual(metrics.status_code, 200)
        self.assertIn("haprion_attention_items", metrics.text)
        self.assertEqual(refused.status_code, 404)


class TheSettingsCard(LoginTestCase):
    def test_saving_replaces_the_list_and_refuses_a_typo(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        with mock.patch("haprion_ui.db.set_status_access") as stored:
            saved = client.post(
                "/settings/status-access",
                data={"csrf_token": token, "networks": "192.0.2.10\n"},
                follow_redirects=False,
            )
            refused = client.post(
                "/settings/status-access",
                data={"csrf_token": token, "networks": "192.0.2.1/24"},
                follow_redirects=False,
            )

        self.assertEqual(saved.status_code, 303)
        stored.assert_called_once()
        self.assertEqual(stored.call_args.kwargs["networks"], ("192.0.2.10/32",))
        self.assertEqual(refused.status_code, 400)
        self.assertIn("host bits", refused.text)
        # Refused on the edit page, with what was typed (26-10-12).
        self.assertIn("<h1>External monitoring</h1>", refused.text)
        self.assertIn(">192.0.2.1/24</textarea>", refused.text)

    def test_the_card_is_a_row_and_the_list_has_a_page_of_its_own(self) -> None:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        entry = StatusAccess(
            "192.0.2.10/32", "localadmin", datetime(2026, 10, 11, 19, 46, tzinfo=UTC)
        )
        with mock.patch("haprion_ui.db.status_access", return_value=[entry]):
            card = client.get("/settings").text.split('id="external-monitoring"', 1)[1]
            card = card.split("</section>", 1)[0]
            page = client.get("/settings/status-access").text

        self.assertIn('href="/settings/status-access">Edit</a>', card)
        self.assertIn("<code>192.0.2.10/32</code>", card)
        self.assertNotIn("<textarea", card)
        self.assertIn('<td data-label="Added by">localadmin</td>', page)
        self.assertIn(">192.0.2.10/32\n</textarea>", page)
        self.assertIn('href="/settings#external-monitoring">Cancel</a>', page)

    def test_off_is_written_as_the_logs_card_writes_it(self) -> None:
        """Review 26-10-24, 04-14 (26-10-25): text, not a pill with no colour."""

        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        with mock.patch("haprion_ui.db.status_access", return_value=[]):
            card = client.get("/settings").text.split('id="external-monitoring"', 1)[1]
        card = card.split("</section>", 1)[0]
        self.assertIn('<td data-label="Status" class="table-empty">Off</td>', card)


class TheManagersOwnServices(unittest.TestCase):
    """B333: the poller, the worker and the nightly maintenance, judged by their traces."""

    def items(self, **facts: Any) -> list[attention.Item]:
        arguments: dict[str, Any] = {
            "cluster_list_at": NOW - timedelta(seconds=20),
            "poller_silent_after": timedelta(minutes=5),
            "rows": [],
            "writes": True,
            "horizons": {
                table: NOW.date() + timedelta(days=ahead)
                for table, ahead in attention.MAINTENANCE_AHEAD.items()
            },
            "now": NOW,
        }
        arguments.update(facts)
        return attention.from_manager(**arguments)

    def test_all_three_at_work_is_nothing(self) -> None:
        self.assertEqual(self.items(), [])

    def test_a_run_that_did_not_finish_for_two_nights_is_listed(self) -> None:
        """Review 26-10-24, 05-09: the horizon was fresh, so nothing was said."""

        self.assertEqual(self.items(maintained_at=NOW - timedelta(hours=40)), [])
        late = NOW - timedelta(days=3)
        (item,) = self.items(maintained_at=late)
        self.assertEqual((item.subject, item.severity, item.since), ("retention", "warning", late))
        self.assertIn("has not finished since", item.message)
        short = {
            table: NOW.date() + timedelta(days=ahead - 3)
            for table, ahead in attention.MAINTENANCE_AHEAD.items()
        }
        (only,) = self.items(maintained_at=late, horizons=short)
        self.assertIn("has not run since", only.message)

    def test_a_poller_that_stopped_writing_is_listed(self) -> None:
        for at in (NOW - timedelta(minutes=6), None):
            with self.subTest(at=at):
                (item,) = self.items(cluster_list_at=at)
                self.assertEqual(
                    (item.kind, item.subject, item.severity), ("manager", "poller", "critical")
                )
                self.assertIn("(haprion-poller)", item.message)

    def test_a_job_waiting_ten_minutes_with_nothing_running_is_the_worker(self) -> None:
        waiting = replace(job(state="pending"), created_at=NOW - timedelta(minutes=11))
        (item,) = self.items(rows=[waiting])
        self.assertEqual((item.subject, item.link), ("worker", "/jobs"))
        self.assertIn("1 job waiting", item.message)
        #
        # Not while one runs (it holds the cluster), not for a job just queued,
        # and not with writes off - then the worker claims nothing on purpose.
        #
        self.assertEqual(self.items(rows=[waiting, job(state="running")]), [])
        self.assertEqual(
            self.items(rows=[replace(job(state="pending"), created_at=NOW - timedelta(minutes=2))]),
            [],
        )
        self.assertEqual(self.items(rows=[waiting], writes=False), [])

    def test_a_job_no_worker_holds_is_listed_and_hides_no_silent_worker(self) -> None:
        """Review 26-10-29, Q01/R01: a worker gone leaves its job `running`, which
        silenced the row about the worker and said nothing itself."""

        gone = replace(job(state="running"), id=12, lease_lapsed_since=NOW - timedelta(minutes=30))
        waiting = replace(
            job(state="pending", cluster="beta"), id=13, created_at=NOW - timedelta(hours=1)
        )
        listed = {item.subject: item for item in self.items(rows=[gone, waiting])}
        self.assertEqual(sorted(listed), ["job 12", "worker"])
        item = listed["job 12"]
        self.assertEqual(
            (item.kind, item.severity, item.cluster, item.link, item.since),
            ("manager", "critical", "alpha", "/jobs#job-12", gone.lease_lapsed_since),
        )
        self.assertEqual(item.message, "running, but no worker has held it since")
        # Its row goes to Events, not to the Dashboard its kind names (rig 26-10-29).
        self.assertEqual((item.page, listed["worker"].page), ("Events", "Events"))
        #
        # A lease just run out is a worker restarting or a helper finishing
        # behind its socket; a living lease still holds the worker's row back.
        #
        recent = replace(gone, lease_lapsed_since=NOW - timedelta(minutes=2))
        self.assertEqual(self.items(rows=[recent]), [])
        self.assertEqual(self.items(rows=[job(state="running"), waiting]), [])
        #
        # A held one is the held row's, and waits for an admin.
        #
        held = replace(gone, held_since=NOW - timedelta(minutes=40))
        (only,) = self.items(rows=[held])
        self.assertEqual(only.subject, "held jobs")

    def test_jobs_a_release_holds_are_not_the_worker_s_silence(self) -> None:
        """Review 26-10-29, Q06: the claims are paused, and the worker does as it should."""

        waiting = replace(job(state="pending"), created_at=NOW - timedelta(minutes=11))
        pause = db.ClaimPause(until=NOW + timedelta(minutes=5), by="release on mgr")
        self.assertEqual(self.items(rows=[waiting], claim_pause=pause), [])
        (item,) = self.items(rows=[waiting], claim_pause=None)
        self.assertEqual(item.subject, "worker")

    def test_a_held_job_waits_for_an_admin_not_for_the_worker(self) -> None:
        """0082: a job queued before the boot is its own row, never the worker's silence."""

        held = replace(
            job(state="pending"),
            created_at=NOW - timedelta(hours=3),
            held_since=NOW - timedelta(minutes=30),
        )
        (item,) = self.items(rows=[held])
        self.assertEqual(
            (item.subject, item.severity, item.link), ("held jobs", "warning", "/jobs")
        )
        #
        # Held after a restart or a restore (review 26-10-29, R04): a restored
        # database's jobs are held without any start.
        #
        self.assertEqual(
            item.message, "1 job held after a restart or a restore waits for Run or Discard"
        )
        #
        # Answered, it is the worker's again.
        #
        answered = replace(held, held_decision="run", held_decided_by="admin")
        (item,) = self.items(rows=[answered])
        self.assertEqual(item.subject, "worker")

    def test_a_partition_horizon_a_day_short_is_the_maintenance_not_run(self) -> None:
        ahead = attention.MAINTENANCE_AHEAD
        metric = NOW.date() + timedelta(days=ahead["metric_frontend"])
        short = {
            "traffic_log": NOW.date() + timedelta(days=ahead["traffic_log"] - 2),
            "metric_frontend": metric,
        }
        (item,) = self.items(horizons=short)
        self.assertEqual((item.subject, item.severity), ("retention", "warning"))
        self.assertIn(f"since {NOW.date() - timedelta(days=2)}", item.message)
        #
        # The night's run not yet made today is not late.
        #
        on_time = {
            "traffic_log": NOW.date() + timedelta(days=ahead["traffic_log"] - 1),
            "metric_frontend": metric,
        }
        self.assertEqual(self.items(horizons=on_time), [])

    def test_a_table_with_no_partition_is_the_maintenance_never_run(self) -> None:
        """Review 26-10-22, 3-2: the metric tables have none until the first run, every
        sample is refused, and the check compared a date it did not have."""

        horizons = {"traffic_log": NOW.date() + timedelta(days=31), "metric_frontend": None}
        (item,) = self.items(horizons=horizons)
        self.assertEqual((item.subject, item.severity), ("retention", "critical"))
        self.assertIn("never run", item.message)

    def test_the_days_ahead_are_the_maintenance_script_s(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "install/platform/bin/haprion-retention"
        ).read_text()
        self.assertIn(f"TRAFFIC_AHEAD_DAYS={attention.MAINTENANCE_AHEAD['traffic_log']}\n", script)
        self.assertIn(
            f"METRIC_AHEAD_DAYS={attention.MAINTENANCE_AHEAD['metric_frontend']}\n", script
        )
        self.assertIn("metric_frontend", script)


class TheDashboardBox(LoginTestCase):
    def test_it_is_drawn_only_when_something_needs_doing(self) -> None:
        item = attention.Item(
            "job", "critical", "alpha", "job 7", "Deploy failed", NOW, "/jobs#job-7"
        )
        some = attention.build_attention([item], status_age={}, stale_after_seconds=40, now=NOW)
        none = attention.build_attention([], status_age={}, stale_after_seconds=40, now=NOW)
        client = self.client()
        self.sign_in(client)

        with mock.patch("haprion_ui.pages.dashboard.attention_items", return_value=some):
            drawn = client.get("/").text
        with mock.patch("haprion_ui.pages.dashboard.attention_items", return_value=none):
            empty = client.get("/").text

        self.assertIn("Needs attention", drawn)
        self.assertIn('<a class="attention-row" href="/jobs#job-7">', drawn)
        self.assertIn("Deploy failed", drawn)
        self.assertNotIn("Needs attention", empty)

    def test_a_node_on_an_older_node_package_says_so_in_its_row_and_in_the_box(self) -> None:
        """26-10-29: the demo's service-b, left behind by an upgrade round."""

        from haprion_ui import demo

        client = self.client(replace(configuration(), demo_fixture=True, clusters=demo.CLUSTERS))
        self.sign_in(client)
        page = client.get("/").text
        said = "haprion-node 0.99.5 (49d2aeb2) is installed; the manager&#39;s is 0.99.6 (0123abcd)"
        self.assertEqual(page.count(f'<small class="warning-text" title="{said}">'), 1)
        self.assertIn("Older node package</small>", page)
        self.assertIn(f"service-b · {said}", page)

    def test_a_settings_row_is_text_while_management_writes_are_off(self) -> None:
        """Review 26-10-24, 04-02: the link answered "Not found" in read-only mode."""

        item = attention.Item(
            "forwarding",
            "warning",
            "alpha",
            "receiver",
            "lines dropped",
            None,
            "/settings/clusters/alpha#delivery",
        )
        some = attention.build_attention([item], status_age={}, stale_after_seconds=40, now=NOW)
        for writes, linked in ((False, False), (True, True)):
            with self.subTest(writes=writes):
                client = self.client(replace(configuration(), management_writes=writes))
                self.sign_in(client)
                with mock.patch("haprion_ui.pages.dashboard.attention_items", return_value=some):
                    drawn = client.get("/").text
                self.assertIn("lines dropped", drawn)
                self.assertEqual('href="/settings/clusters/alpha#delivery"' in drawn, linked)

    def test_every_settings_link_is_one_that_needs_writes(self) -> None:
        for link, needs in (
            ("/settings", True),
            ("/settings#external-monitoring", True),
            ("/settings/clusters/alpha#delivery", True),
            ("/settingsx", False),
            ("/certificates", False),
            ("/#cluster-alpha", False),
        ):
            with self.subTest(link):
                item = attention.Item("logs", "warning", None, "x", "y", None, link)
                self.assertEqual(item.needs_writes, needs)

    def test_a_cluster_s_row_leads_to_its_card(self) -> None:
        """Review 26-10-24, 04-03: the row reloaded the top of the page it was on."""

        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        page = client.get("/").text
        self.assertIn('id="cluster-edge-demo"', page)
        self.assertEqual(attention.card_link("edge-demo"), "/#cluster-edge-demo")


class AFixWaitingInTheRepository(unittest.TestCase):
    """0088, B357: one row per package, the waiting version in the row's own name."""

    def test_each_package_is_a_warning_about_the_manager(self) -> None:
        from haprion_ui.db import PackageWaiting

        at = datetime(2026, 10, 23, 22, 0, tzinfo=UTC)
        [item] = attention.from_packages([PackageWaiting("haprion-cli", "0.99.0", "0.99.1", at)])
        self.assertEqual(
            (item.kind, item.severity, item.cluster, item.subject, item.since),
            ("manager", "warning", None, "haprion-cli 0.99.1", at),
        )
        self.assertEqual(item.message, "waits in the repository; 0.99.0 is installed")
        self.assertEqual(attention.from_packages([]), [])


class TheAcknowledgement(LoginTestCase):
    """B299: an admin leaves a row out until it has gone; a new failure is a new row."""

    FAILED = replace(
        job(state="failed", outcome="failed", operation="deploy"), id=7, created_at=NOW
    )

    def setUp(self) -> None:
        super().setUp()
        for patch in (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[self.FAILED]),
            mock.patch(
                "haprion_ui.db.status_access",
                return_value=[StatusAccess("192.0.2.0/24", "admin", NOW)],
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def counts(self) -> dict[str, int]:
        answer = self.client().get(
            "/status/attention.json", headers={"X-Forwarded-For": "192.0.2.10"}
        )
        counts: dict[str, int] = json.loads(answer.text)["counts"]
        return counts

    def signed_in(self) -> Any:
        #
        # With a cluster: a new installation's dashboard is the first cluster's
        # guide (B315), and the rows are the dashboard's.
        #
        client = self.client(
            replace(
                configuration(), management_writes=True, clusters=(self.FAILED.cluster or "alpha",)
            )
        )
        self.sign_in(client)
        return client

    def test_the_row_offers_it_and_an_acknowledged_row_is_left_out_everywhere(self) -> None:
        page = self.signed_in().get("/")
        self.assertIn('action="/attention/acknowledge"', page.text)
        self.assertIn('name="subject" value="job 7"', page.text)
        self.assertEqual(sum(self.counts().values()), 1)

        self.acks = {("job", self.FAILED.cluster or "", "job 7")}

        self.assertEqual(sum(self.counts().values()), 0)
        self.assertNotIn('value="job 7"', self.signed_in().get("/").text)

    def test_acknowledging_a_shown_row_is_stored_and_audited(self) -> None:
        client = self.signed_in()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        with mock.patch("haprion_ui.db.acknowledge_attention", return_value=True) as stored:
            answer = client.post(
                "/attention/acknowledge",
                data={
                    "csrf_token": token,
                    "kind": "job",
                    "cluster": self.FAILED.cluster or "",
                    "subject": "job 7",
                },
                follow_redirects=False,
            )
        self.assertEqual(answer.status_code, 303)
        self.assertEqual(stored.call_args.args[1], ("job", self.FAILED.cluster or "", "job 7"))
        self.assertIn("attention_acknowledged", self.audit)

    def test_a_row_the_list_does_not_show_is_acknowledged_by_nothing(self) -> None:
        client = self.signed_in()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        with mock.patch("haprion_ui.db.acknowledge_attention") as stored:
            client.post(
                "/attention/acknowledge",
                data={"csrf_token": token, "kind": "job", "cluster": "alpha", "subject": "job 99"},
                follow_redirects=False,
            )
        stored.assert_not_called()

    def test_an_acknowledgement_whose_row_has_gone_is_forgotten(self) -> None:
        kept = ("job", "alpha", "job 7")
        gone = ("node", "alpha", "node-b")
        item = attention.Item("job", "critical", "alpha", "job 7", "Deploy failed", NOW, "/jobs")

        shown, forgotten = attention.unacknowledged([item], {kept, gone})

        self.assertEqual(shown, [])
        self.assertEqual(forgotten, {gone})


if __name__ == "__main__":
    unittest.main()


class ARemovedCluster_sFailures(LoginTestCase):
    """Review 26-10-25, 4-02: no step runs on a cluster that is gone, so nothing settles them."""

    def failures_shown(self, cluster: str) -> bool:
        failed = replace(
            job(state="failed", outcome="failed", operation="deploy"),
            id=7,
            cluster=cluster,
            created_at=NOW,
        )
        with (
            mock.patch("haprion_ui.db.recent_jobs", return_value=[failed]),
            mock.patch("haprion_ui.db.attention_evidence", return_value=[failed]),
        ):
            client = self.client(
                replace(configuration(), management_writes=True, clusters=("alpha",))
            )
            self.sign_in(client)
            return "/jobs#job-7" in client.get("/").text

    def test_are_left_out_and_a_listed_cluster_s_are_not(self) -> None:
        self.assertTrue(self.failures_shown("alpha"))
        self.assertFalse(self.failures_shown("beta"))
