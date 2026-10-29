"""Dynamic blocking on the object page and the dashboard (B271).

The card lists what each node's status says its blocked table holds, a box per
address and *Unblock* for an admin on an installation that writes; the
dashboard says how many per cluster, with the objects linked where the person
may open them. The job is the engine's `dynamic_unblock`.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock
from uuid import uuid4

from haprion_ui import auth, blocked, db, demo
from haprion_ui.db import ClusterStatus
from haprion_ui.form_groups import form_groups
from tests.test_login import configuration
from tests.test_object_page import DraftReading
from tests.test_queue_route import queued

OBSERVED = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
KEY = str(uuid4())


def reading(*nodes: tuple[str, dict[str, Any] | None], cluster: str = "alpha") -> ClusterStatus:
    return ClusterStatus(
        cluster=cluster,
        observed_at=OBSERVED,
        outcome="done",
        result={
            "nodes": [
                {"name": name, "status": {} if held is None else {"blocked": held}}
                for name, held in nodes
            ]
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


def held(count: int, *addresses: tuple[str, int]) -> dict[str, Any]:
    return {
        "count": count,
        "addresses": [{"address": address, "expires_in_ms": left} for address, left in addresses],
    }


class TheCard(unittest.TestCase):
    def test_one_row_per_address_with_the_nodes_holding_it(self) -> None:
        card = blocked.object_card(
            [
                reading(
                    ("node-a", {"shop": held(2, ("192.0.2.10", 60_000), ("192.0.2.7", 1_800_000))}),
                    ("node-b", {"shop": held(1, ("192.0.2.7", 1_200_000))}),
                )
            ],
            cluster="alpha",
            name="shop",
            now=OBSERVED,
        )
        if card is None:
            self.fail("an object holding blocked addresses has a card")
        self.assertEqual(card.count, 2)
        self.assertEqual(
            [(row.address, row.nodes) for row in card.addresses],
            [("192.0.2.7", ("node-a", "node-b")), ("192.0.2.10", ("node-a",))],
        )
        self.assertEqual(card.addresses[0].until, OBSERVED + timedelta(minutes=30))

    def test_the_count_beyond_the_listed_hundred_is_kept(self) -> None:
        card = blocked.object_card(
            [reading(("node-a", {"shop": held(250, ("192.0.2.7", 1000))}))],
            cluster="alpha",
            name="shop",
            now=OBSERVED,
        )
        if card is None:
            self.fail("an object holding blocked addresses has a card")
        self.assertEqual((card.count, card.more), (250, 249))

    def test_a_block_whose_time_ran_out_is_ending_until_the_next_reading(self) -> None:
        """Faded and still counted, never dropped and brought back (26-10-10)."""

        rows = [
            reading(
                ("node-a", {"shop": held(2, ("192.0.2.7", 60_000), ("192.0.2.8", 600_000))}),
            )
        ]
        later = OBSERVED + timedelta(minutes=2)

        card = blocked.object_card(rows, cluster="alpha", name="shop", now=later)
        if card is None:
            self.fail("a block ending is still on the card")
        self.assertEqual(
            [(row.address, row.ending) for row in card.addresses],
            [("192.0.2.7", True), ("192.0.2.8", False)],
        )
        self.assertEqual(card.count, 2)
        self.assertEqual(blocked.cluster_counts(rows, cluster="alpha", now=later), {"shop": 2})
        #
        # The one ending waits for the next reading; the redraw is for the other.
        #
        self.assertEqual(blocked.next_change(rows, ("alpha",), now=later), 480.0)

    def test_the_page_is_drawn_again_a_second_after_the_first_block_ends(self) -> None:
        rows = [reading(("node-a", {"shop": held(1, ("192.0.2.7", 12_500))}))]

        change = blocked.next_change(rows, ("alpha",), now=OBSERVED)
        self.assertEqual(change, 12.5)
        self.assertEqual(blocked.live_seconds(20, change), 14)
        self.assertEqual(blocked.live_seconds(20, 300.0), 20)
        self.assertEqual(blocked.live_seconds(20, None), 20)
        self.assertEqual(blocked.live_seconds(20, -3.0), 1)

    def test_nothing_blocked_or_an_older_node_has_no_card(self) -> None:
        for nodes in (
            (("node-a", None),),
            (("node-a", {"shop": held(0)}),),
            (("node-a", {"other": held(3, ("192.0.2.7", 1000))}),),
        ):
            with self.subTest(nodes=nodes):
                self.assertIsNone(
                    blocked.object_card([reading(*nodes)], cluster="alpha", name="shop")
                )

    def test_the_cluster_counts_name_each_object_once(self) -> None:
        rows = [
            reading(
                ("node-a", {"shop": held(2), "db": held(1), "idle": held(0)}),
                ("node-b", {"shop": held(3)}),
            )
        ]
        self.assertEqual(blocked.cluster_counts(rows, cluster="alpha"), {"db": 1, "shop": 3})

    def test_time_left_reads_as_minutes_and_hours(self) -> None:
        now = OBSERVED
        for left, said in (
            (timedelta(seconds=30), "< 1 min"),
            (timedelta(minutes=27, seconds=40), "27 min"),
            (timedelta(hours=1, minutes=5), "1 h 5 min"),
            (timedelta(hours=2), "2 h"),
        ):
            with self.subTest(said):
                self.assertEqual(blocked.time_left(now + left, now), said)
        self.assertEqual(blocked.time_left(None), "—")


class TheFormSaysHowManyAreBlocked(unittest.TestCase):
    """The mock's line (B271, review 26-10-10 F2): the count after the settings."""

    def test_the_count_ends_the_group_line(self) -> None:
        form = {
            "protocol": "http",
            "block_requests": "300",
            "block_window": "10s",
            "block_for": "30m",
        }

        self.assertEqual(
            form_groups(form, 2)["blocking"].summary,
            "300 requests / 10s → blocked 30m, 404 · 2 blocked",
        )
        self.assertNotIn("blocked ·", form_groups(form)["blocking"].summary)


class TheObjectPageAndTheDashboard(DraftReading):
    def setUp(self) -> None:
        super().setUp()
        self.queued: list[dict[str, Any]] = []
        self.audited: list[dict[str, Any]] = []

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="dynamic_unblock", cluster="edge-demo")

        def audit(_c: object, **fields: Any) -> None:
            self.audited.append(fields)

        for patch in (
            mock.patch("haprion_ui.db.queue_job", side_effect=queue),
            mock.patch("haprion_ui.db.record_audit_event", side_effect=audit),
            mock.patch("haprion_ui.db.recent_jobs", return_value=[]),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def writing_client(self, *, role: str = "admin", writes: bool = True) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(
            replace(
                configuration(),
                demo_fixture=True,
                management_writes=writes,
                clusters=demo.CLUSTERS,
            )
        )
        self.sign_in(client)
        return client

    def post(self, client: Any, **fields: Any) -> Any:
        form: dict[str, Any] = {
            "idempotency_key": KEY,
            auth.CSRF_FIELD: auth.csrf_token(client.cookies[auth.SESSION_COOKIE]),
            "address": ["198.51.100.23", "2001:db8:44::17"],
        }
        form.update(fields)
        return client.post(
            "/proxies/edge-demo/public-web/unblock", data=form, follow_redirects=False
        )

    def test_the_card_lists_the_addresses_with_boxes_and_the_button(self) -> None:
        page = self.writing_client().get("/proxies/edge-demo/public-web")

        card = page.text.split('id="blocked"')[1].split("</article>")[0]
        self.assertIn("<h3>Blocked addresses</h3>", card)
        self.assertIn("2 blocked by dynamic blocking", card)
        self.assertIn('value="2001:db8:44::17"', card)
        self.assertIn("edge-a, edge-b", card)
        self.assertIn(">Unblock</button>", card)

    def test_read_only_lists_them_without_boxes(self) -> None:
        page = self.writing_client(writes=False).get("/proxies/edge-demo/public-web")

        card = page.text.split('id="blocked"')[1].split("</article>")[0]
        self.assertIn("198.51.100.23", card)
        self.assertNotIn('name="address"', card)
        self.assertNotIn("Unblock", card)

    def test_the_last_unblock_is_said_as_it_ended(self) -> None:
        for outcome, said in (
            ("partial", "Not every node lifted the last unblock."),
            ("failed", "The last unblock was not made."),
        ):
            with self.subTest(outcome):
                job = replace(
                    queued(operation="dynamic_unblock", cluster="edge-demo"),
                    state=outcome,
                    outcome=outcome,
                    payload={"object": "public-web", "addresses": ["198.51.100.23"]},
                )
                with mock.patch("haprion_ui.db.recent_jobs", return_value=[job]):
                    page = self.writing_client().get("/proxies/edge-demo/public-web")
                self.assertIn(said, page.text)

    def test_an_unblock_in_flight_spins_on_its_own_card_only(self) -> None:
        """Both cards lose their buttons; only the one the job is for says so (26-10-10)."""

        for operation, spinning, still in (
            ("dynamic_unblock", 'id="blocked"', "<h3>Servers</h3>"),
            ("server_state", "<h3>Servers</h3>", 'id="blocked"'),
        ):
            with self.subTest(operation):
                running = replace(queued(operation=operation, cluster="edge-demo"), state="running")
                with mock.patch("haprion_ui.db.recent_jobs", return_value=[running]):
                    page = self.writing_client().get("/proxies/edge-demo/public-web").text
                own = page.split(spinning)[1].split("</header>")[0]
                other = page.split(still)[1].split("</header>")[0]
                self.assertIn('data-busy="edge-demo"', own)
                self.assertNotIn("data-busy", other)
                self.assertNotIn(">Unblock</button>", page)
                self.assertNotIn('name="state" value="drain"', page)

    def test_the_ticked_addresses_are_queued(self) -> None:
        answer = self.post(self.writing_client())

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/proxies/edge-demo/public-web")
        self.assertEqual(
            (self.queued[0]["operation"], self.queued[0]["cluster"], self.queued[0]["payload"]),
            (
                "dynamic_unblock",
                "edge-demo",
                {"object": "public-web", "addresses": ["198.51.100.23", "2001:db8:44::17"]},
            ),
        )
        audit = [entry for entry in self.audited if entry["action"] == "queue_job"]
        self.assertEqual(audit[0]["detail"]["operation"], "dynamic_unblock")

    def test_nothing_ticked_queues_nothing(self) -> None:
        answer = self.post(self.writing_client(), address=[])

        self.assertEqual(answer.headers["location"], "/proxies/edge-demo/public-web?blocked=none")
        self.assertEqual(self.queued, [])

    def test_a_busy_cluster_is_said_on_the_page(self) -> None:
        client = self.writing_client()
        with mock.patch("haprion_ui.db.queue_job", side_effect=db.ClusterBusy()):
            answer = self.post(client)

        self.assertEqual(answer.headers["location"], "/proxies/edge-demo/public-web?blocked=busy")
        page = client.get(answer.headers["location"])
        self.assertIn("A job is already running for this cluster", page.text)

    def test_only_an_admin_with_a_valid_form_may_unblock(self) -> None:
        self.assertEqual(self.post(self.writing_client(role="reader")).status_code, 403)
        client = self.writing_client()
        self.assertEqual(self.post(client, **{auth.CSRF_FIELD: "forged"}).status_code, 403)
        self.assertEqual(self.queued, [])

    def test_the_page_keeps_itself_current_while_the_object_blocks(self) -> None:
        """A block comes and goes on its own time; the card follows it once per poll."""

        from haprion_ui import reading as page_reading

        original = page_reading.read_source

        def demo_rows(request: Any, config: Any, source: Any) -> Any:
            return original(request, replace(config, demo_fixture=True), source)

        self.account = replace(self.account, role="admin")
        config = replace(configuration(), management_writes=True, clusters=demo.CLUSTERS)
        client = self.client(config)
        self.sign_in(client)
        with mock.patch("haprion_ui.pages.proxies.read_source", side_effect=demo_rows):
            page = client.get("/proxies/edge-demo/public-web").text
            with mock.patch.object(demo, "BLOCKED", {}):
                quiet = client.get("/proxies/edge-demo/public-web").text

        self.assertIn(
            f'<meta name="haproxy-live" content="{config.poller.interval_seconds}">', page
        )
        self.assertNotIn('<meta name="haproxy-live"', quiet)

    def test_the_dashboard_links_the_objects_for_an_admin(self) -> None:
        page = self.writing_client().get("/")

        self.assertIn(
            '2 addresses blocked dynamically: <a href="/proxies/edge-demo/public-web#blocked"',
            page.text,
        )

    def test_a_reader_is_told_how_many_without_a_link(self) -> None:
        page = self.writing_client(role="reader").get("/")

        self.assertIn("2 addresses blocked dynamically</span>", page.text)
        self.assertNotIn("public-web#blocked", page.text)

    def test_a_readers_count_is_on_the_operations_line_not_in_the_header(self) -> None:
        """The header's line ran its traffic figures under it at 1280 px (26-10-12)."""

        page = self.writing_client(role="reader").get("/").text
        card = page.split('class="cluster-header"', 1)[1].split("</article>", 1)[0]
        header, rest = card.split("</header>", 1)

        self.assertNotIn("blocked dynamically", header)
        operations = rest.split('class="operations-line"', 1)[1].split("</footer>", 1)[0]
        self.assertIn("2 addresses blocked dynamically</span>", operations)


if __name__ == "__main__":
    unittest.main()
