"""The page that compares a cluster's frontends and backends.

The object page's card can only draw the backends of a proxy somebody has already
opened, so two questions stay unanswerable there: which backend carries the
traffic, and whether the request reached the cluster at all. The second is the
one this phase began in - a site returning 503 with every server green - and
frontend counters belong to the cluster and its nodes rather than to an object
(B94), so this page is the only place they can be read.

What is worth pinning here is the boundary and the two claims the page makes:
the role that may see every frontend and backend a cluster carries, and that the
cards within a section share one scale so their sizes can be compared.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from haproxy_mgmt.generate import PREFIX, WAF_BACKEND
from haproxy_mgmt.guid import REDIRECT_PREFIX, redirect_name
from haproxy_mgmt.proxy_model import load_proxy

from haproxy_ui import metrics
from tests.test_login import LoginTestCase, configuration


def samples(*values: int, node: str = "node-a", frontend: str = "https-in") -> list[metrics.Sample]:
    """Readings a minute apart, climbing by `values` - a cumulative counter.

    Placed relative to now rather than at a fixed date. The route measures the
    window it draws from the clock, so readings pinned to a calendar date fall
    out of it as soon as that date is yesterday - and the test would then pass
    or fail depending on when it was run.

    Well back from now, not a minute or two. The drawing keeps whole buckets
    only, so the bucket in progress is excluded - and readings placed just
    behind `now` fall inside it or behind it depending on where the clock
    happens to sit in the current ten minutes. That made this pass alone and
    fail in a full run, which is the worst way for a test to be wrong.
    """

    observed = datetime.now(UTC) - timedelta(minutes=45)
    running = 0
    found = []
    for step, value in enumerate(values):
        running += value
        found.append(
            metrics.Sample(
                observed_at=observed + timedelta(minutes=step),
                member=frontend,
                uptime_sec=1000 + step * 60,
                node=node,
                counters=dict.fromkeys(metrics.METRIC_COUNTERS) | {"req_tot": running},
            )
        )
    return found


def measurement(
    intervals: int = 2, counters: tuple[tuple[str, str], ...] = metrics.CARD_COUNTERS
) -> metrics.BackendMeasurement:
    now = datetime.now(UTC)
    return metrics.BackendMeasurement(
        intervals=intervals,
        started_at=now - timedelta(minutes=intervals),
        ended_at=now,
        totals=tuple(
            metrics.Total(label=label, value=1, counted_sec=60.0, span_sec=60.0)
            for _name, label in counters
        ),
        restarted=False,
        handed_over=False,
    )


class ReadingACluster(LoginTestCase):
    """Every database call the page makes, answered with a known shape."""

    frontends: list[tuple[str, bool]] = [("mgd-vip-int-https", True), ("mgd-vip-int-http", True)]
    backends: list[str] = ["mgd-shop-web", "mgd-shop-api", "mgd-shop-redirect-eee20480"]
    dns_pools: list[str] = []

    def setUp(self) -> None:
        super().setUp()
        for name, value in (
            ("read_cluster_frontends", lambda *_a, **_k: self.frontends),
            (
                "read_cluster_backends",
                lambda *_a, **k: self.dns_pools if k.get("dns") else self.backends,
            ),
            ("read_backend_aliases", lambda *_a, **_k: {}),
            ("read_frontend_series", self._frontend_series),
            ("read_backend_series", self._backend_series),
            ("read_frontend_totals", lambda *_a, **_k: measurement()),
            (
                "read_backend_totals",
                lambda *_a, **k: measurement(counters=k.get("counters", metrics.CARD_COUNTERS)),
            ),
        ):
            patch = mock.patch(f"haproxy_ui.db.{name}", side_effect=value)
            patch.start()
            self.addCleanup(patch.stop)

    def _frontend_series(self, *_args: object, **kwargs: object) -> list[metrics.Interval]:
        busy = str(kwargs.get("frontend")).endswith("-https")
        return metrics.intervals(samples(400, 400) if busy else samples(3, 3))

    def _backend_series(self, *_args: object, **kwargs: object) -> list[metrics.Interval]:
        busy = str(kwargs.get("backend")) == "mgd-shop-web"
        return metrics.intervals(samples(400, 400) if busy else samples(1, 1))

    def admin(self) -> object:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        return client

    def page(self, query: str = "") -> object:
        return self.admin().get(f"/clusters/edge-demo/metrics{query}")  # type: ignore[attr-defined]


class WhoMayCompare(ReadingACluster):
    def test_an_admin_opens_it(self) -> None:
        self.assertEqual(self.page().status_code, 200)  # type: ignore[attr-defined]

    def test_a_signed_out_visitor_is_sent_to_the_login(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))
        answer = client.get("/clusters/edge-demo/metrics", follow_redirects=False)

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/login")

    def test_an_operator_is_refused(self) -> None:
        """It names every frontend and backend, which the overview will not show."""

        self.account = replace(self.account, role="operator")
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        self.assertEqual(client.get("/clusters/edge-demo/metrics").status_code, 403)

    def test_a_cluster_that_does_not_exist_is_not_a_page(self) -> None:
        answer = self.admin().get("/clusters/nowhere/metrics")  # type: ignore[attr-defined]

        self.assertEqual(answer.status_code, 404)


class WhatThePageSays(ReadingACluster):
    def test_the_waf_engine_is_not_a_backend_card(self) -> None:
        """Its requests are HAProxy handing requests to the engine (2026-10-04)."""

        self.backends = [*ReadingACluster.backends, WAF_BACKEND]
        text = self.page().text  # type: ignore[attr-defined]

        self.assertNotIn("waf-engine", text)
        self.assertIn("shop-web", text)

    def test_both_halves_are_drawn(self) -> None:
        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn("Frontends", text)
        self.assertIn("Backends", text)

    def test_an_address_is_named_the_way_the_network_page_names_it(self) -> None:
        """`mgd-vip-int-http` is the VIP `vip-int` serving `http`."""

        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn(">vip-int<", text)
        self.assertNotIn("mgd-vip-int-https", text)

    def test_the_protocol_sits_beside_the_name_rather_than_inside_it(self) -> None:
        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn("protocol-https", text)
        self.assertIn("protocol-http", text)

    def test_an_http_address_shows_3xx_where_the_other_addresses_show_2xx(self) -> None:
        text = self.page().text  # type: ignore[attr-defined]
        addresses = text.split("Frontends", 1)[1].split("Backends", 1)[0]
        https_card = addresses.split('protocol-https">', 1)[1]
        https = https_card[
            https_card.index('<dl class="traffic-figures">') : https_card.index("</dl>")
        ]
        http_card = addresses.split('protocol-http">', 1)[1]
        http = http_card[http_card.index('<dl class="traffic-figures">') : http_card.index("</dl>")]

        self.assertIn("2xx", https)
        self.assertNotIn("3xx", https)
        self.assertIn("3xx", http)
        self.assertNotIn("2xx", http)

    def test_a_name_that_does_not_fit_the_rule_is_kept_whole(self) -> None:
        """The generator's rule could change; renaming on a guess would be worse."""

        self.frontends = [("something-handwritten", True)]

        self.assertIn("something-handwritten", self.page().text)  # type: ignore[attr-defined]

    def test_a_raw_port_is_its_vip_with_tcp_and_the_port_beside_it(self) -> None:
        self.frontends = [("mgd-vip-int-tcp-5432", True)]

        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn(">vip-int<", text)
        self.assertIn('protocol-tcp">TCP 5432<', text)

    def test_the_metrics_exporter_is_not_an_address_anything_arrives_at(self) -> None:
        """Seen in the 7- and 30-day windows after the exporter was on (2026-10-01)."""

        self.frontends = [("mgd-metrics", True), ("mgd-vip-int-https", True)]

        text = self.page().text  # type: ignore[attr-defined]

        self.assertNotIn("mgd-metrics", text)
        self.assertIn(">vip-int<", text)

    def test_every_backend_the_cluster_has_is_there(self) -> None:
        """Not only the one somebody already guessed right about."""

        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn("shop-web", text)
        self.assertIn("shop-api", text)

    def test_every_named_graph_says_what_one_bucket_measures(self) -> None:
        text = self.page("?traffic=24h").text  # type: ignore[attr-defined]

        self.assertEqual(text.count('class="traffic-rate">Requests / 10 min'), 5)

    def test_the_bucket_description_changes_with_the_window(self) -> None:
        text = self.page("?traffic=7d").text  # type: ignore[attr-defined]

        self.assertEqual(text.count('class="traffic-rate">Requests / h'), 5)

    def test_a_backend_is_named_without_the_generator_prefix(self) -> None:
        text = self.page().text  # type: ignore[attr-defined]

        self.assertNotIn("mgd-shop-web", text)

    def test_a_redirect_no_document_accounts_for_keeps_its_stored_name(self) -> None:
        """Inventing a name would be worse than showing an opaque one."""

        self.backends = ["mgd-gone-redirect-aaaaaaaa"]

        self.assertIn("gone-redirect-aaaaaaaa", self.page().text)  # type: ignore[attr-defined]

    def test_a_redirect_answer_is_kept_out_of_the_backends(self) -> None:
        """It has no servers, and it would size every real backend against it."""

        text = self.page().text  # type: ignore[attr-defined]
        backends = text.split("Backends", 1)[1].split("Redirect answers", 1)[0]

        self.assertNotIn("redirect-eee20480", backends)
        self.assertIn("Redirect answers", text)
        self.assertIn("shop-redirect-eee20480", text)

    def test_a_redirect_answer_shows_response_classes_that_it_can_answer(self) -> None:
        """Only the response class changes; the card keeps its other five figures."""

        text = self.page().text  # type: ignore[attr-defined]
        redirect_card = text.split("Redirect answers", 1)[1]
        redirect = redirect_card[
            redirect_card.index('<dl class="traffic-figures">') : redirect_card.index("</dl>")
        ]

        self.assertIn("Requests", redirect)
        self.assertIn("3xx", redirect)
        self.assertIn("4xx", redirect)
        self.assertIn("5xx", redirect)
        self.assertIn("Connection errors", redirect)
        self.assertIn("Retries", redirect)
        self.assertNotIn("2xx", redirect)

    def test_a_regular_backend_keeps_2xx_and_does_not_gain_3xx(self) -> None:
        text = self.page().text  # type: ignore[attr-defined]
        backend_card = text.split("Backends", 1)[1].split("Redirect answers", 1)[0]
        backends = backend_card[
            backend_card.index('<dl class="traffic-figures">') : backend_card.index("</dl>")
        ]

        self.assertIn("2xx", backends)
        self.assertNotIn("3xx", backends)

    def test_the_cluster_carries_its_own_accent(self) -> None:
        """Without it a card reads as belonging to whatever came above it."""

        self.assertRegex(self.page().text, r"cluster-accent-\d")  # type: ignore[attr-defined]

    def test_the_window_asked_for_is_the_one_drawn(self) -> None:
        self.assertIn("the last 7 days", self.page("?traffic=7d").text)  # type: ignore[attr-defined]

    def test_a_window_nobody_offers_falls_back_rather_than_failing(self) -> None:
        """It arrives in a bookmark that outlived a change."""

        answer = self.page("?traffic=nonsense")

        self.assertEqual(answer.status_code, 200)  # type: ignore[attr-defined]
        self.assertIn("the last 24 hours", answer.text)  # type: ignore[attr-defined]

    def test_a_cluster_with_no_samples_says_so_rather_than_drawing_nothing(self) -> None:
        self.frontends = []
        self.backends = []

        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn("No address samples in this window", text)
        self.assertIn("No backend samples in this window", text)


class OneScalePerSection(ReadingACluster):
    """The comparison is only true while the cards share a ceiling."""

    def scales(self, text: str) -> list[str]:
        return [
            line.split('aria-label="')[1].split('"')[0]
            for line in text.splitlines()
            if 'aria-label="Requests per' in line
        ]

    def test_every_card_in_a_section_is_drawn_against_the_same_scale(self) -> None:
        labels = self.scales(self.page().text)  # type: ignore[attr-defined]
        described = [label.split("against a scale of ")[1].split(",")[0] for label in labels]

        self.assertTrue(described)
        self.assertEqual(len(set(described[:2])), 1)

    def test_a_quiet_card_still_reports_its_own_peak(self) -> None:
        """So a flat line and an empty card are distinguishable."""

        labels = self.scales(self.page().text)  # type: ignore[attr-defined]
        peaks = {label.split("peaking at ")[1] for label in labels}

        self.assertGreater(len(peaks), 1)


class DnsPoolsAmongTheBackends(ReadingACluster):
    """dnsdist's pools (Fas 19a B4) in the backends' list, with a resolver's figures (26-10-06)."""

    dns_pools = ["resolver"]

    def text(self) -> str:
        return str(self.page().text)  # type: ignore[attr-defined]

    def backend_section(self) -> str:
        text = self.text()
        return text.split('<h4 class="traffic-section">Backends</h4>', 1)[1].split(
            '<h4 class="traffic-section">Redirect answers</h4>', 1
        )[0]

    def test_the_pool_is_drawn_among_the_backends_in_name_order(self) -> None:
        names = re.findall(r'<code class="traffic-backend">([^<]+)</code>', self.backend_section())
        self.assertEqual(names, sorted(names))
        self.assertIn("resolver", names)
        self.assertNotIn('<h4 class="traffic-section">DNS</h4>', self.text())

    def test_its_figures_are_a_resolver_s_and_the_others_keep_theirs(self) -> None:
        cards = self.backend_section().split('<code class="traffic-backend">')[1:]
        resolver = next(card for card in cards if card.startswith("resolver<"))
        figures = [part.split("</dt>")[0] for part in resolver.split("<dt>")[1:]]
        self.assertEqual(figures, ["Queries", "Answered", "Refused", "Unanswered", "Over TCP"])
        self.assertIn("Queries / ", resolver)
        other = next(card for card in cards if not card.startswith("resolver<"))
        self.assertIn("Requests / ", other)

    def test_no_server_table(self) -> None:
        self.assertNotIn("traffic-servers", self.text())


class MarkingARangeOnThePage(ReadingACluster):
    """Two clicks on the drawing, and the figures answer for what was marked.

    The drawing keeps the whole window either way. The marks say which part of
    it the numbers are about, which is the question this page is opened with -
    "which of these carried the traffic between these two moments".
    """

    def marks(self, back: int, forward: int) -> str:
        now = datetime.now(UTC)
        return (
            f"?from={int((now - timedelta(minutes=back)).timestamp())}"
            f"&to={int((now - timedelta(minutes=forward)).timestamp())}"
        )

    def test_the_figures_are_counted_over_the_marked_range(self) -> None:
        with mock.patch(
            "haproxy_ui.db.read_backend_totals", side_effect=lambda *_a, **_k: measurement()
        ) as totals:
            self.page(self.marks(50, 40))

        asked = {(call.kwargs["since"], call.kwargs["until"]) for call in totals.call_args_list}
        self.assertEqual(len(asked), 1)
        since, until = asked.pop()
        self.assertLess(until - since, timedelta(minutes=30))
        self.assertGreater(until - since, timedelta(minutes=5))

    def test_an_unmarked_page_counts_the_whole_window(self) -> None:
        with mock.patch(
            "haproxy_ui.db.read_backend_totals", side_effect=lambda *_a, **_k: measurement()
        ) as totals:
            self.page()

        since, until = (
            totals.call_args_list[0].kwargs["since"],
            totals.call_args_list[0].kwargs["until"],
        )
        self.assertGreater(until - since, timedelta(hours=23))

    def test_the_marked_buckets_are_drawn_as_marked_and_can_be_cleared(self) -> None:
        text = self.page(self.marks(50, 40)).text  # type: ignore[attr-defined]

        self.assertIn('class="traffic-marked"', text)
        self.assertIn('class="traffic-clear"', text)

    def test_an_unmarked_page_marks_nothing(self) -> None:
        text = self.page().text  # type: ignore[attr-defined]

        self.assertNotIn('class="traffic-marked"', text)
        self.assertNotIn('class="traffic-clear"', text)

    def test_every_bucket_is_a_link_that_carries_the_window(self) -> None:
        """So a range can be marked with the keyboard, and without script."""

        text = self.page("?traffic=7d").text  # type: ignore[attr-defined]

        self.assertIn('class="traffic-pick" href="?traffic=7d&amp;from=', text)

    def test_marks_that_outlived_their_window_are_ignored_rather_than_refused(self) -> None:
        answer = self.page("?from=1&to=2")

        self.assertEqual(answer.status_code, 200)  # type: ignore[attr-defined]
        self.assertNotIn('class="traffic-marked"', answer.text)  # type: ignore[attr-defined]


class TheWayBackAndForth(ReadingACluster):
    def setUp(self) -> None:
        super().setUp()
        #
        # The object page reads a draft, and a page whose draft lookup fails is
        # a page that does not render - which would hide what this is about.
        #
        patch = mock.patch("haproxy_ui.db.read_draft", return_value=None)
        patch.start()
        self.addCleanup(patch.stop)

    def test_it_is_its_own_page_rather_than_something_behind_a_proxy(self) -> None:
        """Traffic is a cluster's reading; reaching it through one proxy is odd."""

        page = self.admin().get("/metrics")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn('href="/metrics"', page.text)

    def test_the_listing_no_longer_repeats_the_tab(self) -> None:
        """A link beside the inventory line is redundant once there is a tab."""

        page = self.admin().get("/proxies")  # type: ignore[attr-defined]

        self.assertNotIn("/clusters/edge-demo/metrics", page.text)

    def test_an_object_with_traffic_offers_the_comparison_it_cannot_make(self) -> None:
        """The card can only draw the backend somebody already guessed right."""

        source = (
            Path(__file__).resolve().parents[1] / "src" / "haproxy_ui" / "templates" / "object.html"
        ).read_text()

        self.assertIn("/clusters/{{ object.cluster }}/metrics", source)


if __name__ == "__main__":
    unittest.main()


class NamingARedirectByWhatItDoes(unittest.TestCase):
    """`...-redirect-eee20480` tells an operator nothing about which one.

    The digest is right in the configuration - it is what keeps a redirect's
    counters when a route is added above it - and unreadable on a page. Tested
    against the engine's own model rather than through the route, because what
    is worth pinning is that the two agree about the name, not that a page can
    render one.
    """

    DOCUMENT = b"""
schema: 1
name: shop
hostnames:
  - shop.example.com
listen:
  protocol: https
  certificate: wildcard
routes:
  - path: /old
    backend: null
    redirect:
      location: https://shop.example.com/new
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: tcp
    servers:
      - host: 192.0.2.10
        port: 8080
"""

    def targets(self) -> dict[str, metrics.BackendTarget]:
        return metrics.backend_targets({"shop": load_proxy("shop", self.DOCUMENT)})

    #
    # The name the generator gives the route since 2026-10-06 (B250), the one
    # it gave from 2026-10-05, and the one before that, which older history
    # carries.
    #
    CURRENT = f"shop-{REDIRECT_PREFIX}-old"
    PATHED = f"{PREFIX}-shop-{REDIRECT_PREFIX}-old"
    LEGACY = (
        f"{PREFIX}-shop-{REDIRECT_PREFIX}-"
        f"{redirect_name('/old', 'prefix', 'https://shop.example.com/new')}"
    )
    #
    # And the pool: its own name now, `mgd-shop-web` before.
    #
    POOL = "web"
    OLD_POOL = f"{PREFIX}-shop-web"

    def test_the_generator_and_the_page_agree_on_the_name(self) -> None:
        """Built rather than parsed, so no name is split on somebody's hyphen."""

        from haproxy_mgmt.guid import redirect_suffixes  # noqa: PLC0415

        proxy = load_proxy("shop", self.DOCUMENT)
        self.assertEqual(f"shop-{redirect_suffixes(proxy)[('/old', 'prefix')]}", self.CURRENT)
        self.assertEqual(self.targets()[self.CURRENT].current, self.CURRENT)

    def test_the_older_names_are_the_same_redirect(self) -> None:
        self.assertEqual(self.targets()[self.LEGACY], self.targets()[self.CURRENT])
        self.assertEqual(self.targets()[self.PATHED], self.targets()[self.CURRENT])
        self.assertTrue(self.targets()[self.CURRENT].redirect)

    def test_a_pool_is_labelled_by_its_own_name_under_either(self) -> None:
        targets = self.targets()

        self.assertEqual(targets[self.OLD_POOL], targets[self.POOL])
        self.assertEqual(metrics.backend_label(self.OLD_POOL, targets), "web")
        self.assertFalse(targets[self.POOL].redirect)

    def test_a_name_no_object_accounts_for_loses_only_its_prefix(self) -> None:
        self.assertEqual(metrics.backend_label("mgd-other-web", self.targets()), "other-web")

    def test_it_is_named_by_the_route_and_the_destination(self) -> None:
        described = self.targets()[self.CURRENT].label

        self.assertIn("/old", described)
        self.assertIn("https://shop.example.com/new", described)

    def test_every_name_of_both_backends_is_known(self) -> None:
        self.assertEqual(
            set(self.targets()),
            {self.CURRENT, self.PATHED, self.LEGACY, self.POOL, self.OLD_POOL},
        )

    def test_the_older_name_is_drawn_until_the_current_one_has_history(self) -> None:
        targets = self.targets()

        self.assertEqual(
            metrics.split_backends([self.OLD_POOL, self.LEGACY], targets),
            ([self.OLD_POOL], [self.LEGACY]),
        )
        self.assertEqual(
            metrics.split_backends(
                [self.OLD_POOL, self.POOL, self.LEGACY, self.PATHED, self.CURRENT], targets
            ),
            ([self.POOL], [self.CURRENT]),
        )

    def test_a_pool_is_not_taken_for_a_redirect_by_its_name(self) -> None:
        """`shop-redirect` is a redirect only if a route makes it one."""

        named = f"shop-{REDIRECT_PREFIX}"
        self.assertEqual(metrics.split_backends([named], self.targets()), ([named], []))


class AnAddressNobodyReportedHolding(ReadingACluster):
    """`owns_vip` is nullable, and null is "this node could not say".

    Filtering the listing by it removed the address from the page while its
    rows sat in the table, and the page then said it had no samples. It also
    went blank during a total outage - the one moment this page is opened.
    """

    def test_the_address_is_still_listed(self) -> None:
        self.frontends = [("mgd-vip-int-https", False)]

        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn(">vip-int<", text)
        self.assertNotIn("No address samples in this window", text)

    def test_it_says_what_is_missing_rather_than_drawing_a_line(self) -> None:
        self.frontends = [("mgd-vip-int-https", False)]

        text = self.page().text  # type: ignore[attr-defined]

        self.assertIn("No node reported holding this address", text)

    def test_an_address_that_was_held_is_drawn_as_before(self) -> None:
        self.frontends = [("mgd-vip-int-https", True)]

        self.assertIn("traffic-spark", self.page().text)  # type: ignore[attr-defined]


class TheCardsBehaveTheSameOnBothPages(ReadingACluster):
    def test_the_cluster_view_loads_the_tooltip_script_the_object_page_does(self) -> None:
        """Shared markup promised shared behaviour and delivered half of it."""

        self.assertIn("traffic.js", self.page().text)  # type: ignore[attr-defined]
