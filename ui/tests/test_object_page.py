"""The page behind a proxy row: who may open it, and what it refuses to invent.

The route is the first place the objects cache reaches a screen, so what is
worth testing here is not the rendering but the two boundaries around it - the
role that may see a document naming certificates and backend addresses, and the
refusal to render a page for a name that does not exist.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from unittest import mock

from haproxy_ui import demo
from haproxy_ui.db import ClusterInventory
from haproxy_ui.snapshot import ProductionSnapshot
from tests.test_login import LoginTestCase, configuration

CAPTURED = datetime(2026, 9, 2, 9, 0, tzinfo=UTC)
#
# One cluster serving one proxy, and no objects row at all - which is what a
# snapshot holds.
#
SNAPSHOT = ProductionSnapshot(
    captured_at=CAPTURED,
    clusters=("alpha",),
    status_rows=(),
    inventory_rows=(
        ClusterInventory(
            cluster="alpha",
            observed_at=CAPTURED,
            outcome="done",
            result={
                "version": 12,
                "proxies": [
                    {
                        "name": "app",
                        "protocol": "https",
                        "managed": True,
                        "enabled": True,
                        "hostnames": ["app.example.com"],
                        "bind_ports": [443],
                        "backend_count": 2,
                    }
                ],
            },
            warnings=[],
            error=None,
            poll_error=None,
        ),
    ),
    history_rows=(),
    certificate_rows=(),
    backup_rows=(),
    network_rows=(),
)


class OpeningAnObject(LoginTestCase):
    def demo_client(self) -> object:
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)
        return client

    def test_an_admin_sees_the_document_as_it_is_stored(self) -> None:
        page = self.demo_client().get("/proxies/edge-demo/public-web")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn("app.demo.example", page.text)
        self.assertIn("managed/proxies/public-web.yaml", page.text)

    def test_an_object_this_version_cannot_read_shows_the_refusal_and_the_file(self) -> None:
        """It is the one somebody has to open, so it must open."""

        page = self.demo_client().get("/proxies/edge-demo/staging")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn("cannot read", page.text)
        self.assertIn("routes is required", page.text)

    def test_an_unmanaged_proxy_opens_and_says_where_it_comes_from(self) -> None:
        page = self.demo_client().get("/proxies/edge-demo/metrics")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 200)
        self.assertIn("not written here", page.text)

    def test_a_proxy_with_no_object_never_names_a_file(self) -> None:
        """The card said "managed/proxies/<name>.yaml at <commit>" beside
        "nothing stored", because the path was keyed off the reading's commit
        rather than off this object. It named a file that does not exist."""

        page = self.demo_client().get("/proxies/edge-demo/metrics")  # type: ignore[attr-defined]

        self.assertNotIn("managed/proxies/metrics.yaml", page.text)

    def test_a_name_that_is_neither_stored_nor_served_is_not_a_page(self) -> None:
        """Otherwise every typo looks like a proxy somebody deleted."""

        page = self.demo_client().get("/proxies/edge-demo/nothing-here")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 404)

    def test_an_unknown_cluster_is_not_a_page(self) -> None:
        page = self.demo_client().get("/proxies/no-such-cluster/public-web")  # type: ignore[attr-defined]

        self.assertEqual(page.status_code, 404)

    def test_signing_out_is_a_redirect_and_never_the_document(self) -> None:
        client = self.client(replace(configuration(), demo_fixture=True))

        page = client.get("/proxies/edge-demo/public-web", follow_redirects=False)

        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login")


class InSnapshotMode(LoginTestCase):
    """Dev runs against a captured production snapshot, which carries no objects.

    The reason is in `OBJECTS_SOURCE`: a snapshot is a file copied into the
    development platform, and a stored document names every backend address the
    cluster talks to. The page must say that rather than "not read yet", which
    reads as a poller that is failing and sends somebody looking for a fault
    that is not there.
    """

    def test_the_page_says_the_snapshot_leaves_objects_out(self) -> None:
        client = self.client(replace(configuration(), production_snapshot=True))
        self.sign_in(client)

        with mock.patch("haproxy_ui.snapshot.load_production_snapshot", return_value=SNAPSHOT):
            page = client.get("/proxies/alpha/app")

        self.assertEqual(page.status_code, 200)
        self.assertIn("Not carried in a snapshot", page.text)
        self.assertNotIn("have not been read yet", page.text)


class WhoMayRead(LoginTestCase):
    def test_a_non_admin_is_refused(self) -> None:
        """The document names certificates and every backend address behind a
        site, which the overview deliberately does not show. B68 settled the
        same question for the preview, and this is the same data."""

        self.account = replace(self.account, role="operator")
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        page = client.get("/proxies/edge-demo/public-web")

        self.assertEqual(page.status_code, 403)

    def test_the_overview_offers_the_link_only_to_an_admin(self) -> None:
        """A link that always refuses is worse than no link."""

        self.account = replace(self.account, role="operator")
        client = self.client(replace(configuration(), demo_fixture=True))
        self.sign_in(client)

        page = client.get("/proxies")

        self.assertEqual(page.status_code, 200)
        self.assertIn("public-web", page.text)
        self.assertNotIn('href="/proxies/edge-demo/public-web"', page.text)


class TheFixtureDescribesARealCluster(LoginTestCase):
    def test_it_carries_an_object_that_does_not_parse(self) -> None:
        """Without one, a page could ship that renders only what parses."""

        rows = demo.object_rows()
        entries = [
            entry for row in rows for entry in row.result["objects"] if not entry["readable"]
        ]

        self.assertTrue(entries)
        self.assertTrue(all(entry["document"] for entry in entries))

    def test_unmanaged_proxies_have_no_object(self) -> None:
        """Which is what a cluster part-way through the move looks like."""

        stored = {entry["name"] for row in demo.object_rows() for entry in row.result["objects"]}

        self.assertNotIn("metrics", stored)
        self.assertNotIn("legacy-tcp", stored)
