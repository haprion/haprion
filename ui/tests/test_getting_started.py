"""Getting started on the dashboard (B316): ticked from what the installation is.

Held here: each item is done only when the installation shows it - a cluster
serving, every VIP's TLS chosen, a certificate that is not self-signed, more
than one account or SSO, a certificate from ACME or NDES, every cluster
forwarding its log and backing up - and the optional two are said to be; the
list is an admin's, and Hide removes it for the whole installation, audited.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from haprion_ui import auth
from haprion_ui.getting_started import ClusterFacts, Facts, Vip, checklist, offered_again
from tests.test_login import LoginTestCase, configuration


def cluster(**changes: Any) -> ClusterFacts:
    base = ClusterFacts(
        name="alpha",
        nodes=("node-a", "node-b"),
        owner="node-a",
        vips=(Vip("203.0.113.10", "intermediate", None),),
        logs_forwarded=True,
        backups_scheduled=True,
    )
    return replace(base, **changes)


def facts(**changes: Any) -> Facts:
    base = Facts(
        clusters=(),
        interface_self_signed=True,
        accounts=1,
        sso=False,
        site_certificates=0,
        node_backups_on=False,
        status_access=False,
        features_changed=False,
    )
    return replace(base, **changes)


def item(found: Facts, title: str) -> Any:
    return next(entry for entry in checklist(found).items if entry.title == title)


class TheTicks(unittest.TestCase):
    def test_a_new_installation_has_nothing_done(self) -> None:
        listed = checklist(facts())
        self.assertEqual(listed.done, 0)
        first = listed.items[0]
        self.assertEqual((first.state, first.href), ("No cluster yet", "/settings/new-cluster"))
        self.assertEqual(
            [entry.title for entry in listed.items if entry.optional],
            ["External monitoring", "Enable the features you want to use"],
        )
        self.assertEqual(listed.items[-1].title, "Enable the features you want to use")

    def test_a_cluster_is_done_when_a_node_holds_its_vip(self) -> None:
        serving = item(facts(clusters=(cluster(),)), "Nodes and a cluster")
        self.assertTrue(serving.done)
        self.assertEqual(serving.state, "alpha · node-a, node-b · 203.0.113.10 on node-a")
        unpublished = item(facts(clusters=(cluster(owner=None),)), "Nodes and a cluster")
        self.assertFalse(unpublished.done)
        self.assertEqual(unpublished.state, "alpha · nothing published yet")
        self.assertEqual((unpublished.action, unpublished.deploy), ("Proxies", None))

    def test_a_published_cluster_s_next_step_is_its_deploy(self) -> None:
        """Fas 18 finding 59: the row said Dashboard and led to the page it was on."""

        undeployed = item(
            facts(clusters=(cluster(owner=None, target_version=1),)), "Nodes and a cluster"
        )
        self.assertFalse(undeployed.done)
        self.assertEqual(undeployed.state, "alpha · not deployed yet")
        self.assertEqual(
            (undeployed.action, undeployed.deploy, undeployed.deploy_version),
            ("Deploy configuration", "alpha", 1),
        )

    def test_tls_is_done_when_every_vip_has_it_chosen(self) -> None:
        unset = (Vip("203.0.113.10", None, None), Vip("203.0.113.11", "modern", "198.51.100.5"))
        some = item(facts(clusters=(cluster(vips=unset),)), "TLS and source address")
        self.assertFalse(some.done)
        self.assertEqual(some.state, "TLS chosen on some VIPs · 1 source address")
        two = (
            Vip("203.0.113.10", "modern", "198.51.100.5"),
            Vip("203.0.113.11", "modern", "198.51.100.6"),
        )
        self.assertEqual(
            item(facts(clusters=(cluster(vips=two),)), "TLS and source address").state,
            "TLS 1.3 only · 2 source addresses",
        )
        chosen = item(facts(clusters=(cluster(),)), "TLS and source address")
        self.assertTrue(chosen.done)
        self.assertEqual(chosen.state, "TLS 1.2 and 1.3 · the nodes' own addresses")
        self.assertFalse(item(facts(), "TLS and source address").done)

    def test_the_rest_follow_what_is_installed(self) -> None:
        set_up = facts(
            clusters=(cluster(),),
            interface_self_signed=False,
            accounts=3,
            site_certificates=2,
            node_backups_on=True,
            status_access=True,
            features_changed=True,
        )
        self.assertEqual(checklist(set_up).done, len(checklist(set_up).items))
        self.assertEqual(item(set_up, "Users and sign-in").state, "3 accounts")
        self.assertTrue(item(facts(sso=True), "Users and sign-in").done)
        self.assertFalse(item(facts(interface_self_signed=None), "Interface certificate").done)

    def test_every_cluster_must_forward_and_back_up(self) -> None:
        two = (cluster(), cluster(name="beta", logs_forwarded=False, backups_scheduled=False))
        found = facts(clusters=two, node_backups_on=True)
        logs = item(found, "Traffic log off the nodes")
        backups = item(found, "Node backups")
        self.assertFalse(logs.done)
        self.assertEqual(logs.state, "Forwarded from 1 of 2 clusters")
        self.assertFalse(backups.done)
        self.assertEqual(backups.state, "Scheduled on 1 of 2 clusters")

    def test_backups_turned_off_point_at_features(self) -> None:
        off = item(facts(clusters=(cluster(),)), "Node backups")
        self.assertFalse(off.done)
        self.assertEqual((off.state, off.action), ("Off under Features", "Features"))


class TheWayBack(unittest.TestCase):
    def test_a_week_and_not_longer(self) -> None:
        hidden = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
        self.assertTrue(offered_again(hidden, hidden + timedelta(days=7) - timedelta(seconds=1)))
        self.assertFalse(offered_again(hidden, hidden + timedelta(days=7)))


class OnTheDashboard(LoginTestCase):
    def signed_in(self, *, role: str = "admin", clusters: tuple[str, ...] = ("alpha",)) -> Any:
        self.account = replace(self.account, role=role)
        client = self.client(replace(configuration(), management_writes=True, clusters=clusters))
        self.sign_in(client)
        return client

    def test_an_admin_sees_it_until_it_is_hidden(self) -> None:
        page = self.signed_in().get("/").text
        self.assertIn("Getting started", page)
        self.assertIn('action="/getting-started/hide"', page)
        self.assertIn(">Hide getting started</button>", page)
        self.assertIn("Enable the features you want to use", page)

        self.getting_started_hidden_at = datetime.now(UTC)
        self.assertNotIn("Getting started</h3>", self.signed_in().get("/").text)

    def test_without_a_cluster_the_first_cluster_s_guide_takes_its_place(self) -> None:
        """B315: a new installation's dashboard is the guide, for an admin who may write."""

        page = self.signed_in(clusters=()).get("/").text
        self.assertIn("Set up your first cluster", page)
        self.assertNotIn("Getting started</h3>", page)
        self.assertNotIn("Set up your first cluster", self.signed_in(role="reader").get("/").text)

    def test_a_hidden_list_is_offered_back_for_a_week(self) -> None:
        self.getting_started_hidden_at = datetime.now(UTC) - timedelta(days=6)
        self.assertIn('action="/getting-started/show"', self.signed_in().get("/").text)
        self.assertNotIn(
            'action="/getting-started/show"', self.signed_in(role="reader").get("/").text
        )

        self.getting_started_hidden_at = datetime.now(UTC) - timedelta(days=8)
        self.assertNotIn('action="/getting-started/show"', self.signed_in().get("/").text)

    def test_a_list_that_shows_offers_nothing_back(self) -> None:
        self.assertNotIn('action="/getting-started/show"', self.signed_in().get("/").text)

    def test_show_is_audited_and_an_admin_s(self) -> None:
        self.getting_started_hidden_at = datetime.now(UTC)
        client = self.signed_in()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        refused = client.post(
            "/getting-started/show", data={"csrf_token": "x"}, follow_redirects=False
        )
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(self.shown_again, 0)

        answer = client.post(
            "/getting-started/show", data={"csrf_token": token}, follow_redirects=False
        )
        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.shown_again, 1)
        self.assertIn("getting_started_shown", self.audit)

        reader = self.signed_in(role="reader")
        reader_token = auth.csrf_token(reader.cookies[auth.SESSION_COOKIE])
        self.assertEqual(
            reader.post(
                "/getting-started/show", data={"csrf_token": reader_token}, follow_redirects=False
            ).status_code,
            403,
        )

    def test_a_reader_does_not_see_it(self) -> None:
        self.assertNotIn("Getting started", self.signed_in(role="reader").get("/").text)

    def test_hide_is_stored_audited_and_an_admin_s(self) -> None:
        client = self.signed_in()
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        refused = client.post(
            "/getting-started/hide", data={"csrf_token": "x"}, follow_redirects=False
        )
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(self.hidden_by, [])

        answer = client.post(
            "/getting-started/hide", data={"csrf_token": token}, follow_redirects=False
        )
        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.hidden_by, [self.account.username])
        self.assertIn("getting_started_hidden", self.audit)

        reader = self.signed_in(role="reader")
        reader_token = auth.csrf_token(reader.cookies[auth.SESSION_COOKIE])
        self.assertEqual(
            reader.post(
                "/getting-started/hide", data={"csrf_token": reader_token}, follow_redirects=False
            ).status_code,
            403,
        )


if __name__ == "__main__":
    unittest.main()
