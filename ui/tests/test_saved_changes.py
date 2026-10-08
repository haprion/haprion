"""A cluster's network description and settings are saved before they are published (B257)."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock
from uuid import UUID

from haproxy_ui import db, demo, views
from tests.test_editor_page import EditorTestCase, published
from tests.test_login import configuration
from tests.test_queue_route import QueueRouteTestCase
from tests.test_settings_cluster import SettingsClusterTestCase

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
SAVED_ID = UUID("99999999-9999-4999-8999-999999999999")
#
# The demo cluster's description with one VIP more, as the network form would
# save it: the address an object saved in the same publish could name.
#
WIDER = json.dumps(
    {
        "vips": {
            "public": {"address": "192.0.2.20", "source": "192.0.2.25", "tls": "intermediate"},
            "shop": {"address": "192.0.2.30"},
        },
        "default_vip": "public",
    }
)


def saved(kind: str, document: str, *, cluster: str = "edge-demo", revision: int = 2) -> Any:
    return db.ClusterChange(
        cluster=cluster,
        kind=kind,
        document=document,
        base_hash="a" * 40,
        revision=revision,
        updated_by="operator",
        updated_at=NOW,
        id=SAVED_ID,
    )


class TheNetworkFormSaves(QueueRouteTestCase):
    def form(self, **overrides: Any) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "operation": "network_publish",
            "cluster": "alpha",
            "expected_head": "a" * 40,
            "vip_name": ["public"],
            "vip_address": ["192.0.2.20"],
            "vip_source": ["192.0.2.25"],
            "default_vip_row": "0",
            "default_vip_confirmation": "on",
        }
        fields.update(overrides)
        return fields

    def test_save_writes_the_description_and_queues_nothing(self) -> None:
        answer = self.post(self.writing_client(), **self.form(network_action="save"))

        self.assertEqual((answer.status_code, answer.headers["location"]), (303, "/network"))
        self.assertEqual(self.queued, [])
        (change,) = self.saved_changes
        self.assertEqual((change["kind"], change["expected_revision"]), ("network", None))
        self.assertIn("192.0.2.20", change["document"])

    def test_save_still_asks_for_the_default_vip_confirmation(self) -> None:
        answer = self.post(
            self.writing_client(),
            **self.form(network_action="save", default_vip_confirmation=""),
        )

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved_changes, [])

    def test_save_holds_the_revision_on_the_page(self) -> None:
        self.post(self.writing_client(), **self.form(network_action="save", saved_revision="2"))

        self.assertEqual(self.saved_changes[0]["expected_revision"], 2)
        self.assertEqual(self.queued, [])

    def test_discard_throws_away_the_revision_on_the_page(self) -> None:
        with mock.patch("haproxy_ui.db.discard_cluster_change") as discard:
            answer = self.post(
                self.writing_client(), **self.form(network_action="discard", saved_revision="4")
            )

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(
            discard.call_args.kwargs,
            {"cluster": "alpha", "kind": "network", "expected_revision": 4},
        )
        self.assertEqual(self.queued, [])

    def test_a_head_that_is_not_a_commit_is_refused_before_the_table(self) -> None:
        answer = self.post(
            self.writing_client(), **self.form(network_action="save", expected_head="HEAD")
        )

        self.assertEqual(answer.status_code, 400)
        self.assertEqual(self.saved_changes, [])


#
# What the base fixture's `save_cluster_change` answers with.
#
SAVED_ID_IN_FIXTURE = UUID("88888888-8888-4888-8888-888888888888")


class TheSavedNetworkIsWhatIsShown(QueueRouteTestCase):
    def page(self, changes: dict[str, Any]) -> str:
        with (
            mock.patch("haproxy_ui.db.cluster_networks", return_value=demo.network_rows(NOW)),
            mock.patch(
                "haproxy_ui.db.cluster_changes",
                side_effect=lambda _c, cluster: changes if cluster == "edge-demo" else {},
            ),
        ):
            client = self.client(
                replace(configuration(), management_writes=True, clusters=demo.CLUSTERS)
            )
            self.sign_in(client)
            return str(client.get("/network").text)

    def test_the_form_shows_the_saved_description_and_says_so(self) -> None:
        text = self.page({"network": saved("network", WIDER)})
        card = text.split("service-demo", 1)[0]

        self.assertIn('value="192.0.2.30"', card)
        self.assertIn("<strong>Saved changes</strong> by operator", card)
        self.assertIn('name="saved_revision" value="2"', card)
        self.assertIn("Discard the changes", card)

    def test_without_a_save_the_published_description_is_shown(self) -> None:
        card = self.page({}).split("service-demo", 1)[0]

        self.assertNotIn("192.0.2.30", card)
        self.assertNotIn("Saved changes", card)


class AnObjectIsCheckedAgainstTheSavedNetwork(EditorTestCase):
    def test_a_vip_only_the_saved_network_has_is_offered(self) -> None:
        document = json.dumps(
            {
                "vips": {
                    "main": {"address": "192.0.2.20", "source": "192.0.2.25"},
                    "shop": {"address": "192.0.2.30"},
                },
                "default_vip": "main",
            }
        )
        client = self.editor()
        before = client.get("/proxies/alpha/shop/edit").text
        with mock.patch(
            "haproxy_ui.db.cluster_changes",
            return_value={"network": saved("network", document, cluster="alpha")},
        ):
            after = client.get("/proxies/alpha/shop/edit").text

        self.assertNotIn("192.0.2.30", before)
        self.assertIn("192.0.2.30", after)


class ASavedChangeIsClearedByItsPublish(unittest.TestCase):
    """Cleared once its own page's reading stands at the publish's version or later (F3)."""

    #
    # The cached listing: the base the package was published against (10),
    # the version the publish recorded (11), one before and one after.
    #
    VERSIONS = {"c" * 40: 9, "a" * 40: 10, "d" * 40: 11, "e" * 40: 12}

    def job(self, *, commit: str = "d" * 40, version: int = 11, revision: int = 2) -> Any:
        answer = published(True)
        answer["result"] = {**answer["result"], "hash": commit, "version": version}
        return mock.Mock(
            payload={
                "change": {"id": str(SAVED_ID), "revision": revision},
                "expected_head": "a" * 40,
            },
            result=answer,
        )

    def settle(
        self, head: str | None, jobs: list[Any], *, kind: str = "network"
    ) -> tuple[dict[str, Any], mock.Mock]:
        listing = mock.Mock(
            result={"versions": [{"hash": c, "version": v} for c, v in self.VERSIONS.items()]}
        )
        with (
            mock.patch(
                "haproxy_ui.db.cluster_changes",
                return_value={kind: saved(kind, WIDER)},
            ),
            mock.patch("haproxy_ui.db.change_publishes", return_value=jobs),
            mock.patch("haproxy_ui.db.cluster_history", return_value=listing),
            mock.patch("haproxy_ui.db.discard_cluster_change") as discard,
        ):
            kept = views._settled_changes(mock.Mock(), "edge-demo", {kind: head})
        return kept, discard

    def test_a_reading_at_the_publish_clears_it(self) -> None:
        kept, discard = self.settle("d" * 40, [self.job()])

        self.assertEqual(kept, {})
        self.assertEqual(discard.call_args.kwargs["expected_revision"], 2)

    def test_a_reading_at_a_later_version_clears_it(self) -> None:
        kept, _discard = self.settle("e" * 40, [self.job()])

        self.assertEqual(kept, {})

    def test_a_reading_still_at_the_base_keeps_it(self) -> None:
        kept, discard = self.settle("a" * 40, [self.job()])

        self.assertIn("network", kept)
        discard.assert_not_called()

    def test_a_reading_that_lags_behind_the_base_keeps_it(self) -> None:
        # The network is read by another helper run than the objects the base
        # came from, and can stand at an older version (review 26-10-08, F3).
        kept, discard = self.settle("c" * 40, [self.job()])

        self.assertIn("network", kept)
        discard.assert_not_called()

    def test_a_reading_the_listing_does_not_know_keeps_it(self) -> None:
        kept, _discard = self.settle("f" * 40, [self.job()])

        self.assertIn("network", kept)

    def test_a_kind_without_its_reading_is_kept(self) -> None:
        kept, _discard = self.settle(None, [self.job()])

        self.assertIn("network", kept)

    def test_a_publish_that_changed_nothing_clears_it_at_once(self) -> None:
        # It recorded the commit that was already there, which the reading shows.
        kept, _discard = self.settle("a" * 40, [self.job(commit="a" * 40, version=10)])

        self.assertEqual(kept, {})

    def test_settings_are_judged_by_their_own_reading(self) -> None:
        kept, _discard = self.settle("d" * 40, [self.job()], kind="settings")

        self.assertEqual(kept, {})

    def test_a_save_after_the_publish_is_not_cleared_by_it(self) -> None:
        kept, discard = self.settle("e" * 40, [self.job(revision=1)])

        self.assertIn("network", kept)
        discard.assert_not_called()


class TheSettingsFormSaves(SettingsClusterTestCase):
    def test_save_writes_the_settings_and_queues_nothing(self) -> None:
        answer = self.save(self.client_for(), settings_action="save")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/settings/clusters/service-demo")
        self.assertEqual(self.queued, [])
        self.assertEqual(self.saved_changes[0]["kind"], "settings")

    def test_a_publish_from_the_form_is_no_action(self) -> None:
        answer = self.save(self.client_for(), settings_action="publish")

        self.assertEqual(answer.status_code, 400)
        self.assertEqual((self.queued, self.saved_changes), ([], []))

    def test_the_page_shows_saved_settings(self) -> None:
        document = "metrics:\n  port: 9100\n  sources:\n  - 192.0.2.0/24\n"
        with mock.patch(
            "haproxy_ui.db.cluster_changes",
            return_value={"settings": saved("settings", document, cluster="edge-demo")},
        ):
            page = self.client_for().get("/settings/clusters/edge-demo").text

        self.assertIn('value="9100"', page)
        self.assertIn("<strong>Saved changes</strong> by operator", page)


if __name__ == "__main__":
    unittest.main()
