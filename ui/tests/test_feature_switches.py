"""Feature switches (Fas 13 part 3, §16.5, B193).

Held here: off hides the tab, the pages and the operations, and a kept URL
answers 404; receivers off leaves the certificates page one view, the
registry, and no form offers a receiver; node backups off queues one schedule
job per running timer with `enabled: false` and remembers the schedules, on
queues exactly those again; a busy cluster, a waiting restore or a schedule
that cannot be written back refuses the whole flip.
"""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest import mock

from haproxy_ui import auth, db, features
from haproxy_ui.db import FeatureSwitch
from tests.test_certificates import reading as certificate_reading
from tests.test_certificates import registered, with_registry
from tests.test_login import LoginTestCase, configuration

MOMENT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
SCHEDULE = {
    "time": "04:00",
    "frequency": "daily",
    "weekdays": [],
    "day_of_month": None,
    "retention": 14,
}


def switch(name: str, *, enabled: bool, remembered: dict[str, Any] | None = None) -> FeatureSwitch:
    return FeatureSwitch(name, enabled, remembered or {}, MOMENT, None)


class Switched(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.switches = {
            features.CERT_RECEIVERS: switch(features.CERT_RECEIVERS, enabled=True),
            features.NODE_BACKUPS: switch(features.NODE_BACKUPS, enabled=True),
        }
        self.flips: list[dict[str, Any]] = []
        self.queued: list[tuple[str, dict[str, Any]]] = []
        self.details: list[tuple[str, dict[str, Any]]] = []

        def flip(_c: object, **fields: Any) -> bool:
            self.flips.append(fields)
            return True

        def queue(_c: object, *, operation: str, cluster: str, payload: Any, **_: Any) -> Any:
            self.queued.append((cluster, dict(payload)))
            return SimpleNamespace(
                id=len(self.queued), cluster=cluster, operation=operation, request_id=None
            )

        def audit(_c: object, *, action: str, detail: Any = None, **_: Any) -> None:
            self.audit.append(action)
            self.details.append((action, dict(detail or {})))

        for patch in (
            mock.patch("haproxy_ui.db.set_feature_switch", side_effect=flip),
            mock.patch("haproxy_ui.db.queue_job", side_effect=queue),
            mock.patch("haproxy_ui.db.record_audit_event", side_effect=audit),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def off(self, name: str, remembered: dict[str, Any] | None = None) -> None:
        self.switches[name] = switch(name, enabled=False, remembered=remembered)

    def admin(self) -> Any:
        client = self.client(
            replace(configuration(), management_writes=True, clusters=("alpha", "beta"))
        )
        self.assertEqual(self.sign_in(client).status_code, 303)
        return client

    def post(self, client: Any, path: str, **fields: str) -> Any:
        token = auth.csrf_token(client.cookies[auth.SESSION_COOKIE])
        return client.post(path, data={auth.CSRF_FIELD: token, **fields}, follow_redirects=False)

    # - hiding -----------------------------------------------------------

    def test_node_backups_off_hides_the_tab_the_pages_and_the_operations(self) -> None:
        client = self.admin()
        self.assertIn('href="/backups"', client.get("/").text)

        self.off(features.NODE_BACKUPS)

        self.assertNotIn('href="/backups"', client.get("/").text)
        for path in ("/backups", "/backups/restore/new"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 404)
        answer = self.post(client, "/operations", operation="backup_run", cluster="alpha")
        self.assertEqual(answer.status_code, 404)
        self.assertEqual(self.queued, [])

    def test_receivers_off_hides_their_pages(self) -> None:
        client = self.admin()
        self.off(features.CERT_RECEIVERS)

        for path in ("/certificates/receivers", "/certificates/receivers/new"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 404)
        answer = self.post(client, "/certificates/receivers/new", receiver="lb-01")
        self.assertEqual(answer.status_code, 404)

    def test_receivers_off_leaves_one_view_the_registry_and_no_receiver_to_choose(self) -> None:
        reading = with_registry(
            certificate_reading(),
            registered(fingerprint="a" * 64),
            receivers=("lb-01",),
        )
        with mock.patch("haproxy_ui.db.cluster_certificates", return_value=[reading]):
            client = self.admin()
            on = client.get("/certificates").text
            self.assertIn("certificate-views", on)
            self.assertIn('href="/certificates/receivers"', on)

            self.off(features.CERT_RECEIVERS)
            page = client.get("/certificates?view=clusters").text
            form = client.get("/certificates/new").text

        self.assertIn("Certificate registry", page)
        self.assertNotIn("certificate-views", page)
        self.assertNotIn('href="/certificates/receivers"', page)
        self.assertNotIn("lb-01", form)
        self.assertNotIn("/certificates/receivers", form)

    # - the backup switch ------------------------------------------------

    def test_off_stops_every_running_schedule_and_remembers_it(self) -> None:
        client = self.admin()
        with mock.patch(
            "haproxy_ui.features.schedules_to_stop",
            return_value={"alpha": SCHEDULE, "beta": {**SCHEDULE, "time": "05:00"}},
        ):
            answer = self.post(client, "/settings/features/node_backups", enabled="off")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(answer.headers["location"], "/settings?switched=node_backups-off")
        self.assertEqual(
            self.queued,
            [
                ("alpha", {**SCHEDULE, "enabled": False}),
                ("beta", {**SCHEDULE, "time": "05:00", "enabled": False}),
            ],
        )
        (flipped,) = self.flips
        self.assertEqual((flipped["name"], flipped["enabled"]), ("node_backups", False))
        self.assertEqual(sorted(flipped["remembered"]["schedules"]), ["alpha", "beta"])
        switched = [detail for action, detail in self.details if action == "feature_switched"]
        self.assertEqual(
            switched,
            [
                {
                    "feature": "node_backups",
                    "enabled": False,
                    "schedules": ["alpha", "beta"],
                    "via": "web",
                }
            ],
        )

    def test_on_starts_exactly_what_off_stopped(self) -> None:
        self.off(features.NODE_BACKUPS, remembered={"schedules": {"beta": SCHEDULE}})
        client = self.admin()

        answer = self.post(client, "/settings/features/node_backups", enabled="on")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.queued, [("beta", {**SCHEDULE, "enabled": True})])
        self.assertEqual(self.flips[0]["remembered"], {})

    def test_a_busy_cluster_refuses_the_whole_flip(self) -> None:
        client = self.admin()
        rollbacks = self.pool.rollbacks
        with (
            mock.patch("haproxy_ui.features.schedules_to_stop", return_value={"alpha": SCHEDULE}),
            mock.patch("haproxy_ui.db.queue_job", side_effect=db.ClusterBusy()),
        ):
            answer = self.post(client, "/settings/features/node_backups", enabled="off")

        self.assertEqual(answer.status_code, 409)
        self.assertIn("A job is running on one of the clusters.", answer.text)
        self.assertEqual(self.pool.rollbacks, rollbacks + 1)
        self.assertNotIn("feature_switched", self.audit)

    def test_a_schedule_that_cannot_be_written_back_refuses_before_anything_is_written(
        self,
    ) -> None:
        client = self.admin()
        with mock.patch(
            "haproxy_ui.features.schedules_to_stop",
            side_effect=features.SwitchRefused("alpha's retention could not be read."),
        ):
            answer = self.post(client, "/settings/features/node_backups", enabled="off")

        self.assertEqual(answer.status_code, 409)
        self.assertIn("retention could not be read", answer.text)
        self.assertEqual((self.flips, self.queued), ([], []))

    def test_receivers_flip_without_a_question_or_a_job(self) -> None:
        client = self.admin()

        page = client.get("/settings").text
        self.assertIn('<form method="get" action="/settings/features/node_backups"', page)
        self.assertIn('role="switch" aria-checked="true" aria-label="Node backups"', page)
        answer = self.post(client, "/settings/features/cert_receivers", enabled="off")

        self.assertEqual(answer.status_code, 303)
        self.assertEqual(self.queued, [])
        self.assertEqual(self.flips[0]["enabled"], False)
        self.assertIn(
            "Registered receivers still get new certificates.",
            client.get("/settings?switched=cert_receivers-off").text,
        )

    def test_the_question_names_what_off_does(self) -> None:
        page = self.admin().get("/settings/features/node_backups").text

        self.assertIn("Existing archives are kept", page)
        self.assertIn('name="enabled" value="off"', page)

    def test_a_forged_form_and_an_unknown_switch_are_refused(self) -> None:
        client = self.admin()

        forged = client.post(
            "/settings/features/cert_receivers",
            data={auth.CSRF_FIELD: "forged", "enabled": "off"},
            follow_redirects=False,
        )
        self.assertEqual(forged.status_code, 403)
        self.assertEqual(
            self.post(client, "/settings/features/traffic", enabled="off").status_code, 404
        )
        self.assertEqual(self.flips, [])


class WhatOffStops(unittest.TestCase):
    def overview(self, *clusters: Any) -> Any:
        return SimpleNamespace(clusters=clusters)

    def cluster(self, name: str, *, stale: bool = False, **schedule: Any) -> Any:
        values: dict[str, Any] = {
            "enabled": True,
            "calendar": "*-*-* 04:00:00",
            "time": "04:00",
            "frequency": "daily",
            "weekdays": (),
            "day_of_month": 1,
            "retention": 14,
        }
        values.update(schedule)
        return SimpleNamespace(cluster=name, stale=stale, schedule=SimpleNamespace(**values))

    def test_a_running_timer_is_kept_whole_and_a_stopped_one_is_left_out(self) -> None:
        stopping = features.schedules_to_stop(
            self.overview(self.cluster("alpha"), self.cluster("beta", enabled=False))
        )

        self.assertEqual(list(stopping), ["alpha"])
        self.assertEqual(stopping["alpha"]["retention"], 14)

    def test_what_would_be_guessed_is_refused(self) -> None:
        for cluster, words in (
            (self.cluster("alpha", stale=True), "no fresh backup reading"),
            (self.cluster("alpha", retention=None), "retention could not be read"),
            (self.cluster("alpha", calendar="Mon..Fri 04:00"), "cannot write back"),
        ):
            with self.subTest(words=words), self.assertRaises(features.SwitchRefused) as raised:
                features.schedules_to_stop(self.overview(cluster))
            self.assertIn(words, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
