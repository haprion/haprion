"""`/healthz` judges what it reports (B332, review 2026-10-18 A2).

It used to answer 200 as soon as the database answered at all, while its
docstring promised that a wrong role or an empty database would be noticed -
and the installer, the rollback and the release lists read the answer as proof.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from unittest import mock

from haprion_ui import app, compatibility, db
from tests.test_login import LoginTestCase, configuration

REQUIREMENTS = compatibility.load_requirements(app.REQUIREMENTS)
HEAD = REQUIREMENTS.database_head


def found(**changes: Any) -> db.Health:
    healthy = db.Health(identity="_haprion-web", database="haprion_ui", web=True, revision=HEAD)
    return replace(healthy, **changes)


class Judged(LoginTestCase):
    def answer(self, health: db.Health) -> Any:
        with mock.patch.object(db, "health", return_value=health):
            response = self.client().get("/healthz")
        return response.status_code, response.json()

    def test_the_configured_database_as_the_web_on_this_release_s_schema_is_ok(self) -> None:
        database = configuration().database.name
        status, body = self.answer(found(database=database))
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["schema_revision"], HEAD)

    def test_each_wrong_thing_is_a_503_that_names_it(self) -> None:
        database = configuration().database.name
        cases = {
            "wrong_database": found(database="postgres"),
            "wrong_role": found(database=database, web=False),
            "schema_missing": found(database=database, revision=None),
            "schema_not_accepted": found(database=database, revision="0001"),
        }
        for code, health in cases.items():
            with self.subTest(code), self.assertLogs("haprion_ui", "WARNING"):
                status, body = self.answer(health)
                self.assertEqual(status, 503)
                self.assertFalse(body["ok"])
                self.assertEqual(body["error"]["code"], code)

    def test_a_newer_schema_is_a_rollback_and_answers(self) -> None:
        #
        # `haprion-rollback` runs an older release on a schema whose migrations
        # were declared safe for it; refusing that here would roll it forward.
        #
        database = configuration().database.name
        newer = str(int(HEAD) + 1).zfill(len(HEAD))
        status, _ = self.answer(found(database=database, revision=newer))
        self.assertEqual(status, 200)
