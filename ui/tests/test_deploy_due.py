"""A deploy the nodes wait for looks it (review 2026-10-22, 7-19).

*Deploy configuration* was drawn the same on a converged cluster as on one
whose nodes were behind. The demo fixture has one of each: edge-demo
converged, service-demo behind.
"""

from __future__ import annotations

import re
from dataclasses import replace
from types import SimpleNamespace

from haprion_ui import dashboard
from tests.test_login import LoginTestCase, configuration

BUTTON = re.compile(
    r'name="cluster" value="([a-z-]+)".*?<button class="([^"]*)" type="submit">Deploy configuration<'
)


class TheDeployButton(LoginTestCase):
    def buttons(self, page: str) -> dict[str, str]:
        client = self.client(replace(configuration(), demo_fixture=True, management_writes=True))
        self.sign_in(client)
        text = client.get(page).text
        return {cluster: style for cluster, style in BUTTON.findall(text)}

    def test_is_marked_where_the_nodes_are_behind_and_only_there(self) -> None:
        for page in ("/", "/history"):
            with self.subTest(page):
                self.assertEqual(
                    self.buttons(page),
                    {
                        "edge-demo": "secondary-button",
                        "service-demo": "secondary-button deploy-due",
                    },
                )

    def test_behind_is_what_the_nodes_answered(self) -> None:
        def reading(state: object) -> SimpleNamespace:
            return SimpleNamespace(result={"summary": {"release_state": state}})

        self.assertTrue(dashboard.behind(reading("behind")))
        for state in ("converged", "incomplete", "unknown", None):
            with self.subTest(state):
                self.assertFalse(dashboard.behind(reading(state)))
        self.assertFalse(dashboard.behind(None))
