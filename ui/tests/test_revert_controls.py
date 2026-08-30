from __future__ import annotations

import unittest
from dataclasses import replace
from unittest import mock

from tests.test_history import reading
from tests.test_login import LoginTestCase, configuration


class RevertControlsTests(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.history_rows = mock.patch(
            "haproxy_ui.db.cluster_histories", return_value=[reading(cluster="alpha")]
        )
        self.history_rows.start()
        self.addCleanup(self.history_rows.stop)

    def test_an_admin_posts_the_full_polled_commit_not_the_display_prefix(self) -> None:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)

        page = client.get("/history")

        self.assertEqual(page.status_code, 200)
        self.assertIn('name="operation" value="revert"', page.text)
        self.assertIn('name="version" value="12"', page.text)
        self.assertIn('name="expected_commit" value="' + "a" * 40 + '"', page.text)
        self.assertIn("Does not deploy", page.text)

    def test_read_only_and_reader_views_do_not_render_a_revert_control(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        self.assertNotIn('name="operation" value="revert"', client.get("/history").text)

        self.account = replace(self.account, role="reader")
        reader = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(reader)
        self.assertNotIn('name="operation" value="revert"', reader.get("/history").text)


if __name__ == "__main__":
    unittest.main()
