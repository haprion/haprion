from __future__ import annotations

import unittest
from dataclasses import replace

from tests.test_login import LoginTestCase, configuration


class OperationControlsTests(LoginTestCase):
    def test_an_admin_sees_one_keyed_form_for_each_safe_initial_operation(self) -> None:
        client = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(client)

        page = client.get("/")

        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.text.count('action="/operations"'), 2)
        self.assertIn('name="operation" value="deploy"', page.text)
        self.assertIn('name="operation" value="cert_deploy"', page.text)
        self.assertEqual(page.text.count('name="idempotency_key" value="'), 2)

    def test_the_controls_are_absent_when_writes_are_off_or_the_role_is_reader(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        self.assertNotIn('action="/operations"', client.get("/").text)

        self.account = replace(self.account, role="reader")
        reader = self.client(replace(configuration(), management_writes=True, clusters=("alpha",)))
        self.sign_in(reader)
        self.assertNotIn('action="/operations"', reader.get("/").text)


if __name__ == "__main__":
    unittest.main()
