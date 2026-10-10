"""Who asked for a version, and which account ran the helper (B207).

Held here: a name reaches a trailer only whole and printable, so a line break
can never start a trailer of its own; the person is recorded only when the
interface's worker names one, and the proven account beside it; anyone else,
or nobody named, means the proven account is both; the listing reads the
person back.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from haprion.helper_protocol import HelperProtocolError
from haprion.version_history import (
    MAX_NAME_LENGTH,
    UnfitName,
    caller_account,
    recent_versions,
    request_names,
    requester,
    trailer_name,
    with_request_trailer,
)
from tests.test_publish_helper import git


class NamesTests(unittest.TestCase):
    def test_an_ordinary_name_and_a_display_name_stand(self) -> None:
        for name in ("admin", "svc-app", "Ada Admin", "ada@example.com", "Åsa"):
            with self.subTest(name=name):
                self.assertEqual(trailer_name(name), name)

    def test_what_could_forge_or_blur_a_trailer_is_refused(self) -> None:
        for name in (
            "",
            " ",
            "ada\nRequest-Id: forged",
            "ada\r",
            "ada\t",
            " ada",
            "ada ",
            "ada b",
            "x" * (MAX_NAME_LENGTH + 1),
            None,
            7,
        ):
            with self.subTest(name=name), self.assertRaises(UnfitName):
                trailer_name(name)

    def test_the_named_person_is_recorded_beside_the_proven_account(self) -> None:
        self.assertEqual(
            requester(
                {"requested_by": "Ada Admin"}, {"SUDO_USER": "svc-app"}, interface_account="svc-app"
            ),
            ("Ada Admin", "svc-app"),
        )
        self.assertEqual(requester({}, {"SUDO_USER": "operator"}), ("operator", "operator"))

    def test_only_the_interfaces_worker_may_name_somebody_else(self) -> None:
        named = {"requested_by": "Ada Admin"}
        for sudo_user, worker in (("operator", "svc-app"), ("svc-app", None)):
            with self.subTest(sudo_user=sudo_user, worker=worker):
                self.assertEqual(
                    requester(named, {"SUDO_USER": sudo_user}, interface_account=worker),
                    (sudo_user, sudo_user),
                )
        #
        # Refused whoever sends it: a name that could forge a trailer is bad
        # input even when it would not have been recorded.
        #
        with self.assertRaises(UnfitName):
            requester(
                {"requested_by": "a\nb"}, {"SUDO_USER": "operator"}, interface_account="svc-app"
            )

    def test_without_sudo_the_helpers_own_account_is_the_proven_one(self) -> None:
        self.assertTrue(caller_account({}))
        self.assertEqual(caller_account({"SUDO_USER": "bad\nname"}), caller_account({}))

    def test_a_helper_refuses_an_unfit_name_as_bad_input(self) -> None:
        with self.assertRaises(HelperProtocolError) as raised:
            request_names({"requested_by": "a\nb"}, {"SUDO_USER": "operator"})
        self.assertEqual(raised.exception.exit_code, 65)

    def test_the_trailers_are_written_and_read_back(self) -> None:
        message = with_request_trailer(
            "Publish the shop", "req-1", requested_by="Ada Admin", run_by="svc-app"
        )
        self.assertEqual(
            message,
            "Publish the shop\n\nRequest-Id: req-1\nRequested-By: Ada Admin\nRun-By: svc-app\n",
        )
        self.assertEqual(with_request_trailer("Old", "req-2"), "Old\n\nRequest-Id: req-2\n")

        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)

            git(repo, "init", "-q", "-b", "main")
            git(repo, "config", "user.name", "operator")
            git(repo, "config", "user.email", "operator@example.com")
            git(repo, "commit", "-q", "--allow-empty", "-m", with_request_trailer("Old", "req-2"))
            git(repo, "commit", "-q", "--allow-empty", "-m", message)

            newest, oldest = recent_versions(repo)

        self.assertEqual((newest.requested_by, newest.request_id), ("Ada Admin", "req-1"))
        self.assertEqual((oldest.requested_by, oldest.request_id), (None, "req-2"))
        self.assertEqual(newest.comment, "Publish the shop")


if __name__ == "__main__":
    unittest.main()
