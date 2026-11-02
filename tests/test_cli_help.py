"""`--help` says what each flag is for, and keeps the examples as written (26-11-02)."""

from __future__ import annotations

import io
import unittest
from collections.abc import Callable
from contextlib import redirect_stdout

from haprion.cli import cert_delete, cert_request, cert_target, cluster


def helptext(main: Callable[..., int], *argv: str) -> str:
    shown = io.StringIO()
    try:
        with redirect_stdout(shown):
            main([*argv, "--help"])
    except SystemExit:
        pass
    return shown.getvalue()


class HelpIsNotThin(unittest.TestCase):
    def test_each_flag_of_cluster_add_and_remove_has_a_line(self) -> None:
        added = helptext(cluster.main, "add")
        for phrase in (
            "the new cluster's ID",
            "the address the cluster serves on",
            "the VIP's prefix",
        ):
            self.assertIn(phrase, added)
        self.assertIn("the cluster to remove", helptext(cluster.main, "remove"))

    def test_cert_delete_and_cert_target_describe_their_arguments(self) -> None:
        self.assertIn("the ID of a certificate to delete", helptext(cert_delete.main))
        text = helptext(cert_target.main)
        for phrase in ("a cluster; may be repeated", "a receiver; may be repeated"):
            self.assertIn(phrase, text)

    def test_the_cert_request_example_keeps_its_own_lines(self) -> None:
        text = helptext(cert_request.main)
        self.assertIn("\n    haprion-cert-request --id shop.example", text)
        self.assertIn("\n        --cluster alpha --receiver lb-01", text)


if __name__ == "__main__":
    unittest.main()
