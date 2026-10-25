"""What an apply command makes of a helper that did not answer as it should (review 26-10-24, 06-05)."""

from __future__ import annotations

import subprocess
import unittest

from haprion import exit_codes
from haprion.cli.apply_common import Refused, answer_of

ERROR = '{"operation": "objects", "outcome": "failed", "error": {"code": "x", "message": "no"}}'


def completed(
    returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["sudo"], returncode, stdout, stderr)


class AnExitTheTableHas(unittest.TestCase):
    def refused(self, *args: object, **kwargs: object) -> Refused:
        with self.assertRaises(Refused) as caught:
            answer_of(*args, **kwargs)  # type: ignore[arg-type]
        return caught.exception

    def test_a_signal_or_a_helper_that_never_ran_is_unavailable(self) -> None:
        for returned in (-9, 126, 127, 0):
            with self.subTest(returned=returned):
                refusal = self.refused(completed(returned, stderr="Killed\\n"), "objects")
                self.assertEqual(
                    (refusal.code, refusal.exit_code),
                    ("dependency_unavailable", exit_codes.UNAVAILABLE),
                )

    def test_a_refusal_keeps_the_helper_s_own_exit_when_the_table_has_it(self) -> None:
        self.assertEqual(
            self.refused(completed(75, ERROR), "objects").exit_code, exit_codes.BLOCKED
        )
        self.assertEqual(
            self.refused(completed(-15, ERROR), "objects").exit_code, exit_codes.REFUSED
        )

    def test_a_publish_that_never_answered_is_unknown_not_failed(self) -> None:
        refusal = self.refused(completed(-9, stderr="Killed\\n"), "changes_publish", changes=True)
        self.assertEqual((refusal.code, refusal.exit_code), ("helper_silent", exit_codes.FAILED))
        self.assertIn("whether it published is unknown", str(refusal))
        self.assertIn("haprion-list", str(refusal))
        self.assertIn("Killed", str(refusal))


if __name__ == "__main__":
    unittest.main()
