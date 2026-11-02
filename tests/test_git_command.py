from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from haprion.git_command import trusted

REPO = Path("/srv/haprion/config/alpha")


class GitTrustsWhatRootOwns(unittest.TestCase):
    """26-11-02: a member of the configuration group reads root's repositories."""

    def trust(self, *, caller: int, owner: int | None) -> list[str]:
        stat = (
            mock.patch.object(Path, "stat", side_effect=FileNotFoundError())
            if owner is None
            else mock.patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=owner))
        )
        with mock.patch("haprion.git_command.os.geteuid", return_value=caller), stat:
            return trusted(REPO)

    def test_a_reader_trusts_one_repository_root_owns_by_its_exact_path(self) -> None:
        self.assertEqual(self.trust(caller=1000, owner=0), ["-c", f"safe.directory={REPO}"])

    def test_a_repository_another_account_owns_is_never_trusted(self) -> None:
        self.assertEqual(self.trust(caller=1000, owner=1001), [])

    def test_root_keeps_its_own_configuration(self) -> None:
        self.assertEqual(self.trust(caller=0, owner=0), [])

    def test_a_path_that_is_not_there_is_left_to_git(self) -> None:
        self.assertEqual(self.trust(caller=1000, owner=None), [])


if __name__ == "__main__":
    unittest.main()
