"""tools/release-plan: what the automatic release does next (B355, B505, B506)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
APP = "haprion-upstream-watch[bot]"


def load(name: str, relative: Path) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(relative))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


PLAN = load("release_plan", BASE / "tools" / "release-plan")


class Repository:
    """A main branch with a release tag, and merges onto it at set times."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "--quiet", "--initial-branch=main")
        for relative, text in (
            ("pyproject.toml", '[project]\nname = "haprion"\nversion = "1.1.0"\n'),
            ("ui/pyproject.toml", '[project]\nname = "haprion-ui"\nversion = "1.1.0"\n'),
            ("src/haprion/__init__.py", '"""Engine."""\n\n__version__ = "1.1.0"\n'),
            ("uv.lock", "lock 0\n"),
            ("ui/uv.lock", "lock 0\n"),
            ("certbot/uv.lock", "lock 0\n"),
            ("tools/build-coraza-package.py", "PIN = 0\n"),
            ("src/haprion/generate.py", "x = 0\n"),
            (".github/workflows/ci.yml", "name: CI\n"),
        ):
            self.write(relative, text)
        self.commit("ssavant2", "Version 1.1.0", "2026-11-14T10:00:00+00:00")
        self.git("tag", "v1.1.0")

    def git(
        self, *args: str, author: str = "ssavant2", when: str = "2026-11-14T10:00:00+00:00"
    ) -> str:
        environment = dict(
            os.environ,
            GIT_AUTHOR_NAME=author,
            GIT_AUTHOR_EMAIL=f"{author.strip('[]')}@users.noreply.example.com",
            GIT_COMMITTER_NAME=author,
            GIT_COMMITTER_EMAIL=f"{author.strip('[]')}@users.noreply.example.com",
            GIT_AUTHOR_DATE=when,
            GIT_COMMITTER_DATE=when,
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
        )
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, author: str, subject: str, when: str) -> None:
        self.git("add", "--all", author=author, when=when)
        self.git("commit", "--quiet", "--message", subject, author=author, when=when)

    def merge(
        self,
        number: int,
        author: str,
        subject: str,
        files: dict[str, str],
        *,
        made: str,
        landed: str,
    ) -> None:
        """A pull request: a branch with one commit, merged onto main with a merge commit."""

        branch = f"proposal-{number}"
        self.git("checkout", "--quiet", "-b", branch)
        for relative, text in files.items():
            self.write(relative, text)
        self.commit(author, subject, made)
        self.git("checkout", "--quiet", "main")
        self.git(
            "merge",
            "--quiet",
            "--no-ff",
            "--message",
            f"Merge pull request #{number} from example/{branch}",
            branch,
            author=APP,
            when=landed,
        )

    def decide(self, now: str) -> Any:
        tag = PLAN.last_tag(self.root)
        return PLAN.plan(
            PLAN.changes_since(self.root, tag, APP),
            tag,
            datetime.fromisoformat(now),
            head_version=PLAN.head_version(self.root),
        )


class ReleasePlanTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repository = Repository(Path(directory.name))

    def locks(self, number: int, landed: str) -> None:
        self.repository.merge(
            number,
            APP,
            PLAN.LOCKS_SUBJECT,
            {"uv.lock": f"lock {number}\n", "ui/uv.lock": f"lock {number}\n"},
            made=landed,
            landed=landed,
        )

    def waf(self, number: int, landed: str, *, security: bool = False) -> None:
        self.repository.merge(
            number,
            APP,
            PLAN.WAF_SECURITY_SUBJECT if security else PLAN.WAF_SUBJECT,
            {"tools/build-coraza-package.py": f"PIN = {number}\n"},
            made=landed,
            landed=landed,
        )

    def test_nothing_since_the_tag_is_nothing(self) -> None:
        result = self.repository.decide("2026-12-05T00:00:00+00:00")

        self.assertEqual(result.outcome, "nothing")
        self.assertIsNone(result.next)

    def test_an_update_of_the_actions_never_releases(self) -> None:
        self.repository.merge(
            3,
            PLAN.DEPENDABOT,
            "Bump the actions group with 2 updates",
            {".github/workflows/ci.yml": "name: CI 2\n"},
            made="2026-11-15T08:00:00+00:00",
            landed="2026-11-15T09:00:00+00:00",
        )

        result = self.repository.decide("2027-02-01T00:00:00+00:00")

        self.assertEqual(result.outcome, "nothing")
        self.assertEqual([change.kind for change in result.changes], ["actions"])

    def test_a_security_fix_waits_one_day_from_its_merge(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")

        waiting = self.repository.decide("2026-11-16T08:59:00+00:00")
        due = self.repository.decide("2026-11-16T09:00:00+00:00")

        self.assertEqual(waiting.outcome, "wait")
        self.assertEqual(waiting.due_at, "2026-11-16T09:00:00+00:00")
        self.assertTrue(waiting.security)
        self.assertEqual(due.outcome, "release")
        self.assertEqual(due.next, "1.1.1")
        self.assertEqual(due.reason, "a security fix has waited a day")

    def test_the_day_starts_with_the_first_security_fix_and_takes_what_came_after(self) -> None:
        self.waf(5, "2026-11-15T09:00:00+00:00")
        self.locks(6, "2026-11-20T09:00:00+00:00")
        self.locks(7, "2026-11-21T08:00:00+00:00")

        result = self.repository.decide("2026-11-21T09:00:00+00:00")

        self.assertEqual(result.outcome, "release")
        self.assertEqual([change.pull_request for change in result.changes], [5, 6, 7])

    def test_a_waf_update_without_a_finding_waits_for_the_month(self) -> None:
        self.waf(8, "2026-11-15T09:00:00+00:00")

        waiting = self.repository.decide("2026-11-30T23:59:00+00:00")
        due = self.repository.decide("2026-12-01T00:00:00+00:00")

        self.assertEqual(waiting.outcome, "wait")
        self.assertFalse(waiting.security)
        self.assertEqual(waiting.due_at, "2026-12-01T00:00:00+00:00")
        self.assertEqual(due.outcome, "release")
        self.assertEqual(due.reason, "the month's fixes are due")

    def test_december_s_fixes_are_due_in_january(self) -> None:
        self.waf(9, "2026-12-10T09:00:00+00:00")

        result = self.repository.decide("2026-12-20T00:00:00+00:00")

        self.assertEqual(result.due_at, "2027-01-01T00:00:00+00:00")

    def test_a_waf_update_for_a_finding_is_a_security_fix(self) -> None:
        self.waf(10, "2026-11-15T09:00:00+00:00", security=True)

        result = self.repository.decide("2026-11-16T09:00:00+00:00")

        self.assertEqual(result.outcome, "release")
        self.assertTrue(result.security)

    def test_a_person_s_commit_blocks_the_release(self) -> None:
        self.locks(11, "2026-11-15T09:00:00+00:00")
        self.repository.write("src/haprion/generate.py", "x = 1\n")
        self.repository.commit("ssavant2", "Generate something new", "2026-11-15T10:00:00+00:00")

        result = self.repository.decide("2026-11-20T00:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertTrue(result.security)
        self.assertIn("Generate something new", result.reason)

    def test_the_watch_s_subject_on_other_files_is_not_the_watch(self) -> None:
        self.repository.merge(
            12,
            APP,
            PLAN.LOCKS_SUBJECT,
            {"uv.lock": "lock 12\n", "src/haprion/generate.py": "x = 2\n"},
            made="2026-11-15T09:00:00+00:00",
            landed="2026-11-15T09:00:00+00:00",
        )

        result = self.repository.decide("2026-11-20T00:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")

    def test_the_watch_s_subject_from_a_person_is_not_the_watch(self) -> None:
        self.repository.merge(
            13,
            "ssavant2",
            PLAN.LOCKS_SUBJECT,
            {"uv.lock": "lock 13\n"},
            made="2026-11-15T09:00:00+00:00",
            landed="2026-11-15T09:00:00+00:00",
        )

        self.assertEqual(self.repository.decide("2026-11-20T00:00:00+00:00").outcome, "blocked")

    def bump_merged(self, version: str) -> None:
        self.repository.git("checkout", "--quiet", "-b", "release-watch")
        PLAN.bump(self.repository.root, version)
        self.repository.commit(APP, f"Version {version}", "2026-11-16T10:00:00+00:00")
        self.repository.git("checkout", "--quiet", "main")
        self.repository.git(
            "merge",
            "--quiet",
            "--no-ff",
            "--message",
            "Merge pull request #14 from example/release-watch",
            "release-watch",
            author=APP,
            when="2026-11-16T10:30:00+00:00",
        )

    def test_the_merged_version_is_tagged(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.bump_merged("1.1.1")

        result = self.repository.decide("2026-11-16T11:00:00+00:00")

        self.assertEqual(result.outcome, "tag")
        self.assertEqual(result.next, "1.1.1")
        self.assertTrue(result.security)

    def test_a_version_other_than_the_next_patch_is_left_for_a_person(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.bump_merged("1.2.0")

        result = self.repository.decide("2026-11-16T11:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertIn("1.2.0", result.reason)

    def test_bump_writes_the_three_version_lines(self) -> None:
        PLAN.bump(self.repository.root, "1.1.1")

        root = self.repository.root
        self.assertIn('version = "1.1.1"', (root / "pyproject.toml").read_text())
        self.assertIn('version = "1.1.1"', (root / "ui/pyproject.toml").read_text())
        self.assertIn('__version__ = "1.1.1"', (root / "src/haprion/__init__.py").read_text())
        self.assertEqual(PLAN.head_version(root), "1.1.1")

    def test_bump_refuses_what_is_not_a_version(self) -> None:
        with self.assertRaises(PLAN.PlanError):
            PLAN.bump(self.repository.root, "1.1")

    def test_the_note_lists_what_a_package_carries(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.repository.merge(
            5,
            PLAN.DEPENDABOT,
            "Bump the actions group",
            {".github/workflows/ci.yml": "name: CI 3\n"},
            made="2026-11-15T10:00:00+00:00",
            landed="2026-11-15T10:00:00+00:00",
        )

        note = PLAN.notes(self.repository.decide("2026-11-16T09:00:00+00:00"))

        self.assertIn(f"- #4 {PLAN.LOCKS_SUBJECT} (security)", note)
        self.assertNotIn("actions group", note)
        self.assertIn("v1.1.0", note)

    def test_the_command_answers_in_json(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        out = self.repository.root / "note.md"

        completed = subprocess.run(
            [
                sys.executable,
                str(BASE / "tools" / "release-plan"),
                "decide",
                "--source",
                str(self.repository.root),
                "--now",
                "2026-11-16T09:00:00+00:00",
                "--app",
                APP,
                "--notes",
                str(out),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('"outcome": "release"', completed.stdout)
        self.assertTrue(out.read_text().startswith("An automatic patch release"))

    def test_a_time_without_a_zone_is_refused(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(BASE / "tools" / "release-plan"),
                "decide",
                "--source",
                str(self.repository.root),
                "--now",
                "2026-11-16T09:00:00",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
