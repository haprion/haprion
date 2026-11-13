"""tools/release-plan: what the automatic release does next (B355, B505, B506)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
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
        self.pulls: dict[int, dict[str, Any]] = {}
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
        self.commit("operator", "Version 1.1.0", "2026-11-14T10:00:00+00:00")
        self.git("tag", "v1.1.0")

    def git(
        self, *args: str, author: str = "operator", when: str = "2026-11-14T10:00:00+00:00"
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
        self.register(number, author)

    def register(self, number: int, opened_by: str) -> None:
        """What GitHub says of pull request `number`: merged as main's head."""

        self.pulls[number] = {
            "number": number,
            "author": opened_by,
            "merge_commit_sha": self.git("rev-parse", "HEAD").strip(),
        }

    def pulls_file(self) -> Path:
        path = self.root.parent / f"{self.root.name}-pulls.json"
        path.write_text(json.dumps(list(self.pulls.values())), encoding="utf-8")
        return path

    def decide(self, now: str, *, pulls: bool = True, known: Any = None) -> Any:
        read = PLAN.read_pulls(self.pulls_file()) if pulls else None
        return PLAN.decide(
            self.root,
            PLAN.last_tag(self.root),
            APP,
            read,
            datetime.fromisoformat(now),
            known or PLAN.Known(),
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
        self.repository.commit("operator", "Generate something new", "2026-11-15T10:00:00+00:00")

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
            "operator",
            PLAN.LOCKS_SUBJECT,
            {"uv.lock": "lock 13\n"},
            made="2026-11-15T09:00:00+00:00",
            landed="2026-11-15T09:00:00+00:00",
        )

        self.assertEqual(self.repository.decide("2026-11-20T00:00:00+00:00").outcome, "blocked")

    def test_no_pull_request_data_verifies_no_merge(self) -> None:
        self.locks(15, "2026-11-15T09:00:00+00:00")

        result = self.repository.decide("2026-11-20T00:00:00+00:00", pulls=False)

        self.assertEqual(result.outcome, "blocked")
        self.assertIn("no pull request data", result.reason)

    def test_a_pull_request_opened_by_a_person_is_not_the_watch(self) -> None:
        self.locks(16, "2026-11-15T09:00:00+00:00")
        self.repository.pulls[16]["author"] = "operator"

        result = self.repository.decide("2026-11-20T00:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertIn("opened by operator", result.reason)

    def test_a_merge_commit_github_did_not_make_is_not_verified(self) -> None:
        self.locks(17, "2026-11-15T09:00:00+00:00")
        self.repository.pulls[17]["merge_commit_sha"] = "0" * 40

        result = self.repository.decide("2026-11-20T00:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertIn("merged as 00000000", result.reason)

    def test_a_pull_request_that_was_not_read_is_not_verified(self) -> None:
        self.locks(18, "2026-11-15T09:00:00+00:00")
        del self.repository.pulls[18]

        self.assertEqual(self.repository.decide("2026-11-20T00:00:00+00:00").outcome, "blocked")

    def test_a_direct_commit_with_the_app_s_name_is_not_the_watch(self) -> None:
        self.repository.write("uv.lock", "lock 19\n")
        self.repository.commit(APP, PLAN.LOCKS_SUBJECT, "2026-11-15T09:00:00+00:00")

        result = self.repository.decide("2026-11-20T00:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertIn("no pull request merged", result.reason)

    def test_a_merge_on_the_branch_is_blocked_with_what_it_carries(self) -> None:
        # A person merges main into the watch's branch and edits a file in the merge commit.
        repository = self.repository
        repository.git("checkout", "--quiet", "-b", "upstream-watch")
        repository.write("tools/build-coraza-package.py", "PIN = 20\n")
        repository.commit(APP, PLAN.WAF_SUBJECT, "2026-11-15T10:00:00+00:00")
        repository.git("checkout", "--quiet", "main")
        repository.write("certbot/uv.lock", "lock 1\n")
        repository.commit(APP, "Something on main", "2026-11-15T10:30:00+00:00")
        repository.git("checkout", "--quiet", "upstream-watch")
        repository.git("merge", "--quiet", "--no-ff", "--no-commit", "main")
        repository.write("src/haprion/generate.py", "x = 'person'\n")
        repository.git("add", "--all")
        repository.git("commit", "--quiet", "--message", "Merge branch 'main'")
        repository.git("checkout", "--quiet", "main")
        repository.git(
            "merge",
            "--quiet",
            "--no-ff",
            "--message",
            "Merge pull request #20 from example/upstream-watch",
            "upstream-watch",
            author=APP,
            when="2026-11-15T11:00:00+00:00",
        )
        repository.register(20, APP)

        result = repository.decide("2026-12-02T00:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertTrue(any("on the pull request's branch" in c.why for c in result.changes))

    def test_content_in_a_merge_on_main_is_blocked_even_when_github_says_so(self) -> None:
        repository = self.repository
        repository.git("checkout", "--quiet", "-b", "dependency-watch")
        repository.write("uv.lock", "lock 21\n")
        repository.commit(APP, PLAN.LOCKS_SUBJECT, "2026-11-15T10:00:00+00:00")
        repository.git("checkout", "--quiet", "main")
        repository.git("merge", "--quiet", "--no-ff", "--no-commit", "dependency-watch")
        repository.write("src/haprion/generate.py", "x = 'person'\n")
        repository.git("add", "--all")
        repository.git(
            "commit",
            "--quiet",
            "--message",
            "Merge pull request #21 from example/dependency-watch",
            author=APP,
            when="2026-11-15T11:00:00+00:00",
        )
        repository.register(21, APP)

        result = repository.decide("2026-11-16T12:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertIn("src/haprion/generate.py", result.reason)

    def test_the_decide_command_reads_the_pull_requests_file(self) -> None:
        self.locks(22, "2026-11-15T09:00:00+00:00")

        def run(*extra: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
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
                    *extra,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertIn(
            '"outcome": "release"', run("--pulls", str(self.repository.pulls_file())).stdout
        )
        self.assertIn('"outcome": "blocked"', run().stdout)

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
        self.repository.register(14, APP)

    def test_the_merged_version_is_tagged(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.bump_merged("1.1.1")

        result = self.repository.decide("2026-11-16T11:00:00+00:00")

        self.assertEqual(result.outcome, "tag")
        self.assertEqual(result.next, "1.1.1")
        self.assertTrue(result.security)

    def test_what_lands_after_the_version_merge_is_not_in_the_release(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.bump_merged("1.1.1")
        merged = self.repository.git("rev-parse", "HEAD").strip()
        self.waf(5, "2026-11-16T10:41:00+00:00")

        result = self.repository.decide("2026-11-16T10:53:00+00:00")

        self.assertEqual(result.outcome, "tag")
        self.assertEqual(result.tag_commit, merged)
        self.assertNotEqual(result.tag_commit, self.repository.git("rev-parse", "HEAD").strip())
        self.assertEqual(result.pull_head, self.repository.git("rev-parse", f"{merged}^2").strip())
        self.assertNotIn(5, [change.pull_request for change in result.changes])

    def test_a_person_s_commit_after_the_version_merge_waits_for_the_next_run(self) -> None:
        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.bump_merged("1.1.1")
        self.repository.write("src/haprion/generate.py", "x = 1\n")
        self.repository.commit("operator", "Generate something new", "2026-11-16T11:00:00+00:00")

        self.assertEqual(self.repository.decide("2026-11-16T11:05:00+00:00").outcome, "tag")

    def test_a_version_merge_that_is_not_the_tested_head_is_not_tagged(self) -> None:
        # The proposal was made on an older main; the merge brought a newer
        # WAF pin along, which the installation test never saw.
        repository = self.repository
        self.locks(4, "2026-11-15T09:00:00+00:00")
        repository.git("checkout", "--quiet", "-b", "release-watch")
        PLAN.bump(repository.root, "1.1.1")
        repository.commit(APP, "Version 1.1.1", "2026-11-16T10:00:00+00:00")
        repository.git("checkout", "--quiet", "main")
        self.waf(5, "2026-11-16T10:10:00+00:00")
        repository.git(
            "merge",
            "--quiet",
            "--no-ff",
            "--message",
            "Merge pull request #14 from example/release-watch",
            "release-watch",
            author=APP,
            when="2026-11-16T10:30:00+00:00",
        )
        repository.register(14, APP)

        result = repository.decide("2026-11-16T11:00:00+00:00")

        self.assertEqual(result.outcome, "blocked")
        self.assertIsNone(result.tag_commit)
        self.assertIn("other than its pull request's head", result.reason)

    def tagged(self, version: str = "1.1.1") -> str:
        """The proposal merged and tagged as the workflow does: the tag on the merge."""

        self.locks(4, "2026-11-15T09:00:00+00:00")
        self.bump_merged(version)
        self.repository.git("tag", f"v{version}")
        return self.repository.git("rev-parse", "HEAD").strip()

    def test_an_automatic_tag_without_a_release_is_built_again(self) -> None:
        merge = self.tagged()

        result = self.repository.decide(
            "2026-11-16T12:00:00+00:00", known=PLAN.Known(release="missing")
        )

        self.assertEqual(result.outcome, "rebuild")
        self.assertEqual(result.next, "1.1.1")
        self.assertEqual(result.tag_commit, merge)

    def test_a_tag_made_by_hand_without_a_release_is_left_alone(self) -> None:
        result = self.repository.decide(
            "2026-11-16T12:00:00+00:00", known=PLAN.Known(release="missing")
        )

        self.assertEqual(result.outcome, "nothing")

    def test_a_tag_on_a_merge_a_person_opened_is_not_automatic(self) -> None:
        self.tagged()
        self.repository.pulls[14]["author"] = "operator"

        result = self.repository.decide(
            "2026-11-16T12:00:00+00:00", known=PLAN.Known(release="missing")
        )

        self.assertNotEqual(result.outcome, "rebuild")

    def test_a_release_present_is_no_rebuild(self) -> None:
        self.tagged()

        result = self.repository.decide(
            "2026-11-16T12:00:00+00:00", known=PLAN.Known(release="present")
        )

        self.assertEqual(result.outcome, "nothing")

    def known(self, *published: str, released: str = "2026-11-16T11:00:00+00:00") -> Any:
        return PLAN.Known(
            release="present",
            released_at=datetime.fromisoformat(released),
            published=published,
        )

    def test_a_repository_that_does_not_serve_the_tag_after_three_hours_is_reported(self) -> None:
        self.tagged()

        late = self.repository.decide(
            "2026-11-16T14:00:00+00:00", known=self.known("1.1.0+git20261110120000.0123456789ab")
        )
        early = self.repository.decide(
            "2026-11-16T13:59:00+00:00", known=self.known("1.1.0+git20261110120000.0123456789ab")
        )

        self.assertIn("haprion-cli 1.1.1", late.repository)
        self.assertEqual(early.repository, "")

    def test_a_repository_that_serves_the_tag_is_fine(self) -> None:
        self.tagged()

        result = self.repository.decide(
            "2026-11-17T00:00:00+00:00",
            known=self.known(
                "1.1.0+git20261110120000.0123456789ab", "1.1.1+git20261116110000.a1b2c3d4e5f6"
            ),
        )

        self.assertEqual(result.repository, "")

    def test_what_the_repository_serves_is_only_checked_when_it_was_read(self) -> None:
        self.tagged()

        result = self.repository.decide(
            "2026-11-17T00:00:00+00:00",
            known=PLAN.Known(
                release="present", released_at=datetime.fromisoformat("2026-11-16T11:00:00+00:00")
            ),
        )

        self.assertEqual(result.repository, "")

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
                "--pulls",
                str(self.repository.pulls_file()),
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

    def test_the_decide_command_takes_what_was_asked_of_github_and_the_repository(self) -> None:
        self.tagged()
        published = self.repository.root.parent / "published.txt"
        published.write_text("1.1.0+git20261110120000.0123456789ab\n", encoding="utf-8")

        completed = subprocess.run(
            [
                sys.executable,
                str(BASE / "tools" / "release-plan"),
                "decide",
                "--source",
                str(self.repository.root),
                "--now",
                "2026-11-16T14:00:00+00:00",
                "--app",
                APP,
                "--pulls",
                str(self.repository.pulls_file()),
                "--last-release",
                "present",
                "--released-at",
                "2026-11-16T11:00:00+00:00",
                "--published",
                str(published),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("serves no haprion-cli 1.1.1", json.loads(completed.stdout)["repository"])

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


class TheWorkflowsSayWhatThePlanReads(unittest.TestCase):
    """The subjects and the branch are held in step by hand; these fail when one moves."""

    workflows = BASE / ".github" / "workflows"

    def test_the_watch_s_subjects_are_the_plan_s(self) -> None:
        watch = (self.workflows / "upstream-watch.yml").read_text(encoding="utf-8")

        self.assertIn(f'--message "{PLAN.LOCKS_SUBJECT}"', watch)
        self.assertIn(f'subject="{PLAN.WAF_SUBJECT}"', watch)
        suffix = PLAN.WAF_SECURITY_SUBJECT.removeprefix(PLAN.WAF_SUBJECT)
        self.assertIn(f'subject="${{subject}}{suffix}"', watch)

    def test_the_version_proposal_is_install_tested_as_a_whole_release(self) -> None:
        release = (self.workflows / "auto-release.yml").read_text(encoding="utf-8")
        ci = (self.workflows / "ci.yml").read_text(encoding="utf-8")

        self.assertIn("BRANCH: release-watch", release)
        self.assertIn("github.head_ref == 'release-watch'", ci)
        self.assertIn('if [[ "${HEAD_REF}" == release-watch ]]', ci)
        self.assertIn('--message "Version ${VERSION}"', release)

    def test_the_checks_the_merge_waits_for_are_ci_s_jobs(self) -> None:
        release = (self.workflows / "auto-release.yml").read_text(encoding="utf-8")
        ci = (self.workflows / "ci.yml").read_text(encoding="utf-8")

        for name in ("Source, quality, and security gates", "Installation test"):
            self.assertIn(f"    name: {name}\n", ci)
            self.assertIn(f"            {name}\n", release)

    def test_the_tag_stands_on_the_merge_whose_head_was_checked(self) -> None:
        release = (self.workflows / "auto-release.yml").read_text(encoding="utf-8")

        self.assertIn("tag_commit: ${{ steps.plan.outputs.tag_commit }}", release)
        self.assertIn('"${TAG_COMMIT}:refs/tags/v${VERSION}"', release)
        self.assertEqual(release.count("ref: ${{ needs.plan.outputs.tag_commit }}"), 2)
        self.assertNotIn("outputs.head", release)
        # the checks are the proposal's own, each by name and the latest run of it
        self.assertIn("commits/${PULL_HEAD}/check-runs", release)
        self.assertIn('-f check_name="${name}" -f filter=latest', release)
        # a proposal behind main is closed, not merged
        self.assertIn("compare/main...${head}", release)
        self.assertIn(".behind_by", release)

    def test_the_repository_is_read_where_the_site_puts_its_index(self) -> None:
        release = (self.workflows / "auto-release.yml").read_text(encoding="utf-8")
        apt = (BASE / "tools" / "build-apt-repo").read_text(encoding="utf-8")

        self.assertIn('ARCHITECTURE = "amd64"', apt)
        self.assertIn('COMPONENT = "main"', apt)
        self.assertIn("dists/deb13/main/binary-amd64/Packages", release)
        self.assertIn('"Package: haprion-cli"', release)
        self.assertIn("UNPUBLISHED_TITLE", release)

    def test_a_tag_without_a_release_is_built_again_and_not_tagged_again(self) -> None:
        release = (self.workflows / "auto-release.yml").read_text(encoding="utf-8")

        self.assertIn("needs.plan.outputs.outcome == 'rebuild'", release)
        self.assertIn('if [[ "${OUTCOME}" == tag ]]; then', release)


if __name__ == "__main__":
    unittest.main()
