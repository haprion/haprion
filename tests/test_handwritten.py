"""The one reader of the handwritten layers (B529): which files, no link followed, one fingerprint."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import handwritten
from haprion.cli import handwritten_helper, publish, readings_helper
from haprion.cli.caller import CallerError
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "00000000-0000-4000-8000-000000000529"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class DraftFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "config" / "alpha"
        self.repo.mkdir(parents=True)
        git(self.repo, "init", "--quiet", "--initial-branch=main")
        git(self.repo, "config", "user.name", "operator")
        git(self.repo, "config", "user.email", "operator@example.com")
        self.write("core/haproxy.cfg", "global\n    tune.stick-counters 4\n")
        self.write("manual/conf.d/10-site.cfg", "frontend site\n")
        self.write("managed/network.yaml", "networks: {}\n")
        self.write(".gitignore", "*.swp\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "--quiet", "-m", "first")
        self.head = git(self.repo, "rev-parse", "HEAD")

    def write(self, relative: str, text: str | bytes) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    def draft(self) -> handwritten.Draft:
        return handwritten.read_draft(self.repo, self.head)[0]


class WhatIsPending(DraftFixture):
    def test_a_draft_that_is_the_version_has_nothing_pending(self) -> None:
        draft = self.draft()

        self.assertEqual(draft.pending, ())
        self.assertEqual(sorted(draft.files), ["core/haproxy.cfg", "manual/conf.d/10-site.cfg"])

    def test_new_changed_and_deleted_are_named_by_path(self) -> None:
        self.write("core/haproxy.cfg", "global\n    tune.stick-counters 6\n")
        self.write("manual/conf.d/20-new.cfg", "backend new\n")
        (self.repo / "manual/conf.d/10-site.cfg").unlink()

        self.assertEqual(
            self.draft().pending,
            (
                handwritten.Pending("core/haproxy.cfg", handwritten.CHANGED),
                handwritten.Pending("manual/conf.d/10-site.cfg", handwritten.DELETED),
                handwritten.Pending("manual/conf.d/20-new.cfg", handwritten.NEW),
            ),
        )

    def test_managed_and_ignored_files_are_not_the_draft(self) -> None:
        self.write("managed/network.yaml", "networks: {changed: true}\n")
        self.write("core/haproxy.cfg.swp", "editor state\n")

        self.assertEqual(self.draft().pending, ())

    def test_the_index_does_not_decide(self) -> None:
        """A staged edit is pending as one on disk is: the files are compared, not git's index."""

        self.write("core/haproxy.cfg", "global\n    tune.stick-counters 6\n")
        git(self.repo, "add", "core/haproxy.cfg")

        self.assertEqual(
            self.draft().pending, (handwritten.Pending("core/haproxy.cfg", handwritten.CHANGED),)
        )

    def test_the_diff_is_against_the_version(self) -> None:
        self.write("core/haproxy.cfg", "global\n    tune.stick-counters 6\n")
        draft, published = handwritten.read_draft(self.repo, self.head)

        diff = draft.diff(published)

        self.assertEqual([change.path for change in diff.files], ["core/haproxy.cfg"])
        self.assertIn("+    tune.stick-counters 6", diff.files[0].lines)
        self.assertIn("-    tune.stick-counters 4", diff.files[0].lines)


class TheFingerprint(DraftFixture):
    def test_the_same_files_give_the_same_fingerprint(self) -> None:
        self.assertEqual(self.draft().fingerprint, self.draft().fingerprint)

    def test_a_changed_byte_or_a_moved_file_changes_it(self) -> None:
        before = self.draft().fingerprint
        self.write("core/haproxy.cfg", "global\n    tune.stick-counters 5\n")
        changed = self.draft().fingerprint
        os.rename(self.repo / "core/haproxy.cfg", self.repo / "core/other.cfg")
        moved = self.draft().fingerprint

        self.assertEqual(len({before, changed, moved}), 3)

    def test_paths_and_contents_cannot_run_into_each_other(self) -> None:
        self.assertNotEqual(
            handwritten.fingerprint({"core/a": b"bc"}),
            handwritten.fingerprint({"core/ab": b"c"}),
        )


class NoLinkIsFollowed(DraftFixture):
    def assert_refused(self) -> None:
        with self.assertRaises(handwritten.HandwrittenError) as raised:
            handwritten.read_layers(self.repo)
        self.assertIn("symbolic link", str(raised.exception))

    def test_a_link_to_a_file_outside_is_refused(self) -> None:
        secret = Path(self.temporary.name) / "secret"
        secret.write_text("not configuration\n", encoding="utf-8")
        (self.repo / "core/secret.cfg").symlink_to(secret)

        self.assert_refused()

    def test_a_linked_directory_is_refused(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "x.cfg").write_text("frontend x\n", encoding="utf-8")
        (self.repo / "manual/linked").symlink_to(outside)

        self.assert_refused()

    def test_a_tracked_link_is_refused_and_not_dropped(self) -> None:
        """The terminal skipped it, which removed it from the next version (B529)."""

        (self.repo / "core/alias.cfg").symlink_to("haproxy.cfg")
        git(self.repo, "add", "core/alias.cfg")
        git(self.repo, "commit", "--quiet", "-m", "alias")

        self.assert_refused()

    def test_the_terminal_publish_refuses_a_link_with_its_name(self) -> None:
        (self.repo / "core/alias.cfg").symlink_to("haproxy.cfg")

        with self.assertRaises(CallerError) as raised:
            publish.collect_layers(self.repo)

        self.assertIn("core/alias.cfg", str(raised.exception))


class WhatTheReaderSaysOfAnOddDraft(DraftFixture):
    def test_a_directory_that_became_a_file_is_a_removal_and_a_new_file(self) -> None:
        """B530, H06: as `git add -A` takes it, not as a link."""

        self.write("core/maps/hosts.map", "192.0.2.1 a\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "--quiet", "-m", "maps")
        self.head = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "core/maps/hosts.map").unlink()
        (self.repo / "core/maps").rmdir()
        self.write("core/maps", "now a file\n")

        self.assertEqual(
            self.draft().pending,
            (
                handwritten.Pending("core/maps", handwritten.NEW),
                handwritten.Pending("core/maps/hosts.map", handwritten.DELETED),
            ),
        )

    def test_a_draft_area_that_cannot_be_opened_is_a_reading_that_failed(self) -> None:
        """B530, H07: unreadable, not a draft that is wrong."""

        with self.assertRaises(handwritten.HandwrittenUnreadable):
            handwritten.read_layers(self.root / "missing")

    def test_a_file_the_reader_may_not_read_says_what_to_do(self) -> None:
        """B530, H12: the terminal reads as the person running it."""

        if os.geteuid() == 0:
            self.skipTest("root reads every file")
        os.chmod(self.repo / "core/haproxy.cfg", 0)
        self.addCleanup(os.chmod, self.repo / "core/haproxy.cfg", 0o600)

        with self.assertRaises(handwritten.HandwrittenError) as raised:
            handwritten.read_layers(self.repo)

        self.assertIn("chmod g+r", str(raised.exception))
        self.assertNotIsInstance(raised.exception, handwritten.HandwrittenUnreadable)


class OnlyText(DraftFixture):
    def test_a_file_that_is_not_utf8_is_refused_by_name(self) -> None:
        self.write("manual/conf.d/latin.cfg", b"caf\xe9\n")

        with self.assertRaises(handwritten.HandwrittenError) as raised:
            handwritten.read_layers(self.repo)

        self.assertIn("manual/conf.d/latin.cfg", str(raised.exception))

    def test_a_nul_byte_is_refused(self) -> None:
        self.write("core/haproxy.cfg", b"global\0\n")

        with self.assertRaises(handwritten.HandwrittenError):
            handwritten.read_layers(self.repo)

    def test_a_tracked_file_replaced_by_a_fifo_is_not_read(self) -> None:
        """git lists no untracked FIFO; a tracked path that became one reaches the reader."""

        (self.repo / "core/haproxy.cfg").unlink()
        os.mkfifo(self.repo / "core/haproxy.cfg")

        with self.assertRaises(handwritten.HandwrittenError) as raised:
            handwritten.read_layers(self.repo)

        self.assertIn("not a file", str(raised.exception))


class TheReading(DraftFixture):
    """The helper's answer, as the poller receives it inside the readings call."""

    def policy(self) -> Path:
        roots = {name: self.root / name for name in ("config", "published", "certs")}
        for directory in roots.values():
            directory.mkdir(exist_ok=True)
        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(self.repo)
        entry["publish_path"] = str(roots["published"] / "alpha")
        entry["validation_certs"] = str(roots["certs"])
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters), encoding="utf-8")
        path = self.root / "runtime-policy.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "cluster_file": str(self.root / "clusters.yaml"),
                    "config_root": str(roots["config"]),
                    "publish_root": str(roots["published"]),
                    "validation_certs_root": str(roots["certs"]),
                }
            ),
            encoding="utf-8",
        )
        return path

    def ask(self) -> tuple[int, dict[str, Any]]:
        out = io.StringIO()
        code = readings_helper.main(
            [],
            policy_path=self.policy(),
            input_stream=io.BytesIO(
                readings_helper.build_request("alpha", REQUEST_ID, {"handwritten": {}}).encode()
            ),
            output_stream=out,
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
        )
        self.assertEqual(code, 0)
        answer = assert_contract("haprion-readings", out.getvalue())["result"]["reads"]
        reading = answer["handwritten"]
        document = assert_contract("haprion-handwritten", json.dumps(reading["envelope"]))
        return reading["exit_code"], document["result"]

    def test_a_clean_draft_reads_clean(self) -> None:
        code, result = self.ask()

        self.assertEqual((code, result), (0, {"state": "clean", "head": self.head}))

    def test_a_pending_draft_names_its_files_and_the_fingerprint(self) -> None:
        self.write("core/haproxy.cfg", "global\n    tune.stick-counters 6\n")

        code, result = self.ask()

        self.assertEqual(code, 0)
        self.assertEqual(result["state"], "pending")
        self.assertEqual(result["pending"], [{"path": "core/haproxy.cfg", "kind": "changed"}])
        self.assertEqual(result["fingerprint"], self.draft().fingerprint)
        self.assertEqual([item["path"] for item in result["diff"]["files"]], ["core/haproxy.cfg"])

    def test_a_link_reads_refused_with_the_publish_s_words(self) -> None:
        (self.repo / "core/alias.cfg").symlink_to("haproxy.cfg")

        code, result = self.ask()

        self.assertEqual((code, result["state"]), (0, "refused"))
        self.assertIn("core/alias.cfg", result["message"])

    def test_a_draft_area_that_cannot_be_read_is_a_reading_that_failed(self) -> None:
        """B530, N4: `failed` with `handwritten_unavailable`, never `refused`."""

        broken = handwritten.HandwrittenUnreadable("the draft area cannot be opened")
        with mock.patch.object(handwritten, "read_draft", side_effect=broken):
            out = io.StringIO()
            readings_helper.main(
                [],
                policy_path=self.policy(),
                input_stream=io.BytesIO(
                    readings_helper.build_request("alpha", REQUEST_ID, {"handwritten": {}}).encode()
                ),
                output_stream=out,
                error_stream=io.StringIO(),
                require_secure=False,
                require_root=False,
            )
        envelope = json.loads(out.getvalue())["result"]["reads"]["handwritten"]["envelope"]

        document = assert_contract("haprion-handwritten", json.dumps(envelope))
        self.assertEqual(
            (document["outcome"], document["error"]["code"]), ("failed", "handwritten_unavailable")
        )

    def test_it_is_asked_inside_the_readings_call(self) -> None:
        self.assertIs(readings_helper.READINGS["handwritten"], handwritten_helper.main)
        self.assertNotIn("handwritten", readings_helper.MANAGER_READINGS)


class TheNamesInASentence(unittest.TestCase):
    def test_the_first_five_and_how_many_more(self) -> None:
        found = tuple(handwritten.Pending(f"core/{n}.cfg", handwritten.NEW) for n in range(7))

        self.assertEqual(
            handwritten.listed_paths(found),
            "core/0.cfg, core/1.cfg, core/2.cfg, core/3.cfg, core/4.cfg and 2 more",
        )


if __name__ == "__main__":
    unittest.main()
