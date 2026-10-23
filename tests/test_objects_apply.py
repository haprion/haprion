"""``haprion-objects apply`` and ``remove``: the objects from files (Fas 23, B293)."""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion import exit_codes
from haprion.cli import changes_publish, objects
from tests.contract_schema import assert_contract
from tests.test_proxy_model import MINIMAL

HEAD = "a" * 40


def document(name: str, port: int = 8080) -> str:
    return (
        MINIMAL.decode()
        .replace("name: shop", f"name: {name}")
        .replace("shop.example.com", f"{name}.example.com")
        .replace("port: 8080", f"port: {port}")
    )


class Fakes:
    """The two helpers, answering as the installed ones do; nothing is run."""

    def __init__(self, stored: dict[str, str], head: str | None = HEAD) -> None:
        self.stored = dict(stored)
        self.head = head
        self.published: list[dict[str, Any]] = []
        self.refuse: dict[str, Any] | None = None

    def read(self, cluster: str, request_id: str) -> subprocess.CompletedProcess[str]:
        answer = {
            "schema_version": 1,
            "ok": True,
            "outcome": "done",
            "operation": "objects",
            "cluster": cluster,
            "request_id": request_id,
            "result": {
                "commit": self.head,
                "objects": [
                    {"name": name, "readable": True, "document": text}
                    for name, text in sorted(self.stored.items())
                ],
            },
            "warnings": [],
            "error": None,
        }
        return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

    def publish(self, request: str) -> subprocess.CompletedProcess[str]:
        sent = json.loads(request)
        self.published.append(sent)
        if self.refuse is not None:
            answer = {"operation": changes_publish.OPERATION, "result": None, "error": self.refuse}
            return subprocess.CompletedProcess([], 65, json.dumps(answer), "")
        parameters = sent["parameters"]
        if parameters["expected_head"] != self.head:
            answer = {
                "operation": changes_publish.OPERATION,
                "result": None,
                "error": {"code": "expected_target_changed", "message": "moved"},
            }
            return subprocess.CompletedProcess([], 75, json.dumps(answer), "")
        for name, text in parameters["objects"].items():
            if text is None:
                self.stored.pop(name)
            else:
                self.stored[name] = text
        self.head = f"{len(self.published):040x}"
        answer = {
            "operation": changes_publish.OPERATION,
            "result": {"changed": True, "version": 10 + len(self.published), "hash": self.head},
            "error": None,
        }
        return subprocess.CompletedProcess([], 0, json.dumps(answer), "")


class ObjectsFromFiles(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, name: str, text: str) -> Path:
        path = self.root / f"{name}.yaml"
        path.write_text(text)
        return path

    def run_cli(self, fakes: Fakes, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = objects.main(
            list(argv),
            stream_out=out,
            stream_err=err,
            run_helper=fakes.read,
            run_publish=fakes.publish,
        )
        return code, out.getvalue(), err.getvalue()

    def test_a_new_and_a_changed_object_are_one_version_fenced_on_the_head(self) -> None:
        fakes = Fakes({"api": document("api"), "kept": document("kept")})
        self.write("api", document("api", port=9090))
        self.write("shop", document("shop"))
        self.write("kept", document("kept"))

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")

        self.assertEqual(code, 0)
        (sent,) = fakes.published
        self.assertEqual(sent["parameters"]["expected_head"], HEAD)
        self.assertEqual(sorted(sent["parameters"]["objects"]), ["api", "shop"])
        answer = assert_contract("haprion-objects-apply", out)
        self.assertEqual(answer["result"]["changed"], True)
        self.assertEqual(
            (answer["result"]["added"], answer["result"]["updated"], answer["result"]["unchanged"]),
            (["shop"], ["api"], ["kept"]),
        )

    def test_the_same_files_again_change_nothing(self) -> None:
        fakes = Fakes({"shop": document("shop")})
        self.write("shop", document("shop"))

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")

        self.assertEqual((code, fakes.published), (0, []))
        self.assertEqual(json.loads(out)["result"]["changed"], False)

    def test_check_shows_the_difference_and_publishes_nothing(self) -> None:
        fakes = Fakes({"shop": document("shop")})
        self.write("shop", document("shop", port=9090))

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--check")

        self.assertEqual((code, fakes.published), (0, []))
        self.assertIn("Would change shop", out)
        self.assertIn("-        port: 8080", out)
        self.assertIn("+        port: 9090", out)

    def test_an_object_no_file_names_stays_unless_pruned(self) -> None:
        stored = {"shop": document("shop"), "old": document("old")}
        self.write("shop", document("shop"))

        kept = Fakes(stored)
        self.run_cli(kept, "apply", "-c", "alpha", str(self.root))
        pruned = Fakes(stored)
        code, _, _ = self.run_cli(pruned, "apply", "-c", "alpha", str(self.root), "--prune")

        self.assertEqual(kept.published, [])
        self.assertEqual(code, 0)
        self.assertEqual(pruned.published[0]["parameters"]["objects"], {"old": None})

    def test_removing_what_is_not_stored_is_already_done(self) -> None:
        fakes = Fakes({"shop": document("shop")})

        code, out, _ = self.run_cli(fakes, "remove", "-c", "alpha", "gone", "shop", "--json")

        self.assertEqual(code, 0)
        self.assertEqual(fakes.published[0]["parameters"]["objects"], {"shop": None})
        self.assertEqual(json.loads(out)["result"]["unchanged"], ["gone"])
        code, out, _ = self.run_cli(fakes, "remove", "-c", "alpha", "shop", "--json")
        self.assertEqual((code, json.loads(out)["result"]["changed"]), (0, False))

    def test_a_wrong_file_is_named_before_the_manager_is_asked(self) -> None:
        fakes = Fakes({})
        self.write("shop", document("other"))

        code, _, err = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root))

        self.assertEqual(code, 65)
        self.assertIn("shop.yaml", err)
        self.assertEqual(fakes.published, [])

    def test_more_than_one_publish_takes_is_batched_and_each_batch_fenced(self) -> None:
        count = changes_publish.MAX_OBJECTS + 6
        fakes = Fakes({})
        for number in range(count):
            self.write(f"site{number:03d}", document(f"site{number:03d}"))

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")

        self.assertEqual(code, 0)
        self.assertEqual(
            [len(sent["parameters"]["objects"]) for sent in fakes.published],
            [changes_publish.MAX_OBJECTS, 6],
        )
        self.assertEqual(fakes.published[1]["parameters"]["expected_head"], f"{1:040x}")
        self.assertEqual(len(fakes.stored), count)
        self.assertEqual(len(json.loads(out)["result"]["versions"]), 2)

    def test_a_later_batch_refused_is_partial_with_the_versions_published(self) -> None:
        """Review 2026-10-22, 4-2: the published versions were only in the message."""

        fakes = Fakes({})
        for number in range(changes_publish.MAX_OBJECTS + 6):
            self.write(f"site{number:03d}", document(f"site{number:03d}"))
        first = fakes.publish

        def refuse_the_second(request: str) -> subprocess.CompletedProcess[str]:
            if fakes.published:
                fakes.refuse = {"code": "changes_invalid", "message": "no VIP named edge"}
            return first(request)

        fakes.publish = refuse_the_second  # type: ignore[method-assign]

        code, out, err = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")

        answer = assert_contract("haprion-objects-apply", out)
        self.assertEqual((code, answer["outcome"]), (exit_codes.PARTIAL, "partial"))
        self.assertEqual([v["version"] for v in answer["result"]["versions"]], [11])
        self.assertEqual(answer["warnings"][0]["code"], "changes_invalid")
        self.assertIn("1 earlier batch(es) published", err)

    def test_a_head_that_moved_is_blocked(self) -> None:
        fakes = Fakes({})
        fakes.head = "f" * 40
        self.write("shop", document("shop"))

        def read_the_old_head(cluster: str, request_id: str) -> subprocess.CompletedProcess[str]:
            fakes.head, seen = HEAD, fakes.head
            try:
                return Fakes.read(fakes, cluster, request_id)
            finally:
                fakes.head = seen

        fakes.read = read_the_old_head  # type: ignore[method-assign]

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")

        answer = assert_contract("haprion-objects-apply", out)
        self.assertEqual((code, answer["outcome"]), (exit_codes.BLOCKED, "blocked"))
        self.assertEqual(answer["error"]["code"], "expected_target_changed")

    def test_a_refusal_is_the_helpers_own_words_and_exit(self) -> None:
        fakes = Fakes({})
        fakes.refuse = {"code": "changes_invalid", "message": "no VIP named edge"}
        self.write("shop", document("shop"))

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")

        answer = assert_contract("haprion-objects-apply", out)
        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(
            (answer["error"]["code"], answer["error"]["message"]),
            ("changes_invalid", "no VIP named edge"),
        )

    def test_haproxy_s_words_on_a_refused_candidate_are_shown(self) -> None:
        # The install test (Fas 18): `apply` said the candidate was invalid
        # and not why, where `haprion-publish` shows HAProxy's text.
        fakes = Fakes({})
        words = "[ALERT] config : parsing [haproxy.cfg:12] : unknown keyword 'bogus'"
        fakes.refuse = {
            "code": "candidate_invalid",
            "message": "these changes did not produce a valid HAProxy candidate.",
            "details": {"diagnostics": words},
        }
        self.write("shop", document("shop"))

        code, _, err = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root))
        self.assertEqual(code, 65)
        self.assertIn(words, err)

        code, out, _ = self.run_cli(fakes, "apply", "-c", "alpha", str(self.root), "--json")
        answer = assert_contract("haprion-objects-apply", out)
        self.assertEqual(answer["error"]["details"], {"diagnostics": words})

    def test_reading_still_works_as_before(self) -> None:
        fakes = Fakes({"shop": document("shop")})

        code, out, _ = self.run_cli(fakes, "-c", "alpha", "--show", "shop")

        self.assertEqual((code, out), (0, document("shop")))


if __name__ == "__main__":
    unittest.main()


class ThroughTheRealHelper(unittest.TestCase):
    """Applied twice through the publish helper itself: one version, then none.

    The fakes above prove what is sent; this proves the helper stores a
    document exactly as sent, which is what makes the second run a no-op.
    """

    def test_the_same_files_twice_publish_once(self) -> None:
        import tempfile as temp

        from tests.test_changes_publish_network import NetworkPublishFixture
        from tests.test_publish_helper import git

        fixture = type("Fixture", (NetworkPublishFixture,), {"runTest": lambda self: None})()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with temp.TemporaryDirectory() as raw, temp.TemporaryDirectory() as files:
            policy = fixture.runtime(Path(raw))
            self.assertEqual(fixture.publish_network(policy, fixture.request())[0], 0)
            Path(files, "shop.yaml").write_text(document("shop"))

            def read(cluster: str, request_id: str) -> subprocess.CompletedProcess[str]:
                folder = fixture.repo / "managed" / "proxies"
                stored = (
                    {path.stem: path.read_text() for path in folder.glob("*.yaml")}
                    if folder.is_dir()
                    else {}
                )
                fakes = Fakes(stored, head=git(fixture.repo, "rev-parse", "HEAD"))
                return fakes.read(cluster, request_id)

            def publish(request: str) -> subprocess.CompletedProcess[str]:
                code, answer, err = fixture.publish_network(policy, io.BytesIO(request.encode()))
                return subprocess.CompletedProcess([], code, json.dumps(answer), err)

            answers = []
            for _ in range(2):
                out = io.StringIO()
                code = objects.main(
                    ["apply", "-c", "alpha", files, "--json"],
                    stream_out=out,
                    run_helper=read,
                    run_publish=publish,
                )
                self.assertEqual(code, 0, out.getvalue())
                answers.append(json.loads(out.getvalue())["result"])

            self.assertEqual((answers[0]["changed"], answers[0]["added"]), (True, ["shop"]))
            self.assertEqual((answers[1]["changed"], answers[1]["unchanged"]), (False, ["shop"]))
            self.assertEqual(
                (fixture.repo / "managed/proxies/shop.yaml").read_text(), document("shop")
            )
