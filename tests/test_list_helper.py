"""The root-only half of `haproxy-list`.

The poller cannot read a cluster repository, and must not be given a group
membership that would let it read every published configuration for the sake of
a version listing. It asks root for exactly this instead. These tests hold the
boundary: no arguments cross it, the cluster is resolved inside it, and every
failure comes back as an envelope rather than as helper output nobody parses.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from haproxy_mgmt.cli import list_helper
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "66666666-6666-4666-8666-666666666666"
SCHEMA_DIR = BASE / "schemas" / "v1"
SCHEMA_ID = "https://example.com/haproxy-manager/schemas/v1/haproxy-list.schema.json"


def list_validator() -> Draft202012Validator:
    """The frozen phase-0 schema, loaded the way the contract tests load it."""

    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        registry.contents(SCHEMA_ID), registry=registry, format_checker=FormatChecker()
    )


ENVIRONMENT = {
    "GIT_AUTHOR_NAME": "Example Maintainer",
    "GIT_AUTHOR_EMAIL": "maintainer@example.com",
    "GIT_COMMITTER_NAME": "Example Maintainer",
    "GIT_COMMITTER_EMAIL": "maintainer@example.com",
    "GIT_AUTHOR_DATE": "2026-01-02T03:04:05+00:00",
    "GIT_COMMITTER_DATE": "2026-01-02T03:04:05+00:00",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, **ENVIRONMENT},
    ).stdout.strip()


def request(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "operation": "list",
        "cluster": "alpha",
        "request_id": REQUEST_ID,
        "parameters": {},
    }
    document.update(overrides)
    return json.dumps(document).encode()


class ListHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def runtime(self, *, commits: list[str], published: int | None) -> Path:
        config_root = self.root / "config"
        publish_root = self.root / "published"
        cert_root = self.root / "certs"
        for directory in (config_root, publish_root, cert_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        repo = config_root / "alpha"
        (repo / "core").mkdir(parents=True, exist_ok=True)
        if commits:
            git(repo, "init", "-q", "-b", "main")
            for index, comment in enumerate(commits, start=1):
                (repo / "core/haproxy.cfg").write_text(f"global\n  # version {index}\n")
                git(repo, "add", "-A")
                git(repo, "commit", "-qm", comment)

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(repo)
        entry["publish_path"] = str(publish_root / "alpha")
        entry["validation_certs"] = str(cert_root)
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters), encoding="utf-8")

        if published is not None:
            commit = git(repo, "rev-list", "--first-parent", "--reverse", "HEAD").split()[
                published - 1
            ]
            release = publish_root / "alpha" / "current" / entry["node_path"]
            release.mkdir(parents=True, exist_ok=True)
            (release / "RELEASE").write_text(
                f"schema=1\ncluster=alpha\nversion={published}\nhash={commit}\n",
                encoding="utf-8",
            )

        policy = {
            "schema_version": 1,
            "cluster_file": str(self.root / "clusters.yaml"),
            "config_root": str(config_root),
            "publish_root": str(publish_root),
            "validation_certs_root": str(cert_root),
        }
        policy_path = self.root / "runtime-policy.yaml"
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path

    def run_helper(
        self,
        *,
        commits: list[str] | None = None,
        published: int | None = None,
        argv: list[str] | None = None,
        payload: bytes | None = None,
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = list_helper.main(
            argv if argv is not None else [],
            policy_path=self.runtime(
                commits=["Initial", "Add a backend"] if commits is None else commits,
                published=published,
            ),
            input_stream=io.BytesIO(payload if payload is not None else request()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
        )
        return code, out.getvalue(), err.getvalue()

    def test_it_returns_the_listing_and_which_version_is_published(self) -> None:
        code, out, _ = self.run_helper(published=1)

        document = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(document["operation"], "list")
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["request_id"], REQUEST_ID)
        self.assertEqual(document["result"]["published_version"], 1)
        self.assertEqual(document["result"]["unpublished"], 1)
        self.assertEqual([row["version"] for row in document["result"]["versions"]], [2, 1])

    def test_an_unpublished_cluster_answers_without_a_release(self) -> None:
        code, out, _ = self.run_helper()

        result = json.loads(out)["result"]
        self.assertEqual(code, 0)
        self.assertIsNone(result["published_version"])
        self.assertIsNone(result["published_hash"])
        self.assertEqual(result["unpublished"], 2)

    def test_a_missing_repository_is_a_failed_envelope_not_a_crash(self) -> None:
        code, out, _ = self.run_helper(commits=[])

        document = json.loads(out)
        self.assertEqual(code, 68)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "history_unavailable")
        self.assertIsNone(document["result"])

    def test_the_answer_validates_against_the_frozen_list_schema(self) -> None:
        #
        # The result shape was frozen in phase 0, before this helper existed.
        # Checking the real output against it here is what keeps the interface's
        # source and the published contract from being two different documents.
        #
        _, out, _ = self.run_helper(published=1)

        errors = sorted(list_validator().iter_errors(json.loads(out)), key=str)
        self.assertEqual([error.message for error in errors], [])

    def test_a_failed_answer_also_validates(self) -> None:
        _, out, _ = self.run_helper(commits=[])

        errors = sorted(list_validator().iter_errors(json.loads(out)), key=str)
        self.assertEqual([error.message for error in errors], [])

    def test_an_unknown_cluster_is_refused_in_the_frozen_envelope(self) -> None:
        """A refusal is a result. The contract promises one document on stdout
        on every path, and a caller that gets an exit code and nothing to parse
        has to guess what happened."""

        code, out, err = self.run_helper(payload=request(cluster="beta"))

        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)
        document = assert_contract("haproxy-list", out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIsNone(document["result"])

    def test_no_argument_reaches_the_privileged_side(self) -> None:
        code, _, err = self.run_helper(argv=["-c", "alpha"])

        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", err)

    def test_a_request_for_another_operation_is_refused(self) -> None:
        code, out, err = self.run_helper(payload=request(operation="publish"))

        self.assertEqual(out, "")
        self.assertNotEqual(code, 0)
        self.assertIn("ERROR", err)

    def test_the_listing_is_ten_unless_the_caller_asks_for_more(self) -> None:
        commits = [f"Change {step}" for step in range(1, 15)]
        _, ten, _ = self.run_helper(commits=commits)
        # The same repository again, with nothing added to it.
        _, all_of_them, _ = self.run_helper(commits=[], payload=request(parameters={"limit": 250}))

        self.assertEqual(len(json.loads(ten)["result"]["versions"]), 10)
        self.assertTrue(json.loads(ten)["result"]["truncated"])
        self.assertEqual(len(json.loads(all_of_them)["result"]["versions"]), 14)
        self.assertFalse(json.loads(all_of_them)["result"]["truncated"])

    def test_a_limit_outside_one_to_two_hundred_and_fifty_is_refused(self) -> None:
        for limit in (0, 251, True, "10", 2.5):
            with self.subTest(limit=limit):
                code, out, err = self.run_helper(payload=request(parameters={"limit": limit}))
                self.assertEqual((code, out), (65, ""))
                self.assertIn("parameters.limit", err)

    def test_an_unknown_parameter_is_refused_before_any_repository_is_read(self) -> None:
        code, out, err = self.run_helper(payload=request(parameters={"offset": 50}))

        self.assertEqual(out, "")
        self.assertNotEqual(code, 0)
        self.assertIn("ERROR", err)


if __name__ == "__main__":
    unittest.main()
