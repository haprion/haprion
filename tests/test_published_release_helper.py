"""The published release stamp, read for `haprion-config-status` (B266)."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

from haprion.cli import config_status, published_release_helper

BASE = Path(__file__).resolve().parents[1]
STAMP = "release=20261009-120000\ncommit=0123456789ab\n"


class PublishedRelease(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        clusters: dict[str, Any] = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        published = self.root / "published"
        for cluster_id, cluster in clusters["clusters"].items():
            cluster["publish_path"] = str(published / cluster_id)
        cluster_file = self.root / "clusters.yaml"
        cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False))
        policy = yaml.safe_load((BASE / "examples/runtime-policy.yaml").read_text())
        policy["cluster_file"] = str(cluster_file)
        policy["publish_root"] = str(published)
        self.policy = self.root / "runtime-policy.yaml"
        self.policy.write_text(yaml.safe_dump(policy, sort_keys=False))
        alpha = clusters["clusters"]["alpha"]
        self.release = published / "alpha" / "current" / alpha["node_path"] / "RELEASE"

    def ask(self, line: str, argv: list[str] | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = published_release_helper.main(
            argv or [],
            policy_path=self.policy,
            input_stream=io.StringIO(line),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
        )
        return code, out.getvalue(), err.getvalue()

    def test_the_stamp_is_passed_through_verbatim(self) -> None:
        self.release.parent.mkdir(parents=True)
        self.release.write_text(STAMP)

        self.assertEqual(self.ask("alpha\n"), (0, STAMP, ""))

    def test_a_cluster_with_nothing_published_says_so(self) -> None:
        self.assertEqual(self.ask("alpha\n"), (0, "state=unpublished\n", ""))

    def test_an_unknown_cluster_is_the_configuration_s_error(self) -> None:
        code, out, err = self.ask("gamma\n")

        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("gamma", err)

    def test_arguments_and_unusable_names_are_refused(self) -> None:
        self.assertEqual(self.ask("alpha\n", ["alpha"])[0], 64)
        for line in ("", "../alpha\n", "Alpha\n", "a" * 80 + "\n"):
            with self.subTest(line=line):
                self.assertEqual(self.ask(line)[0], 64)

    def test_it_must_run_as_root(self) -> None:
        err = io.StringIO()
        code = published_release_helper.main(
            [], input_stream=io.StringIO("alpha\n"), error_stream=err, require_root=True
        )

        self.assertEqual(
            (code, err.getvalue()),
            (68, "ERROR: haprion-published-release-helper must run as root.\n"),
        )

    def test_the_status_command_asks_this_helper_in_the_release(self) -> None:
        self.assertEqual(
            config_status.RELEASE_HELPER,
            "/opt/haprion/current/bin/haprion-published-release-helper",
        )


if __name__ == "__main__":
    unittest.main()
