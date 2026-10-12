"""``haprion-network apply``: the network description from a file (Fas 23, B293).

Read through the real read helper and published through the real publish
helper, against a repository of the publish tests' own: the document the
reading reports is the one the publish stored, so the same file twice is one
version.
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haprion.cli import network, network_helper
from tests.contract_schema import assert_contract
from tests.test_changes_publish_network import NETWORK, NetworkPublishFixture
from tests.test_publish_helper import git

CHANGED = NETWORK.replace("198.51.100.0/24", "198.51.100.0/25")


class TheNetworkFromAFile(NetworkPublishFixture):
    def run_apply(self, policy: Path, path: Path, *extra: str) -> tuple[int, str, str]:
        def read(cluster: str, request_id: str) -> subprocess.CompletedProcess[str]:
            out = io.StringIO()
            request = {
                "schema_version": 1,
                "operation": "network",
                "cluster": cluster,
                "request_id": request_id,
                "parameters": {},
            }
            code = network_helper.main(
                [],
                policy_path=policy,
                input_stream=io.BytesIO(json.dumps(request).encode()),
                output_stream=out,
                error_stream=io.StringIO(),
                require_secure=False,
                require_root=False,
            )
            return subprocess.CompletedProcess([], code, out.getvalue(), "")

        def publish(request: str) -> subprocess.CompletedProcess[str]:
            code, answer, err = self.publish_network(policy, io.BytesIO(request.encode()))
            return subprocess.CompletedProcess([], code, json.dumps(answer), err)

        out, err = io.StringIO(), io.StringIO()
        code = network.main(
            ["apply", "-c", "alpha", str(path), *extra],
            stream_out=out,
            stream_err=err,
            run_helper=read,
            run_publish=publish,
        )
        return code, out.getvalue(), err.getvalue()

    def published(self, policy: Path) -> None:
        self.assertEqual(self.publish_network(policy, self.request())[0], 0)

    def test_the_reading_carries_the_document_as_committed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.published(policy)
            out = io.StringIO()
            request = json.dumps(
                {
                    "schema_version": 1,
                    "operation": "network",
                    "cluster": "alpha",
                    "request_id": "77777777-7777-4777-8777-777777777777",
                    "parameters": {},
                }
            )
            network_helper.main(
                [],
                policy_path=policy,
                input_stream=io.BytesIO(request.encode()),
                output_stream=out,
                require_secure=False,
                require_root=False,
            )

            answer = assert_contract("haprion-network", out.getvalue())

        self.assertEqual(answer["result"]["document"], NETWORK)

    def test_a_change_is_one_version_and_the_same_file_again_none(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as files:
            policy = self.runtime(Path(raw))
            self.published(policy)
            path = Path(files, "network.yaml")
            path.write_text(CHANGED)
            before = git(self.repo, "rev-list", "--count", "HEAD")

            first = self.run_apply(policy, path, "--json")
            second = self.run_apply(policy, path, "--json")

            self.assertEqual((first[0], second[0]), (0, 0))
            one: dict[str, Any] = assert_contract("haprion-network-apply", first[1])
            two: dict[str, Any] = assert_contract("haprion-network-apply", second[1])
            self.assertEqual((one["result"]["changed"], two["result"]["changed"]), (True, False))
            self.assertEqual((self.repo / "managed/network.yaml").read_text(), CHANGED)
            self.assertEqual(int(git(self.repo, "rev-list", "--count", "HEAD")), int(before) + 1)

    def test_check_shows_the_difference_and_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as files:
            policy = self.runtime(Path(raw))
            self.published(policy)
            path = Path(files, "network.yaml")
            path.write_text(CHANGED)
            head = git(self.repo, "rev-parse", "HEAD")

            code, out, _ = self.run_apply(policy, path, "--check")

            self.assertEqual(code, 0)
            self.assertIn("Would change managed/network.yaml", out)
            self.assertIn("+  - 198.51.100.0/25", out)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), head)

    def test_a_wrong_file_is_named_and_nothing_is_published(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as files:
            policy = self.runtime(Path(raw))
            self.published(policy)
            path = Path(files, "network.yaml")
            path.write_text(NETWORK.replace("default_vip: main", "default_vip: nowhere"))
            head = git(self.repo, "rev-parse", "HEAD")

            code, _, err = self.run_apply(policy, path)

            self.assertEqual(code, 65)
            self.assertIn("network.yaml", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), head)

    def test_a_derived_network_has_nothing_to_change(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as files:
            policy = self.runtime(Path(raw))
            path = Path(files, "network.yaml")
            path.write_text(NETWORK)

            code, out, _ = self.run_apply(policy, path, "--json")

            answer = assert_contract("haprion-network-apply", out)
            self.assertEqual((code, answer["error"]["code"]), (65, "network_not_managed"))


if __name__ == "__main__":
    unittest.main()
