"""Which clusters exist, as the poller asks for them (B206/B211)."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt.cli import cluster_list_helper
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "88888888-8888-4888-8888-888888888888"


def policy_in(root: Path, mutate=None) -> Path:  # type: ignore[no-untyped-def]
    clusters = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
    if mutate is not None:
        mutate(clusters)
    cluster_file = root / "clusters.yaml"
    cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False))
    policy = yaml.safe_load((BASE / "examples" / "runtime-policy.yaml").read_text())
    policy["cluster_file"] = str(cluster_file)
    path = root / "runtime-policy.yaml"
    path.write_text(yaml.safe_dump(policy, sort_keys=False))
    return path


def ask(policy: Path, request: str | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cluster_list_helper.main(
        [],
        policy_path=policy,
        input_stream=io.BytesIO(
            (request or cluster_list_helper.build_request(REQUEST_ID)).encode()
        ),
        output_stream=out,
        error_stream=err,
        require_secure=False,
        require_root=False,
    )
    return code, out.getvalue(), err.getvalue()


class TheList(unittest.TestCase):
    def test_every_cluster_in_the_file_s_order(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            code, out, err = ask(policy_in(Path(raw)))

        self.assertEqual((code, err), (0, ""))
        document = assert_contract("haproxy-cluster-list", out)
        expected = list(
            yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())["clusters"]
        )
        self.assertEqual([entry["id"] for entry in document["result"]["clusters"]], expected)
        self.assertEqual(document["result"]["clusters"][0]["nodes"], 2)

    def test_a_cluster_file_the_engine_refuses_is_a_failure_not_a_short_list(self) -> None:
        def broken(data: dict[str, object]) -> None:
            data["schema_version"] = 2

        with tempfile.TemporaryDirectory() as raw:
            code, out, _err = ask(policy_in(Path(raw), broken))

        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(out)["outcome"], "failed")

    def test_a_request_naming_a_cluster_is_refused(self) -> None:
        request = json.loads(cluster_list_helper.build_request(REQUEST_ID))
        request["cluster"] = "alpha"
        with tempfile.TemporaryDirectory() as raw:
            code, out, _err = ask(policy_in(Path(raw)), json.dumps(request))

        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
