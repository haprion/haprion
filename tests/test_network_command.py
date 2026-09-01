"""``haproxy-network``: the addresses a cluster serves on, and where they came from.

The command exists so that "which addresses does this cluster have, and can
they be edited" is answerable without opening a file - by an operator on the
command line, and by the interface's poller, through the same helper and the
same result. The tests below are mostly about the second half of that question:
a description read from the cluster repository can be changed by publishing,
and one derived from the engine's own configuration cannot.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

import yaml

from haproxy_mgmt.cli import network, network_helper
from haproxy_mgmt.config import ConfigError, Vip
from haproxy_mgmt.network_inventory import network_result
from tests.contract_schema import assert_contract

REQUEST_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class FakeCluster:
    """A cluster whose repository is a directory the test controls."""

    def __init__(self, config_path: Path) -> None:
        self.cluster_id = "alpha"
        self.vip = "192.0.2.20"
        self.config_path = config_path
        self.vips = {"main": Vip(name="main", address="192.0.2.20")}
        self.default_vip = "main"
        self.sources: dict[str, str] = {}
        self.networks: dict[str, tuple[str, ...]] = {}

    def network(self):
        from haproxy_mgmt.config import Network, load_network

        found = load_network(self.config_path, vip=self.vip)
        if found is not None:
            return found
        return Network(
            vips=self.vips,
            default_vip=self.default_vip,
            sources=self.sources,
            networks=self.networks,
        )


class TheResultSaysWhereItCameFrom(unittest.TestCase):
    def test_a_repository_description_is_reported_as_editable_ground(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "managed").mkdir()
            (root / "managed" / "network.yaml").write_text(
                yaml.safe_dump(
                    {
                        "vips": {"dmz": {"address": "198.51.100.20", "source": "198.51.100.25"}},
                        "sources": {"outbound": "192.0.2.35"},
                        "networks": {"office": ["198.51.100.0/24"]},
                    }
                ),
                encoding="utf-8",
            )
            result = network_result(FakeCluster(root))  # type: ignore[arg-type]

        self.assertEqual(result["origin"], "repository")
        self.assertEqual(result["default_vip"], "dmz")
        self.assertEqual(
            result["vips"], [{"name": "dmz", "address": "198.51.100.20", "source": "198.51.100.25"}]
        )
        self.assertEqual(result["sources"], [{"name": "outbound", "address": "192.0.2.35"}])
        self.assertEqual(result["groups"], [{"name": "office", "members": ["198.51.100.0/24"]}])

    def test_a_derived_description_says_so_and_still_answers(self) -> None:
        #
        # Every cluster that predates the move is in this state. It must read
        # correctly and it must be distinguishable, because only the first kind
        # can be edited by publishing.
        #
        with tempfile.TemporaryDirectory() as raw:
            result = network_result(FakeCluster(Path(raw)))  # type: ignore[arg-type]

        self.assertEqual(result["origin"], "cluster_file")
        self.assertEqual(
            result["vips"], [{"name": "main", "address": "192.0.2.20", "source": None}]
        )

    def test_the_ownership_address_is_reported_beside_the_tables_not_inside_them(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = network_result(FakeCluster(Path(raw)))  # type: ignore[arg-type]

        self.assertEqual(result["ownership_vip"], "192.0.2.20")


class TheHelperAnswersInTheFrozenEnvelope(unittest.TestCase):
    def _run(self, *, cluster: str = "alpha", description: object = None):
        request = {
            "schema_version": 1,
            "operation": "network",
            "cluster": cluster,
            "request_id": REQUEST_ID,
            "parameters": {},
        }
        out, err = io.StringIO(), io.StringIO()

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "managed").mkdir()
            if description is not None:
                (root / "managed" / "network.yaml").write_text(
                    yaml.safe_dump(description), encoding="utf-8"
                )

            class Config:
                @staticmethod
                def cluster(cluster_id: str) -> object:
                    if cluster_id != "alpha":
                        raise ConfigError(f"unknown cluster '{cluster_id}'", exit_code=64)
                    return FakeCluster(root)

            original_policy = network_helper.load_policy
            original_config = network_helper.load_runtime_config
            network_helper.load_policy = lambda *a, **k: object()  # type: ignore[assignment]
            network_helper.load_runtime_config = lambda *a, **k: Config()  # type: ignore[assignment]
            try:
                code = network_helper.main(
                    [],
                    input_stream=io.BytesIO(json.dumps(request).encode("utf-8")),
                    output_stream=out,
                    error_stream=err,
                    require_root=False,
                )
            finally:
                network_helper.load_policy = original_policy  # type: ignore[assignment]
                network_helper.load_runtime_config = original_config  # type: ignore[assignment]
        return code, out.getvalue(), err.getvalue()

    def test_a_description_from_the_helper_matches_the_frozen_schema(self) -> None:
        code, out, err = self._run(
            description={"vips": {"internal": {"address": "192.0.2.20", "source": "192.0.2.25"}}}
        )

        self.assertEqual((code, err), (0, ""))
        document = assert_contract("haproxy-network", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["origin"], "repository")

    def test_an_unknown_cluster_is_refused_in_the_frozen_envelope(self) -> None:
        code, out, err = self._run(cluster="beta")

        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)
        document = assert_contract("haproxy-network", out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIsNone(document["result"])

    def test_a_description_that_does_not_parse_is_refused_rather_than_ignored(self) -> None:
        #
        # Falling back to the engine's tables here would answer with a
        # different network than the one somebody wrote, and the caller would
        # have no way to tell.
        #
        code, out, err = self._run(
            description={"vips": {"internal": {"address": "not-an-address"}}}
        )

        self.assertNotEqual(code, 0)
        self.assertIn("ERROR", err)
        document = assert_contract("haproxy-network", out)
        self.assertEqual(document["outcome"], "failed")

    def test_an_argument_never_reaches_the_helper(self) -> None:
        out, err = io.StringIO(), io.StringIO()

        code = network_helper.main(
            ["--cluster", "alpha"],
            input_stream=io.BytesIO(b"{}"),
            output_stream=out,
            error_stream=err,
            require_root=False,
        )

        self.assertNotEqual(code, 0)
        self.assertEqual(out.getvalue(), "")


class TheCommandRendersWhatTheHelperSaid(unittest.TestCase):
    def _document(self, **overrides: object) -> dict[str, object]:
        result = {
            "cluster": "alpha",
            "origin": "repository",
            "ownership_vip": "192.0.2.20",
            "default_vip": "internal",
            "vips": [{"name": "internal", "address": "192.0.2.20", "source": "192.0.2.25"}],
            "sources": [{"name": "outbound", "address": "192.0.2.35"}],
            "groups": [{"name": "office", "members": ["198.51.100.0/24"]}],
        } | overrides
        return {
            "schema_version": 1,
            "ok": True,
            "outcome": "done",
            "operation": "network",
            "cluster": "alpha",
            "request_id": REQUEST_ID,
            "result": result,
            "warnings": [],
            "error": None,
        }

    def _run(self, argv: list[str], document: object, *, code: int = 0):
        out, err = io.StringIO(), io.StringIO()
        completed = CompletedProcess(
            args=[], returncode=code, stdout=json.dumps(document), stderr=""
        )
        status = network.main(argv, stream_out=out, stream_err=err, run_helper=lambda *a: completed)
        return status, out.getvalue(), err.getvalue()

    def test_the_tables_are_printed_with_the_default_marked(self) -> None:
        status, out, err = self._run(["-c", "alpha"], self._document())

        self.assertEqual((status, err), (0, ""))
        self.assertIn("internal", out)
        self.assertIn("192.0.2.25", out)
        self.assertIn("outbound", out)
        self.assertIn("office", out)
        self.assertIn("managed/network.yaml", out)
        self.assertIn("Node ownership is checked against 192.0.2.20", out)

    def test_a_derived_description_says_where_it_came_from(self) -> None:
        status, out, _ = self._run(
            ["-c", "alpha"],
            self._document(origin="cluster_file", default_vip="main"),
        )

        self.assertEqual(status, 0)
        self.assertIn("no managed/network.yaml", out)

    def test_empty_tables_say_so_rather_than_printing_a_bare_header(self) -> None:
        status, out, _ = self._run(["-c", "alpha"], self._document(sources=[], groups=[]))

        self.assertEqual(status, 0)
        self.assertIn("every object leaves from its VIP's default", out)
        self.assertIn("none defined", out)

    def test_json_mode_passes_the_envelope_through_untouched(self) -> None:
        document = self._document()
        status, out, _ = self._run(["-c", "alpha", "--json"], document)

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out), document)

    def test_a_helper_that_returns_no_json_is_reported_rather_than_parsed(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        completed = CompletedProcess(args=[], returncode=68, stdout="", stderr="sudo: refused")

        status = network.main(
            ["-c", "alpha"], stream_out=out, stream_err=err, run_helper=lambda *a: completed
        )

        self.assertEqual(status, 68)
        self.assertIn("sudo: refused", err.getvalue())

    def test_a_failed_envelope_is_reported_as_the_helper_s_error(self) -> None:
        document = self._document()
        document["outcome"] = "failed"
        document["result"] = None
        document["error"] = {"code": "bad_input", "message": "unknown cluster 'beta'"}

        status, _, err = self._run(["-c", "alpha"], document, code=64)

        self.assertEqual(status, 64)
        self.assertIn("unknown cluster", err)

    def test_the_request_the_command_builds_is_the_one_the_helper_expects(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(command, *, input, capture_output, text, check):  # noqa: A002
            captured.update(json.loads(input))
            return CompletedProcess(args=command, returncode=0, stdout="{}", stderr="")

        original = network.subprocess.run
        network.subprocess.run = fake_run  # type: ignore[assignment]
        try:
            network.run_network_helper("alpha", REQUEST_ID)
        finally:
            network.subprocess.run = original  # type: ignore[assignment]

        self.assertEqual(captured["operation"], "network")
        self.assertEqual(captured["cluster"], "alpha")
        self.assertEqual(captured["request_id"], REQUEST_ID)
        self.assertEqual(captured["parameters"], {})


if __name__ == "__main__":
    unittest.main()
