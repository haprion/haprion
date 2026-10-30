"""`haprion-objects`, both halves.

The helper reads a committed tree inside the privilege boundary; the command
renders what came back and never decides anything itself.
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path

import yaml

from haprion import exit_codes
from haprion.cli import objects, objects_helper
from haprion.git_command import GitError
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "55555555-5555-4555-8555-555555555555"
HEAD = "d" * 40

SHOP = b"""
schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 192.0.2.10
        port: 8080
"""


def request(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "operation": "objects",
        "cluster": "alpha",
        "request_id": REQUEST_ID,
        "parameters": {},
    }
    document.update(overrides)
    return json.dumps(document).encode()


class ObjectsHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def runtime(self) -> Path:
        config_root = self.root / "config"
        publish_root = self.root / "published"
        cert_root = self.root / "certs"
        for directory in (config_root, publish_root, cert_root):
            directory.mkdir(parents=True, exist_ok=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")
        (config_root / "alpha").mkdir(exist_ok=True)
        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        entry = clusters["clusters"]["alpha"]
        entry["config_path"] = str(config_root / "alpha")
        entry["publish_path"] = str(publish_root / "alpha")
        entry["validation_certs"] = str(cert_root)
        (self.root / "clusters.yaml").write_text(yaml.safe_dump(clusters), encoding="utf-8")
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
        tree_reader: Callable[[Path, str], Mapping[str, bytes]] | None = None,
        head_resolver: Callable[[Path], tuple[str, str]] | None = None,
        parent_resolver: Callable[[Path, str], str | None] | None = None,
        cluster: str = "alpha",
        parameters: dict[str, object] | None = None,
        waf: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        read = tree_reader or (lambda _repo, _commit: {"managed/proxies/shop.yaml": SHOP})
        resolve = head_resolver or (lambda _repo: ("refs/heads/main", HEAD))
        code = objects_helper.main(
            [],
            policy_path=self.runtime(),
            input_stream=io.BytesIO(request(cluster=cluster, parameters=parameters or {})),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            tree_reader=read,
            head_resolver=resolve,
            parent_resolver=parent_resolver or (lambda _repo, _commit: None),
            waf_versions=lambda: waf or {"engine": "0.9.0-2", "crs": "4.25.1"},
        )
        return code, out.getvalue(), err.getvalue()

    def test_the_listing_says_what_the_manager_can_publish_a_waf_with(self) -> None:
        """B231: the engine and the rule set on the manager, beside the objects.
        A package installed or upgraded is a new listing, not an unchanged one."""

        _, first, _ = self.run_helper()
        result = assert_contract("haprion-objects", first)["result"]
        self.assertEqual(result["waf"], {"engine": "0.9.0-2", "crs": "4.25.1"})
        _, again, _ = self.run_helper(
            parameters={"unchanged_since": result["fingerprint"]},
            waf={"engine": "0.9.0-3", "crs": "4.25.1"},
        )
        changed = json.loads(again)["result"]
        self.assertNotIn("unchanged", changed)
        self.assertEqual(changed["waf"]["engine"], "0.9.0-3")

    def test_the_listing_names_the_commit_its_head_was_made_on(self) -> None:
        """B411: the poller follows a rename only across one publish, which this tells it."""

        _, out, _ = self.run_helper(parent_resolver=lambda _repo, _commit: "c" * 40)
        self.assertEqual(assert_contract("haprion-objects", out)["result"]["parent"], "c" * 40)

        _, out, _ = self.run_helper()
        self.assertIsNone(assert_contract("haprion-objects", out)["result"]["parent"])

    def test_a_parent_that_cannot_be_read_does_not_fail_the_listing(self) -> None:
        def broken(_repo: Path, _commit: str) -> str | None:
            raise GitError("git rev-list failed")

        code, out, _ = self.run_helper(parent_resolver=broken)

        self.assertEqual(code, 0)
        self.assertIsNone(json.loads(out)["result"]["parent"])

    def test_it_reads_head_rather_than_the_published_release(self) -> None:
        """The base a publish checks its snapshot against.

        Inventory reads the commit the RELEASE stamp names, because it answers
        what a node is serving. A draft is made against what is committed, so
        recording anything else would compare it to a commit nobody publishes
        onto.
        """

        seen: list[tuple[Path, str]] = []

        def tree(repo: Path, commit: str) -> dict[str, bytes]:
            seen.append((repo, commit))
            return {"managed/proxies/shop.yaml": SHOP}

        code, out, _ = self.run_helper(tree_reader=tree)

        self.assertEqual(code, 0)
        self.assertEqual(seen[0][1], HEAD)
        document = assert_contract("haprion-objects", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["request_id"], REQUEST_ID)
        self.assertEqual(document["result"]["commit"], HEAD)
        self.assertEqual(document["result"]["objects"][0]["name"], "shop")

    def test_the_document_crosses_the_boundary_unchanged(self) -> None:
        _, out, _ = self.run_helper()

        document = json.loads(out)
        self.assertEqual(document["result"]["objects"][0]["document"], SHOP.decode())

    def test_a_tree_that_cannot_be_listed_is_a_structured_failed_envelope(self) -> None:
        code, out, _ = self.run_helper(
            tree_reader=lambda _repo, _commit: {"managed/proxies/nested/shop.yaml": SHOP}
        )

        self.assertEqual(code, 65)
        document = assert_contract("haprion-objects", out)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "objects_invalid")

    def test_a_repository_that_is_not_on_a_branch_says_so(self) -> None:
        """Detached HEAD is refused upstream; the helper reports it rather than crashing."""

        from haprion.repo_snapshot import PublishError

        def detached(_repo: Path) -> tuple[str, str]:
            raise PublishError("the repository is not on a branch.")

        code, out, _ = self.run_helper(head_resolver=detached)

        self.assertEqual(code, 65)
        document = assert_contract("haprion-objects", out)
        self.assertEqual(document["error"]["code"], "objects_unavailable")

    def test_an_unknown_cluster_is_refused_in_the_frozen_envelope(self) -> None:
        code, out, err = self.run_helper(cluster="beta")

        self.assertEqual(code, 64)
        self.assertIn("unknown cluster", err)
        document = assert_contract("haprion-objects", out)
        self.assertEqual(document["error"]["code"], "bad_input")

    def test_protocol_and_argument_errors_do_not_cross_the_boundary(self) -> None:
        err = io.StringIO()

        code = objects_helper.main(
            ["-c", "alpha"],
            policy_path=self.runtime(),
            input_stream=io.BytesIO(request()),
            output_stream=io.StringIO(),
            error_stream=err,
            require_secure=False,
            require_root=False,
        )

        self.assertEqual(code, 64)
        self.assertIn("no command-line arguments", err.getvalue())

    # B222: a caller holding the current listing is told so, without a tree read.
    def test_the_fingerprint_sent_back_is_answered_as_unchanged(self) -> None:
        _, first, _ = self.run_helper()
        known = json.loads(first)["result"]["fingerprint"]
        reads: list[str] = []

        def tree(_repo: Path, commit: str) -> dict[str, bytes]:
            reads.append(commit)
            return {"managed/proxies/shop.yaml": SHOP}

        code, out, _ = self.run_helper(tree_reader=tree, parameters={"unchanged_since": known})

        self.assertEqual(code, 0)
        document = assert_contract("haprion-objects", out)
        self.assertIs(document["result"]["unchanged"], True)
        self.assertEqual(document["result"]["objects"], [])
        self.assertEqual(document["result"]["fingerprint"], known)
        self.assertEqual(reads, [])

    def test_a_new_commit_or_network_is_a_full_listing(self) -> None:
        _, first, _ = self.run_helper()
        known = json.loads(first)["result"]["fingerprint"]

        moved = lambda _repo: ("refs/heads/main", "b" * 40)  # noqa: E731
        _, out, _ = self.run_helper(head_resolver=moved, parameters={"unchanged_since": known})
        self.assertNotIn("unchanged", json.loads(out)["result"])
        self.assertEqual(json.loads(out)["result"]["objects"][0]["name"], "shop")

        network = self.root / "config/alpha/managed/network.yaml"
        network.parent.mkdir(parents=True)
        network.write_text(
            "vips:\n  internal:\n    address: 192.0.2.40\ndefault_vip: internal\n",
            encoding="utf-8",
        )
        _, out, _ = self.run_helper(parameters={"unchanged_since": known})
        self.assertNotIn("unchanged", json.loads(out)["result"])

    def test_a_fingerprint_that_is_not_one_is_refused(self) -> None:
        code, out, err = self.run_helper(parameters={"unchanged_since": "../../etc"})

        # Review 26-10-24, 06-10: the request is read, so the refusal is bound to it.
        self.assertEqual(code, exit_codes.USAGE)
        self.assertEqual(assert_contract("haprion-objects", out)["error"]["code"], "bad_input")
        self.assertIn("unchanged_since", err)

    # B222: the helper reads the network description the generator reads.

    def test_each_object_carries_its_vip_from_the_cluster_file(self) -> None:
        code, out, _ = self.run_helper()

        self.assertEqual(code, 0)
        entry = assert_contract("haprion-objects", out)["result"]["objects"][0]
        self.assertEqual(
            entry["vip"], {"name": "internal", "address": "192.0.2.20", "default": True}
        )
        self.assertEqual(entry["servers"], ["192.0.2.10:8080"])

    def test_a_network_that_cannot_be_read_withholds_only_the_addresses(self) -> None:
        self.runtime()
        network = self.root / "config/alpha/managed/network.yaml"
        network.parent.mkdir(parents=True)
        network.write_text("vips: [this is not a table\n", encoding="utf-8")

        code, out, _ = self.run_helper()

        self.assertEqual(code, 0)
        document = assert_contract("haprion-objects", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual([w["code"] for w in document["warnings"]], ["network_unreadable"])
        self.assertIsNone(document["result"]["objects"][0]["vip"])


def answer(**result: object) -> subprocess.CompletedProcess[str]:
    document = {
        "schema_version": 1,
        "ok": True,
        "outcome": "done",
        "operation": "objects",
        "cluster": "alpha",
        "request_id": REQUEST_ID,
        "result": {"commit": HEAD, "generated_at": "2026-09-02T08:05:00Z", "objects": [], **result},
        "warnings": [],
        "error": None,
    }
    return subprocess.CompletedProcess([], 0, json.dumps(document), "")


class ObjectsCommandTests(unittest.TestCase):
    def run_command(
        self, argv: list[str], completed: subprocess.CompletedProcess[str]
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = objects.main(
            argv,
            stream_out=out,
            stream_err=err,
            run_helper=lambda _cluster, _request: completed,
        )
        return code, out.getvalue(), err.getvalue()

    def readable(self) -> dict[str, object]:
        return {
            "name": "shop",
            "document": SHOP.decode(),
            "readable": True,
            "problem": None,
            "protocol": "http",
            "hostnames": ["shop.example.com"],
        }

    def test_the_listing_names_what_each_object_serves(self) -> None:
        code, out, _ = self.run_command(["-c", "alpha"], answer(objects=[self.readable()]))

        self.assertEqual(code, 0)
        self.assertIn("shop", out)
        self.assertIn("http", out)
        self.assertIn("shop.example.com", out)

    def test_the_listing_says_which_vip_and_an_older_helper_says_dash(self) -> None:
        on_vip = {
            **self.readable(),
            "vip": {"name": "dmz", "address": "198.51.100.20", "default": False},
        }
        _, out, _ = self.run_command(["-c", "alpha"], answer(objects=[on_vip]))
        _, older, _ = self.run_command(["-c", "alpha"], answer(objects=[self.readable()]))

        self.assertIn("http   198.51.100.20    shop.example.com", out)
        self.assertIn("http   -                shop.example.com", older)

    def test_an_unreadable_object_is_listed_with_what_is_wrong(self) -> None:
        """Hiding it would hide the one file somebody has to open."""

        broken = {
            "name": "half-written",
            "document": "schema: 1\n",
            "readable": False,
            "problem": "half-written.listen must be a mapping",
            "protocol": None,
            "hostnames": [],
        }

        code, out, _ = self.run_command(["-c", "alpha"], answer(objects=[broken]))

        self.assertEqual(code, 0)
        self.assertIn("half-written", out)
        self.assertIn("CANNOT READ", out)
        self.assertIn("must be a mapping", out)

    def test_show_prints_one_document_and_nothing_else(self) -> None:
        """So it can be piped or diffed without going through a browser."""

        code, out, _ = self.run_command(
            ["-c", "alpha", "--show", "shop"], answer(objects=[self.readable()])
        )

        self.assertEqual(code, 0)
        self.assertEqual(out, SHOP.decode())

    def test_advanced_says_where_each_line_goes_and_why_one_is_refused(self) -> None:
        entry = self.readable()
        entry["document"] = SHOP.decode() + (
            "advanced: |\n  http-request deny if { path /x }\n  bind :8080\n"
        )
        entry["readable"] = False

        code, out, _ = self.run_command(
            ["-c", "alpha", "--advanced", "shop"], answer(objects=[entry])
        )

        self.assertEqual(code, 65)
        self.assertIn("   1  placed   every pool", out)
        self.assertIn("   2  refused  -", out)
        self.assertIn("the address an object listens on is set in the form", out)

    def test_advanced_on_an_object_without_text_says_so(self) -> None:
        code, out, _ = self.run_command(
            ["-c", "alpha", "--advanced", "shop"], answer(objects=[self.readable()])
        )

        self.assertEqual((code, out), (0, "shop has no advanced config.\n"))

    def test_show_for_a_name_that_is_not_there_says_so(self) -> None:
        code, out, err = self.run_command(
            ["-c", "alpha", "--show", "missing"], answer(objects=[self.readable()])
        )

        self.assertEqual(code, 66)
        self.assertEqual(out, "")
        self.assertIn("missing", err)

    def test_a_cluster_with_no_objects_says_so_rather_than_printing_a_header(self) -> None:
        code, out, _ = self.run_command(["-c", "alpha"], answer())

        self.assertEqual(code, 0)
        self.assertIn("No stored objects.", out)

    def test_json_mode_passes_the_envelope_through(self) -> None:
        code, out, _ = self.run_command(
            ["-c", "alpha", "--json"], answer(objects=[self.readable()])
        )

        self.assertEqual(code, 0)
        assert_contract("haprion-objects", out)

    def test_a_helper_that_returned_nothing_is_reported_not_rendered(self) -> None:
        empty = subprocess.CompletedProcess([], 68, "", "sudo: a password is required")

        code, out, err = self.run_command(["-c", "alpha"], empty)

        self.assertEqual(code, 68)
        self.assertEqual(out, "")
        self.assertIn("password", err)


if __name__ == "__main__":
    unittest.main()
