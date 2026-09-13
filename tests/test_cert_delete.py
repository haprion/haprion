"""Deleting certificates: what is refused, what goes, and what is left and said.

Most of what is held here is refusal, because the operation is the one thing
in the project that removes key material. The rest is the shape of the answer:
one row per certificate, with every layer that was touched or kept on it, so
an operator reading the job knows what to clean up by hand and what not to.
"""

from __future__ import annotations

import io
import json
import subprocess
import unittest
import uuid
from pathlib import Path
from typing import Any

import yaml

from haproxy_mgmt import cert_delete
from haproxy_mgmt.cert_delete import Guards, delete, read_guards
from haproxy_mgmt.cert_inventory import FULLCHAIN, PRIVKEY
from haproxy_mgmt.cli import cert_delete_helper
from haproxy_mgmt.config import load_policy, load_runtime_config
from tests.test_cert_publish import Fixture
from tests.test_proxy_model import with_lines

#
# One certificate per cluster the tests never delete, for the reason the
# registry tests give: the engine refuses a cluster nobody names.
#
KEEPERS: dict[str, dict[str, object]] = {
    "keeper-alpha.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
    "keeper-beta.example": {"source": {"kind": "acme"}, "clusters": ["beta"]},
}


def commit(repo: Path, files: dict[str, bytes]) -> None:
    """A cluster repository with one commit holding `files`."""

    def git(*args: str) -> None:
        subprocess.run(["/usr/bin/git", "-C", str(repo), *args], check=True, capture_output=True)

    repo.mkdir(exist_ok=True)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Example Maintainer")
    git("config", "user.email", "maintainer@example.com")
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    git("add", "-A")
    git("commit", "-qm", "objects")


class DeleteFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.renewal = self.root / "renewal"
        self.renewal.mkdir()
        self.certbot_calls: list[tuple[str, ...]] = []
        self.node_calls: list[tuple[str, str]] = []
        self.node_answers: dict[str, tuple[int, str]] = {}

    def prepared(self, certificates: dict[str, dict[str, Any]]) -> Path:
        policy_path = self.write_config(KEEPERS | certificates)
        (self.root / "certificates.yaml").chmod(0o640)
        #
        # Material and lineage for every certificate, as publish and certbot
        # would have left them, so a deletion has something to remove.
        #
        for certificate_id, raw in (KEEPERS | certificates).items():
            (self.dist / f"{certificate_id}.pem").write_text("pem\n", encoding="utf-8")
            (self.renewal / f"{certificate_id}.conf").write_text("version = 5.8.0\n")
            if "lb-01" in (raw.get("receivers") or []):
                (self.receiver_dir / FULLCHAIN).write_text("chain\n", encoding="utf-8")
                (self.receiver_dir / PRIVKEY).write_text("key\n", encoding="utf-8")
        #
        # Nodes reachable through an identity the policy names; the key only
        # has to exist for the loader.
        #
        key = self.root / "id_ed25519"
        key.write_text("dummy\n", encoding="utf-8")
        key.chmod(0o600)
        policy = yaml.safe_load(policy_path.read_text())
        policy["cert_deploy_identity"] = {"user": "svc-cert", "key": str(key)}
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path

    def certbot(self, command: tuple[str, ...]) -> tuple[int, str]:
        self.certbot_calls.append(tuple(command))
        conf = self.renewal / f"{command[3]}.conf"
        conf.unlink(missing_ok=True)
        return 0, ""

    def node(self, identity: Any, host: str, certificate_id: str) -> tuple[int, str]:
        self.node_calls.append((host, certificate_id))
        return self.node_answers.get(host, (0, "removed"))

    def run_delete(
        self, policy_path: Path, *certificate_ids: str, guards: Guards | None = None
    ) -> cert_delete.Report:
        return delete(
            certificate_ids,
            load_policy(policy_path, require_secure=False),
            require_secure=False,
            renewal_directory=self.renewal,
            store=self.store,
            certbot="/usr/bin/certbot",
            lineage_remover=self.certbot,
            node_remover=self.node,
            guards_reader=lambda runtime, ids: guards or Guards(),
        )

    def registered(self) -> set[str]:
        return set(yaml.safe_load((self.root / "certificates.yaml").read_text())["certificates"])


class WhatIsRefused(DeleteFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.before = (self.root / "certificates.yaml").read_bytes()

    def assert_untouched(self, report: cert_delete.Report, certificate_id: str, code: str) -> None:
        (outcome,) = [o for o in report.outcomes if o.certificate_id == certificate_id]
        self.assertEqual(outcome.state, "refused")
        self.assertEqual(outcome.code, code)
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), self.before)
        self.assertTrue((self.dist / f"{certificate_id}.pem").exists())
        self.assertTrue((self.renewal / f"{certificate_id}.conf").exists())
        self.assertEqual(self.certbot_calls, [])
        self.assertEqual(self.node_calls, [])

    def test_a_certificate_that_is_not_registered(self) -> None:
        report = self.run_delete(self.policy_path, "nobody.example")
        (outcome,) = report.outcomes
        self.assertEqual((outcome.state, outcome.code), ("refused", "not_registered"))

    def test_a_certificate_a_committed_object_names(self) -> None:
        guards = Guards(referenced={"example.com": ("alpha/shop",)})
        report = self.run_delete(self.policy_path, "example.com", guards=guards)
        self.assert_untouched(report, "example.com", "referenced_by_object")
        self.assertIn("alpha/shop", report.outcomes[0].reason)

    def test_a_cluster_s_default_certificate(self) -> None:
        guards = Guards(defaults={"example.com": ("alpha",)})
        report = self.run_delete(self.policy_path, "example.com", guards=guards)
        self.assert_untouched(report, "example.com", "cluster_default")

    def test_a_cluster_s_last_certificate(self) -> None:
        """The keeper is beta's only certificate; taking it would make beta unloadable."""

        report = self.run_delete(self.policy_path, "keeper-beta.example")
        self.assert_untouched(report, "keeper-beta.example", "cluster_uncovered")

    def test_the_second_of_two_that_cover_a_cluster_together(self) -> None:
        """Guards see the first deletion: the registry is re-read between certificates."""

        report = self.run_delete(self.policy_path, "example.com", "keeper-alpha.example")
        self.assertEqual(report.removed, ("example.com",))
        self.assertEqual(report.refused, ("keeper-alpha.example",))
        self.assertEqual(report.outcomes[1].code, "cluster_uncovered")
        self.assertEqual(self.registered(), {"keeper-alpha.example", "keeper-beta.example"})


class WhatGoes(DeleteFixture):
    def test_every_layer_is_removed_and_reported(self) -> None:
        policy_path = self.prepared(
            {
                "example.com": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                }
            }
        )
        report = self.run_delete(policy_path, "example.com")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "removed", outcome)
        self.assertNotIn("example.com", self.registered())
        self.assertFalse((self.dist / "example.com.pem").exists())
        self.assertFalse((self.receiver_dir / FULLCHAIN).exists())
        self.assertFalse((self.receiver_dir / PRIVKEY).exists())
        self.assertEqual(
            self.certbot_calls,
            [
                (
                    "/usr/bin/certbot",
                    "delete",
                    "--cert-name",
                    "example.com",
                    "--non-interactive",
                    "--quiet",
                )
            ],
        )
        self.assertEqual(
            self.node_calls,
            [("node-a.example.com", "example.com"), ("node-b.example.com", "example.com")],
        )
        states = {layer.name: layer.state for layer in outcome.layers}
        self.assertEqual(states["registry"], "removed")
        self.assertEqual(states["lineage example.com"], "removed")
        self.assertEqual({copy.state for copy in outcome.nodes}, {"removed"})
        #
        # The keepers, and their material, are exactly as they were.
        #
        self.assertTrue((self.dist / "keeper-alpha.example.pem").exists())
        self.assertTrue((self.renewal / "keeper-alpha.example.conf").exists())

    def test_an_explicit_lineage_name_is_the_one_certbot_is_asked_for(self) -> None:
        policy_path = self.prepared(
            {
                "wild": {
                    "source": {"kind": "acme", "lineage": "example.com-wildcard"},
                    "clusters": ["alpha"],
                }
            }
        )
        (self.renewal / "example.com-wildcard.conf").write_text("version = 5.8.0\n")
        report = self.run_delete(policy_path, "wild")
        self.assertEqual(report.removed, ("wild",))
        self.assertEqual(self.certbot_calls[0][3], "example.com-wildcard")

    def test_an_imported_certificate_loses_its_store_directory_not_a_lineage(self) -> None:
        policy_path = self.prepared(
            {"imported.example": {"source": {"kind": "import"}, "clusters": ["alpha"]}}
        )
        (self.store / "imported.example").mkdir()
        (self.store / "imported.example" / "fullchain.pem").write_text("x\n")
        report = self.run_delete(policy_path, "imported.example")
        self.assertEqual(report.removed, ("imported.example",))
        self.assertFalse((self.store / "imported.example").exists())
        self.assertEqual(self.certbot_calls, [])

    def test_a_missing_lineage_or_file_is_absent_not_failed(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        (self.renewal / "example.com.conf").unlink()
        (self.dist / "example.com.pem").unlink()
        report = self.run_delete(policy_path, "example.com")
        self.assertEqual(report.removed, ("example.com",))
        self.assertEqual({layer.state for layer in report.outcomes[0].layers[1:]}, {"absent"})
        self.assertEqual(self.certbot_calls, [])


class WhatIsLeftAndSaid(DeleteFixture):
    def test_a_node_that_does_not_know_the_verb_keeps_its_copy_by_name(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.node_answers["node-b.example.com"] = (1, "unknown request: cert-remove")
        report = self.run_delete(policy_path, "example.com")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "incomplete")
        self.assertNotIn("example.com", self.registered())
        copies = {copy.node: copy.state for copy in outcome.nodes}
        self.assertEqual(copies, {"node-a": "removed", "node-b": "kept"})
        self.assertIn("unknown request", outcome.nodes[1].detail)

    def test_an_unreachable_node_is_said_and_the_batch_continues(self) -> None:
        policy_path = self.prepared(
            {
                "one.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "two.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        self.node_answers["node-a.example.com"] = (255, "connection refused")
        report = self.run_delete(policy_path, "one.example", "two.example")
        self.assertEqual(report.incomplete, ("one.example", "two.example"))
        self.assertEqual(report.outcomes[0].nodes[0].state, "unreachable")

    def test_a_certbot_failure_keeps_the_lineage_row_and_the_rest_goes(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.certbot = lambda command: (1, "certbot: No certificate found")  # type: ignore[method-assign]
        report = self.run_delete(policy_path, "example.com")
        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "incomplete")
        lineage = [layer for layer in outcome.layers if layer.name.startswith("lineage")][0]
        self.assertEqual(lineage.state, "failed")
        self.assertIn("No certificate found", lineage.detail)
        self.assertFalse((self.dist / "example.com.pem").exists())


class TheGuardsReadTheCommittedObjects(DeleteFixture):
    def test_an_https_object_naming_the_certificate_is_found_at_head(self) -> None:
        policy_path = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "unused.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        shop = with_lines(("  protocol: http", "  protocol: https\n  certificate: example.com"))
        commit(runtime.clusters["alpha"].config_path, {"managed/proxies/shop.yaml": shop})
        commit(runtime.clusters["beta"].config_path, {"managed/proxies/.gitkeep": b""})

        guards = read_guards(runtime, ["example.com", "unused.example", "keeper-alpha.example"])

        self.assertEqual(guards.referenced, {"example.com": ("alpha/shop",)})
        #
        # The fixture defaults each cluster to the first certificate naming it.
        #
        self.assertEqual(guards.defaults, {"keeper-alpha.example": ("alpha",)})


class TheHelper(DeleteFixture):
    def invoke(self, policy_path: Path, *certificate_ids: str) -> tuple[int, dict[str, Any], str]:
        request = cert_delete_helper.build_request(str(uuid.uuid4()), certificates=certificate_ids)
        output, errors = io.StringIO(), io.StringIO()
        code = cert_delete_helper.main(
            [],
            policy_path=policy_path,
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            renewal_directory=self.renewal,
            store=self.store,
            lineage_remover=self.certbot,
            node_remover=self.node,
            guards_reader=lambda runtime, ids: Guards(),
        )
        document = json.loads(output.getvalue()) if output.getvalue() else {}
        return code, document, errors.getvalue()

    def test_all_gone_is_done(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        code, document, _ = self.invoke(policy_path, "example.com")
        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["removed"], ["example.com"])

    def test_one_refused_is_partial_with_a_warning_per_row(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        code, document, _ = self.invoke(policy_path, "example.com", "keeper-beta.example")
        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(document["result"]["refused"], ["keeper-beta.example"])
        self.assertEqual(document["warnings"][0]["code"], "cluster_uncovered")

    def test_kept_node_copies_make_a_partial_not_a_failure(self) -> None:
        """The first live run (job 578, 2026-09-13): nodes without the verb."""

        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.node_answers["node-a.example.com"] = (1, "unknown request: cert-remove")
        self.node_answers["node-b.example.com"] = (1, "unknown request: cert-remove")
        code, document, _ = self.invoke(policy_path, "example.com")
        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(document["result"]["incomplete"], ["example.com"])
        self.assertNotIn("example.com", self.registered())

    def test_nothing_removed_at_all_is_failed(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        (self.root / "certificates.yaml").chmod(0o000)
        self.addCleanup((self.root / "certificates.yaml").chmod, 0o640)
        code, document, _ = self.invoke(policy_path, "example.com")
        self.assertNotEqual(document["outcome"], "done")

    def test_every_one_refused_is_blocked_and_nothing_is_touched(self) -> None:
        policy_path = self.prepared({})
        before = (self.root / "certificates.yaml").read_bytes()
        code, document, _ = self.invoke(policy_path, "keeper-alpha.example", "nobody.example")
        self.assertEqual(code, 65)
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "all_refused")
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), before)

    def test_an_empty_list_and_an_argument_are_refused(self) -> None:
        policy_path = self.prepared({})
        code, document, _ = self.invoke(policy_path)
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertEqual(
            cert_delete_helper.main(
                ["--help"], input_stream=io.BytesIO(b""), error_stream=io.StringIO()
            ),
            64,
        )


if __name__ == "__main__":
    unittest.main()
