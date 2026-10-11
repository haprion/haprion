"""The three certificate helpers at their privilege boundary.

What is held here is mostly what they refuse, because that is what a privilege
boundary is for: command-line arguments, a request naming a cluster, a request
for another operation, a target nobody registered, and - the one the phase gate
names in its own sentence - any way to get private key material back out.

The work itself is `issue`, `publish` and `set_targets`, tested where they live.
These tests are about the shape of the request and the shape of the answer.
"""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from typing import Any

import yaml

from haprion.cert_delete import Guards
from haprion.cli import cert_issue_helper, cert_job, cert_publish_helper, cert_target_helper
from haprion.envelope import new_request_id
from haprion.helper_protocol import HelperProtocolError
from tests.test_cert_issue import FakeCertbot
from tests.test_cert_publish import Fixture, issue
from tests.test_cert_registry import KEEPERS


class HelperFixture(Fixture):
    """One manager, one registry, and a way to run any of the three helpers."""

    def setUp(self) -> None:
        super().setUp()
        self.configure()
        self.deployed: list[str] = []

    def configure(self) -> None:
        """The policy and registry, rewritten so a receiver registered later is in them."""

        self.policy_path = self.write_config(
            KEEPERS | {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        #
        # The ACME block the issuing helper reads its secret paths from. The
        # helper refuses DNS-01 without it, correctly, so a fixture that left it
        # out would only ever measure that refusal.
        #
        document = yaml.safe_load(self.policy_path.read_text())
        document["acme"] = {
            "dns_cloudflare_credentials": str(self.root / "cloudflare.ini"),
            "webroot": str(self.root / "webroot"),
        }
        self.policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        (self.root / "certificates.yaml").chmod(0o640)

    def deployer(self, cluster: str) -> int:
        self.deployed.append(cluster)
        return 0

    def run_helper(
        self, module: Any, request: str, *, argv: list[str] | None = None, **options: Any
    ) -> tuple[int, dict[str, Any] | None, str]:
        out, err = io.StringIO(), io.StringIO()
        code = module.main(
            argv if argv is not None else [],
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            deployer=self.deployer,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            **options,
        )
        raw = out.getvalue()
        return code, (json.loads(raw) if raw.strip() else None), err.getvalue()

    def request(self, operation: str, parameters: dict[str, Any], *, cluster: Any = None) -> str:
        return json.dumps(
            {
                "schema_version": 1,
                "operation": operation,
                "cluster": cluster,
                "request_id": new_request_id(),
                "parameters": parameters,
            },
            separators=(",", ":"),
        )


class TheBoundaryEveryOneOfThemHolds(HelperFixture):
    MODULES = (
        (cert_issue_helper, {"domain": "new.example", "method": "dns-01", "clusters": ["alpha"]}),
        (cert_publish_helper, {"certificates": [], "deploy": False}),
        (
            cert_target_helper,
            {"certificates": ["example.com"], "add": {"clusters": ["alpha"]}, "deploy": False},
        ),
    )

    def test_no_command_line_arguments_are_accepted(self) -> None:
        """The sudoers rule grants the helper with an empty argument list and nothing else."""

        for module, parameters in self.MODULES:
            with self.subTest(helper=module.OPERATION):
                code, document, errors = self.run_helper(
                    module,
                    self.request(module.OPERATION, parameters),
                    argv=["--policy", "/etc/passwd"],
                )

                self.assertEqual(code, 64)
                self.assertIsNone(document)
                self.assertIn("no command-line arguments", errors)

    def test_a_request_naming_a_cluster_is_refused(self) -> None:
        """These operations have no cluster, and a request that thinks otherwise is not theirs."""

        for module, parameters in self.MODULES:
            with self.subTest(helper=module.OPERATION):
                code, document, errors = self.run_helper(
                    module, self.request(module.OPERATION, parameters, cluster="alpha")
                )

                self.assertEqual(code, 64)
                self.assertIsNone(document)
                self.assertIn("acts on no cluster", errors)

    def test_a_request_for_another_operation_is_refused(self) -> None:
        for module, parameters in self.MODULES:
            with self.subTest(helper=module.OPERATION):
                code, _, errors = self.run_helper(module, self.request("deploy", parameters))

                self.assertEqual(code, 64)
                self.assertIn("not allowed by this helper", errors)

    def test_an_unknown_parameter_is_refused_rather_than_ignored(self) -> None:
        for module, parameters in self.MODULES:
            with self.subTest(helper=module.OPERATION):
                code, _, errors = self.run_helper(
                    module, self.request(module.OPERATION, parameters | {"webroot": "/srv"})
                )

                self.assertEqual(code, 65)
                self.assertIn("unknown field", errors)

    def test_the_sudoers_example_grants_exactly_the_three_helper_paths(self) -> None:
        """The rule and the module must name the same path, or the grant is for nothing."""

        rules = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-worker.sudoers.example"
        ).read_text(encoding="utf-8")
        for module, _ in self.MODULES:
            with self.subTest(helper=module.OPERATION):
                self.assertIn(f'NOPASSWD: {module.HELPER} ""', rules)


class NoWayBackToTheKey(HelperFixture):
    """The phase gate's own sentence: no app identity can read private key material.

    The helpers write key material to targets. What is measured here is that
    none of them ever puts any of it in the answer the caller reads - not in the
    result, not in a warning, not in a failure's details.
    """

    def answers(self) -> list[str]:
        issue(self.live / "example.com", "example.com")
        for name in KEEPERS:
            issue(self.live / name, name)
        documents = []
        for module, parameters in (
            (cert_publish_helper, {"certificates": ["example.com"], "deploy": False}),
            (
                cert_target_helper,
                {"certificate": "example.com", "clusters": ["alpha"], "deploy": False},
            ),
        ):
            _, document, errors = self.run_helper(
                module, self.request(module.OPERATION, parameters)
            )
            documents.append(json.dumps(document))
            documents.append(errors)
        return documents

    def test_no_private_key_appears_in_any_answer(self) -> None:
        answers = self.answers()
        key = (self.live / "example.com" / "privkey.pem").read_text(encoding="utf-8")
        secret = "".join(key.splitlines()[1:-1])[:32]

        for answer in answers:
            self.assertNotIn(secret, answer)
            self.assertNotIn("PRIVATE KEY", answer)


class WhatIssuingAnswers(HelperFixture):
    def test_a_certificate_is_issued_registered_published_and_rolled_out(self) -> None:
        certbot = FakeCertbot(self.live)
        for name in KEEPERS:
            issue(self.live / name, name)

        code, document, _ = self.run_helper(
            cert_issue_helper,
            self.request(
                "cert_issue",
                {"domain": "new.example", "method": "dns-01", "clusters": ["alpha"]},
            ),
            certbot=certbot,
        )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        self.assertIsNone(document["cluster"])
        self.assertEqual(document["result"]["id"], "new.example")
        self.assertEqual(document["result"]["targets"]["clusters"], ["alpha"])
        self.assertEqual(self.deployed, ["alpha"])

    def test_a_receiver_s_format_is_registered_with_the_new_certificate(self) -> None:
        certbot = FakeCertbot(self.live)
        for name in KEEPERS:
            issue(self.live / name, name)
        self.register("certserver1.example.net", layout="per-certificate")
        self.configure()

        code, document, err = self.run_helper(
            cert_issue_helper,
            self.request(
                "cert_issue",
                {
                    "domain": "new.example",
                    "method": "dns-01",
                    "receivers": ["certserver1.example.net"],
                    "formats": {"certserver1.example.net": "pkcs12"},
                },
            ),
            certbot=certbot,
        )

        self.assertEqual(code, 0, err)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        raw = yaml.safe_load((self.root / "certificates.yaml").read_text())
        self.assertEqual(
            raw["certificates"]["new.example"]["receivers"],
            [{"id": "certserver1.example.net", "format": "pkcs12"}],
        )
        self.assertTrue(
            (self.receiver_path("certserver1.example.net") / "new.example" / "new.example.pfx").exists()
        )

    def test_the_terminal_flag_is_receiver_equals_format_and_nothing_else(self) -> None:
        self.assertEqual(cert_job.format_flags(["lb-01=pkcs12"], ["lb-01"]), {"lb-01": "pkcs12"})
        for flags, receivers in (
            (["lb-01"], ["lb-01"]),
            (["lb-01=der"], ["lb-01"]),
            (["lb-02=pkcs12"], ["lb-01"]),
        ):
            with self.subTest(flags=flags), self.assertRaises(HelperProtocolError):
                cert_job.format_flags(flags, receivers)

    def test_a_wildcard_over_http_01_is_refused_before_certbot_runs(self) -> None:
        certbot = FakeCertbot(self.live)

        code, document, _ = self.run_helper(
            cert_issue_helper,
            self.request(
                "cert_issue",
                {"domain": "*.new.example", "method": "http-01", "clusters": ["alpha"]},
            ),
            certbot=certbot,
        )

        self.assertEqual(code, 64)
        assert document is not None
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(certbot.calls, [])

    def test_certbot_s_own_words_reach_the_caller(self) -> None:
        certbot = FakeCertbot(
            self.live, returncode=1, output="DNS problem: NXDOMAIN looking up TXT"
        )

        code, document, _ = self.run_helper(
            cert_issue_helper,
            self.request(
                "cert_issue",
                {"domain": "new.example", "method": "dns-01", "clusters": ["alpha"]},
            ),
            certbot=certbot,
        )

        self.assertEqual(code, 1)
        assert document is not None
        self.assertEqual(document["error"]["code"], "certbot_failed")
        self.assertIn("NXDOMAIN", document["error"]["details"]["diagnostics"])


class WhatRetargetingAnswers(HelperFixture):
    """The batch with a delta (2026-09-15); the engine is measured in test_cert_retarget."""

    def test_adding_a_target_publishes_and_rolls_the_new_cluster_out(self) -> None:
        for name in ("example.com", *KEEPERS):
            issue(self.live / name, name)
        # Rolled out as a renewal leaves it, so only the new cluster is due.
        self.run_publish(self.policy_path, deployer=lambda _cluster_id: 0)

        code, document, _ = self.run_helper(
            cert_target_helper,
            self.request(
                "cert_target",
                {
                    "certificates": ["example.com"],
                    "add": {"clusters": ["beta"], "receivers": ["lb-01"]},
                },
            ),
        )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        result = document["result"]
        self.assertEqual(result["action"], "add")
        self.assertEqual(result["changed"], ["example.com"])
        self.assertEqual(result["certificates"][0]["added"], ["beta", "lb-01"])
        self.assertEqual(result["deployments"], [{"cluster": "beta", "exit_code": 0}])
        self.assertEqual(self.deployed, ["beta"])

    def test_an_unregistered_receiver_is_a_refused_row_and_the_registry_is_untouched(self) -> None:
        registry = self.root / "certificates.yaml"
        before = registry.read_bytes()

        code, document, _ = self.run_helper(
            cert_target_helper,
            self.request(
                "cert_target",
                {"certificates": ["example.com"], "add": {"receivers": ["lb-99"]}, "deploy": False},
            ),
        )

        self.assertEqual(code, 65)
        assert document is not None
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "all_refused")
        self.assertEqual(document["result"]["certificates"][0]["code"], "unknown_receiver")
        self.assertEqual(registry.read_bytes(), before)

    def test_a_request_must_say_add_or_remove_and_not_both(self) -> None:
        for parameters in (
            {"certificates": ["example.com"]},
            {
                "certificates": ["example.com"],
                "add": {"clusters": ["beta"]},
                "remove": {"clusters": ["alpha"]},
            },
            {"certificates": ["example.com"], "add": {"clusters": []}},
            {"certificates": ["example.com"], "add": {"nodes": ["x"]}},
            {"certificates": [], "add": {"clusters": ["beta"]}},
        ):
            with self.subTest(parameters=parameters):
                code, document, _ = self.run_helper(
                    cert_target_helper, self.request("cert_target", parameters)
                )
                self.assertEqual(code, 65)
                assert document is not None
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_a_format_travels_with_the_added_receiver(self) -> None:
        for name in ("example.com", *KEEPERS):
            issue(self.live / name, name)
        self.register("certserver1.example.net", layout="per-certificate")
        self.configure()

        code, document, err = self.run_helper(
            cert_target_helper,
            self.request(
                "cert_target",
                {
                    "certificates": ["example.com"],
                    "add": {
                        "receivers": ["certserver1.example.net"],
                        "formats": {"certserver1.example.net": "pkcs12"},
                    },
                    "deploy": False,
                },
            ),
        )

        self.assertEqual(code, 0, err)
        assert document is not None
        self.assertEqual(document["outcome"], "done")
        raw = yaml.safe_load((self.root / "certificates.yaml").read_text())
        self.assertEqual(
            raw["certificates"]["example.com"]["receivers"],
            [{"id": "certserver1.example.net", "format": "pkcs12"}],
        )
        bundle = self.receiver_path("certserver1.example.net") / "example.com" / "example.com.pfx"
        self.assertTrue(bundle.exists())

    def test_a_format_for_a_receiver_not_added_or_under_remove_is_the_request_s_fault(self) -> None:
        for parameters in (
            {
                "certificates": ["example.com"],
                "add": {"receivers": ["lb-01"], "formats": {"lb-02": "pkcs12"}},
            },
            {
                "certificates": ["example.com"],
                "add": {"receivers": ["lb-01"], "formats": {"lb-01": "der"}},
            },
            {
                "certificates": ["example.com"],
                "remove": {"receivers": ["lb-01"], "formats": {"lb-01": "pkcs12"}},
            },
        ):
            with self.subTest(parameters=parameters):
                code, document, _ = self.run_helper(
                    cert_target_helper, self.request("cert_target", parameters)
                )
                self.assertEqual(code, 65)
                assert document is not None
                self.assertEqual(document["error"]["code"], "bad_input")

    def test_the_request_the_interface_builds_carries_formats_only_when_stated(self) -> None:
        bare = json.loads(
            cert_target_helper.build_request(
                "r1", certificates=("a.example",), action="add", receivers=("lb-01",)
            )
        )
        stated = json.loads(
            cert_target_helper.build_request(
                "r1",
                certificates=("a.example",),
                action="add",
                receivers=("lb-01",),
                formats={"lb-01": "pkcs12"},
            )
        )

        self.assertNotIn("formats", bare["parameters"]["add"])
        self.assertEqual(stated["parameters"]["add"]["formats"], {"lb-01": "pkcs12"})

    def test_removing_a_cluster_asks_its_nodes_and_never_the_deployer(self) -> None:
        asked: list[str] = []
        key = self.root / "id_ed25519"
        key.write_text("dummy\n", encoding="utf-8")
        key.chmod(0o600)
        policy = yaml.safe_load(self.policy_path.read_text())
        policy["cert_deploy_identity"] = {"key": str(key)}
        self.policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

        def node(identity: Any, host: str, verb: str, certificate_id: str) -> tuple[int, str]:
            asked.append(host)
            return 0, f"Removed {certificate_id}."

        code, document, _ = self.run_helper(
            cert_target_helper,
            self.request(
                "cert_target",
                {
                    "certificates": ["example.com", "keeper-alpha.example"],
                    "remove": {"clusters": ["alpha"]},
                },
            ),
            node_remover=node,
            guards_reader=lambda runtime, ids: Guards(),
        )

        self.assertEqual(code, 0)
        assert document is not None
        # example.com leaves alpha; the keeper is then alpha's last and is refused.
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(document["result"]["changed"], ["example.com"])
        self.assertEqual(document["result"]["refused"], ["keeper-alpha.example"])
        self.assertEqual(self.deployed, [])
        self.assertEqual(asked, ["node-a.example.com", "node-b.example.com"])
        self.assertEqual(document["warnings"][0]["code"], "cluster_uncovered")


class WhatPublishingAnswers(HelperFixture):
    def test_an_imported_entry_without_material_is_a_warning_and_not_a_failure(self) -> None:
        """`partial` is reachable today, and this is the entry that reaches it.

        An imported certificate has no bytes until the import flow exists, and a
        registry holding one reaches this outcome on every single run.
        """

        self.policy_path = self.write_config(
            KEEPERS | {"imported.example": {"source": {"kind": "import"}, "clusters": ["alpha"]}}
        )
        for name in KEEPERS:
            issue(self.live / name, name)

        code, document, _ = self.run_helper(
            cert_publish_helper, self.request("cert_publish", {"certificates": [], "deploy": False})
        )

        self.assertEqual(code, 0)
        assert document is not None
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(
            [
                entry["id"]
                for entry in document["result"]["certificates"]
                if entry["status"] == "skipped"
            ],
            ["imported.example"],
        )
        self.assertEqual([w["code"] for w in document["warnings"]], ["source_missing"])


if __name__ == "__main__":
    unittest.main()
