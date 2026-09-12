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

from haproxy_mgmt.cli import cert_issue_helper, cert_publish_helper, cert_target_helper
from haproxy_mgmt.envelope import new_request_id
from tests.test_cert_issue import FakeCertbot
from tests.test_cert_publish import Fixture, issue
from tests.test_cert_registry import KEEPERS


class HelperFixture(Fixture):
    """One manager, one registry, and a way to run any of the three helpers."""

    def setUp(self) -> None:
        super().setUp()
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
        self.deployed: list[str] = []

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
            {"certificate": "example.com", "clusters": ["alpha"], "deploy": False},
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
            / "install/platform/examples/haproxy-ui-worker.sudoers.example"
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
    def test_the_targets_become_exactly_those_asked_for_and_the_drop_is_named(self) -> None:
        issue(self.live / "example.com", "example.com")
        for name in KEEPERS:
            issue(self.live / name, name)

        code, document, _ = self.run_helper(
            cert_target_helper,
            self.request(
                "cert_target",
                {"certificate": "example.com", "receivers": ["lb-01"], "deploy": False},
            ),
        )

        self.assertEqual(code, 0)
        assert document is not None
        registry = document["result"]["registry"]
        self.assertEqual(registry["targets"], {"clusters": [], "receivers": ["lb-01"]})
        self.assertEqual(registry["abandoned"], ["alpha"])
        self.assertEqual(document["outcome"], "partial")
        self.assertIn("target_abandoned", [warning["code"] for warning in document["warnings"]])

    def test_an_unregistered_receiver_is_refused_and_the_registry_is_untouched(self) -> None:
        registry = self.root / "certificates.yaml"
        before = registry.read_bytes()

        code, document, _ = self.run_helper(
            cert_target_helper,
            self.request(
                "cert_target",
                {"certificate": "example.com", "receivers": ["lb-99"], "deploy": False},
            ),
        )

        self.assertEqual(code, 64)
        assert document is not None
        self.assertEqual(document["error"]["code"], "unknown_receiver")
        self.assertEqual(registry.read_bytes(), before)


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
