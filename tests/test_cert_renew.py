"""The renewal timer reconstructs profile environments per lineage."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
from dataclasses import replace
from typing import Any
from unittest import mock

import yaml

from haprion import cert_issue, dns_profiles, dns_provider_catalog, exit_codes
from haprion.cli import cert_renew
from haprion.cli.cert_publish import ClusterDeployer
from haprion.config import ConfigError, load_policy, load_runtime_config
from haprion.dns_profile_keys import generate, render_private_key
from tests.contract_schema import assert_contract
from tests.test_cert_publish import Fixture, issue


def _commands(*args: Any, **kwargs: Any) -> tuple[cert_renew.RenewalInvocation, ...]:
    renewals = cert_renew.invocations(*args, **kwargs)
    assert renewals.problems == ()  # every lineage here can be prepared
    return renewals.commands


class TheHelp(unittest.TestCase):
    def test_it_says_the_ndes_certificates_are_renewed_too(self) -> None:
        """Review 26-10-24, 16-09: someone after an NDES renewal passed the command by."""

        shown = io.StringIO()
        with contextlib.redirect_stdout(shown), self.assertRaises(SystemExit):
            cert_renew.main(["--help"])
        help_text = " ".join(shown.getvalue().split())
        self.assertIn("every certbot lineage that is due, then every NDES certificate", help_text)
        self.assertIn("NDES", cert_renew.__doc__ or "")


class RenewalInvocations(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.profile_dir = self.root / "profiles"
        self.profile_dir.mkdir(mode=0o700)
        policy_path = self.write_config(
            {
                "example.com": {
                    "source": {"kind": "acme", "dns_profile": "aws-main"},
                    "clusters": ["alpha"],
                },
                "legacy.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                },
            }
        )
        private, public = generate()
        private_path = self.root / "profile.key"
        private_path.write_text(render_private_key(private), encoding="utf-8")
        private_path.chmod(0o600)
        document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        document["acme"] = {
            "certbot": "/opt/certbot/bin/certbot",
            "dns_profiles": {
                "directory": str(self.profile_dir),
                "private_keys": [str(private_path)],
            },
        }
        policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        self.policy = load_policy(policy_path, require_secure=False)
        self.runtime = load_runtime_config(self.policy, require_secure=False)
        ciphertext = dns_profiles.seal_profile(
            public,
            profile_id="aws-main",
            provider_id="route53",
            revision=1,
            fields={"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret-value"},
        )
        opened = dns_profiles.open_profile(
            private,
            ciphertext,
            profile_id="aws-main",
            provider_id="route53",
            revision=1,
        )
        assert self.policy.acme is not None and self.policy.acme.dns_profiles is not None
        dns_profiles.materialize(self.policy.acme.dns_profiles, opened, require_secure=False)
        self.renewal = self.root / "renewal"
        self.renewal.mkdir()
        for lineage in ("example.com", "legacy.example", "orphan.example"):
            (self.renewal / f"{lineage}.conf").write_text(
                "[renewalparams]\nauthenticator = dns-cloudflare\n", encoding="utf-8"
            )

    def test_each_lineage_is_bounded_and_only_route53_gets_its_environment(self) -> None:
        commands = _commands(
            self.policy,
            self.runtime,
            renewal_directory=self.renewal,
            binary="/new/certbot",
            dry_run=True,
            run_deploy_hooks=True,
            require_secure=False,
        )

        self.assertEqual(
            [command.lineage for command in commands],
            [
                "example.com",
                "legacy.example",
                "orphan.example",
            ],
        )
        profiled = commands[0]
        self.assertEqual(
            profiled.environment["AWS_SHARED_CREDENTIALS_FILE"],
            str(self.profile_dir / "aws-main"),
        )
        self.assertIn("secret-value", profiled.redactions)
        self.assertEqual(profiled.arguments[0], "/new/certbot")
        self.assertIn("--cert-name", profiled.arguments)
        self.assertIn("--dry-run", profiled.arguments)
        self.assertIn("--run-deploy-hooks", profiled.arguments)
        self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", commands[1].environment)
        self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", commands[2].environment)

    def test_the_nightly_renewal_waits_as_long_as_the_profile_s_provider(self) -> None:
        #
        # Route53's own wait is short, so the budget is made to depend on it
        # visibly: the profiled lineage must carry what its provider asks for.
        #
        with mock.patch.object(cert_issue, "certbot_timeout", lambda seconds: 5000 + seconds):
            commands = _commands(
                self.policy, self.runtime, renewal_directory=self.renewal, require_secure=False
            )
        route53 = dns_provider_catalog.provider_by_id("route53").propagation_seconds
        self.assertEqual(commands[0].timeout, 5000 + route53)
        self.assertEqual(commands[1].timeout, cert_issue.CERTBOT_TIMEOUT)

    def test_a_host_where_certbot_never_issued_has_nothing_to_renew(self) -> None:
        """A new manager has no renewal directory; the setup step's dry run
        and the nightly timer stopped on it (26-10-14)."""

        commands = _commands(
            self.policy,
            self.runtime,
            renewal_directory=self.root / "absent",
            require_secure=False,
        )
        self.assertEqual(commands, ())

    def test_one_lineage_that_cannot_be_prepared_spares_the_others_and_ndes(self) -> None:
        """Logic review 26-10-22, L3: one unreadable DNS profile stopped the
        whole pass before certbot ran for any lineage and before NDES."""

        (self.profile_dir / "aws-main").unlink()
        ran: list[str] = []

        def certbot(arguments: tuple[str, ...], **_: object) -> mock.Mock:
            ran.append(arguments[arguments.index("--cert-name") + 1])
            return mock.Mock(returncode=0, stdout="", stderr="")

        errors = io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(cert_renew, "load_policy", return_value=self.policy),
            mock.patch.object(cert_renew, "load_runtime_config", return_value=self.runtime),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", self.renewal),
            mock.patch("subprocess.run", side_effect=certbot),
            mock.patch.object(cert_renew, "renew_ndes", return_value=False) as ndes,
            mock.patch.object(cert_renew, "redistribute", return_value=False),
            contextlib.redirect_stderr(errors),
        ):
            code = cert_renew.main([])

        self.assertEqual(ran, ["legacy.example", "orphan.example"])
        ndes.assert_called_once()
        self.assertEqual(code, 1)
        self.assertIn("'example.com' could not be prepared", errors.getvalue())

    def test_no_registry_still_stops_the_pass(self) -> None:
        renewals = None
        with self.assertRaises(ConfigError):
            renewals = cert_renew.invocations(
                self.policy,
                replace(self.runtime, registry=None),
                renewal_directory=self.renewal,
                require_secure=False,
            )
        self.assertIsNone(renewals)

    def test_scrubbing_is_literal_and_longest_first(self) -> None:
        self.assertEqual(
            cert_renew._scrub("secret-value and secret", ("secret", "secret-value")),
            "[redacted] and [redacted]",
        )


class TheDistributionIsRedone(Fixture):
    """A rollout that failed after a renewal is finished by the timer, not by the next renewal."""

    def setUp(self) -> None:
        super().setUp()
        issue(self.live / "keeper.example", "keeper.example")
        self.policy_path = self.write_config(self.keeper())
        self.policy = load_policy(self.policy_path, require_secure=False)
        self.runtime = load_runtime_config(self.policy, require_secure=False)
        self.deployed: list[str] = []

    def redo(self, answer: int, errors: io.StringIO | None = None) -> bool:
        def deployer(cluster_id: str) -> int:
            self.deployed.append(cluster_id)
            return answer

        return cert_renew.redistribute(
            self.policy,
            errors=errors or io.StringIO(),
            require_secure=False,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            deployer=deployer,
            installer=None,
        )

    def test_a_cluster_whose_rollout_failed_is_rolled_out_by_the_next_pass(self) -> None:
        first = self.run_publish(self.policy_path, deployer=lambda _cluster_id: 3)
        self.assertEqual([d.exit_code for d in first.deployments], [3])

        self.assertFalse(self.redo(0))
        self.assertEqual(self.deployed, ["alpha"])

        self.assertFalse(self.redo(0))
        self.assertEqual(self.deployed, ["alpha"], "settled: the next pass finds nothing due")

    def test_a_rollout_that_fails_again_makes_the_pass_fail_and_says_which_cluster(self) -> None:
        self.run_publish(self.policy_path, deployer=lambda _cluster_id: 3)
        errors = io.StringIO()

        self.assertTrue(self.redo(3, errors))
        self.assertIn("deploy alpha: exit 3", errors.getvalue())

    def redo_asking(self, code: int, error: str, errors: io.StringIO | None = None) -> bool:
        """The pass with the real deployer, its question to `haprion-cert-deploy` answered."""

        outer = self
        sink = errors or io.StringIO()

        class Asked(ClusterDeployer):
            def ask(self, cluster_id: str) -> tuple[int, str]:
                outer.deployed.append(cluster_id)
                return code, error

        return cert_renew.redistribute(
            self.policy,
            errors=sink,
            require_secure=False,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            deployer=Asked(sink),
            installer=None,
        )

    def test_a_deploy_that_met_another_deploy_is_not_a_failure_of_the_timer(self) -> None:
        """Only the cluster lock is a wait: the error code says so (26-11-05, EE04, XX02)."""

        self.run_publish(self.policy_path, deployer=lambda _cluster_id: exit_codes.BLOCKED)
        errors = io.StringIO()

        self.assertFalse(self.redo_asking(exit_codes.BLOCKED, "operation_locked", errors))
        self.assertIn("WARNING: deploy alpha", errors.getvalue())

        self.assertFalse(self.redo(0), "the mark stood, so the next pass rolls it out")
        self.assertEqual(self.deployed, ["alpha", "alpha"])

    def test_a_deploy_blocked_for_any_other_reason_keeps_the_timer_red(self) -> None:
        for error in ("", "node_status_unavailable", "split_brain"):
            with self.subTest(error=error):
                self.run_publish(self.policy_path, deployer=lambda _cluster_id: exit_codes.BLOCKED)
                errors = io.StringIO()

                self.assertTrue(self.redo_asking(exit_codes.BLOCKED, error, errors))
                self.assertIn("deploy alpha: exit 75", errors.getvalue())

    def test_a_plain_deployer_that_answers_blocked_is_not_taken_for_a_wait(self) -> None:
        self.run_publish(self.policy_path, deployer=lambda _cluster_id: exit_codes.BLOCKED)

        self.assertTrue(self.redo(exit_codes.BLOCKED))

    def test_the_registry_is_read_again_after_certbot(self) -> None:
        """Remove from... run while certbot worked is not undone (26-11-05, EE01)."""

        # The pass was started with alpha; the registry now says beta.
        self.write_config({"keeper.example": {"source": {"kind": "acme"}, "clusters": ["beta"]}})

        self.assertFalse(self.redo(0))
        self.assertEqual(self.deployed, ["beta"])

    def test_a_registry_that_cannot_be_read_again_fails_the_pass(self) -> None:
        errors = io.StringIO()
        with mock.patch.object(
            cert_renew, "load_runtime_config", side_effect=ConfigError("registry is broken")
        ):
            self.assertTrue(self.redo(0, errors))
        self.assertIn("registry is broken", errors.getvalue())
        self.assertEqual(self.deployed, [])

    def test_a_pass_with_nothing_due_asks_no_node(self) -> None:
        self.run_publish(self.policy_path, deployer=lambda _cluster_id: 0)

        self.assertFalse(self.redo(0))
        self.assertEqual(self.deployed, [])

    def run_main(self, *argv: str) -> mock.Mock:
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(cert_renew, "load_policy", return_value=self.policy),
            mock.patch.object(cert_renew, "load_runtime_config", return_value=self.runtime),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", self.root / "absent"),
            mock.patch.object(cert_renew, "renew_ndes", return_value=False),
            mock.patch.object(cert_renew, "redistribute", return_value=False) as again,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            cert_renew.main(list(argv))
        return again

    def test_the_timer_s_ordinary_run_ends_with_the_pass(self) -> None:
        self.run_main().assert_called_once()

    def test_a_dry_run_and_the_named_renewals_do_not_publish(self) -> None:
        for argv in (["--dry-run"], ["--acme-now", "keeper.example"], ["--ndes-now", "x.example"]):
            renewed = mock.Mock(
                certbot_seconds=1.0, publish=mock.Mock(certificates=(), failed=(), warnings=())
            )
            with (
                self.subTest(argv=argv),
                mock.patch.object(cert_issue, "renew", return_value=renewed),
            ):
                self.run_main(*argv).assert_not_called()

    def dry_run_of(self, certificate_id: str, *, lineage: bool = True) -> tuple[int, str]:
        errors = io.StringIO()
        renewal = self.root / "renewal"
        renewal.mkdir(exist_ok=True)
        if lineage:
            (renewal / "keeper.example.conf").write_text("[renewalparams]\n")
        with (
            mock.patch.object(cert_issue, "renew") as renew,
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(cert_renew, "load_policy", return_value=self.policy),
            mock.patch.object(cert_renew, "load_runtime_config", return_value=self.runtime),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", renewal),
            mock.patch.object(cert_renew, "renew_ndes", return_value=False),
            contextlib.redirect_stderr(errors),
        ):
            code = cert_renew.main(["--acme-now", certificate_id, "--dry-run"])
        renew.assert_not_called()
        return code, errors.getvalue()

    def test_a_dry_run_of_a_named_lineage_says_it_would_renew_and_asks_no_one(self) -> None:
        code, said = self.dry_run_of("keeper.example")

        self.assertEqual(code, 0)
        self.assertIn("would renew keeper.example (forced)", said)

    def test_a_flag_that_is_wrong_with_json_is_a_document(self) -> None:
        """W04: the parser's own error left stdout empty for a script that asked for JSON."""

        for argv in (
            ["--json", "--acme-now", "Bad ID!"],
            ["--json", "--ndes-now", "Bad ID!"],
            ["--json", "--certbot", "relative/certbot"],
        ):
            shown = io.StringIO()
            with (
                self.subTest(argv=argv),
                mock.patch("os.geteuid", return_value=0),
                contextlib.redirect_stdout(shown),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = cert_renew.main(argv)
            document = assert_contract("haprion-cert-renew", shown.getvalue())
            self.assertEqual((code, document["error"]["code"]), (64, "bad_input"))

    def test_a_dry_run_of_a_certificate_that_is_not_there_is_refused_as_the_run_is(self) -> None:
        """K09: it said it would renew `typo.example`, and the run refused the same name."""

        code, said = self.dry_run_of("typo.example")

        self.assertEqual(code, 1)
        self.assertIn("[not_registered] typo.example", said)
        self.assertNotIn("would renew", said)

    def test_a_dry_run_of_a_certificate_certbot_has_no_lineage_for_is_refused(self) -> None:
        code, said = self.dry_run_of("keeper.example", lineage=False)

        self.assertEqual(code, 1)
        self.assertIn("[no_lineage] keeper.example", said)


class TheNdesPassReadsTheRegistryAfterCertbot(Fixture):
    """Remove from... run while certbot worked is not undone by the NDES pass (26-11-05, XX03)."""

    def test_the_pass_gets_the_registry_as_it_is_then(self) -> None:
        issue(self.live / "keeper.example", "keeper.example")
        policy = load_policy(self.write_config(self.keeper()), require_secure=False)
        before = load_runtime_config(policy, require_secure=False)
        after = replace(before, clusters={})

        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(cert_renew, "load_policy", return_value=policy),
            mock.patch.object(cert_renew, "load_runtime_config", side_effect=[before, after]),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", self.root / "absent"),
            mock.patch.object(cert_renew, "renew_ndes", return_value=False) as ndes,
            mock.patch.object(cert_renew, "redistribute", return_value=False),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            cert_renew.main([])

        self.assertIs(ndes.call_args.args[1], after)

    def test_a_registry_that_cannot_be_read_then_fails_the_pass(self) -> None:
        issue(self.live / "keeper.example", "keeper.example")
        policy = load_policy(self.write_config(self.keeper()), require_secure=False)
        before = load_runtime_config(policy, require_secure=False)
        errors = io.StringIO()

        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(cert_renew, "load_policy", return_value=policy),
            mock.patch.object(
                cert_renew, "load_runtime_config", side_effect=[before, ConfigError("broken")]
            ),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", self.root / "absent"),
            mock.patch.object(cert_renew, "renew_ndes", return_value=False) as ndes,
            mock.patch.object(cert_renew, "redistribute", return_value=False),
            contextlib.redirect_stderr(errors),
        ):
            code = cert_renew.main([])

        ndes.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("ERROR: ndes pass: broken", errors.getvalue())


class TheAnswerIsADocumentWhenAsked(Fixture):
    """K12: the timer's command answers `--json` in a contract, like the rest."""

    def setUp(self) -> None:
        super().setUp()
        issue(self.live / "keeper.example", "keeper.example")
        self.policy = load_policy(self.write_config(self.keeper()), require_secure=False)
        self.runtime = load_runtime_config(self.policy, require_secure=False)

    def run_json(
        self, *argv: str, ndes_failed: bool = False, root: bool = True
    ) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=0 if root else 1000),
            mock.patch.object(cert_renew, "load_policy", return_value=self.policy),
            mock.patch.object(cert_renew, "load_runtime_config", return_value=self.runtime),
            mock.patch.object(cert_renew, "RENEWAL_DIRECTORY", self.root / "absent"),
            mock.patch.object(cert_renew, "renew_ndes", return_value=ndes_failed),
            mock.patch.object(cert_renew, "redistribute", return_value=False),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = cert_renew.main([*argv, "--json"])
        return code, out.getvalue(), err.getvalue()

    def test_a_pass_that_failed_nowhere_is_done(self) -> None:
        code, out, _ = self.run_json()

        answer = assert_contract("haprion-cert-renew", out)
        self.assertEqual((code, answer["outcome"]), (0, "done"))
        self.assertEqual(answer["result"], {"dry_run": False, "lineages": 0, "failed": []})

    def test_a_pass_that_failed_says_where(self) -> None:
        code, out, _ = self.run_json("--dry-run", ndes_failed=True)

        answer = assert_contract("haprion-cert-renew", out)
        self.assertEqual(
            (code, answer["outcome"], answer["error"]["code"]), (1, "failed", "renewal_failed")
        )
        self.assertEqual(answer["result"], {"dry_run": True, "lineages": 0, "failed": ["ndes"]})

    def test_a_caller_who_is_not_root_gets_a_document_and_the_not_root_exit(self) -> None:
        code, out, _ = self.run_json(root=False)

        answer = assert_contract("haprion-cert-renew", out)
        self.assertEqual((code, answer["error"]["code"]), (77, "not_root"))

    def test_a_policy_that_cannot_be_read_is_a_document(self) -> None:
        out = io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                cert_renew, "load_policy", side_effect=ConfigError("no policy", exit_code=66)
            ),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = cert_renew.main(["--json"])

        answer = assert_contract("haprion-cert-renew", out.getvalue())
        self.assertEqual((code, answer["outcome"]), (66, "failed"))


class TheDeployerReadsTheResultDocument(unittest.TestCase):
    def deploy(self, stdout: str, code: int) -> tuple[ClusterDeployer, int]:
        deployer = ClusterDeployer(io.StringIO())
        done = subprocess.CompletedProcess([], code, stdout=stdout)
        with mock.patch.object(subprocess, "run", return_value=done) as run:
            result = deployer("alpha")
        self.assertEqual(run.call_args.args[0][1:], ["-c", "alpha", "--json"])
        return deployer, result

    def test_the_lock_is_told_by_the_error_code(self) -> None:
        document = json.dumps({"error": {"code": "operation_locked", "message": "busy"}})

        deployer, code = self.deploy(document, exit_codes.BLOCKED)

        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(deployer.overlapped, {"alpha"})

    def test_another_blocked_deploy_and_an_unreadable_answer_are_not_the_lock(self) -> None:
        other = json.dumps({"error": {"code": "split_brain", "message": "x"}})
        for stdout in (other, "not json", json.dumps({"error": None}), "[]"):
            with self.subTest(stdout=stdout):
                deployer, code = self.deploy(stdout, exit_codes.BLOCKED)

                self.assertEqual(code, exit_codes.BLOCKED)
                self.assertEqual(deployer.overlapped, set())


if __name__ == "__main__":
    unittest.main()
