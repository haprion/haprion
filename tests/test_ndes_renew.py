"""Scheduled NDES renewal: who is due, what one attempt leaves behind, and the pass in cert-renew."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from typing import Any

from haproxy_mgmt import ndes_renew, ndes_state
from haproxy_mgmt.cert_import import import_certificate
from haproxy_mgmt.cert_inventory import registry_result
from haproxy_mgmt.cli import cert_renew, cert_scep
from haproxy_mgmt.config import load_policy, load_runtime_config
from tests.test_cert_scep import ScepFixture


class RenewFixture(ScepFixture):
    """One NDES certificate in the registry, imported the way an enrollment leaves it."""

    def setUp(self) -> None:
        super().setUp()
        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        import_certificate(
            certificate_id="web.example.com",
            material=self.material(),
            clusters=("alpha",),
            receivers=(),
            policy=policy,
            runtime=runtime,
            deployer=lambda cluster: 0,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
            ndes_profile="certserver1",
        )
        self.policy = load_policy(self.policy_path, require_secure=False)
        self.runtime = load_runtime_config(self.policy, require_secure=False)
        due, _ = ndes_renew.candidates(
            self.runtime,
            self.policy,
            now=datetime.now(UTC),
            threshold_days=100000,
            live=self.live,
            store=self.store,
        )
        self.not_after = due[0].not_after

    def candidates(
        self, *, now: datetime, threshold_days: int = 30, only: tuple[str, ...] = ()
    ) -> tuple[list[ndes_renew.Candidate], list[ndes_renew.Outcome]]:
        return ndes_renew.candidates(
            self.runtime,
            self.policy,
            now=now,
            threshold_days=threshold_days,
            only=only,
            live=self.live,
            store=self.store,
        )


class WhoIsDue(RenewFixture):
    def test_a_certificate_inside_the_threshold_is_due_with_its_names_and_targets(self) -> None:
        due, problems = self.candidates(now=self.not_after - timedelta(days=10))
        self.assertEqual(problems, [])
        (candidate,) = due
        self.assertEqual(candidate.certificate_id, "web.example.com")
        self.assertEqual(candidate.profile_id, "certserver1")
        self.assertEqual(candidate.clusters, ("alpha",))
        self.assertEqual(candidate.days_left, 10)
        # CN first, then the other SANs, as the enrollment asks for them.
        self.assertTrue(candidate.domains)
        self.assertEqual(len(candidate.domains), len(set(candidate.domains)))

    def test_a_certificate_outside_the_threshold_is_not_due_unless_named(self) -> None:
        due, _ = self.candidates(now=self.not_after - timedelta(days=200))
        self.assertEqual(due, [])
        due, _ = self.candidates(
            now=self.not_after - timedelta(days=200), only=("web.example.com",)
        )
        self.assertEqual([c.certificate_id for c in due], ["web.example.com"])

    def test_certbot_s_certificates_are_not_the_pass_s_and_naming_one_is_said(self) -> None:
        due, problems = self.candidates(
            now=self.not_after - timedelta(days=1), only=("keeper-alpha.example",)
        )
        self.assertEqual([c.certificate_id for c in due], ["web.example.com"])
        self.assertEqual(
            [(p.certificate_id, p.outcome) for p in problems], [("keeper-alpha.example", "skipped")]
        )


class WhatAnAttemptLeaves(RenewFixture):
    def test_each_outcome_is_recorded_and_the_listing_reads_it_back(self) -> None:
        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        due, _ = self.candidates(now=now, only=("web.example.com",))
        answers: list[tuple[dict[str, Any], int]] = [
            ({"outcome": "done", "result": {"state": "issued"}}, 0),
            ({"outcome": "partial", "result": {"state": "pending"}}, 0),
            ({"outcome": "failed", "error": {"code": "scep_failed", "message": "CA_REJECTED"}}, 1),
        ]
        expected = [
            ("renewed", ""),
            ("pending", "CA approval is pending; resume the request"),
            ("failed", "CA_REJECTED"),
        ]
        for answer, (outcome, message) in zip(answers, expected, strict=True):
            outcomes = ndes_renew.renew(
                due, state_root=self.ndes_policy.state_root, enroll=lambda c, a=answer: a, now=now
            )
            self.assertEqual((outcomes[0].outcome, outcomes[0].message), (outcome, message))
            record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
            self.assertEqual(
                record,
                {"attempted_at": "2026-09-15T20:00:00Z", "outcome": outcome, "message": message},
            )
            listed = registry_result(
                self.runtime.registry,  # type: ignore[arg-type]
                certificate_root=self.dist,
                renewed=frozenset(),
                now=now,
                live=self.live,
                store=self.store,
                request_root=self.ndes_policy.state_root,
            )
            (row,) = [r for r in listed["certificates"] if r["id"] == "web.example.com"]
            self.assertEqual(row["renewal"], record)
            self.assertTrue(row["readable"])

    def test_an_exception_from_the_enrollment_is_a_failed_record_not_a_crash(self) -> None:
        now = datetime.now(UTC)
        due, _ = self.candidates(now=now, only=("web.example.com",))

        def boom(candidate: ndes_renew.Candidate) -> tuple[dict[str, Any], int]:
            raise RuntimeError("socket gone")

        (outcome,) = ndes_renew.renew(
            due, state_root=self.ndes_policy.state_root, enroll=boom, now=now
        )
        self.assertEqual((outcome.outcome, outcome.message), ("failed", "socket gone"))

    def test_a_record_that_is_not_one_is_none(self) -> None:
        root = self.ndes_policy.state_root
        self.assertIsNone(ndes_state.renewal_record(root, "web.example.com"))
        ndes_state.records_directory(root).mkdir(exist_ok=True)
        ndes_state.record_path(root, "web.example.com").write_text('{"outcome": "odd"}')
        self.assertIsNone(ndes_state.renewal_record(root, "web.example.com"))


class ThePassInCertRenew(RenewFixture):
    def test_the_pass_renews_what_is_due_through_the_scep_engine(self) -> None:
        asked: list[dict[str, Any]] = []

        def fake_enroll(**kwargs: Any) -> tuple[dict[str, Any], int]:
            asked.append(kwargs)
            return {"outcome": "done", "result": {"state": "issued"}}, 0

        errors = io.StringIO()
        original = cert_scep.enroll
        cert_scep.enroll = fake_enroll  # type: ignore[assignment]
        try:
            failed = cert_renew.renew_ndes(
                self.policy,
                self.runtime,
                now=self.not_after - timedelta(days=5),
                errors=errors,
                policy_path=self.policy_path,
                live=self.live,
                store=self.store,
            )
        finally:
            cert_scep.enroll = original  # type: ignore[assignment]
        self.assertFalse(failed)
        (request,) = asked
        self.assertEqual(request["certificate_id"], "web.example.com")
        self.assertEqual(request["profile_id"], "certserver1")
        self.assertEqual(request["clusters"], ("alpha",))
        self.assertFalse(request["resume"])
        self.assertIn("web.example.com: renewed", errors.getvalue())

    def test_a_request_the_ca_still_holds_is_resumed_not_asked_again(self) -> None:
        """Asking anew was refused as `already_exists`, and the row went from
        "Renewal pending" to "Renewal failed" the day after (review
        2026-09-17, finding 2)."""

        self.pending("web.example.com")
        asked: list[dict[str, Any]] = []

        def fake_enroll(**kwargs: Any) -> tuple[dict[str, Any], int]:
            asked.append(kwargs)
            return {"outcome": "partial", "result": {"state": "pending"}}, 0

        original = cert_scep.enroll
        cert_scep.enroll = fake_enroll  # type: ignore[assignment]
        try:
            cert_renew.renew_ndes(
                self.policy,
                self.runtime,
                now=self.not_after - timedelta(days=5),
                errors=io.StringIO(),
                policy_path=self.policy_path,
                live=self.live,
                store=self.store,
            )
        finally:
            cert_scep.enroll = original  # type: ignore[assignment]
        (request,) = asked
        self.assertTrue(request["resume"])
        record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
        self.assertEqual(record["outcome"], "pending")  # type: ignore[index]

    def test_a_dry_run_says_who_would_renew_and_touches_nothing(self) -> None:
        errors = io.StringIO()
        failed = cert_renew.renew_ndes(
            self.policy,
            self.runtime,
            now=self.not_after - timedelta(days=5),
            dry_run=True,
            errors=errors,
            policy_path=self.policy_path,
            live=self.live,
            store=self.store,
        )
        self.assertFalse(failed)
        self.assertIn("expires in 5 days; would renew", errors.getvalue())
        self.assertIsNone(ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com"))

    def test_a_refusal_and_a_named_non_ndes_certificate_are_failures(self) -> None:
        errors = io.StringIO()
        failed = cert_renew.renew_ndes(
            self.policy,
            self.runtime,
            only=("keeper-alpha.example",),
            now=self.not_after - timedelta(days=500),
            errors=errors,
            policy_path=self.policy_path,
            live=self.live,
            store=self.store,
        )
        self.assertTrue(failed)
        self.assertIn("ERROR: keeper-alpha.example: not an NDES certificate", errors.getvalue())

        def refuse(**kwargs: Any) -> tuple[dict[str, Any], int]:
            raise cert_scep.ScepRefusal("busy", "another enrollment is running", 75)

        original = cert_scep.enroll
        cert_scep.enroll = refuse  # type: ignore[assignment]
        try:
            failed = cert_renew.renew_ndes(
                self.policy,
                self.runtime,
                only=("web.example.com",),
                now=self.not_after - timedelta(days=500),
                errors=io.StringIO(),
                policy_path=self.policy_path,
                live=self.live,
                store=self.store,
            )
        finally:
            cert_scep.enroll = original  # type: ignore[assignment]
        self.assertTrue(failed)
        record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
        self.assertEqual((record or {}).get("message"), "another enrollment is running")

    def test_the_threshold_comes_from_the_policy(self) -> None:
        self.assertEqual(self.policy.ndes.renew_days, 30)  # type: ignore[union-attr]
