"""Scheduled NDES renewal: who is due, what one attempt leaves behind, and the pass in cert-renew."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import exit_codes, ndes, ndes_renew, ndes_state
from haprion.cert_import import import_certificate
from haprion.cert_inventory import registry_result
from haprion.cli import cert_renew, cert_scep
from haprion.config import load_policy, load_runtime_config
from tests.test_cert_scep import ScepFixture


def answering(answer: tuple[dict[str, Any], int]) -> ndes_renew.Enroller:
    """An enroller that gives every candidate the same answer."""

    def enroll(_candidate: ndes_renew.Candidate) -> tuple[dict[str, Any], int]:
        return answer

    return enroll


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
                due, state_root=self.ndes_policy.state_root, enroll=answering(answer), now=now
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

    def listed_row(self, now: datetime) -> dict[str, Any]:
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
        self.assertIsInstance(row, dict)
        return dict(row)

    def test_a_readable_row_says_when_the_ca_still_holds_a_request_for_it(self) -> None:
        """Review 2026-10-29 again, BB01: a failed resume left a request nobody could abandon.

        The row's word is the request on the disk, not the record: a failed
        renewal may still hold one, and a "pending" record may outlive it.
        """

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        due, _ = self.candidates(now=now, only=("web.example.com",))
        self.assertNotIn("request_state", self.listed_row(now))
        self.pending("web.example.com")
        for answer in (
            ({"outcome": "partial", "result": {"state": "pending"}}, 0),
            ({"outcome": "failed", "error": {"code": "bad_input", "message": "changed"}}, 65),
        ):
            ndes_renew.renew(
                due, state_root=self.ndes_policy.state_root, enroll=answering(answer), now=now
            )
            row = self.listed_row(now)
            self.assertTrue(row["readable"])
            self.assertEqual(row["request_state"], "pending")
        ndes_state.remove_request(self.ndes_policy.state_root, "web.example.com")
        self.assertNotIn("request_state", self.listed_row(now))

    def test_an_abandon_takes_the_renewal_s_word_about_the_request_with_it(self) -> None:
        """Review 2026-10-29 again, BB03: the row went back to Renewal pending after 90 s."""

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        due, _ = self.candidates(now=now, only=("web.example.com",))
        for outcome, answer, kept in (
            ("pending", ({"outcome": "partial", "result": {"state": "pending"}}, 0), False),
            ("failed", ({"outcome": "failed", "error": {"message": "changed"}}, 65), False),
            ("renewed", ({"outcome": "done", "result": {"state": "issued"}}, 0), True),
        ):
            with self.subTest(outcome=outcome):
                ndes_renew.renew(
                    due, state_root=self.ndes_policy.state_root, enroll=answering(answer), now=now
                )
                self.pending("web.example.com")
                code = cert_scep.main(
                    ["--id", "web.example.com", "--abandon", "--json"],
                    policy_path=self.policy_path,
                    output_stream=io.StringIO(),
                    error_stream=io.StringIO(),
                    require_secure=False,
                    require_root=False,
                )
                self.assertEqual(code, 0)
                record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
                self.assertEqual(record is not None, kept)
                row = self.listed_row(now)
                self.assertNotIn("request_state", row)
                self.assertEqual("renewal" in row, kept)

    def failed_pass(self, now: datetime, message: str = "CA_REJECTED") -> None:
        due, _ = self.candidates(now=now, only=("web.example.com",))
        ndes_renew.renew(
            due,
            state_root=self.ndes_policy.state_root,
            enroll=answering(({"outcome": "failed", "error": {"message": message}}, 1)),
            now=now,
        )
        self.assertEqual(self.listed_row(now)["renewal"]["outcome"], "failed")

    def enrolled(self, state: str, *, terminal: bool) -> int:
        """One enrollment the way the page's job or `haprion-cert-scep` makes it."""

        directory = ndes_state.request_directory(self.ndes_policy.state_root, "web.example.com")
        directory.mkdir(mode=0o700, exist_ok=True)
        enrollment = ndes.Enrollment(
            state, directory, self.material() if state == "issued" else None
        )
        with (
            mock.patch.object(ndes, "enroll") as engine,
            mock.patch.object(ndes, "validate_certificate"),
        ):
            engine.return_value.__enter__.return_value = enrollment
            if terminal:
                return cert_scep.main(
                    ["--id", "web.example.com", "--resume", "--json"],
                    policy_path=self.policy_path,
                    output_stream=io.StringIO(),
                    error_stream=io.StringIO(),
                    require_secure=False,
                    require_root=False,
                    deployer=self.deploy,
                    live=self.live,
                    store=self.store,
                    lock_path=self.lock,
                )
            code, _doc, _errors = self.helper({"id": "web.example.com", "resume": True})
            return code

    def test_a_renewal_that_succeeds_anywhere_ends_the_pass_s_failure(self) -> None:
        """Review 2026-10-29, round 2, BBB01: only the pass wrote the record, and only abandon took it.

        *Renew…*, *Resume enrollment* and the terminal command left the
        failure on the row for as long as the new certificate was not due.
        """

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                self.failed_pass(now)
                self.pending("web.example.com")
                self.assertEqual(self.enrolled("issued", terminal=terminal), 0)
                self.assertIsNone(
                    ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
                )
                row = self.listed_row(now)
                self.assertNotIn("renewal", row)
                self.assertNotIn("request_state", row)

    def test_a_request_the_ca_now_holds_ends_the_pass_s_failure(self) -> None:
        """BBB02's other half: a resume the CA answers with "pending" is the row's newest word."""

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                self.pending("web.example.com")
                self.failed_pass(now, "Certmonger enrollment timed out: CA_UNREACHABLE")
                self.assertEqual(self.enrolled("pending", terminal=terminal), exit_codes.PARTIAL)
                row = self.listed_row(now)
                self.assertNotIn("renewal", row)
                self.assertEqual(row["request_state"], "pending")
                ndes_state.remove_request(self.ndes_policy.state_root, "web.example.com")

    def test_a_record_about_an_earlier_certificate_is_not_the_row_s(self) -> None:
        """The record names the certificate it tried to renew; another one on the row is not its."""

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        self.failed_pass(now)
        path = ndes_state.record_path(self.ndes_policy.state_root, "web.example.com")
        written = json.loads(path.read_text())
        self.assertRegex(written["fingerprint_sha256"], "^[0-9a-f]{64}$")
        self.assertEqual(written["fingerprint_sha256"], self.listed_row(now)["fingerprint_sha256"])
        path.write_text(json.dumps({**written, "fingerprint_sha256": "0" * 64}))
        self.assertNotIn("renewal", self.listed_row(now))
        # A record written before records named one is the row's when it is
        # newer than the certificate, and not when it is older.
        del written["fingerprint_sha256"]
        made = datetime.fromisoformat(self.listed_row(now)["not_before"])
        later = (made + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        path.write_text(json.dumps({**written, "attempted_at": later}))
        self.assertEqual(self.listed_row(now)["renewal"]["outcome"], "failed")
        path.write_text(json.dumps({**written, "attempted_at": "2000-01-01T00:00:00Z"}))
        self.assertNotIn("renewal", self.listed_row(now))

    def test_a_busy_enrollment_is_no_attempt_of_the_pass(self) -> None:
        """Another enrollment holding the lock says nothing about this certificate's renewal."""

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        self.failed_pass(now)
        due, _ = self.candidates(now=now, only=("web.example.com",))
        busy = {"outcome": "failed", "error": {"code": "busy", "message": "another enrollment"}}
        (outcome,) = ndes_renew.renew(
            due, state_root=self.ndes_policy.state_root, enroll=answering((busy, 75)), now=now
        )
        self.assertEqual(outcome.outcome, "skipped")
        record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
        self.assertEqual((record or {}).get("message"), "CA_REJECTED")

    def test_an_abandon_that_cannot_take_the_record_is_still_an_abandon(self) -> None:
        """Round 2, cosmetic: the request was gone and the answer said the state was unavailable."""

        now = datetime(2026, 9, 15, 20, 0, tzinfo=UTC)
        self.pending("web.example.com")
        self.failed_pass(now)
        output = io.StringIO()
        with mock.patch.object(Path, "unlink", side_effect=PermissionError("read-only")):
            code = cert_scep.main(
                ["--id", "web.example.com", "--abandon", "--json"],
                policy_path=self.policy_path,
                output_stream=output,
                error_stream=io.StringIO(),
                require_secure=False,
                require_root=False,
            )
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["result"]["state"], "abandoned")
        self.assertFalse(
            ndes_state.request_is_pending(self.ndes_policy.state_root, "web.example.com")
        )

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
        with mock.patch.object(cert_scep, "enroll", fake_enroll):
            failed = cert_renew.renew_ndes(
                self.policy,
                self.runtime,
                now=self.not_after - timedelta(days=5),
                errors=errors,
                policy_path=self.policy_path,
                live=self.live,
                store=self.store,
            )
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

        with mock.patch.object(cert_scep, "enroll", fake_enroll):
            cert_renew.renew_ndes(
                self.policy,
                self.runtime,
                now=self.not_after - timedelta(days=5),
                errors=io.StringIO(),
                policy_path=self.policy_path,
                live=self.live,
                store=self.store,
            )
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
            raise cert_scep.ScepRefusal("profile_unavailable", "the profile is gone", 78)

        with mock.patch.object(cert_scep, "enroll", refuse):
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
        self.assertTrue(failed)
        record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
        self.assertEqual((record or {}).get("message"), "the profile is gone")

        # Busy is no attempt and writes nothing, but a certificate asked for by
        # name that was not renewed is still the command's failure.
        def busy(**kwargs: Any) -> tuple[dict[str, Any], int]:
            raise cert_scep.ScepRefusal("busy", "another enrollment is running", 75)

        errors = io.StringIO()
        with mock.patch.object(cert_scep, "enroll", busy):
            failed = cert_renew.renew_ndes(
                self.policy,
                self.runtime,
                only=("web.example.com",),
                now=self.not_after - timedelta(days=500),
                errors=errors,
                policy_path=self.policy_path,
                live=self.live,
                store=self.store,
            )
        self.assertTrue(failed)
        self.assertIn("web.example.com: skipped another enrollment is running", errors.getvalue())
        record = ndes_state.renewal_record(self.ndes_policy.state_root, "web.example.com")
        self.assertEqual((record or {}).get("message"), "the profile is gone")

    def test_the_threshold_comes_from_the_policy(self) -> None:
        self.assertEqual(self.policy.ndes.renew_days, 30)  # type: ignore[union-attr]
