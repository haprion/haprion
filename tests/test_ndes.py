"""Protected enrollment staging and verification with real X.509 material."""

from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

from haproxy_mgmt import cert_import, ndes
from haproxy_mgmt.config import DnsProfilesPolicy, NdesPolicy
from haproxy_mgmt.ndes_profiles import OpenedProfile
from tests.test_cert_import import Pki, openssl

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"
DOMAINS = ("service.example.com", "*.service.example.com")


class EnrollmentStaging(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        state = self.root / "state"
        state.mkdir(mode=0o700)
        ca = self.root / "ca.pem"
        ca.write_text("example CA material")
        self.policy = NdesPolicy(
            ENDPOINT,
            ca,
            ca,
            self.root / "client",
            state,
            DnsProfilesPolicy(self.root / "profiles", ()),
        )
        self.profile = OpenedProfile(
            "internal-ca", ENDPOINT, "0123456789abcdef", 1, "example-challenge"
        )
        self.directory = state / hashlib.sha256(b"service.example.com").hexdigest()[:24]
        for patch in (
            mock.patch.object(ndes, "validate_policy"),
            mock.patch.object(ndes, "instance", return_value=nullcontext()),
            mock.patch.object(ndes, "wait_for_ca"),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def enroll(self, *, resume: bool = False) -> ndes.Enrollment:
        with ndes.enroll(
            self.policy,
            certificate_id="service.example.com",
            profile=self.profile,
            domains=DOMAINS,
            require_secure=False,
            timeout=0,
            resume=resume,
        ) as result:
            return result

    def test_pending_preserves_state_but_removes_plain_challenge_file(self) -> None:
        with (
            mock.patch.object(ndes, "command") as command,
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            enrolled = self.enroll()
        self.assertEqual(enrolled.state, "pending")
        self.assertTrue((self.directory / "request.json").exists())
        self.assertFalse((self.directory / "challenge").exists())
        calls = command.call_args_list
        self.assertEqual(calls[1].args[2][0], "request")
        self.assertIn("-R", calls[1].args[2])
        self.assertNotIn("example-challenge", repr(calls))

    def test_a_rejected_request_takes_its_directory_with_it(self) -> None:
        """Nothing is left to resume once the CA has said no; the directory
        would only refuse the next attempt with "resume it instead" and
        hold the profile in use (review 2026-09-17, finding 2). A new
        request for the same ID is possible straight after."""

        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_REJECTED"),
            self.assertRaises(ndes.NdesError) as caught,
        ):
            self.enroll()
        self.assertTrue(caught.exception.discard)
        self.assertFalse(self.directory.exists())
        with (
            mock.patch.object(ndes, "command") as command,
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.assertEqual(self.enroll().state, "pending")
        self.assertEqual(command.call_args_list[1].args[2][0], "request")
        self.assertTrue((self.directory / "request.json").exists())

    def test_a_request_certmonger_did_not_take_leaves_nothing_behind(self) -> None:
        """`add-ca` or `request` failing means no request exists to resume."""

        with (
            mock.patch.object(
                ndes, "command", side_effect=ndes.NdesError("scep_failed", "no", exit_code=1)
            ),
            self.assertRaises(ndes.NdesError) as caught,
        ):
            self.enroll()
        self.assertTrue(caught.exception.discard)
        self.assertFalse(self.directory.exists())

    def test_a_timeout_in_a_state_that_may_still_finish_keeps_the_request(self) -> None:
        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="SUBMITTING"),
            self.assertRaises(ndes.NdesError) as caught,
        ):
            self.enroll()
        self.assertEqual(caught.exception.code, "scep_timeout")
        self.assertFalse(caught.exception.discard)
        self.assertTrue((self.directory / "request.json").exists())
        self.assertFalse((self.directory / "challenge").exists())

    def test_unreachable_is_a_failure_not_pending_and_the_request_stays(self) -> None:
        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_UNREACHABLE"),
            self.assertRaises(ndes.NdesError),
        ):
            self.enroll()
        self.assertFalse((self.directory / "challenge").exists())

    def test_abandon_removes_a_request_under_its_lock_and_says_whether_there_was_one(
        self,
    ) -> None:
        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll()
        self.assertTrue(ndes.abandon(self.policy, "service.example.com", require_secure=False))
        self.assertFalse(self.directory.exists())
        self.assertFalse(ndes.abandon(self.policy, "service.example.com", require_secure=False))

    def test_resume_does_not_submit_a_new_key_or_request(self) -> None:
        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll()
        with (
            mock.patch.object(ndes, "command") as command,
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll(resume=True)
        self.assertEqual(command.call_count, 0)
        with self.assertRaises(ndes.NdesError):
            self.enroll()

    def test_a_finished_request_left_behind_gives_way_to_a_new_one(self) -> None:
        """Only a request the CA still holds is resumed; an answered one is over (job 925)."""

        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll()
        (self.directory / "cert.pem").write_text("issued, and the cleanup never ran")
        (self.directory / "privkey.pem").write_text("the old key")
        with (
            mock.patch.object(ndes, "command") as command,
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            enrolled = self.enroll()
        self.assertEqual(enrolled.state, "pending")
        self.assertEqual(command.call_args_list[1].args[2][0], "request")
        self.assertFalse((self.directory / "cert.pem").exists())
        self.assertFalse((self.directory / "privkey.pem").exists())

    def test_add_ca_is_followed_by_the_wait_before_the_request(self) -> None:
        order: list[str] = []
        with (
            mock.patch.object(ndes, "command", side_effect=lambda p, d, a: order.append(a[0])),
            mock.patch.object(ndes, "wait_for_ca", side_effect=lambda p, d: order.append("wait")),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll()
        self.assertEqual(order, ["add-ca", "wait", "request"])

    def test_wrong_names_and_trust_are_refused_before_a_process_starts(self) -> None:
        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll()
        self.policy.issuing_ca.write_text("changed example CA material")
        with mock.patch.object(ndes, "instance") as instance, self.assertRaises(ndes.NdesError):
            self.enroll(resume=True)
        self.assertFalse(instance.called)
        with self.assertRaises(ndes.NdesError):
            ndes.names(["example.com\nextra"])


class IssuedCertificate(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pki = Pki(self.root / "pki", names=DOMAINS)
        extensions = self.pki.directory / (DOMAINS[0] + ".ext")
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:service.example.com,DNS:*.service.example.com\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        )
        openssl(
            "x509",
            "-req",
            "-in",
            str(self.pki.directory / (DOMAINS[0] + ".csr")),
            "-CA",
            str(self.pki.intermediate),
            "-CAkey",
            str(self.pki.intermediate_key),
            "-CAcreateserial",
            "-out",
            str(self.pki.leaf),
            "-days",
            "30",
            "-extfile",
            str(extensions),
        )
        self.material = cert_import.assemble(
            [
                self.pki.leaf.read_text(),
                self.pki.intermediate.read_text(),
                self.pki.root.read_text(),
            ],
            [self.pki.leaf_key.read_text()],
        )
        (self.root / "issuing-ca.pem").write_text(self.pki.root.read_text())

    def test_valid_leaf_wildcard_and_chain_pass_without_root_in_fullchain(self) -> None:
        ndes.validate_certificate(self.material, DOMAINS, self.root)
        self.assertEqual(len(self.material.chain), 1)
        self.assertFalse((self.root / "verify-leaf.pem").exists())

    def test_wrong_requested_names_and_untrusted_root_fail(self) -> None:
        with self.assertRaises(ndes.NdesError):
            ndes.validate_certificate(self.material, ["other.example.com"], self.root)
        other = Pki(self.root / "other", names=("other.example.com",))
        (self.root / "issuing-ca.pem").write_text(other.root.read_text())
        with self.assertRaisesRegex(ndes.NdesError, "chain"):
            ndes.validate_certificate(self.material, DOMAINS, self.root)

    def test_leaf_without_basic_constraints_passes_as_ad_cs_issues_it(self) -> None:
        # The first live NDES issuance (2026-09-15) came back without the
        # extension and was refused as "not an end-entity certificate".
        extensions = self.pki.directory / (DOMAINS[0] + ".adcs.ext")
        extensions.write_text(
            "subjectAltName=DNS:service.example.com,DNS:*.service.example.com\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        )
        leaf = self.root / "adcs-leaf.pem"
        openssl(
            "x509",
            "-req",
            "-in",
            str(self.pki.directory / (DOMAINS[0] + ".csr")),
            "-CA",
            str(self.pki.intermediate),
            "-CAkey",
            str(self.pki.intermediate_key),
            "-CAcreateserial",
            "-out",
            str(leaf),
            "-days",
            "30",
            "-extfile",
            str(extensions),
        )
        material = cert_import.assemble(
            [leaf.read_text(), self.pki.intermediate.read_text()], [self.pki.leaf_key.read_text()]
        )
        ndes.validate_certificate(material, DOMAINS, self.root)

    def test_ca_certificate_offered_as_leaf_is_refused(self) -> None:
        material = cert_import.assemble(
            [self.pki.intermediate.read_text(), self.pki.root.read_text()],
            [self.pki.intermediate_key.read_text()],
        )
        with self.assertRaises(ndes.NdesError):
            ndes.validate_certificate(material, DOMAINS, self.root)

    def test_missing_server_eku_and_key_usages_fail(self) -> None:
        _, cert = self.pki._signed(
            DOMAINS[0], self.pki.intermediate, self.pki.intermediate_key, sans=DOMAINS
        )
        material = cert_import.assemble(
            [cert.read_text(), self.pki.intermediate.read_text()], [self.pki.leaf_key.read_text()]
        )
        with self.assertRaises(ndes.NdesError):
            ndes.validate_certificate(material, DOMAINS, self.root)


class WaitingForTheCa(unittest.TestCase):
    def test_the_request_waits_for_the_ca_s_certificates(self) -> None:
        """Job 932 (2026-09-21): submitted before the RA certificate was fetched, parked for good."""

        answers = iter(
            [
                "CA 'ndes':\n\tca-type: EXTERNAL\n",
                "CA 'ndes':\n\tSCEP CA certificate thumbprint (SHA1): AB\n",
            ]
        )
        with (
            mock.patch.object(
                ndes, "command", side_effect=lambda p, d, a: next(answers)
            ) as command,
            mock.patch.object(time, "sleep"),
        ):
            ndes.wait_for_ca(mock.Mock(), Path("/nowhere"), timeout=5)
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args.args[2], ["list-cas", "-c", "ndes"])

        with (
            mock.patch.object(ndes, "command", return_value="CA 'ndes':\n"),
            mock.patch.object(time, "sleep"),
            mock.patch.object(time, "monotonic", side_effect=[0, 0, 100]),
            self.assertRaises(ndes.NdesError) as caught,
        ):
            ndes.wait_for_ca(mock.Mock(), Path("/nowhere"), timeout=5)
        self.assertTrue(caught.exception.discard)
