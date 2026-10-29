"""Protected enrollment staging and verification with real X.509 material."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
import unittest
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from unittest import mock

from haprion import cert_import, ndes
from haprion.config import SYSTEM_TRUST, DnsProfilesPolicy, NdesPolicy, NdesServer
from haprion.ndes_profiles import OpenedProfile
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
            (NdesServer(ENDPOINT, ca, ca),),
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

    def test_a_resume_that_differs_names_what_changed_and_how_to_give_it_up(self) -> None:
        """Review 2026-10-29, B06 (B388): "resume must use the original endpoint, trust and DNS names"."""

        with (
            mock.patch.object(ndes, "command"),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
        ):
            self.enroll()
        self.profile = replace(self.profile, revision=2)
        (self.root / "ca.pem").write_text("renewed CA material")
        with self.assertRaises(ndes.NdesError) as caught:
            self.enroll(resume=True)
        said = str(caught.exception)
        self.assertIn("the profile's revision", said)
        self.assertIn("the NDES server's CA", said)
        self.assertNotIn("DNS names", said)
        self.assertIn("haprion-cert-scep --id service.example.com --abandon", said)
        self.assertIn("Abandon request", said)

    def test_the_caller_s_own_failure_is_its_own_not_the_lock_s(self) -> None:
        """Review 2026-10-22, 4-4: a disk-full import was told "NDES state is unavailable"."""

        for raised in (OSError(28, "No space left on device"), BlockingIOError()):
            with (
                self.subTest(raised=type(raised).__name__),
                mock.patch.object(ndes, "command"),
                mock.patch.object(ndes, "status", return_value="CA_WORKING"),
                self.assertRaises(type(raised)) as caught,
                ndes.enroll(
                    self.policy,
                    certificate_id="service.example.com",
                    profile=self.profile,
                    domains=DOMAINS,
                    require_secure=False,
                    timeout=0,
                ),
            ):
                raise raised
            self.assertIs(caught.exception, raised)
            shutil.rmtree(self.directory)

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
        self.policy.servers[0].issuing_ca.write_text("changed example CA material")
        with mock.patch.object(ndes, "instance") as instance, self.assertRaises(ndes.NdesError):
            self.enroll(resume=True)
        self.assertFalse(instance.called)
        with self.assertRaises(ndes.NdesError):
            ndes.names(["example.com\nextra"])

    def test_the_profile_s_server_is_the_one_enrolled_with(self) -> None:
        """B385: with two servers confirmed, the profile's address picks one; the
        system's store is recorded as such, so a ca-certificates update between a
        request and its resume does not refuse the resume."""

        other = "https://ca2.example.com/certsrv/mscep/mscep.dll"
        issuing = self.root / "other-ca.pem"
        issuing.write_text("other example CA material")
        self.policy = replace(
            self.policy, servers=(*self.policy.servers, NdesServer(other, issuing))
        )
        self.profile = replace(self.profile, endpoint=other)
        added: list[list[str]] = []
        with (
            mock.patch.object(ndes, "command", side_effect=lambda p, d, a: added.append(list(a))),
            mock.patch.object(ndes, "status", return_value="CA_WORKING"),
            mock.patch.object(
                ndes,
                "secure_file",
                side_effect=lambda path, **_: (
                    path.read_bytes() if path != SYSTEM_TRUST else b"system store"
                ),
            ),
        ):
            self.enroll()
        helper = next(arguments for arguments in added if arguments[0] == "add-ca")[-1]
        self.assertIn(f"-u {other}", helper)
        record = json.loads((self.directory / "request.json").read_text())
        self.assertEqual(record["endpoint"], other)
        self.assertEqual(record["tls_ca_sha256"], "system")
        self.assertEqual(
            (self.directory / "issuing-ca.pem").read_text(), "other example CA material"
        )

    def test_a_profile_on_a_server_not_confirmed_is_refused(self) -> None:
        self.profile = replace(
            self.profile, endpoint="https://ca3.example.com/certsrv/mscep/mscep.dll"
        )
        with mock.patch.object(ndes, "instance") as instance, self.assertRaises(ndes.NdesError):
            self.enroll()
        self.assertFalse(instance.called)


class ThePolicysAddress(unittest.TestCase):
    def test_the_address_rule_is_the_profiles_own(self) -> None:
        """Review 2026-10-29, B13: a copy let quotes and backslashes, an empty ? and # through."""

        policy = NdesPolicy(
            servers=(),
            client_root=Path("/nonexistent"),
            state_root=Path("/nonexistent"),
            profiles=DnsProfilesPolicy(directory=Path("/nonexistent"), private_keys=()),
        )
        for endpoint in (
            "https://ca.example.com/certsrv/mscep/mscep.dll?",
            "https://ca.example.com/certsrv/mscep/mscep.dll#",
            'https://ca.example.com/certsrv/"mscep.dll',
            "https://ca.example.com/certsrv\\mscep.dll",
        ):
            server = NdesServer(endpoint=endpoint, issuing_ca=Path("/nonexistent"))
            with self.subTest(endpoint=endpoint), self.assertRaises(ndes.NdesError) as caught:
                ndes.validate_policy(policy, server, require_secure=False)
            self.assertEqual(caught.exception.code, "bad_input")


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

    def test_a_certificate_from_a_ca_other_than_the_one_confirmed_points_to_the_server(
        self,
    ) -> None:
        """Review 2026-10-29, B01: a renewed CA failed every renewal as "chain or server purpose"."""

        other = Pki(self.root / "renewed", names=("other.example.com",))
        (self.root / "issuing-ca.pem").write_text(other.root.read_text())
        with self.assertRaises(ndes.NdesError) as caught:
            ndes.validate_certificate(self.material, DOMAINS, self.root)
        self.assertEqual(caught.exception.code, "untrusted_certificate")
        self.assertIn("confirm the server's new CA under NDES profiles", str(caught.exception))
        self.assertNotIn("purpose", str(caught.exception))

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
