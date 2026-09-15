"""Protected enrollment staging and verification with real X.509 material."""

from __future__ import annotations

import hashlib
import tempfile
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
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def enroll(self, **options: object) -> object:
        with ndes.enroll(
            self.policy,
            certificate_id="service.example.com",
            profile=self.profile,
            domains=DOMAINS,
            require_secure=False,
            timeout=0,
            **options,
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

    def test_unreachable_and_rejected_are_failures_not_pending(self) -> None:
        for state in ("CA_REJECTED", "CA_UNREACHABLE"):
            with (
                self.subTest(state=state),
                mock.patch.object(ndes, "command"),
                mock.patch.object(ndes, "status", return_value=state),
                self.assertRaises(ndes.NdesError),
            ):
                self.enroll(resume=(self.directory / "request.json").exists())
        self.assertFalse((self.directory / "challenge").exists())

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
