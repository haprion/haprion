"""The upload helper (C9, B165): four file forms, the sealed box and what is refused.

Real material from the same PKI the import tests use, exported into every
form the interface accepts, sealed the way the web seals it, and opened by
the helper against the same key. What is checked at the end is what the
store holds - and what nothing else does: no output of the helper carries
the key.
"""

from __future__ import annotations

import base64
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haproxy_mgmt import cert_import, cert_upload
from haproxy_mgmt.cert_import import MAX_UPLOAD_BYTES, ImportError_, read_bytes
from haproxy_mgmt.cert_inventory import PRIVKEY
from haproxy_mgmt.cli import cert_import_helper
from haproxy_mgmt.dns_profile_keys import generate, render_private_key
from tests.contract_schema import assert_contract
from tests.test_cert_import import KEEPERS, OPENSSL, Pki
from tests.test_cert_publish import Fixture

KEY_MARK = "PRIVATE KEY"
# The passphrase the test PKCS#12 is exported with: a fixture, not a secret.
PKCS12_PASSWORD = "pw"  # noqa: S105 - the fixture export's passphrase, not a credential


class ReadingOneFile(unittest.TestCase):
    """`read_bytes`: what is in the bytes decides the form, not a file name."""

    _directory: tempfile.TemporaryDirectory[str]
    pki: Pki

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.pki = Pki(Path(cls._directory.name) / "pki")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_pem_with_key_and_chain(self) -> None:
        data = (
            self.pki.leaf.read_bytes()
            + self.pki.leaf_key.read_bytes()
            + self.pki.intermediate.read_bytes()
        )
        certificates, keys = read_bytes(data)
        self.assertEqual((len(certificates), len(keys)), (2, 1))

    def test_pem_certificate_alone(self) -> None:
        certificates, keys = read_bytes(self.pki.leaf.read_bytes())
        self.assertEqual((len(certificates), len(keys)), (1, 0))

    def test_pkcs12_with_its_password(self) -> None:
        bundle = self.pki.pkcs12(PKCS12_PASSWORD)
        certificates, keys = read_bytes(bundle.read_bytes(), password=PKCS12_PASSWORD)
        self.assertEqual((len(certificates), len(keys)), (2, 1))

    def test_the_password_never_touches_the_disk(self) -> None:
        """B165's promise, at the one place a file is written: only the upload itself.

        The temporary directory is gone when the call returns, and the
        password reached `read_pkcs12` as a value, not as a file.
        """

        written: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def watched(*args: Any, **kwargs: Any) -> str:
            directory = str(real_mkdtemp(*args, **kwargs))
            written.append(directory)
            return directory

        bundle = self.pki.pkcs12(PKCS12_PASSWORD)
        with (
            mock.patch.object(tempfile, "mkdtemp", side_effect=watched),
            mock.patch.object(cert_import, "read_pkcs12", wraps=cert_import.read_pkcs12) as spied,
        ):
            read_bytes(bundle.read_bytes(), password=PKCS12_PASSWORD)
        self.assertEqual(len(written), 1)
        self.assertFalse(Path(written[0]).exists())
        self.assertIsNone(spied.call_args.args[1])
        self.assertEqual(spied.call_args.kwargs["password"], PKCS12_PASSWORD)

    def test_pkcs12_with_the_wrong_password_says_so(self) -> None:
        bundle = self.pki.pkcs12(PKCS12_PASSWORD)
        with self.assertRaises(ImportError_) as caught:
            read_bytes(bundle.read_bytes(), password="wrong")  # noqa: S106 - the wrong one, on purpose
        self.assertEqual(caught.exception.code, "bad_input")
        self.assertIn("PKCS#12", str(caught.exception))

    def test_der_certificate(self) -> None:
        der = subprocess.run(
            [OPENSSL, "x509", "-in", str(self.pki.leaf), "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout
        certificates, keys = read_bytes(der)
        self.assertEqual((len(certificates), len(keys)), (1, 0))

    def test_pkcs7_bundle_in_both_encodings(self) -> None:
        pem = subprocess.run(
            [
                OPENSSL,
                "crl2pkcs7",
                "-nocrl",
                "-certfile",
                str(self.pki.leaf),
                "-certfile",
                str(self.pki.intermediate),
            ],
            capture_output=True,
            check=True,
        ).stdout
        certificates, keys = read_bytes(pem)
        self.assertEqual((len(certificates), len(keys)), (2, 0))
        der = subprocess.run(
            [OPENSSL, "pkcs7", "-outform", "DER"],
            input=pem,
            capture_output=True,
            check=True,
        ).stdout
        certificates, keys = read_bytes(der)
        self.assertEqual((len(certificates), len(keys)), (2, 0))

    def test_what_is_refused(self) -> None:
        for data, password, words in (
            (b"", None, "empty"),
            (b"hello there", None, "not PEM"),
            (b"\x30\x03\x02\x01\x01", None, "not PEM"),
            (b"x" * (MAX_UPLOAD_BYTES + 1), None, "larger than"),
        ):
            with self.subTest(words=words), self.assertRaises(ImportError_) as caught:
                read_bytes(data, password=password)
            self.assertEqual(caught.exception.code, "bad_input")
            self.assertIn(words, str(caught.exception))


class SealingAndOpening(unittest.TestCase):
    def test_the_box_binds_the_id_and_the_key(self) -> None:
        private, public = generate()
        other_private, _ = generate()
        box = cert_upload.seal_upload(
            public, certificate_id="shop.example", data=b"bytes", password=PKCS12_PASSWORD
        )

        opened = cert_upload.open_upload(private, box, certificate_id="shop.example")
        self.assertEqual(
            (opened.data, opened.password, opened.key_id),
            (b"bytes", PKCS12_PASSWORD, public.key_id),
        )
        with self.assertRaises(cert_upload.UploadError) as wrong_id:
            cert_upload.open_upload(private, box, certificate_id="other.example")
        self.assertIn("another certificate", str(wrong_id.exception))
        with self.assertRaises(cert_upload.UploadError) as wrong_key:
            cert_upload.open_upload(other_private, box, certificate_id="shop.example")
        self.assertIn("not sealed against", str(wrong_key.exception))

    def test_no_password_is_none_and_a_line_break_is_refused(self) -> None:
        private, public = generate()
        box = cert_upload.seal_upload(public, certificate_id="a", data=b"x", password="")
        self.assertIsNone(cert_upload.open_upload(private, box, certificate_id="a").password)
        with self.assertRaises(cert_upload.UploadError):
            cert_upload.seal_upload(
                public,
                certificate_id="a",
                data=b"x",
                password="a\nb",  # noqa: S106 - a line break, which is what is refused
            )
        with self.assertRaises(cert_upload.UploadError):
            cert_upload.seal_upload(public, certificate_id="a", data=b"")
        with self.assertRaises(cert_upload.UploadError):
            cert_upload.seal_upload(public, certificate_id="A", data=b"x")

    def test_a_request_carries_the_box_as_base64_and_nothing_else(self) -> None:
        text = cert_upload.build_request(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            certificate_id="shop.example",
            key_id="0" * 16,
            ciphertext=b"\x00\x01",
            clusters=("alpha",),
            receivers=("lb-01",),
            formats={"lb-01": "pkcs12"},
        )
        document = json.loads(text)
        self.assertEqual(document["operation"], "cert_import")
        self.assertIsNone(document["cluster"])
        self.assertEqual(
            document["parameters"]["ciphertext"], base64.b64encode(b"\x00\x01").decode()
        )
        self.assertEqual(
            set(document["parameters"]),
            {"certificate", "key_id", "ciphertext", "clusters", "receivers", "formats"},
        )


class HelperFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.pki = Pki(self.root / "pki")
        self.private, self.public = generate()
        self.private_path = self.root / "upload.key"
        self.private_path.write_text(render_private_key(self.private), encoding="utf-8")
        self.private_path.chmod(0o600)
        self.policy_path = self.write_config(KEEPERS)
        (self.root / "certificates.yaml").chmod(0o640)
        document = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))
        document["acme"] = {
            "dns_profiles": {
                "directory": str(self.root / "profiles"),
                "private_keys": [str(self.private_path)],
            }
        }
        (self.root / "profiles").mkdir(mode=0o700)
        self.policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        self.deployed: list[str] = []

    def request(self, data: bytes, *, password: str | None = None, **overrides: Any) -> str:
        certificate_id = overrides.pop("certificate", "shop.example")
        box = cert_upload.seal_upload(
            self.public, certificate_id=certificate_id, data=data, password=password
        )
        parameters: dict[str, Any] = {
            "certificate": certificate_id,
            "key_id": self.public.key_id,
            "ciphertext": base64.b64encode(box).decode("ascii"),
            "clusters": ["alpha"],
            "receivers": [],
            **overrides,
        }
        return json.dumps(
            {
                "schema_version": 1,
                "operation": "cert_import",
                "cluster": None,
                "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "parameters": parameters,
            },
            separators=(",", ":"),
        )

    def deploy(self, cluster: str) -> int:
        self.deployed.append(cluster)
        return 0

    def invoke(
        self, request: str, *, argv: list[str] | None = None
    ) -> tuple[int, dict[str, Any], str]:
        output, errors = io.StringIO(), io.StringIO()
        code = cert_import_helper.main(
            argv or [],
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        document = (
            assert_contract("haprion-cert-import", output.getvalue()) if output.getvalue() else {}
        )
        self.assertNotIn(KEY_MARK, output.getvalue() + errors.getvalue())
        return code, document, errors.getvalue()

    def pair(self) -> bytes:
        return (
            self.pki.leaf.read_bytes()
            + self.pki.leaf_key.read_bytes()
            + self.pki.intermediate.read_bytes()
        )


class TheHelper(HelperFixture):
    def test_a_pem_pair_is_imported_registered_and_rolled_out(self) -> None:
        code, document, errors = self.invoke(self.request(self.pair()))

        self.assertEqual(code, 0, errors)
        self.assertEqual((document["operation"], document["outcome"]), ("cert_import", "done"))
        self.assertEqual(document["result"]["certificate"], "shop.example")
        self.assertEqual(document["result"]["chain_length"], 1)
        self.assertTrue((self.store / "shop.example" / PRIVKEY).is_file())
        self.assertEqual(self.deployed, ["alpha"])
        registry = yaml.safe_load((self.root / "certificates.yaml").read_text())
        self.assertEqual(registry["certificates"]["shop.example"]["source"]["kind"], "import")

    def test_a_pkcs12_with_its_password(self) -> None:
        bundle = self.pki.pkcs12(PKCS12_PASSWORD).read_bytes()
        code, document, errors = self.invoke(self.request(bundle, password=PKCS12_PASSWORD))

        self.assertEqual(code, 0, errors)
        self.assertEqual(document["outcome"], "done")

    def test_a_certificate_alone_renews_on_the_stored_key(self) -> None:
        code, _, errors = self.invoke(self.request(self.pair()))
        self.assertEqual(code, 0, errors)
        #
        # A second certificate on the same key - what a CA returns for a
        # renewal, or for a CSR made here.
        #
        renewed_pki = Pki(self.root / "pki2")
        renewed = subprocess.run(
            [
                OPENSSL,
                "x509",
                "-req",
                "-in",
                str(self.pki_csr()),
                "-CA",
                str(renewed_pki.intermediate),
                "-CAkey",
                str(renewed_pki.intermediate_key),
                "-CAcreateserial",
                "-days",
                "20",
            ],
            capture_output=True,
            check=True,
        ).stdout

        code, document, errors = self.invoke(self.request(renewed))

        self.assertEqual(code, 0, errors)
        self.assertEqual(document["result"]["replaced"], True)
        self.assertEqual(document["result"]["chain_length"], 0)

    def pki_csr(self) -> Path:
        csr = self.root / "renew.csr"
        subprocess.run(
            [
                OPENSSL,
                "req",
                "-new",
                "-key",
                str(self.pki.leaf_key),
                "-subj",
                "/CN=shop.example",
                "-out",
                str(csr),
            ],
            capture_output=True,
            check=True,
        )
        return csr

    def test_a_certificate_alone_with_no_stored_key_is_refused_with_the_way_out(self) -> None:
        code, document, errors = self.invoke(self.request(self.pki.leaf.read_bytes()))

        self.assertEqual(code, 65)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "no_key")
        self.assertIn("haprion-cert-import", document["error"]["message"])
        self.assertFalse((self.store / "shop.example").exists())

    def test_a_key_that_does_not_belong_leaves_nothing_behind(self) -> None:
        data = self.pki.leaf.read_bytes() + self.pki.intermediate_key.read_bytes()
        code, document, _ = self.invoke(self.request(data))

        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "key_mismatch")
        self.assertFalse((self.store / "shop.example").exists())

    def test_a_box_for_another_certificate_is_blocked_by_binding(self) -> None:
        request = json.loads(self.request(self.pair(), certificate="other.example"))
        request["parameters"]["certificate"] = "shop.example"
        code, document, _ = self.invoke(json.dumps(request))

        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "upload_binding_mismatch")
        self.assertEqual(document["error"]["details"]["binding"], "sealed_upload")

    def test_an_unknown_key_id_and_bad_parameters_are_refused_before_opening(self) -> None:
        code, document, _ = self.invoke(self.request(self.pair(), key_id="f" * 16))
        self.assertEqual((code, document["error"]["code"]), (78, "profile_key_unavailable"))
        code, document, _ = self.invoke(self.request(self.pair(), ciphertext="not base64!"))
        self.assertEqual((code, document["error"]["code"]), (65, "bad_input"))
        code, document, _ = self.invoke(self.request(self.pair(), clusters=["../etc"]))
        self.assertEqual((code, document["error"]["code"]), (65, "bad_input"))

    def test_the_sudoers_rule_names_exactly_the_no_argument_helper(self) -> None:
        example = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haproxy-ui-worker.sudoers.example"
        ).read_text(encoding="utf-8")
        self.assertIn(f'NOPASSWD: {cert_import_helper.HELPER} ""', example)

    def test_arguments_are_refused(self) -> None:
        code, document, errors = self.invoke(self.request(self.pair()), argv=["--x"])
        self.assertEqual(code, 64)
        self.assertEqual(document, {})
        self.assertIn("argument", errors)


if __name__ == "__main__":
    unittest.main()
