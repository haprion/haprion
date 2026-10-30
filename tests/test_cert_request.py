"""A signing request made on the manager (C9b): what is made, what is refused, what comes back.

The round trip is the test that matters: a request is made, the CSR is
signed by the same test PKI the import tests use, and the certificate alone
- no key - is imported over the waiting request, through the engine the
interface's upload calls. What is checked at the end is the store, the
registry and the targets the request named; and that no output of any of it
carries the key.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import cert_delete, cert_import, cert_request, cert_request_state
from haprion.cert_inventory import FULLCHAIN, PRIVKEY, registry_result
from haprion.cert_request import RequestError, make_request
from haprion.cert_request_state import CSR, RECORD, TARGETS, pending_csr, pending_csrs
from haprion.cli import cert_import as import_command
from haprion.cli import cert_request as command
from haprion.cli import cert_request_helper
from haprion.config import load_policy, load_runtime_config
from haprion.ndes_state import request_directory
from tests.contract_schema import assert_contract
from tests.test_cert_import import KEEPERS, OPENSSL, Pki
from tests.test_cert_publish import Fixture

KEY_MARK = "PRIVATE KEY"
REQUEST_MARK = "CERTIFICATE REQUEST"
REQUEST_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"


def csr_text(csr_pem: str) -> str:
    return subprocess.run(
        [OPENSSL, "req", "-noout", "-text"],
        input=csr_pem,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


class RequestFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.write_config(KEEPERS)
        (self.root / "certificates.yaml").chmod(0o640)
        self.deployed: list[str] = []
        self.pki = Pki(self.root / "pki")

    def deploy(self, cluster: str) -> int:
        """Stands in for the deploy: records the cluster and succeeds."""

        self.deployed.append(cluster)
        return 0

    def loaded(self) -> tuple[Any, Any]:
        policy = load_policy(self.policy_path, require_secure=False)
        return policy, load_runtime_config(policy, require_secure=False)

    def request(self, certificate_id: str = "shop.example.net", **overrides: Any) -> Any:
        policy, runtime = self.loaded()
        options: dict[str, Any] = {
            "domains": [certificate_id, "*." + certificate_id],
            "key_kind": "ec-p256",
            "clusters": ["alpha"],
            "receivers": [],
            "formats": None,
            **overrides,
        }
        return make_request(
            certificate_id=certificate_id,
            policy=policy,
            runtime=runtime,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            now=datetime(2026, 9, 21, 10, 30, tzinfo=UTC),
            **options,
        )

    def sign(self, csr_pem: str, *, days: int = 30) -> str:
        """The test PKI's intermediate signs the request, SANs copied from it."""

        csr = self.root / "signed.csr"
        csr.write_text(csr_pem, encoding="ascii")
        ext = self.root / "signed.ext"
        #
        # The names are restated from the CSR's own SAN line, which is what
        # a CA honours.
        #
        names = [
            line.strip()
            for line in csr_text(csr_pem).splitlines()
            if line.strip().startswith("DNS:")
        ]
        ext.write_text("basicConstraints=CA:FALSE\nsubjectAltName=" + names[0] + "\n")
        out = self.root / "signed.pem"
        subprocess.run(
            [
                OPENSSL,
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(self.pki.intermediate),
                "-CAkey",
                str(self.pki.intermediate_key),
                "-CAcreateserial",
                "-out",
                str(out),
                "-days",
                str(days),
                "-extfile",
                str(ext),
            ],
            capture_output=True,
            check=True,
        )
        return out.read_text(encoding="ascii")

    def import_signed(self, certificate_id: str, signed_pem: str, **targets: Any) -> Any:
        """The keyless path the upload helper takes: the stored key is the pair's."""

        certificates, keys = cert_import.read_bytes(signed_pem.encode("ascii"))
        self.assertEqual(keys, [])
        stored = cert_import.stored_key(self.store, certificate_id)
        assert stored is not None
        material = cert_import.assemble(
            certificates + [self.pki.intermediate.read_text()], [stored]
        )
        policy, runtime = self.loaded()
        return cert_import.import_certificate(
            certificate_id=certificate_id,
            material=material,
            clusters=targets.get("clusters", ()),
            receivers=targets.get("receivers", ()),
            formats=targets.get("formats"),
            policy=policy,
            runtime=runtime,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
        )

    def registered(self) -> dict[str, Any]:
        document: dict[str, Any] = yaml.safe_load((self.root / "certificates.yaml").read_text())
        return dict(document["certificates"])


class WhatARequestIs(RequestFixture):
    def test_key_csr_and_records_in_the_store_and_nothing_in_the_registry(self) -> None:
        result = self.request(receivers=["lb-01"], formats={"lb-01": "pkcs12"})

        directory = self.store / "shop.example.net"
        self.assertEqual(oct(directory.stat().st_mode & 0o777), "0o700")
        for name in (PRIVKEY, CSR, RECORD, TARGETS):
            self.assertEqual(oct((directory / name).stat().st_mode & 0o777), "0o600", name)
        self.assertFalse((directory / FULLCHAIN).exists())
        self.assertIn(KEY_MARK, (directory / PRIVKEY).read_text())
        self.assertEqual((directory / CSR).read_text(), result.csr_pem)
        text = csr_text(result.csr_pem)
        self.assertIn("CN = shop.example.net", text.replace("CN=", "CN = "))
        self.assertIn("DNS:shop.example.net, DNS:*.shop.example.net", text)
        self.assertIn("prime256v1", text)
        self.assertEqual(
            json.loads((directory / TARGETS).read_text()),
            {"clusters": ["alpha"], "receivers": ["lb-01"], "formats": {"lb-01": "pkcs12"}},
        )
        self.assertEqual(
            json.loads((directory / RECORD).read_text()),
            {
                "certificate": "shop.example.net",
                "domains": ["shop.example.net", "*.shop.example.net"],
                "key_type": "ec-p256",
                "requested_at": "2026-09-21T10:30:00+00:00",
            },
        )
        self.assertNotIn("shop.example.net", self.registered())
        self.assertNotIn(KEY_MARK, json.dumps(result.as_dict()))
        self.assertEqual(result.as_dict()["state"], "pending")
        self.assertEqual([entry.name for entry in self.store.iterdir()], ["shop.example.net"])

    def test_rsa_keys_on_request(self) -> None:
        result = self.request("rsa.example.net", domains=["rsa.example.net"], key_kind="rsa-2048")
        self.assertIn("2048 bit", csr_text(result.csr_pem))
        self.assertEqual(result.key_type, "rsa-2048")

    def test_the_default_key_type_and_a_wrong_one(self) -> None:
        self.assertEqual(cert_request.key_type(""), "ec-p256")
        self.assertEqual(cert_request.key_type(None), "ec-p256")
        with self.assertRaises(RequestError):
            cert_request.key_type("dsa-1024")

    def test_the_listing_shows_it_as_pending_with_the_csr_and_the_targets(self) -> None:
        result = self.request(receivers=["lb-01"])
        _policy, runtime = self.loaded()

        listing = registry_result(
            runtime.registry,
            certificate_root=self.dist,
            renewed=frozenset(),
            now=datetime.now(UTC),
            live=self.live,
            store=self.store,
        )
        rows = {row["id"]: row for row in listing["certificates"]}
        row = rows["shop.example.net"]
        self.assertEqual(row["request_state"], "pending")
        self.assertFalse(row["readable"])
        self.assertEqual(row["source"], {"kind": "import", "lineage": None})
        self.assertEqual(row["request"]["kind"], "csr")
        self.assertEqual(row["request"]["domains"], ["shop.example.net", "*.shop.example.net"])
        self.assertEqual(row["request"]["csr_pem"], result.csr_pem)
        self.assertEqual(row["targets"]["clusters"], ["alpha"])
        self.assertEqual([r["id"] for r in row["targets"]["receivers"]], ["lb-01"])
        self.assertIsNone(row["distribution"])
        self.assertNotIn(KEY_MARK, json.dumps(listing))

    def test_a_directory_without_a_record_is_not_pending(self) -> None:
        self.request()
        (self.store / "shop.example.net" / RECORD).unlink()
        self.assertIsNone(pending_csr(self.store, "shop.example.net"))
        self.assertEqual(pending_csrs(self.store), ())
        #
        # ...but the key is still there, so the name is still taken.
        #
        with self.assertRaises(RequestError) as caught:
            self.request()
        self.assertEqual(caught.exception.code, "already_exists")


class WhatIsRefusedBeforeWriting(RequestFixture):
    def assert_nothing_written(self) -> None:
        self.assertEqual(list(self.store.iterdir()), [])

    def test_a_wildcard_cn_and_bad_names(self) -> None:
        for domains in (["*.shop.example.net"], [], ["not a name"], ["a"] * 33):
            with self.subTest(domains=domains), self.assertRaises(RequestError) as caught:
                self.request(domains=domains)
            self.assertEqual(caught.exception.code, "bad_input")
        self.assert_nothing_written()

    def test_a_name_the_registry_certbot_or_the_store_has(self) -> None:
        with self.assertRaises(RequestError) as registered:
            self.request("keeper-alpha.example", domains=["keeper-alpha.example"])
        self.assertIn("already in the registry", str(registered.exception))

        (self.live / "lineage.example").mkdir()
        with self.assertRaises(RequestError) as lineage:
            self.request("lineage.example", domains=["lineage.example"])
        self.assertIn("certbot has a lineage", str(lineage.exception))

        (self.store / "stored.example").mkdir()
        (self.store / "stored.example" / FULLCHAIN).write_text("x")
        with self.assertRaises(RequestError) as stored:
            self.request("stored.example", domains=["stored.example"])
        self.assertIn("already holds material", str(stored.exception))

        self.request()
        with self.assertRaises(RequestError) as twice:
            self.request()
        self.assertIn("already waiting", str(twice.exception))
        for exc in (registered, lineage, stored, twice):
            self.assertEqual(exc.exception.code, "already_exists")

    def test_unknown_targets_and_a_format_for_nobody(self) -> None:
        with self.assertRaises(RequestError) as cluster:
            self.request(clusters=["gamma"])
        self.assertEqual(cluster.exception.code, "unknown_cluster")
        with self.assertRaises(RequestError) as receiver:
            self.request(receivers=["nobody"])
        self.assertEqual(receiver.exception.code, "unknown_receiver")
        with self.assertRaises(RequestError) as form:
            self.request(receivers=["lb-01"], formats={"other": "pem"})
        self.assertEqual(form.exception.code, "bad_input")
        self.assert_nothing_written()

    def test_openssl_failing_leaves_no_staging_behind(self) -> None:
        with (
            mock.patch.object(cert_request, "OPENSSL", "/nonexistent/openssl"),
            self.assertRaises(RequestError) as caught,
        ):
            self.request()
        self.assertEqual(caught.exception.code, "dependency_unavailable")
        self.assert_nothing_written()


class TheRoundTrip(RequestFixture):
    def test_the_signed_certificate_lands_on_the_requested_targets(self) -> None:
        result = self.request(receivers=["lb-01"], formats={"lb-01": "pkcs12"})
        signed = self.sign(result.csr_pem)

        imported = self.import_signed("shop.example.net", signed)

        self.assertFalse(imported.replaced)
        directory = self.store / "shop.example.net"
        self.assertTrue((directory / FULLCHAIN).is_file())
        for name in (CSR, RECORD, TARGETS):
            self.assertFalse((directory / name).exists(), name)
        self.assertIsNone(pending_csr(self.store, "shop.example.net"))
        entry = self.registered()["shop.example.net"]
        self.assertEqual(entry["source"], {"kind": "import"})
        self.assertEqual(entry["clusters"], ["alpha"])
        self.assertEqual(entry["receivers"], [{"id": "lb-01", "format": "pkcs12"}])
        self.assertEqual(self.deployed, ["alpha"])
        self.assertEqual(imported.facts.sans, ("shop.example.net", "*.shop.example.net"))
        self.assertNotIn(KEY_MARK, json.dumps(imported.as_dict()))

    def test_targets_named_at_upload_are_added_to_the_requested_ones(self) -> None:
        result = self.request(clusters=["alpha"])
        signed = self.sign(result.csr_pem)

        self.import_signed("shop.example.net", signed, receivers=["lb-01"])

        entry = self.registered()["shop.example.net"]
        self.assertEqual(entry["clusters"], ["alpha"])
        self.assertEqual(entry["receivers"], ["lb-01"])

    def test_a_certificate_for_another_key_is_refused_and_the_request_kept(self) -> None:
        self.request()
        with self.assertRaises(cert_import.ImportError_) as caught:
            self.import_signed("shop.example.net", self.pki.leaf.read_text())
        self.assertEqual(caught.exception.code, "key_mismatch")
        self.assertIsNotNone(pending_csr(self.store, "shop.example.net"))

    def test_the_terminal_import_takes_the_signed_certificate_without_a_key(self) -> None:
        """CLI parity: what the row's upload does, `haprion-cert-import` does without `--key`."""

        result = self.request(receivers=["lb-01"])
        signed = self.root / "signed-cli.pem"
        signed.write_text(self.sign(result.csr_pem), encoding="ascii")

        out, err = io.StringIO(), io.StringIO()
        code = import_command.main(
            [
                "--id",
                "shop.example.net",
                "--certificate",
                str(signed),
                "--chain",
                str(self.pki.intermediate),
                "--json",
            ],
            policy_path=self.policy_path,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        self.assertEqual(code, 0, err.getvalue())
        document = assert_contract("haprion-cert-import", out.getvalue())
        self.assertFalse(document["result"]["replaced"])
        self.assertNotIn(KEY_MARK, out.getvalue() + err.getvalue())
        entry = self.registered()["shop.example.net"]
        self.assertEqual((entry["clusters"], entry["receivers"]), (["alpha"], ["lb-01"]))
        self.assertIsNone(pending_csr(self.store, "shop.example.net"))

        # Without a stored key, `--certificate` alone is still refused.
        out, err = io.StringIO(), io.StringIO()
        code = import_command.main(
            ["--id", "other.example.net", "--certificate", str(signed)],
            policy_path=self.policy_path,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        self.assertEqual(code, 65)
        self.assertIn("--key is required", err.getvalue())

    def test_the_wrong_certificate_on_a_pending_row_says_what_the_row_waits_for(self) -> None:
        self.request()
        with self.assertRaises(cert_import.ImportError_) as caught:
            cert_import.read_material(
                certificate=self.pki.leaf,
                key=None,
                chain=None,
                pkcs12=None,
                password_file=None,
                stored=cert_import.stored_key(self.store, "shop.example.net"),
            )
        self.assertEqual(caught.exception.code, "key_mismatch")
        self.assertIn("signing request made here", str(caught.exception))

    def test_deleting_the_row_takes_the_key_away(self) -> None:
        """`cert_delete` on a pending row: not registered, so swept by name."""

        self.request()
        policy, _runtime = self.loaded()
        report = cert_delete.delete(
            ["shop.example.net"],
            policy,
            require_secure=False,
            renewal_directory=self.root / "renewal",
            store=self.store,
            certbot="/usr/bin/certbot",
            lock_path=self.lock,
            lineage_remover=lambda arguments: (0, ""),
            node_remover=lambda identity, host, verb, certificate_id: (0, ""),
            guards_reader=lambda runtime, ids: cert_delete.Guards(),
        )
        outcome = next(c for c in report.outcomes if c.certificate_id == "shop.example.net")
        #
        # The store layer is the one this is about; the fixture has no
        # deploy identity, so the node layer is reported kept, as it says.
        #
        store_layer = next(layer for layer in outcome.layers if layer.name.startswith("import "))
        self.assertEqual(store_layer.state, "removed", outcome)
        self.assertNotEqual(outcome.state, "refused")
        self.assertFalse((self.store / "shop.example.net").exists())


class TheHelperAndTheCommand(RequestFixture):
    def helper(self, parameters: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "cert_request",
                "cluster": None,
                "request_id": REQUEST_ID,
                "parameters": parameters,
            }
        )
        output, errors = io.StringIO(), io.StringIO()
        code = cert_request_helper.main(
            [],
            policy_path=self.policy_path,
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        self.assertNotIn(KEY_MARK, output.getvalue() + errors.getvalue())
        document = (
            assert_contract("haprion-cert-request", output.getvalue()) if output.getvalue() else {}
        )
        return code, document, errors.getvalue()

    def test_the_helper_makes_the_request_and_reports_the_csr(self) -> None:
        code, document, errors = self.helper(
            {
                "id": "shop.example.net",
                "domains": ["shop.example.net"],
                "key_type": "ec-p256",
                "clusters": ["alpha"],
                "receivers": ["lb-01"],
                "formats": {"lb-01": "pkcs12"},
            }
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual((document["outcome"], document["request_id"]), ("done", REQUEST_ID))
        self.assertIn(REQUEST_MARK, document["result"]["csr_pem"])
        self.assertTrue((self.store / "shop.example.net" / PRIVKEY).is_file())
        self.assertEqual(
            json.loads((self.store / "shop.example.net" / TARGETS).read_text())["formats"],
            {"lb-01": "pkcs12"},
        )

    def test_the_helper_refuses_bad_parameters_in_an_envelope(self) -> None:
        for parameters, words in (
            ({"id": "shop.example.net", "domains": [], "clusters": []}, "domains"),
            ({"id": "shop.example.net", "domains": ["a.example"], "key_type": "dsa"}, "key_type"),
            ({"id": "Shop", "domains": ["a.example"]}, "certificate"),
            ({"id": "shop.example.net", "domains": ["a.example"], "extra": 1}, "extra"),
        ):
            with self.subTest(words=words):
                code, document, errors = self.helper(parameters)
                self.assertEqual(code, 65)
                if document:
                    self.assertEqual(document["outcome"], "failed")
                    self.assertEqual(document["error"]["code"], "bad_input")
                self.assertIn(words, errors)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_a_request_with_no_target_is_refused_as_the_web_refuses_it(self) -> None:
        code, document, _ = self.helper({"id": "shop.example.net", "domains": ["shop.example.net"]})
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertIn("at least one target", document["error"]["message"])
        self.assertEqual(list(self.store.iterdir()), [])

    def test_the_helper_says_when_the_name_is_taken(self) -> None:
        code, document, _ = self.helper(
            {
                "id": "keeper-alpha.example",
                "domains": ["keeper-alpha.example"],
                "clusters": ["alpha"],
            }
        )
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "already_exists")

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        output, errors = io.StringIO(), io.StringIO()
        code = command.main(
            list(argv),
            policy_path=self.policy_path,
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        self.assertNotIn(KEY_MARK, output.getvalue() + errors.getvalue())
        return code, output.getvalue(), errors.getvalue()

    def test_the_command_prints_the_csr_or_the_envelope(self) -> None:
        code, output, errors = self.run_cli(
            "--id",
            "shop.example.net",
            "--domain",
            "shop.example.net",
            "--domain",
            "*.shop.example.net",
            "--cluster",
            "alpha",
            "--receiver",
            "lb-01",
            "--format",
            "lb-01=pkcs12",
        )
        self.assertEqual(code, 0, errors)
        self.assertIn("shop.example.net: pending; key ec-p256", output)
        self.assertIn(REQUEST_MARK, output)

        shutil.rmtree(self.store / "shop.example.net")
        code, output, errors = self.run_cli(
            "--id",
            "rsa.example.net",
            "--domain",
            "rsa.example.net",
            "--key-type",
            "rsa-2048",
            "--cluster",
            "alpha",
            "--json",
        )
        self.assertEqual(code, 0, errors)
        document = assert_contract("haprion-cert-request", output)
        self.assertEqual(document["result"]["key_type"], "rsa-2048")

    def test_a_malformed_format_is_a_usage_error_as_in_the_other_commands(self) -> None:
        code, _, errors = self.run_cli(
            "--id", "a.example", "--domain", "a.example", "--receiver", "lb-01", "--format", "x"
        )
        self.assertEqual(code, 64, errors)

    def test_the_command_refuses_in_the_envelope_shape(self) -> None:
        code, output, errors = self.run_cli(
            "--id",
            "keeper-alpha.example",
            "--domain",
            "keeper-alpha.example",
            "--cluster",
            "alpha",
            "--json",
        )
        self.assertEqual(code, 65)
        self.assertEqual(
            assert_contract("haprion-cert-request", output)["error"]["code"], "already_exists"
        )
        self.assertIn("already_exists", errors)

    def test_the_command_requires_root(self) -> None:
        output, errors = io.StringIO(), io.StringIO()
        code = command.main(
            ["--id", "a.example", "--domain", "a.example"],
            policy_path=self.policy_path,
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=True,
        )
        self.assertEqual(code, 77)
        self.assertIn("must run as root", errors.getvalue())


class TheStateModuleAgreesWithTheInventory(unittest.TestCase):
    def test_the_material_file_has_one_name(self) -> None:
        self.assertEqual(cert_request_state.MATERIAL, FULLCHAIN)

    def test_each_of_the_five_places_holds_an_id_and_an_allowed_one_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            live, store, requests = root / "live", root / "store", root / "requests"
            for directory in (live, store, requests):
                directory.mkdir()

            def holder(certificate_id: str, **extra: Any) -> str | None:
                found = cert_request_state.id_holder(
                    certificate_id,
                    registered_kind=extra.pop("registered_kind", None),
                    live=live,
                    store=store,
                    request_root=requests,
                    **extra,
                )
                return found.kind if found is not None else None

            self.assertIsNone(holder("free.example"))
            self.assertEqual(
                holder("a.example", registered_kind="acme"), cert_request_state.HELD_BY_ENTRY
            )
            self.assertEqual(
                holder("a.example", registered_kind="import"),
                cert_request_state.HELD_BY_IMPORT_ENTRY,
            )
            (live / "b.example").mkdir()
            self.assertEqual(holder("b.example"), cert_request_state.HELD_BY_LINEAGE)
            (store / "c.example").mkdir()
            self.assertEqual(holder("c.example"), cert_request_state.HELD_BY_MATERIAL)
            self.assertIsNone(holder("c.example", allow=(cert_request_state.HELD_BY_MATERIAL,)))
            (store / "d.example").mkdir()
            (store / "d.example" / cert_request_state.CSR).write_text("CSR")
            self.assertEqual(holder("d.example"), cert_request_state.HELD_BY_CSR)
            enrollment = request_directory(requests, "e.example")
            enrollment.mkdir()
            (enrollment / "request.json").write_text("{}")
            self.assertEqual(holder("e.example"), cert_request_state.HELD_BY_ENROLLMENT)
            self.assertIsNone(holder("e.example", allow=(cert_request_state.HELD_BY_ENROLLMENT,)))

    def test_targets_of_nothing_pending_are_empty(self) -> None:
        self.assertEqual(
            cert_request_state.request_targets(Path("/nonexistent"), "a.example"), ((), (), {})
        )
