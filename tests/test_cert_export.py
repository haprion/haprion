"""Exportable certificates (B255): made with no targets, and the only keys given out.

Real material throughout, made with the openssl the engine reads it with, and a
real registry in a temporary directory. What carries weight is the boundary:
every way an exportable entry is made keeps it target-less and single-named,
and the export refuses every entry without the mark.
"""

from __future__ import annotations

import base64
import io
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import pkcs12

from haprion import cert_registry
from haprion.cert_export import ExportError, export
from haprion.cert_import import ImportError_, import_certificate
from haprion.cert_inventory import OPENSSL, registry_result
from haprion.certificates import CERTIFICATE_OPENING, MAX_CERTIFICATE_BYTES
from haprion.cli import cert_export_helper
from haprion.config import (
    BmcTarget,
    ConfigError,
    load_policy,
    load_registry,
    load_runtime_config,
)
from tests.contract_schema import assert_contract
from tests.test_cert_import import KEEPERS, ImportFixture, Pki

#
# Assembled, so the secret scanner does not take a test bundle's password for one.
#
BUNDLE_PASSWORD = "-".join(("s3cret", "pass"))
DEVICE = "bmc01.example"


class ExportableFixture(ImportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.device = Pki(self.root / "device", names=(DEVICE,))

    def runtime(self) -> Any:
        policy = load_policy(self.policy_path, require_secure=False)
        return policy, load_runtime_config(policy, require_secure=False)

    def make_exportable(self) -> Any:
        policy, runtime = self.runtime()
        return import_certificate(
            certificate_id=DEVICE,
            material=self.device_material(),
            clusters=(),
            receivers=(),
            policy=policy,
            runtime=runtime,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
            exportable=True,
        )

    def device_material(self) -> Any:
        from haprion.cert_import import read_material

        return read_material(
            certificate=self.device.leaf,
            key=self.device.leaf_key,
            chain=self.device.intermediate,
            pkcs12=None,
            password_file=None,
        )

    def registry(self) -> Any:
        return load_registry(self.root / "certificates.yaml", require_secure=False)


class TheRegistryHoldsTheMark(ExportableFixture):
    def write(self, entry: dict[str, Any]) -> Path:
        path = self.write_config({**KEEPERS, DEVICE: entry})
        return path

    def test_an_exportable_entry_has_no_targets(self) -> None:
        for extra in ({"clusters": ["alpha"]}, {"interface": True}):
            with self.subTest(extra=extra), self.assertRaises(ConfigError):
                self.write({"source": {"kind": "import"}, "exportable": True, **extra})
                load_registry(self.root / "certificates.yaml", require_secure=False)

    def test_the_mark_is_true_or_false(self) -> None:
        with self.assertRaises(ConfigError):
            self.write({"source": {"kind": "import"}, "exportable": "yes"})
            load_registry(self.root / "certificates.yaml", require_secure=False)

    def test_an_exportable_entry_is_never_given_a_target_afterwards(self) -> None:
        self.make_exportable()
        policy, runtime = self.runtime()
        with self.assertRaises(cert_registry.RegistryError) as refused:
            cert_registry.set_targets(
                self.root / "certificates.yaml",
                certificate_id=DEVICE,
                clusters=("alpha",),
                receivers=(),
                runtime=runtime,
                require_secure=False,
            )
        self.assertIn("exportable", str(refused.exception))


PINNED = "ab" * 32
BMC = {"address": "bmc01.example", "fingerprint_sha256": PINNED, "username": "admin"}


REDFISH = {"transport": "redfish", "fingerprint_sha256": PINNED, "username": "admin"}


class ABmcReceiver(ExportableFixture):
    """B538: a BMC is a receiver, `transport: redfish`, kept apart from the fetching ones."""

    def write(self, entry: dict[str, Any], **bmcs: dict[str, Any]) -> Path:
        self.extra_receivers = {name.replace("_", "."): fields for name, fields in bmcs.items()}
        return self.write_config({**KEEPERS, DEVICE: entry})

    def test_a_certificate_names_its_bmc_among_its_receivers_on_443_unless_said(self) -> None:
        self.write(
            {"source": {"kind": "import"}, "exportable": True, "receivers": ["bmc01.example"]},
            bmc01_example=REDFISH,
        )
        registry = self.registry()
        entry = registry.certificates[DEVICE]
        self.assertEqual(entry.receivers, ())
        assert entry.bmc is not None
        self.assertEqual(
            (entry.bmc.address, entry.bmc.port, entry.bmc.fingerprint_sha256, entry.bmc.username),
            ("bmc01.example", 443, PINNED, "admin"),
        )
        self.assertNotIn("bmc01.example", registry.receivers)
        self.assertEqual(registry.certificate_of("bmc01.example"), DEVICE)
        self.assertEqual(registry.legacy_bmcs, ())
        self.write(
            {"source": {"kind": "import"}, "exportable": True, "receivers": ["bmc01.example"]},
            bmc01_example={**REDFISH, "port": 8443},
        )
        bmc = self.registry().certificates[DEVICE].bmc
        self.assertEqual(bmc.port if bmc else None, 8443)

    def test_a_bmc_carries_one_certificate_and_a_certificate_has_one_bmc(self) -> None:
        self.write({"source": {"kind": "import"}, "exportable": True}, bmc01_example=REDFISH)
        self.assertIsNone(self.registry().certificate_of("bmc01.example"))
        for entry, others, said in (
            (
                {"source": {"kind": "import"}, "receivers": ["bmc01.example"]},
                {
                    "keeper-alpha.example": {
                        "source": {"kind": "acme"},
                        "clusters": ["alpha"],
                        "receivers": ["bmc01.example"],
                    }
                },
                "already carries",
            ),
            (
                {"source": {"kind": "import"}, "receivers": ["bmc01.example", "bmc02.example"]},
                {},
                "more than one BMC",
            ),
            (
                {
                    "source": {"kind": "import"},
                    "receivers": [{"id": "bmc01.example", "format": "pkcs12"}],
                },
                {},
                "takes no format",
            ),
            (
                {"source": {"kind": "import"}, "interface": True, "receivers": ["bmc01.example"]},
                {},
                "",
            ),
        ):
            with self.subTest(entry=entry):
                self.extra_receivers = {"bmc01.example": REDFISH, "bmc02.example": REDFISH}
                self.write_config({**KEEPERS, **others, DEVICE: entry})
                with self.assertRaisesRegex(ConfigError, said):
                    self.registry()

    def test_any_certificate_may_name_a_bmc_and_an_exportable_one_no_fetching_receiver(
        self,
    ) -> None:
        self.write(
            {"source": {"kind": "import"}, "receivers": ["bmc01.example"]}, bmc01_example=REDFISH
        )
        self.assertIsNotNone(self.registry().certificates[DEVICE].bmc)
        self.write({"source": {"kind": "import"}, "exportable": True, "receivers": ["lb-01"]})
        with self.assertRaisesRegex(ConfigError, "exportable"):
            self.registry()

    def test_a_bmc_receiver_is_held_to_its_shape(self) -> None:
        for fields, name, said in (
            ({**REDFISH, "port": 0}, "bmc01.example", "port"),
            ({**REDFISH, "port": "443"}, "bmc01.example", "port"),
            (
                {**REDFISH, "fingerprint_sha256": PINNED.upper()},
                "bmc01.example",
                "fingerprint_sha256",
            ),
            ({**REDFISH, "path": "/srv/x"}, "bmc01.example", "unknown"),
            ({k: v for k, v in REDFISH.items() if k != "username"}, "bmc01.example", "username"),
            ({**REDFISH, "username": " admin"}, "bmc01.example", "username"),
            (REDFISH, "bmc_01", "name or address"),
        ):
            with self.subTest(fields=fields, name=name):
                self.extra_receivers = {name: fields}
                self.write_config(
                    {**KEEPERS, DEVICE: {"source": {"kind": "import"}, "exportable": True}}
                )
                with self.assertRaisesRegex(ConfigError, said):
                    self.registry()

    def test_the_form_before_b538_is_read_and_the_next_write_puts_it_among_the_receivers(
        self,
    ) -> None:
        self.make_exportable()
        self.extra_receivers = {}
        self.write_config({**KEEPERS, DEVICE: {**self.registered()[DEVICE], "bmc": BMC}})
        registry = self.registry()
        self.assertEqual(registry.legacy_bmcs, (DEVICE,))
        self.assertEqual(registry.certificate_of("bmc01.example"), DEVICE)
        policy, runtime = self.runtime()
        #
        # A renewal is an import: the first write of any kind settles it.
        #
        import_certificate(
            certificate_id=DEVICE,
            material=self.device_material(),
            clusters=(),
            receivers=(),
            policy=policy,
            runtime=runtime,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
        )
        document = cert_registry.read_document(self.root / "certificates.yaml")
        self.assertNotIn("bmc", document["certificates"][DEVICE])
        self.assertEqual(document["certificates"][DEVICE]["receivers"], ["bmc01.example"])
        self.assertEqual(document["receivers"]["bmc01.example"], REDFISH)
        registry = self.registry()
        self.assertEqual(registry.legacy_bmcs, ())
        self.assertEqual(registry.certificate_of("bmc01.example"), DEVICE)
        exported = export(registry, DEVICE, "pem-key", live=self.live, store=self.store)
        self.assertEqual(exported.content, self.device.leaf_key.read_bytes())

    def test_the_writer_registers_moves_and_takes_away_a_bmc(self) -> None:
        self.make_exportable()
        policy, runtime = self.runtime()
        path = self.root / "certificates.yaml"

        def set_bmc(receiver_id: str, target: BmcTarget | None, certificate: Any) -> None:
            cert_registry.set_bmc_receiver(
                path,
                receiver_id=receiver_id,
                target=target,
                certificate_id=certificate,
                runtime=runtime,
                require_secure=False,
                lock_path=self.lock,
            )

        target = BmcTarget(address="bmc01.example", fingerprint_sha256=PINNED, username="admin")
        set_bmc("bmc01.example", target, DEVICE)
        self.assertEqual(self.registered()[DEVICE]["receivers"], ["bmc01.example"])
        set_bmc(
            "bmc01.example",
            BmcTarget(
                address="bmc01.example", fingerprint_sha256=PINNED, username="admin", port=8443
            ),
            cert_registry.KEEP,
        )
        self.assertEqual(self.registry().certificates[DEVICE].bmc.port, 8443)  # type: ignore[union-attr]
        set_bmc("bmc01.example", target, None)
        self.assertNotIn("receivers", self.registered()[DEVICE])
        self.assertIn("bmc01.example", self.registry().bmcs)
        set_bmc("bmc01.example", None, cert_registry.KEEP)
        self.assertNotIn("bmc01.example", self.registry().bmcs)
        for receiver_id, certificate, code in (
            ("lb-01", DEVICE, "already_exists"),
            ("bmc01.example", "missing.example", "not_registered"),
        ):
            with (
                self.subTest(receiver_id=receiver_id),
                self.assertRaises(cert_registry.RegistryError) as refused,
            ):
                set_bmc(
                    receiver_id,
                    BmcTarget(address=receiver_id, fingerprint_sha256=PINNED, username="admin"),
                    certificate,
                )
            self.assertEqual(refused.exception.code, code)

    def test_a_target_change_keeps_the_certificates_bmc(self) -> None:
        self.write(
            {"source": {"kind": "import"}, "clusters": ["alpha"], "receivers": ["bmc01.example"]},
            bmc01_example=REDFISH,
        )
        _policy, runtime = self.runtime()
        change = cert_registry.set_targets(
            self.root / "certificates.yaml",
            certificate_id=DEVICE,
            clusters=("alpha",),
            receivers=("lb-01",),
            runtime=runtime,
            require_secure=False,
        )
        self.assertEqual((change.added, change.abandoned), (("lb-01",), ()))
        self.assertEqual(self.registered()[DEVICE]["receivers"], ["lb-01", "bmc01.example"])
        with self.assertRaises(cert_registry.RegistryError) as refused:
            cert_registry.set_targets(
                self.root / "certificates.yaml",
                certificate_id=DEVICE,
                clusters=("alpha",),
                receivers=("bmc01.example",),
                runtime=runtime,
                require_secure=False,
            )
        self.assertEqual(refused.exception.code, "unknown_receiver")

    def test_the_listing_names_the_bmc_and_its_receiver_in_its_contract(self) -> None:
        from datetime import UTC, datetime

        self.make_exportable()
        self.extra_receivers = {"bmc01.example": REDFISH, "bmc02.example": REDFISH}
        self.write_config(
            {**KEEPERS, DEVICE: {**self.registered()[DEVICE], "receivers": ["bmc01.example"]}}
        )
        listed = registry_result(
            self.registry(),
            certificate_root=self.dist,
            renewed=frozenset(),
            now=datetime.now(UTC),
            live=self.live,
            store=self.store,
        )
        row = next(entry for entry in listed["certificates"] if entry["id"] == DEVICE)
        other = next(entry for entry in listed["certificates"] if entry["id"] != DEVICE)
        self.assertEqual(row["bmc"], {**BMC, "port": 443})
        self.assertNotIn("bmc", other)
        self.assertEqual(
            listed["bmc_records"],
            [
                {
                    "id": "bmc01.example",
                    "port": 443,
                    "username": "admin",
                    "fingerprint_sha256": PINNED,
                    "certificate": DEVICE,
                },
                {
                    "id": "bmc02.example",
                    "port": 443,
                    "username": "admin",
                    "fingerprint_sha256": PINNED,
                    "certificate": None,
                },
            ],
        )
        self.assertNotIn("bmc01.example", [r["id"] for r in listed["receiver_records"]])
        assert_contract(
            "haprion-cert-list",
            json.dumps(
                {
                    "schema_version": 1,
                    "ok": True,
                    "outcome": "done",
                    "operation": "cert_list",
                    "cluster": None,
                    "request_id": "99999999-9999-4999-8999-999999999996",
                    "result": {"interface_served": None, "registry": listed},
                    "warnings": [],
                    "error": None,
                }
            ),
        )


class MakingOne(ExportableFixture):
    def test_an_import_marks_it_and_names_no_target(self) -> None:
        result = self.make_exportable()

        self.assertTrue(result.exportable)
        self.assertEqual(
            self.registered()[DEVICE], {"source": {"kind": "import"}, "exportable": True}
        )
        self.assertEqual(self.deployed, [])

    def test_a_renewal_arriving_as_an_import_keeps_the_mark(self) -> None:
        self.make_exportable()
        policy, runtime = self.runtime()

        import_certificate(
            certificate_id=DEVICE,
            material=self.device_material(),
            clusters=(),
            receivers=(),
            policy=policy,
            runtime=runtime,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
        )

        self.assertTrue(self.registered()[DEVICE]["exportable"])

    def test_an_exportable_import_with_a_target_is_refused_before_the_store(self) -> None:
        policy, runtime = self.runtime()
        with self.assertRaises(ImportError_):
            import_certificate(
                certificate_id=DEVICE,
                material=self.device_material(),
                clusters=("alpha",),
                receivers=(),
                policy=policy,
                runtime=runtime,
                deployer=self.deploy,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
                require_secure=False,
                exportable=True,
            )
        self.assertFalse((self.store / DEVICE).exists())

    def test_a_wildcard_is_never_exportable(self) -> None:
        wild = Pki(self.root / "wild", names=("wild.example", "*.wild.example"))
        from haprion.cert_import import read_material

        material = read_material(
            certificate=wild.leaf,
            key=wild.leaf_key,
            chain=wild.intermediate,
            pkcs12=None,
            password_file=None,
        )
        policy, runtime = self.runtime()
        with self.assertRaises(ImportError_):
            import_certificate(
                certificate_id="wild.example",
                material=material,
                clusters=(),
                receivers=(),
                policy=policy,
                runtime=runtime,
                deployer=self.deploy,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
                require_secure=False,
                exportable=True,
            )


class TheListingCarriesThePublicChainOnly(ExportableFixture):
    def test_the_chain_is_listed_and_the_key_is_not(self) -> None:
        self.make_exportable()
        from datetime import UTC, datetime

        listed = registry_result(
            self.registry(),
            certificate_root=self.dist,
            renewed=frozenset(),
            now=datetime.now(UTC),
            live=self.live,
            store=self.store,
        )
        row = next(entry for entry in listed["certificates"] if entry["id"] == DEVICE)
        other = next(entry for entry in listed["certificates"] if entry["id"] != DEVICE)

        self.assertTrue(row["exportable"])
        self.assertTrue(row["fullchain_pem"].startswith(CERTIFICATE_OPENING + "\n"))
        self.assertNotIn("PRIVATE KEY", json.dumps(listed))
        self.assertNotIn("fullchain_pem", other)


class Exporting(ExportableFixture):
    def test_the_key_alone_is_the_stored_key(self) -> None:
        self.make_exportable()

        exported = export(self.registry(), DEVICE, "pem-key", live=self.live, store=self.store)

        self.assertEqual(exported.content, self.device.leaf_key.read_bytes())
        self.assertEqual(exported.filename, f"{DEVICE}.key.pem")

    def test_both_bundles_open_with_their_password_and_hold_the_chain(self) -> None:
        self.make_exportable()
        for form, cipher in (("pfx", "AES-256-CBC"), ("pfx-compatible", "3-KeyTripleDES")):
            with self.subTest(form=form):
                exported = export(
                    self.registry(), DEVICE, form, BUNDLE_PASSWORD, live=self.live, store=self.store
                )
                key, certificate, chain = pkcs12.load_key_and_certificates(
                    exported.content, BUNDLE_PASSWORD.encode()
                )
                self.assertIsNotNone(key)
                self.assertIsNotNone(certificate)
                self.assertEqual(len(chain), 1)
                bundle = self.root / f"{form}.pfx"
                bundle.write_bytes(exported.content)
                info = subprocess.run(
                    [OPENSSL, "pkcs12", "-in", str(bundle), "-info", "-noout", "-passin",
                     f"pass:{BUNDLE_PASSWORD}"],
                    capture_output=True, text=True, check=True,
                )  # fmt: skip
                self.assertIn(cipher, info.stderr + info.stdout)
                self.assertNotIn("RC2", info.stderr + info.stdout)

    def test_a_bundle_needs_a_password_and_the_key_takes_none(self) -> None:
        self.make_exportable()
        for form, password in (("pfx", None), ("pfx", "short"), ("pem-key", BUNDLE_PASSWORD)):
            with self.subTest(form=form, password=password), self.assertRaises(ExportError):
                export(self.registry(), DEVICE, form, password, live=self.live, store=self.store)

    def test_an_implausibly_large_file_is_refused_unread(self) -> None:
        self.make_exportable()
        (self.store / DEVICE / "privkey.pem").write_bytes(b"x" * (MAX_CERTIFICATE_BYTES + 1))

        with self.assertRaises(ExportError) as refused:
            export(self.registry(), DEVICE, "pem-key", live=self.live, store=self.store)

        self.assertEqual(refused.exception.code, "dependency_unavailable")
        self.assertIn("implausibly large", str(refused.exception))

    def test_a_certificate_without_the_mark_gives_nothing_out(self) -> None:
        self.make_exportable()
        self.run_import("shop.example", self.material(), clusters=("alpha",))

        with self.assertRaises(ExportError) as refused:
            export(self.registry(), "shop.example", "pem-key", live=self.live, store=self.store)

        self.assertEqual(refused.exception.code, "not_exportable")


class TheHelper(ExportableFixture):
    def ask(self, **parameters: Any) -> tuple[int, str]:
        request = {
            "schema_version": 1,
            "operation": "cert_export",
            "cluster": None,
            "request_id": "11111111-2222-4333-8444-555555555555",
            "parameters": {"id": DEVICE, "requested_by": "admin", **parameters},
        }
        out, err = io.StringIO(), io.StringIO()
        if True:
            code = cert_export_helper.main(
                [],
                policy_path=self.policy_path,
                input_stream=io.BytesIO(json.dumps(request).encode() + b"\n"),
                output_stream=out,
                error_stream=err,
                require_secure=False,
                require_root=False,
                live=self.live,
                store=self.store,
            )
        self.journal = err.getvalue()
        return code, out.getvalue()

    def test_an_export_answers_in_its_contract_and_says_so_in_the_journal(self) -> None:
        self.make_exportable()

        code, answer = self.ask(format="pfx", password=BUNDLE_PASSWORD)

        self.assertEqual(code, 0)
        document = assert_contract("haprion-cert-export", answer)
        self.assertNotIn(BUNDLE_PASSWORD, answer)
        pkcs12.load_key_and_certificates(
            base64.b64decode(document["result"]["content_base64"]), BUNDLE_PASSWORD.encode()
        )
        self.assertIn(f"exported {DEVICE} as pfx for admin", self.journal)
        self.assertNotIn(BUNDLE_PASSWORD, self.journal)

    def test_a_refusal_is_a_failure_envelope(self) -> None:
        self.run_import("shop.example", self.material(), clusters=("alpha",))

        code, answer = self.ask(id="shop.example", format="pem-key")

        self.assertEqual(code, 65)
        document = assert_contract("haprion-cert-export", answer)
        self.assertEqual(document["error"]["code"], "not_exportable")


if __name__ == "__main__":
    unittest.main()
