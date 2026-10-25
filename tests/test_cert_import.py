"""Importing a certificate: what is refused before anything is written, and what an import is.

Real material, made with the same openssl the engine reads it with: a root,
an intermediate and a leaf, so the chain has an order to get wrong.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import cert_import, cert_pending, exit_codes
from haprion.cert_import import (
    ImportError_,
    Material,
    assemble,
    import_certificate,
    read_material,
    split_blocks,
)
from haprion.cert_inventory import FULLCHAIN, PRIVKEY
from haprion.cli import cert_import as command
from haprion.config import load_policy, load_runtime_config
from tests.contract_schema import assert_contract
from tests.test_cert_publish import Fixture

OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"
KEEPERS: dict[str, dict[str, object]] = {
    "keeper-alpha.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
    "keeper-beta.example": {"source": {"kind": "acme"}, "clusters": ["beta"]},
}


def openssl(*arguments: str, stdin: str | None = None) -> str:
    completed = subprocess.run(
        [OPENSSL, *arguments], input=stdin, capture_output=True, text=True, check=True
    )
    return completed.stdout


class Pki:
    """A root, an intermediate under it and a leaf under that, in `directory`."""

    def __init__(self, directory: Path, *, names: tuple[str, ...] = ("shop.example",)) -> None:
        self.directory = directory
        directory.mkdir(exist_ok=True)
        self.root_key, self.root = self._self_signed("Test Root")
        self.intermediate_key, self.intermediate = self._signed(
            "Test Issuing CA", self.root, self.root_key, ca=True
        )
        self.names = names
        self.leaf_key, self.leaf = self._signed(
            names[0], self.intermediate, self.intermediate_key, sans=names
        )

    def _self_signed(self, common_name: str) -> tuple[Path, Path]:
        key = self.directory / f"{common_name}.key"
        cert = self.directory / f"{common_name}.pem"
        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            f"/CN={common_name}",
            "-days",
            "30",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        )
        return key, cert

    def _signed(
        self,
        common_name: str,
        issuer: Path,
        issuer_key: Path,
        *,
        ca: bool = False,
        sans: tuple[str, ...] = (),
        days: int = 30,
    ) -> tuple[Path, Path]:
        key = self.directory / f"{common_name}.key"
        csr = self.directory / f"{common_name}.csr"
        cert = self.directory / f"{common_name}.pem"
        ext = self.directory / f"{common_name}.ext"
        openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={common_name}",
        )
        lines = ["basicConstraints=critical,CA:TRUE"] if ca else ["basicConstraints=CA:FALSE"]
        if sans:
            lines.append("subjectAltName=" + ",".join(f"DNS:{name}" for name in sans))
        ext.write_text("\n".join(lines) + "\n")
        openssl(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(issuer),
            "-CAkey",
            str(issuer_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            str(days),
            "-extfile",
            str(ext),
        )
        return key, cert

    def pkcs12(self, password: str) -> Path:
        bundle = self.directory / "export.pfx"
        openssl(
            "pkcs12",
            "-export",
            "-inkey",
            str(self.leaf_key),
            "-in",
            str(self.leaf),
            "-certfile",
            str(self.intermediate),
            "-out",
            str(bundle),
            "-passout",
            f"pass:{password}",
        )
        return bundle


class ImportFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.pki_dir = self.root / "pki"
        self.pki_dir.mkdir()
        self.pki = Pki(self.pki_dir)
        self.deployed: list[str] = []
        self.policy_path = self.write_config(KEEPERS)
        (self.root / "certificates.yaml").chmod(0o640)

    def deploy(self, cluster: str) -> int:
        """Stands in for the deploy: records the cluster and succeeds."""

        self.deployed.append(cluster)
        return 0

    def material(self) -> Material:
        return read_material(
            certificate=self.pki.leaf,
            key=self.pki.leaf_key,
            chain=self.pki.intermediate,
            pkcs12=None,
            password_file=None,
        )

    def run_import(self, certificate_id: str, material: Material, **targets: Any) -> Any:
        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        return import_certificate(
            certificate_id=certificate_id,
            material=material,
            clusters=targets.get("clusters", ()),
            receivers=targets.get("receivers", ()),
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


class ReadingTheMaterial(ImportFixture):
    def test_blocks_are_found_and_bag_attributes_dropped(self) -> None:
        text = "Bag Attributes\n    friendlyName: x\n" + self.pki.leaf.read_text()
        text += "Key Attributes: <No Attributes>\n" + self.pki.leaf_key.read_text()
        certificates, keys = split_blocks(text)
        self.assertEqual((len(certificates), len(keys)), (1, 1))
        #
        # The attribute lines, not the word: base64 can spell "Bag" by chance, and
        # did in a gate run on 2026-10-09.
        #
        self.assertNotIn("Bag Attributes", certificates[0] + keys[0])
        self.assertNotIn("friendlyName", certificates[0] + keys[0])
        self.assertNotIn("Key Attributes", certificates[0] + keys[0])

    def test_an_encrypted_key_is_refused(self) -> None:
        encrypted = openssl("pkey", "-in", str(self.pki.leaf_key), "-aes256", "-passout", "pass:x")
        with self.assertRaises(ImportError_) as refused:
            split_blocks(encrypted)
        self.assertIn("encrypted", str(refused.exception))

    def test_the_chain_is_ordered_from_the_leaf_and_the_root_is_dropped(self) -> None:
        """Handed root, intermediate, leaf - the wrong way round - with the key last."""

        certificates, _ = split_blocks(
            self.pki.root.read_text()
            + self.pki.intermediate.read_text()
            + self.pki.leaf.read_text()
        )
        _, keys = split_blocks(self.pki.leaf_key.read_text())
        material = assemble(certificates, keys)
        self.assertEqual(material.leaf, certificates[2])
        self.assertEqual(material.chain, (certificates[1],))
        self.assertEqual(material.fullchain, certificates[2] + certificates[1])

    def test_a_key_that_belongs_to_no_certificate_is_refused(self) -> None:
        certificates, _ = split_blocks(self.pki.leaf.read_text())
        _, keys = split_blocks(self.pki.intermediate_key.read_text())
        with self.assertRaises(ImportError_) as refused:
            assemble(certificates, keys)
        self.assertEqual(refused.exception.code, "key_mismatch")

    def test_two_keys_or_no_certificate_are_refused(self) -> None:
        _, keys = split_blocks(self.pki.leaf_key.read_text() + self.pki.root_key.read_text())
        with self.assertRaises(ImportError_):
            assemble([self.pki.leaf.read_text()], keys)
        with self.assertRaises(ImportError_):
            assemble([], keys[:1])

    def test_a_key_in_the_certificate_file_is_refused(self) -> None:
        mixed = self.pki_dir / "mixed.pem"
        mixed.write_text(self.pki.leaf.read_text() + self.pki.leaf_key.read_text())
        with self.assertRaises(ImportError_) as refused:
            read_material(
                certificate=mixed,
                key=self.pki.leaf_key,
                chain=None,
                pkcs12=None,
                password_file=None,
            )
        self.assertIn("keep the key in --key", str(refused.exception))

    def test_a_pkcs12_is_read_with_its_password_from_a_file(self) -> None:
        bundle = self.pki.pkcs12("s3cret")
        passphrase_file = self.pki_dir / "passphrase"
        passphrase_file.write_text("s3cret\n")
        material = read_material(
            certificate=None, key=None, chain=None, pkcs12=bundle, password_file=passphrase_file
        )
        self.assertEqual(len(material.chain), 1)
        self.assertEqual(
            cert_import.public_key_of_certificate(material.leaf),
            cert_import.public_key_of_key(material.key),
        )

    def test_a_wrong_pkcs12_password_is_refused(self) -> None:
        bundle = self.pki.pkcs12("s3cret")
        passphrase_file = self.pki_dir / "passphrase"
        passphrase_file.write_text("wrong\n")
        with self.assertRaises(ImportError_) as refused:
            read_material(
                certificate=None, key=None, chain=None, pkcs12=bundle, password_file=passphrase_file
            )
        self.assertEqual(refused.exception.code, "bad_input")


class WhatIsRefusedBeforeWriting(ImportFixture):
    def assert_nothing_written(self, certificate_id: str) -> None:
        self.assertFalse((self.store / certificate_id).exists())
        self.assertNotIn(certificate_id, self.registered())
        self.assertEqual(self.deployed, [])

    def test_an_expired_certificate(self) -> None:
        material = self.material()
        with self.assertRaises(ImportError_) as refused:
            import_certificate(
                certificate_id="shop.example",
                material=material,
                clusters=["alpha"],
                receivers=(),
                policy=load_policy(self.policy_path, require_secure=False),
                runtime=load_runtime_config(
                    load_policy(self.policy_path, require_secure=False), require_secure=False
                ),
                live=self.live,
                store=self.store,
                lock_path=self.lock,
                require_secure=False,
                now=datetime.now(UTC) + timedelta(days=60),
            )
        self.assertEqual(refused.exception.code, "expired")
        self.assert_nothing_written("shop.example")

    def test_an_id_certbot_owns(self) -> None:
        (self.live / "shop.example").mkdir()
        with self.assertRaises(ImportError_) as refused:
            self.run_import("shop.example", self.material(), clusters=["alpha"])
        self.assertEqual(refused.exception.code, "already_exists")
        self.assert_nothing_written("shop.example")

    def test_an_id_registered_as_acme(self) -> None:
        with self.assertRaises(ImportError_) as refused:
            self.run_import("keeper-alpha.example", self.material(), clusters=["alpha"])
        self.assertEqual(refused.exception.code, "not_import")
        self.assertFalse((self.store / "keeper-alpha.example").exists())

    def test_an_invalid_id_and_an_unknown_cluster(self) -> None:
        with self.assertRaises(ImportError_):
            self.run_import("Shop/Example", self.material(), clusters=["alpha"])
        with self.assertRaises(ImportError_) as refused:
            self.run_import("shop.example", self.material(), clusters=["gamma"])
        self.assertEqual(refused.exception.code, "unknown_cluster")
        with self.assertRaises(ImportError_) as refused:
            self.run_import("shop.example", self.material(), receivers=["nobody"])
        self.assertEqual(refused.exception.code, "unknown_receiver")
        self.assert_nothing_written("shop.example")


class WhatAnImportIs(ImportFixture):
    def test_store_registry_targets_and_rollout(self) -> None:
        result = self.run_import("shop.example", self.material(), clusters=["alpha"])

        directory = self.store / "shop.example"
        self.assertEqual(oct(directory.stat().st_mode & 0o777), "0o700")
        for name in (PRIVKEY, "cert.pem", "chain.pem", FULLCHAIN):
            self.assertEqual(oct((directory / name).stat().st_mode & 0o777), "0o600", name)
        self.assertEqual(
            (directory / FULLCHAIN).read_text(),
            (directory / "cert.pem").read_text() + (directory / "chain.pem").read_text(),
        )
        self.assertEqual(
            self.registered()["shop.example"],
            {"source": {"kind": "import"}, "clusters": ["alpha"]},
        )
        self.assertTrue((self.dist / "alpha" / "shop.example.pem").exists())
        self.assertEqual(self.deployed, ["alpha"])
        self.assertFalse(result.replaced)
        self.assertEqual(result.facts.sans, ("shop.example",))
        self.assertEqual(result.chain_length, 1)
        self.assertEqual(result.publish.failed, ())
        #
        # The key is in the store and in the published file, and nowhere in
        # what the result says.
        #
        self.assertNotIn("PRIVATE", json.dumps(result.as_dict()))

    def test_a_second_import_replaces_the_material_and_keeps_the_targets(self) -> None:
        self.run_import("shop.example", self.material(), clusters=["alpha"])
        self.deployed.clear()
        rotated = Pki(self.pki_dir / "rotated", names=("shop.example", "www.shop.example"))
        material = read_material(
            certificate=rotated.leaf,
            key=rotated.leaf_key,
            chain=rotated.intermediate,
            pkcs12=None,
            password_file=None,
        )
        result = self.run_import("shop.example", material)
        self.assertTrue(result.replaced)
        self.assertEqual(result.facts.sans, ("shop.example", "www.shop.example"))
        self.assertEqual(self.registered()["shop.example"]["clusters"], ["alpha"])
        self.assertEqual((self.store / "shop.example" / FULLCHAIN).read_text(), material.fullchain)
        self.assertEqual([p.name for p in self.store.iterdir()], ["shop.example"])
        self.assertEqual(self.deployed, ["alpha"])

    def test_a_second_import_naming_a_target_adds_it_and_keeps_the_rest(self) -> None:
        """Targets named on a re-import are added, never a replacement (2026-09-19)."""

        self.run_import("shop.example", self.material(), clusters=["alpha"])

        self.run_import("shop.example", self.material(), receivers=["lb-01"])

        self.assertEqual(self.registered()["shop.example"]["clusters"], ["alpha"])
        self.assertEqual(self.registered()["shop.example"]["receivers"], ["lb-01"])

    def test_a_receiver_only_import_publishes_the_pair(self) -> None:
        self.run_import("pve.example", self.material(), receivers=["lb-01"])
        self.assertTrue((self.receiver_dir / "pve.example" / FULLCHAIN).exists())
        self.assertTrue((self.receiver_dir / "pve.example" / PRIVKEY).exists())
        self.assertEqual(list(self.dist.rglob("pve.example.pem")), [])
        self.assertEqual(self.deployed, [])


class TheCommand(ImportFixture):
    def run_cli(self, *argv: str, **options: Any) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = command.main(
            list(argv),
            policy_path=self.policy_path,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=options.pop("require_root", False),
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )
        return code, out.getvalue(), err.getvalue()

    def test_usage_and_root(self) -> None:
        code, out, _ = self.run_cli("--id", "x")
        self.assertEqual(code, 64)
        self.assertIn("Usage", out)
        code, _, err = self.run_cli(
            "--id",
            "x",
            "--certificate",
            str(self.pki.leaf),
            "--key",
            str(self.pki.leaf_key),
            require_root=True,
        )
        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertIn("not_root", err)

    def test_pem_files_with_json(self) -> None:
        code, out, err = self.run_cli(
            "--id",
            "shop.example",
            "--certificate",
            str(self.pki.leaf),
            "--key",
            str(self.pki.leaf_key),
            "--chain",
            str(self.pki.intermediate),
            "--cluster",
            "alpha",
            "--json",
        )
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual((document["operation"], document["outcome"]), ("cert_import", "done"))
        self.assertEqual(document["result"]["certificate"], "shop.example")
        self.assertNotIn("PRIVATE", out)
        self.assertEqual(self.deployed, ["alpha"])

    def test_a_due_note_that_cannot_be_written_is_said(self) -> None:
        """Review 26-10-24, 13-06: the publish's warning reaches the answer."""

        with mock.patch.object(cert_pending.Ledger, "keep", side_effect=OSError("disk full")):
            code, out, err = self.run_cli(
                "--id",
                "shop.example",
                "--certificate",
                str(self.pki.leaf),
                "--key",
                str(self.pki.leaf_key),
                "--cluster",
                "alpha",
                "--json",
            )
        self.assertEqual(code, 0, err)
        document = assert_contract("haprion-cert-import", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(
            [warning["code"] for warning in document["warnings"]], ["pending_unrecorded"]
        )

    def test_pkcs12_at_a_terminal(self) -> None:
        bundle = self.pki.pkcs12("pw")
        passphrase_file = self.pki_dir / "passphrase"
        passphrase_file.write_text("pw\n")
        code, out, err = self.run_cli(
            "--id",
            "shop.example",
            "--pkcs12",
            str(bundle),
            "--password-file",
            str(passphrase_file),
            "--cluster",
            "alpha",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("imported shop.example (shop.example)", out)
        self.assertIn("chain of 1", out)
        self.assertIn("deploy alpha: ok", out)

    def test_a_refusal_writes_a_failure_envelope(self) -> None:
        code, out, err = self.run_cli(
            "--id",
            "shop.example",
            "--certificate",
            str(self.pki.leaf),
            "--key",
            str(self.pki.intermediate_key),
            "--json",
        )
        self.assertEqual(code, 65)
        self.assertEqual(json.loads(out)["error"]["code"], "key_mismatch")
        self.assertIn("key_mismatch", err)


class AnAuthorityIsImportedWithoutAKey(ImportFixture):
    """A CA file for the pools to verify against (B276): certificates only, clusters only."""

    def blocks(self, *paths: Path) -> tuple[str, ...]:
        data = "".join(path.read_text() for path in paths).encode()
        certificates, keys = cert_import.read_bytes(data)
        return cert_import.authority_blocks(certificates, keys)

    def run_authority(self, certificate_id: str, blocks: tuple[str, ...], **targets: Any) -> Any:
        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        return cert_import.import_authority(
            certificate_id=certificate_id,
            blocks=blocks,
            clusters=targets.get("clusters", ()),
            policy=policy,
            runtime=runtime,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
        )

    def test_a_root_and_its_intermediate_land_in_the_clusters_ca_directory(self) -> None:
        result = self.run_authority(
            "corp-root", self.blocks(self.pki.root, self.pki.intermediate), clusters=["alpha"]
        )

        self.assertTrue(result.authority)
        self.assertEqual(result.chain_length, 1)
        self.assertEqual(
            self.registered()["corp-root"], {"source": {"kind": "authority"}, "clusters": ["alpha"]}
        )
        published = (self.dist / "alpha" / "ca" / "corp-root.pem").read_text()
        self.assertEqual(published.count("BEGIN CERTIFICATE"), 2)
        self.assertNotIn("PRIVATE KEY", published)
        self.assertEqual(self.deployed, ["alpha"])
        self.assertFalse((self.store / "corp-root" / PRIVKEY).exists())

    def test_the_cluster_reads_it_as_an_authority_and_not_as_a_certificate(self) -> None:
        self.run_authority("corp-root", self.blocks(self.pki.root), clusters=["alpha"])

        policy = load_policy(self.policy_path, require_secure=False)
        cluster = load_runtime_config(policy, require_secure=False).cluster("alpha")
        self.assertEqual(cluster.authority_ids, ("corp-root",))
        self.assertNotIn("corp-root", cluster.certificate_ids)

    def test_a_key_in_the_file_is_refused(self) -> None:
        data = (self.pki.root.read_text() + self.pki.root_key.read_text()).encode()
        certificates, keys = cert_import.read_bytes(data)

        with self.assertRaises(ImportError_) as caught:
            cert_import.authority_blocks(certificates, keys)
        self.assertIn("private key", str(caught.exception))

    def test_a_server_certificate_is_not_a_ca(self) -> None:
        with self.assertRaises(ImportError_) as caught:
            self.blocks(self.pki.leaf)
        self.assertEqual(caught.exception.code, "not_authority")

    def test_a_certificate_cannot_be_imported_over_a_ca(self) -> None:
        self.run_authority("corp-root", self.blocks(self.pki.root), clusters=["alpha"])

        with self.assertRaises(ImportError_) as caught:
            self.run_import("corp-root", self.material(), clusters=["alpha"])
        self.assertEqual(caught.exception.code, "not_import")

    def test_a_ca_cannot_be_imported_over_a_certificate(self) -> None:
        self.run_import("shop.example", self.material(), clusters=["alpha"])

        with self.assertRaises(ImportError_) as caught:
            self.run_authority("shop.example", self.blocks(self.pki.root), clusters=["alpha"])
        self.assertEqual(caught.exception.code, "not_import")

    def test_a_second_import_replaces_the_file_and_keeps_the_clusters(self) -> None:
        self.run_authority("corp-root", self.blocks(self.pki.root), clusters=["alpha"])
        result = self.run_authority(
            "corp-root", self.blocks(self.pki.root, self.pki.intermediate), clusters=["beta"]
        )

        self.assertTrue(result.replaced)
        self.assertEqual(self.registered()["corp-root"]["clusters"], ["alpha", "beta"])
        for cluster_id in ("alpha", "beta"):
            published = (self.dist / cluster_id / "ca" / "corp-root.pem").read_text()
            self.assertEqual(published.count("BEGIN CERTIFICATE"), 2, cluster_id)

    def test_the_command_takes_a_file_and_says_what_it_imported(self) -> None:
        output, errors = io.StringIO(), io.StringIO()
        code = command.main(
            ["--id", "corp-root", "--authority", str(self.pki.root), "--cluster", "alpha"],
            policy_path=self.policy_path,
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            deployer=self.deploy,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
        )

        self.assertEqual(code, 0, errors.getvalue())
        self.assertIn("imported CA corp-root", output.getvalue())

    def test_the_command_refuses_a_key_or_a_receiver_beside_a_ca(self) -> None:
        for extra in (["--key", str(self.pki.root_key)], ["--receiver", "lb-01"]):
            output = io.StringIO()
            code = command.main(
                ["--id", "corp-root", "--authority", str(self.pki.root), *extra],
                policy_path=self.policy_path,
                output_stream=output,
                error_stream=io.StringIO(),
                require_secure=False,
                require_root=False,
            )
            self.assertEqual(code, 64, extra)


if __name__ == "__main__":
    unittest.main()
