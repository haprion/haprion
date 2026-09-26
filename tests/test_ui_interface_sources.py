"""The interface certificate through every way a certificate arrives (B188, D4-D5).

Held here: an issue, an import, an NDES renewal and a signing request each
carry the mark and nothing else - no targets; a rotated or renewed interface
certificate stays the interface's; a new one takes the mark from the old,
and the old is deleted only once the new one is served; the entry that
serves the interface cannot be deleted; the listing says which one it is.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haproxy_mgmt import cert_delete, cert_registry
from haproxy_mgmt.cert_delete import Guards
from haproxy_mgmt.cert_import import ImportError_, import_certificate, read_material
from haproxy_mgmt.cert_issue import IssueError, build_request
from haproxy_mgmt.cert_publish import Material as PublishMaterial
from haproxy_mgmt.cert_request import RequestError, make_request
from haproxy_mgmt.cert_request_state import request_is_interface
from haproxy_mgmt.config import load_policy, load_runtime_config
from haproxy_mgmt.ndes_state import request_is_interface as ndes_request_is_interface
from haproxy_mgmt.ndes_state import write_targets
from tests.test_cert_import import KEEPERS, ImportFixture, Pki


class ClaimingTheMark(unittest.TestCase):
    def test_the_mark_moves_and_the_previous_holder_is_named(self) -> None:
        certificates: dict[str, Any] = {
            "old.example": {"source": {"kind": "import"}, "interface": True},
            "new.example": {"source": {"kind": "import"}},
            "shop.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
        }

        displaced = cert_registry.claim_interface(certificates, "new.example")

        self.assertEqual(displaced, "old.example")
        self.assertEqual(certificates["old.example"], {"source": {"kind": "import"}})
        self.assertTrue(certificates["new.example"]["interface"])
        self.assertNotIn("interface", certificates["shop.example"])

    def test_claiming_it_again_displaces_nothing(self) -> None:
        certificates: dict[str, Any] = {
            "ui.example": {"source": {"kind": "import"}, "interface": True}
        }

        self.assertIsNone(cert_registry.claim_interface(certificates, "ui.example"))


class Importing(ImportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.installed: list[str] = []
        self.retirements: list[tuple[str | None, bool]] = []

        def retire(displaced: str | None, *, served: bool, **_: Any) -> dict[str, Any] | None:
            self.retirements.append((displaced, served))
            return (
                None if displaced is None else {"id": displaced, "state": "removed", "reason": ""}
            )

        patcher = mock.patch.object(cert_delete, "retire_displaced_interface", side_effect=retire)
        patcher.start()
        self.addCleanup(patcher.stop)

    def installer(self, material: PublishMaterial) -> bool:
        self.installed.append(material.certificate_id)
        return True

    def import_as_interface(self, certificate_id: str, pki: Pki | None = None, **extra: Any) -> Any:
        pki = pki or self.pki
        material = read_material(
            certificate=pki.leaf,
            key=pki.leaf_key,
            chain=pki.intermediate,
            pkcs12=None,
            password_file=None,
        )
        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        return import_certificate(
            certificate_id=certificate_id,
            material=material,
            clusters=extra.pop("clusters", ()),
            receivers=extra.pop("receivers", ()),
            policy=policy,
            runtime=runtime,
            deployer=lambda cluster: 0,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            require_secure=False,
            installer=self.installer,
            **extra,
        )

    def test_it_is_marked_installed_and_has_no_target(self) -> None:
        result = self.import_as_interface("shop.example", interface=True)

        self.assertEqual(
            self.registered()["shop.example"], {"source": {"kind": "import"}, "interface": True}
        )
        self.assertEqual(self.installed, ["shop.example"])
        self.assertTrue(result.as_dict()["interface"])
        self.assertEqual(self.retirements, [(None, True)])

    def test_the_listing_names_the_interface_s_entry_and_no_other(self) -> None:
        from datetime import UTC, datetime

        from haproxy_mgmt.cert_inventory import registry_result

        self.import_as_interface("shop.example", interface=True)
        runtime = load_runtime_config(
            load_policy(self.policy_path, require_secure=False), require_secure=False
        )
        assert runtime.registry is not None

        rows = registry_result(
            runtime.registry,
            certificate_root=self.dist,
            renewed=frozenset(),
            now=datetime.now(UTC),
            live=self.live,
            store=self.store,
        )["certificates"]

        marked = [row["id"] for row in rows if row.get("interface")]
        self.assertEqual(marked, ["shop.example"])
        self.assertTrue(all("interface" not in row for row in rows if row["id"] != "shop.example"))

    def test_a_rotated_interface_certificate_stays_the_interface_s(self) -> None:
        self.import_as_interface("shop.example", interface=True)
        rotated = Pki(self.pki_dir / "rotated", names=("shop.example",))

        result = self.import_as_interface("shop.example", pki=rotated)

        self.assertTrue(self.registered()["shop.example"]["interface"])
        self.assertEqual(self.installed, ["shop.example", "shop.example"])
        self.assertTrue(result.as_dict()["interface"])

    def test_a_new_one_takes_the_mark_and_the_old_is_handed_on(self) -> None:
        self.import_as_interface("shop.example", interface=True)
        other = Pki(self.pki_dir / "other", names=("shop.example",))

        result = self.import_as_interface("shop-2.example", pki=other, interface=True)

        registered = self.registered()
        self.assertNotIn("interface", registered["shop.example"])
        self.assertTrue(registered["shop-2.example"]["interface"])
        self.assertEqual(self.retirements[-1], ("shop.example", True))
        self.assertEqual(result.as_dict()["retired"]["id"], "shop.example")

    def test_the_old_one_is_not_handed_on_when_the_new_one_is_not_served(self) -> None:
        self.import_as_interface("shop.example", interface=True)
        other = Pki(self.pki_dir / "other", names=("shop.example",))

        def refusing(material: PublishMaterial) -> bool:
            from haproxy_mgmt.cert_publish import PublishError

            raise PublishError("install_failed", "nginx said no")

        self.installer = refusing  # type: ignore[method-assign]
        self.import_as_interface("shop-2.example", pki=other, interface=True)

        self.assertEqual(self.retirements[-1], ("shop.example", False))

    def test_targets_are_refused_before_the_store_is_written(self) -> None:
        with self.assertRaises(ImportError_) as caught:
            self.import_as_interface("shop.example", interface=True, clusters=["alpha"])

        self.assertEqual(caught.exception.code, "bad_input")
        self.assertFalse((self.store / "shop.example").exists())

    def test_an_id_that_already_has_targets_cannot_become_the_interface_s(self) -> None:
        self.import_as_interface("shop.example", clusters=["alpha"])

        with self.assertRaises(ImportError_):
            self.import_as_interface("shop.example", interface=True)

        self.assertNotIn("interface", self.registered()["shop.example"])


class SigningRequests(ImportFixture):
    def test_the_request_remembers_it_is_for_the_interface(self) -> None:
        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)

        make_request(
            certificate_id="ui.example",
            domains=["ui.example"],
            key_kind="ec-p256",
            clusters=(),
            receivers=(),
            formats=None,
            policy=policy,
            runtime=runtime,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            interface=True,
        )

        self.assertTrue(request_is_interface(self.store, "ui.example"))

    def test_a_request_for_the_interface_names_no_target(self) -> None:
        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)

        with self.assertRaises(RequestError):
            make_request(
                certificate_id="ui.example",
                domains=["ui.example"],
                key_kind="ec-p256",
                clusters=("alpha",),
                receivers=(),
                formats=None,
                policy=policy,
                runtime=runtime,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
                interface=True,
            )


class NdesRequests(unittest.TestCase):
    def test_a_waiting_enrollment_remembers_it_is_for_the_interface(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ui.example").mkdir(mode=0o700)
            with mock.patch(
                "haproxy_mgmt.ndes_state.request_directory", return_value=root / "ui.example"
            ):
                write_targets(root, "ui.example", clusters=(), receivers=(), interface=True)
                self.assertTrue(ndes_request_is_interface(root, "ui.example"))
                stored = json.loads((root / "ui.example" / "targets.json").read_text())
                self.assertIs(stored["interface"], True)
                write_targets(root, "ui.example", clusters=("alpha",), receivers=())
                self.assertFalse(ndes_request_is_interface(root, "ui.example"))


class Issuing(ImportFixture):
    def test_the_interface_certificate_needs_no_target_and_takes_none(self) -> None:
        runtime = load_runtime_config(
            load_policy(self.policy_path, require_secure=False), require_secure=False
        )

        request = build_request(
            domain="ui.example",
            method="dns-01",
            clusters=(),
            receivers=(),
            runtime=runtime,
            interface=True,
        )
        self.assertTrue(request.interface)

        with self.assertRaisesRegex(IssueError, "has no targets"):
            build_request(
                domain="ui.example",
                method="dns-01",
                clusters=("alpha",),
                receivers=(),
                runtime=runtime,
                interface=True,
            )
        with self.assertRaisesRegex(IssueError, "at least one target"):
            build_request(
                domain="ui.example", method="dns-01", clusters=(), receivers=(), runtime=runtime
            )


class Deleting(ImportFixture):
    def test_the_entry_that_serves_the_interface_is_refused(self) -> None:
        self.policy_path = self.write_config(
            KEEPERS | {"ui.example": {"source": {"kind": "import"}, "interface": True}}
        )
        runtime = load_runtime_config(
            load_policy(self.policy_path, require_secure=False), require_secure=False
        )

        refused = cert_delete.refusal("ui.example", runtime, Guards())

        self.assertEqual(refused and refused[0], "serves_interface")

    def test_the_displaced_one_is_deleted_only_once_the_new_one_is_served(self) -> None:
        policy = load_policy(self.policy_path, require_secure=False)
        deleted: list[list[str]] = []

        with mock.patch.object(
            cert_delete,
            "delete",
            side_effect=lambda ids, *a, **k: (
                deleted.append(list(ids)),
                cert_delete.Report((cert_delete.CertificateOutcome(ids[0], "removed"),)),
            )[1],
        ):
            kept = cert_delete.retire_displaced_interface(
                "old.example", served=False, policy=policy, certbot="/bin/false"
            )
            removed = cert_delete.retire_displaced_interface(
                "old.example", served=True, policy=policy, certbot="/bin/false"
            )
            nothing = cert_delete.retire_displaced_interface(
                None, served=True, policy=policy, certbot="/bin/false"
            )

        self.assertEqual(kept and kept["state"], "kept")
        self.assertEqual(removed and removed["state"], "removed")
        self.assertIsNone(nothing)
        self.assertEqual(deleted, [["old.example"]])


if __name__ == "__main__":
    unittest.main()
