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
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import cert_delete, cert_registry, ui_interface
from haprion.cert_delete import Guards
from haprion.cert_import import ImportError_, import_certificate, read_material
from haprion.cert_issue import IssueError, build_request
from haprion.cert_publish import Material as PublishMaterial
from haprion.cert_request import RequestError, make_request
from haprion.cert_request_state import request_is_interface
from haprion.config import load_policy, load_runtime_config
from haprion.ndes_state import request_is_interface as ndes_request_is_interface
from haprion.ndes_state import write_targets
from tests.test_cert_import import KEEPERS, ImportFixture, Pki


class ServedAs(ImportFixture):
    """An interface served as `ui.example`: what a certificate for it is held to before a CA is asked."""

    SERVER_NAME = "ui.example"

    def setUp(self) -> None:
        super().setUp()
        config = self.root / "ui-tls.conf"
        config.write_text(
            f"TLS_CERT={self.root / 'ui.crt'}\nTLS_KEY={self.root / 'ui.key'}\n"
            f"SERVER_NAME={self.SERVER_NAME}\n"
        )
        patcher = mock.patch.object(ui_interface, "UI_TLS_CONFIG", config)
        patcher.start()
        self.addCleanup(patcher.stop)


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


class Importing(ServedAs):
    SERVER_NAME = "shop.example"

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

        from haprion.cert_inventory import registry_result

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
            from haprion.cert_publish import PublishError

            raise PublishError("install_failed", "nginx said no")

        self.installer = refusing  # type: ignore[method-assign]
        self.import_as_interface("shop-2.example", pki=other, interface=True)

        self.assertEqual(self.retirements[-1], ("shop.example", False))

    def test_targets_are_refused_before_the_store_is_written(self) -> None:
        with self.assertRaises(ImportError_) as caught:
            self.import_as_interface("shop.example", interface=True, clusters=["alpha"])

        self.assertEqual(caught.exception.code, "bad_input")
        self.assertFalse((self.store / "shop.example").exists())

    def test_a_certificate_that_does_not_name_the_interface_is_refused_before_the_mark_moves(
        self,
    ) -> None:
        self.import_as_interface("shop.example", interface=True)
        wrong = Pki(self.pki_dir / "wrong", names=("elsewhere.example",))

        with self.assertRaises(ImportError_) as caught:
            self.import_as_interface("shop-2.example", pki=wrong, interface=True)

        self.assertEqual(caught.exception.code, "bad_input")
        self.assertFalse((self.store / "shop-2.example").exists())
        registered = self.registered()
        self.assertTrue(registered["shop.example"]["interface"])
        self.assertNotIn("shop-2.example", registered)
        self.assertEqual(self.retirements, [(None, True)])

    def test_an_id_that_already_has_targets_cannot_become_the_interface_s(self) -> None:
        self.import_as_interface("shop.example", clusters=["alpha"])

        with self.assertRaises(ImportError_):
            self.import_as_interface("shop.example", interface=True)

        self.assertNotIn("interface", self.registered()["shop.example"])


class SigningRequests(ServedAs):
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

    def test_a_request_for_a_name_the_interface_is_not_served_on_is_refused(self) -> None:
        """Review 26-10-24, 15-03: refused before anything is made, not after it is signed."""

        policy = load_policy(self.policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)

        with self.assertRaises(RequestError) as caught:
            make_request(
                certificate_id="shop.example",
                domains=["shop.example"],
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

        self.assertEqual(caught.exception.code, "bad_input")
        self.assertIn("ui.example", str(caught.exception))
        self.assertFalse(request_is_interface(self.store, "shop.example"))

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
                "haprion.ndes_state.request_directory", return_value=root / "ui.example"
            ):
                write_targets(root, "ui.example", clusters=(), receivers=(), interface=True)
                self.assertTrue(ndes_request_is_interface(root, "ui.example"))
                stored = json.loads((root / "ui.example" / "targets.json").read_text())
                self.assertIs(stored["interface"], True)
                write_targets(root, "ui.example", clusters=("alpha",), receivers=())
                self.assertFalse(ndes_request_is_interface(root, "ui.example"))


class Issuing(ServedAs):
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

    def test_a_name_the_interface_is_not_served_on_is_refused_before_certbot(self) -> None:
        """Review 26-10-24, 15-03: certbot issued it, then the install refused it."""

        runtime = load_runtime_config(
            load_policy(self.policy_path, require_secure=False), require_secure=False
        )
        with self.assertRaises(IssueError) as caught:
            build_request(
                domain="shop.example",
                method="dns-01",
                clusters=(),
                receivers=(),
                runtime=runtime,
                interface=True,
            )
        self.assertEqual(caught.exception.code, "bad_input")
        self.assertIn("ui.example", str(caught.exception))


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

        def removing(ids: Sequence[str], *_: Any, **__: Any) -> cert_delete.Report:
            deleted.append(list(ids))
            return cert_delete.Report((cert_delete.CertificateOutcome(ids[0], "removed"),))

        with mock.patch.object(
            cert_delete,
            "delete",
            side_effect=removing,
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


class TheCommandsAndHelpers(ServedAs):
    SERVER_NAME = "shop.example"

    """`--interface` at the terminal, `interface` in a job; nothing else changes."""

    def test_every_issuing_helper_takes_the_field_and_the_publish_helper_does_not(self) -> None:
        from haprion.cli import (
            cert_import_helper,
            cert_issue_helper,
            cert_publish_helper,
            cert_request_helper,
            cert_scep_helper,
        )

        for helper in (
            cert_issue_helper,
            cert_import_helper,
            cert_request_helper,
            cert_scep_helper,
        ):
            self.assertIn("interface", helper.PARAMETERS, helper.__name__)
        self.assertNotIn("interface", cert_publish_helper.PARAMETERS)

    def test_the_field_is_a_boolean_and_absent_means_no(self) -> None:
        from haprion.cli import cert_job
        from haprion.helper_protocol import HelperProtocolError

        self.assertFalse(cert_job.interface({}))
        self.assertTrue(cert_job.interface({"interface": True}))
        with self.assertRaises(HelperProtocolError):
            cert_job.interface({"interface": "yes"})

    def test_the_requests_the_worker_sends_carry_it_only_when_set(self) -> None:
        from haprion.cli import cert_issue_helper, cert_request_helper, cert_scep_helper

        plain = json.loads(
            cert_issue_helper.build_request("r", domain="ui.example", method="dns-01")
        )
        marked = json.loads(
            cert_issue_helper.build_request(
                "r", domain="ui.example", method="dns-01", interface=True
            )
        )
        self.assertNotIn("interface", plain["parameters"])
        self.assertIs(marked["parameters"]["interface"], True)
        for built in (
            cert_request_helper.build_request(
                "r", certificate_id="ui.example", domains=("ui.example",), interface=True
            ),
            cert_scep_helper.build_request(
                "r",
                certificate_id="ui.example",
                profile_id="p",
                domains=("ui.example",),
                interface=True,
            ),
        ):
            self.assertIs(json.loads(built)["parameters"]["interface"], True)

    def test_import_at_the_terminal_marks_and_installs(self) -> None:
        import io

        from haprion.cli import cert_import as command

        installed: list[str] = []

        def installing(material: Any) -> bool:
            installed.append(material.certificate_id)
            return True

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cert_delete, "retire_displaced_interface", return_value=None):
            code = command.main(
                [
                    "--id",
                    "shop.example",
                    "--certificate",
                    str(self.pki.leaf),
                    "--key",
                    str(self.pki.leaf_key),
                    "--chain",
                    str(self.pki.intermediate),
                    "--interface",
                    "--json",
                ],
                policy_path=self.policy_path,
                output_stream=out,
                error_stream=err,
                require_secure=False,
                require_root=False,
                deployer=lambda cluster: 0,
                installer=installing,
                live=self.live,
                store=self.store,
                lock_path=self.lock,
            )

        self.assertEqual(code, 0, err.getvalue())
        self.assertTrue(self.registered()["shop.example"]["interface"])
        self.assertEqual(installed, ["shop.example"])
        self.assertTrue(json.loads(out.getvalue())["result"]["interface"])
