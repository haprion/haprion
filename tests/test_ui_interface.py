"""The interface certificate's way to nginx (B188, D2).

What is held here: a certificate that does not name the interface's
`SERVER_NAME` never reaches `haproxy-ui-tls`; one nginx already serves is not
installed again, so a renewal of something else costs no reload; the key is
handed over in a private file that does not outlive the call; and the
command's refusal comes back as the publisher's own kind of failure. The
publisher gives the entry to its installer and to nothing else.

`haproxy-ui-tls` itself is not run: it needs root, nginx and a reload. The
runner is replaced by one that does what the command does to the served
certificate - copies it into place - so the next call measures a real file.
"""

from __future__ import annotations

import io
import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haproxy_mgmt import helper_socket, ui_interface
from haproxy_mgmt.cert_publish import Material, PublishError, read_material
from haproxy_mgmt.cli import ui_tls_helper
from haproxy_mgmt.config import CertificateSource, RegisteredCertificate
from tests.contract_schema import assert_contract
from tests.test_cert_publish import Fixture, issue


class Names(unittest.TestCase):
    def test_an_exact_name_or_one_wildcard_label(self) -> None:
        self.assertTrue(ui_interface.covers(("mgr.example.net",), "mgr.example.net"))
        self.assertTrue(ui_interface.covers(("MGR.example.net",), "mgr.example.net"))
        self.assertTrue(ui_interface.covers(("*.example.net",), "mgr.example.net"))
        self.assertFalse(ui_interface.covers(("*.example.net",), "example.net"))
        self.assertFalse(ui_interface.covers(("*.example.net",), "a.mgr.example.net"))
        self.assertFalse(ui_interface.covers(("mgr-b.example.net",), "mgr.example.net"))
        self.assertFalse(ui_interface.covers((), "mgr.example.net"))


class TheConfiguration(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "ui-tls.conf"

    def test_the_installer_s_own_file_is_read(self) -> None:
        self.path.write_text(
            "# Read by haproxy-ui-tls. Written by 05-platform-nginx.\n"
            "TLS_CERT=/etc/haproxy-manager/tls/ui.crt\n"
            "TLS_KEY=/etc/haproxy-manager/tls/ui.key\n"
            "SERVER_NAME=Mgr.example.net\n"
        )

        config = ui_interface.read_config(self.path)

        self.assertEqual(config.cert, Path("/etc/haproxy-manager/tls/ui.crt"))
        self.assertEqual(config.server_name, "mgr.example.net")

    def test_anything_a_shell_would_evaluate_is_refused(self) -> None:
        for line in ("SERVER_NAME=$(hostname)", "SERVER_NAME='a b'", "export SERVER_NAME=x"):
            self.path.write_text(f"TLS_CERT=/a\nTLS_KEY=/b\n{line}\n")
            with self.assertRaisesRegex(PublishError, "not a plain assignment"):
                ui_interface.read_config(self.path)

    def test_a_missing_value_is_refused(self) -> None:
        self.path.write_text("TLS_CERT=/a\nTLS_KEY=/b\n")
        with self.assertRaisesRegex(PublishError, "does not set SERVER_NAME"):
            ui_interface.read_config(self.path)


class Installing(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.served = self.root / "tls" / "ui.crt"
        self.served.parent.mkdir()
        self.config = self.root / "ui-tls.conf"
        self.config.write_text(
            f"TLS_CERT={self.served}\nTLS_KEY={self.root / 'tls' / 'ui.key'}\n"
            "SERVER_NAME=mgr.example.net\n"
        )
        self.calls: list[list[str]] = []
        self.handed: list[tuple[int, str]] = []
        self.answer = subprocess.CompletedProcess([], 0, "", "")

    def material(self, *names: str) -> Material:
        live = self.root / "live" / names[0]
        issue(live, names[0], sans=names)
        entry = RegisteredCertificate(
            certificate_id=names[0],
            source=CertificateSource(kind="acme", lineage=names[0]),
            clusters=(),
            receivers=(),
            interface=True,
        )
        return read_material(entry, live=self.root / "live")

    def runner(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        cert, key = Path(argv[argv.index("--cert") + 1]), Path(argv[argv.index("--key") + 1])
        self.handed.append((stat.S_IMODE(key.stat().st_mode), str(key.parent)))
        if self.answer.returncode == 0:
            shutil.copyfile(cert, self.served)
        return self.answer

    def install(self, material: Material) -> bool:
        return ui_interface.install(
            material,
            config_path=self.config,
            command=Path("/usr/local/sbin/haproxy-ui-tls"),
            run=self.runner,
        )

    def test_it_is_installed_once_and_then_left_alone(self) -> None:
        material = self.material("mgr.example.net")

        self.assertTrue(self.install(material))
        self.assertFalse(self.install(material))

        self.assertEqual(len(self.calls), 1)
        argv = self.calls[0]
        self.assertEqual(
            argv[:4], ["/usr/local/sbin/haproxy-ui-tls", "--config", str(self.config), "install"]
        )
        mode, handed_from = self.handed[0]
        self.assertEqual(mode, 0o600)
        self.assertFalse(Path(handed_from).exists())

    def test_a_wildcard_serves_the_name(self) -> None:
        self.assertTrue(self.install(self.material("wild.example.net", "*.example.net")))

    def test_a_certificate_for_another_name_never_reaches_the_command(self) -> None:
        material = self.material("lb-01.example.net")

        with self.assertRaises(PublishError) as caught:
            self.install(material)

        self.assertEqual(caught.exception.code, "name_mismatch")
        self.assertIn("mgr.example.net", str(caught.exception))
        self.assertEqual(self.calls, [])

    def test_the_command_s_refusal_is_the_reason_given(self) -> None:
        self.answer = subprocess.CompletedProcess(
            [],
            1,
            "",
            "  nginx: test failed\nERROR: nginx rejected the new pair; the previous one has been restored\n",
        )

        with self.assertRaises(PublishError) as caught:
            self.install(self.material("mgr.example.net"))

        self.assertEqual(caught.exception.code, "install_failed")
        self.assertIn("previous one has been restored", str(caught.exception))
        self.assertFalse(Path(self.handed[0][1]).exists())


class ThePublisher(Fixture):
    def entries(self) -> dict[str, dict[str, Any]]:
        issue(self.live / "mgr.example.net", "mgr.example.net", sans=("mgr.example.net",))
        return self.keeper() | {"mgr.example.net": {"source": {"kind": "acme"}, "interface": True}}

    def test_the_entry_goes_to_the_installer_and_nowhere_else(self) -> None:
        policy = self.write_config(self.entries())
        handed: list[str] = []

        def installer(material: Material) -> bool:
            handed.append(material.certificate_id)
            return True

        report = self.run_publish(policy, installer=installer)

        self.assertEqual(handed, ["mgr.example.net"])
        by_id = {entry.certificate_id: entry for entry in report.certificates}
        self.assertEqual(by_id["mgr.example.net"].status, "published")
        self.assertEqual(
            [t.as_dict() for t in by_id["mgr.example.net"].targets],
            [{"kind": "interface", "name": "interface", "changed": True}],
        )
        self.assertFalse((self.dist / "mgr.example.net.pem").exists())
        self.assertEqual(report.changed_clusters, ("alpha",))

    def test_without_an_installer_it_is_skipped_and_said_so(self) -> None:
        policy = self.write_config(self.entries())

        report = self.run_publish(policy)

        entry = next(e for e in report.certificates if e.certificate_id == "mgr.example.net")
        self.assertEqual(entry.status, "skipped")
        self.assertEqual(entry.error and entry.error[0], "installer_unavailable")

    def test_an_installer_s_refusal_fails_that_certificate_only(self) -> None:
        policy = self.write_config(self.entries())

        def installer(material: Material) -> bool:
            raise PublishError("name_mismatch", "not this name")

        report = self.run_publish(policy, installer=installer)

        self.assertEqual(self.status(report, "mgr.example.net"), "failed")
        self.assertEqual(self.status(report, "keeper.example"), "published")

    def test_the_command_reports_the_interface_target(self) -> None:
        policy = self.write_config(self.entries())

        code, out, _ = self.run_command(policy, "--json", installer=lambda material: True)

        self.assertEqual(code, 0)
        by_id = {c["id"]: c for c in json.loads(out)["result"]["certificates"]}
        self.assertEqual(by_id["mgr.example.net"]["targets"][0]["kind"], "interface")


if __name__ == "__main__":
    unittest.main()


class TheSocketHelper(Fixture):
    """D3: an ID in, the marked entry installed, the contract's document out."""

    def setUp(self) -> None:
        super().setUp()
        issue(self.live / "mgr.example.net", "mgr.example.net", sans=("mgr.example.net",))
        issue(self.live / "example.com", "example.com", sans=("example.com",))
        self.policy = self.write_config(
            self.keeper()
            | {
                "mgr.example.net": {"source": {"kind": "acme"}, "interface": True},
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        self.handed: list[str] = []

    def ask(self, parameters: dict[str, Any], installer: Any = None) -> tuple[int, str, str]:
        def fake(material: Material) -> bool:
            self.handed.append(material.certificate_id)
            return True

        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "ui_tls_install",
                "cluster": None,
                "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "parameters": parameters,
            }
        ).encode()
        out, err = io.StringIO(), io.StringIO()
        code = ui_tls_helper.main(
            [],
            policy_path=self.policy,
            input_stream=io.BytesIO(request),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            live=self.live,
            store=self.store,
            installer=installer or fake,
        )
        return code, out.getvalue(), err.getvalue()

    def test_the_marked_entry_is_installed_and_described(self) -> None:
        code, out, _ = self.ask({"id": "mgr.example.net"})

        self.assertEqual(code, 0)
        document = assert_contract("haproxy-ui-tls-install", out)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["id"], "mgr.example.net")
        self.assertTrue(document["result"]["changed"])
        self.assertEqual(self.handed, ["mgr.example.net"])
        self.assertNotIn("PRIVATE", out)

    def test_any_other_certificate_is_refused_before_anything_runs(self) -> None:
        for certificate_id, wanted in (
            ("example.com", "bad_input"),
            ("nobody.example.org", "unknown_certificate"),
            ("../etc/passwd", "bad_input"),
        ):
            code, out, _ = self.ask({"id": certificate_id})
            document = assert_contract("haproxy-ui-tls-install", out)
            self.assertNotEqual(code, 0)
            self.assertEqual(document["error"]["code"], wanted, certificate_id)
        self.assertEqual(self.handed, [])

    def test_nothing_but_the_id_is_taken(self) -> None:
        code, out, err = self.ask({"id": "mgr.example.net", "cert": "/tmp/x.pem"})

        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("cert", err)
        self.assertEqual(self.handed, [])

    def test_the_installer_s_refusal_is_the_answer(self) -> None:
        def refusing(material: Material) -> bool:
            raise PublishError("name_mismatch", "the certificate does not name mgr.example.net")

        code, out, _ = self.ask({"id": "mgr.example.net"}, installer=refusing)

        document = assert_contract("haproxy-ui-tls-install", out)
        self.assertEqual(code, 64)
        self.assertEqual(document["error"]["code"], "name_mismatch")


class TheSocketClient(unittest.TestCase):
    """The sandboxed side reads the helper's answer back into the publisher's terms."""

    def material(self) -> Material:
        return Material(
            certificate_id="mgr.example.net",
            fullchain=b"",
            privkey=b"",
            facts=mock.Mock(),
            fingerprint="a" * 64,
        )

    def answer(self, document: dict[str, Any] | Exception) -> Any:
        installer = ui_interface.socket_installer(path="/nonexistent/ui-tls.sock")
        side = document if isinstance(document, Exception) else None
        value = None if isinstance(document, Exception) else json.dumps(document)
        with mock.patch.object(helper_socket, "ask", side_effect=side, return_value=value) as ask:
            try:
                return installer(self.material())
            finally:
                request = ask.call_args.args[0]
                self.assertEqual(request["parameters"], {"id": "mgr.example.net"})

    def test_done_says_whether_it_changed(self) -> None:
        result = {"id": "mgr.example.net", "changed": False, "fingerprint_sha256": "a" * 64}
        self.assertFalse(self.answer({"outcome": "done", "result": result}))

    def test_a_different_leaf_installed_is_not_claimed(self) -> None:
        result = {"id": "mgr.example.net", "changed": True, "fingerprint_sha256": "b" * 64}
        with self.assertRaises(PublishError) as caught:
            self.answer({"outcome": "done", "result": result})
        self.assertEqual(caught.exception.code, "material_changed")

    def test_a_refusal_keeps_the_helper_s_code(self) -> None:
        with self.assertRaises(PublishError) as caught:
            self.answer({"outcome": "failed", "error": {"code": "name_mismatch", "message": "no"}})
        self.assertEqual(caught.exception.code, "name_mismatch")

    def test_no_service_and_a_silent_one_read_differently(self) -> None:
        with self.assertRaises(PublishError) as caught:
            self.answer(helper_socket.HelperUnavailable("nothing listens."))
        self.assertEqual(caught.exception.code, "dependency_unavailable")
        self.assertIn("haproxy-ui-tls-helper.socket", str(caught.exception))

        with self.assertRaises(PublishError) as caught:
            self.answer(helper_socket.HelperSilent("it stopped answering."))
        self.assertEqual(caught.exception.code, "helper_silent")
        self.assertIn("may still have installed", str(caught.exception))


class WhatIsServed(unittest.TestCase):
    """The listing's word on the pair nginx serves, self-signed or not."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config = self.root / "ui-tls.conf"
        self.config.write_text(
            f"TLS_CERT={self.root / 'live' / 'mgr.example.net' / 'fullchain.pem'}\n"
            f"TLS_KEY={self.root / 'live' / 'mgr.example.net' / 'privkey.pem'}\n"
            "SERVER_NAME=mgr.example.net\n"
        )

    def test_the_installer_s_self_signed_pair_says_so(self) -> None:
        issue(self.root / "live" / "mgr.example.net", "mgr.example.net", sans=("mgr.example.net",))

        served = ui_interface.served_description(self.config)

        assert served is not None
        self.assertTrue(served["self_signed"])
        self.assertEqual(served["server_name"], "mgr.example.net")
        self.assertEqual(served["sans"], ["mgr.example.net"])
        self.assertRegex(str(served["fingerprint_sha256"]), r"^[0-9a-f]{64}$")

    def test_a_certificate_a_ca_signed_is_not_self_signed(self) -> None:
        from tests.test_cert_import import Pki

        pki = Pki(self.root / "pki", names=("mgr.example.net",))
        target = self.root / "live" / "mgr.example.net"
        target.mkdir(parents=True)
        (target / "fullchain.pem").write_text(pki.leaf.read_text() + pki.intermediate.read_text())

        served = ui_interface.served_description(self.config)

        assert served is not None
        self.assertFalse(served["self_signed"])
        self.assertIn("Test Issuing CA", str(served["issuer"]))

    def test_nothing_readable_is_none_not_an_error(self) -> None:
        self.assertIsNone(ui_interface.served_description(self.config))
        self.assertIsNone(ui_interface.served_description(self.root / "absent.conf"))
