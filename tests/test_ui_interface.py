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

import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from haproxy_mgmt import ui_interface
from haproxy_mgmt.cert_publish import Material, PublishError, read_material
from haproxy_mgmt.config import CertificateSource, RegisteredCertificate
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
