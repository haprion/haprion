"""The Redfish client against a BMC of our own making (B526, B536).

A real TLS server on localhost speaking the calls the client makes: a session,
the manager, Supermicro's upload action and the reset. A reset swaps the
certificate the server presents for the one uploaded - unless told to keep the
old, or to be away for a few questions first - so the install is measured the
way it is in the field: by what the socket serves afterwards.
"""

from __future__ import annotations

import json
import re
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from haprion import bmc_redfish
from haprion.bmc_redfish import BmcError
from haprion.cert_inventory import OPENSSL
from tests.spawned import free_port

USER, PASSWORD = "svc-app", "-".join(("not", "the", "real", "one"))
WRONG = "-".join(("not", "this", "one"))


def make_pair(directory: Path, name: str) -> tuple[str, str]:
    key, cert = directory / f"{name}.key", directory / f"{name}.pem"
    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-subj",
            f"/CN={name}.example",
        ],
        check=True,
        capture_output=True,
    )
    return cert.read_text(), key.read_text()


class FakeBmc:
    """What the client is measured against; every request is kept."""

    def __init__(self, directory: Path, cert: str, key: str) -> None:
        self.directory = directory
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.sessions: set[str] = set()
        self.deleted: list[str] = []
        self.uploaded: dict[str, bytes] = {}
        self.upload_answer: tuple[int, dict[str, Any]] = (
            200,
            {"Success": {"Message": "SSL certificate and private key were successfully uploaded"}},
        )
        self.keep_old_after_reset = False
        self.may_upload: bool | None = True
        self.away_after_reset = 0
        self.away = 0
        self.reset_body: dict[str, Any] | None = None
        self.context = self._context(cert, key)
        self.port = free_port()
        bmc = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                pass

            def _answer(
                self, status: int, document: Any, headers: dict[str, str] | None = None
            ) -> None:
                body = json.dumps(document).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def _read(self) -> bytes:
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def _authorised(self) -> bool:
                if self.headers.get("X-Auth-Token") in bmc.sessions:
                    return True
                self._answer(401, {"error": {"message": "no session"}})
                return False

            def do_POST(self) -> None:
                body = self._read()
                bmc.requests.append(("POST", self.path, dict(self.headers), body))
                if self.path == bmc_redfish.SESSIONS:
                    sent = json.loads(body)
                    if (sent.get("UserName"), sent.get("Password")) != (USER, PASSWORD):
                        self._answer(401, {"error": {"message": "bad credentials"}})
                        return
                    token = f"token-{len(bmc.sessions)}"
                    bmc.sessions.add(token)
                    self._answer(
                        201,
                        {},
                        {"X-Auth-Token": token, "Location": f"{bmc_redfish.SESSIONS}/{token}"},
                    )
                elif not self._authorised():
                    return
                elif self.path == bmc_redfish.UPLOAD and b"filename=" not in body:
                    #
                    # An upload with no file, as measured on X13 (26-11-26).
                    #
                    if bmc.may_upload is None:
                        self._answer(500, {"error": {"code": "Base.1.10.InternalError"}})
                    elif bmc.may_upload:
                        self._answer(400, {"error": {"code": "SMC.1.0.OemSslcertMissingItem"}})
                    else:
                        self._answer(403, {"error": {"code": "Base.1.10.InsufficientPrivilege"}})
                elif self.path == bmc_redfish.UPLOAD:
                    bmc.uploaded = parts(self.headers["Content-Type"], body)
                    status, document = bmc.upload_answer
                    self._answer(status, document)
                elif self.path == "/redfish/v1/Managers/1/Actions/Manager.Reset":
                    bmc.reset_body = json.loads(body)
                    self._answer(200, {})
                    bmc.restart()
                else:
                    self._answer(404, {"error": {"message": "no such action"}})

            def do_GET(self) -> None:
                bmc.requests.append(("GET", self.path, dict(self.headers), b""))
                if not self._authorised():
                    return
                if self.path == bmc_redfish.MANAGERS:
                    self._answer(200, {"Members": [{"@odata.id": "/redfish/v1/Managers/1"}]})
                elif self.path == "/redfish/v1/Managers/1":
                    self._answer(200, {"Model": "X13SCL-IF", "FirmwareVersion": "01.09.06"})
                else:
                    self._answer(404, {"error": {"message": "no such resource"}})

            def do_DELETE(self) -> None:
                bmc.requests.append(("DELETE", self.path, dict(self.headers), b""))
                token = self.path.rsplit("/", 1)[-1]
                bmc.deleted.append(token)
                bmc.sessions.discard(token)
                self._answer(200, {})

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self) -> tuple[Any, Any]:
                raw, address = self.socket.accept()
                if bmc.away > 0:
                    bmc.away -= 1
                    raw.close()
                    raise OSError("away")
                return bmc.context.wrap_socket(raw, server_side=True), address

            def handle_error(self, request: Any, client_address: Any) -> None:
                pass

        self.server = Server(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _context(self, cert: str, key: str) -> ssl.SSLContext:
        cert_path = self.directory / "serving.pem"
        key_path = self.directory / "serving.key"
        cert_path.write_text(cert)
        key_path.write_text(key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        return context

    def restart(self) -> None:
        self.away = self.away_after_reset
        if not self.keep_old_after_reset:
            self.context = self._context(
                self.uploaded["cert_file"].decode(), self.uploaded["key_file"].decode()
            )

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def parts(content_type: str, body: bytes) -> dict[str, bytes]:
    boundary = re.search(r"boundary=(\S+)", content_type)
    assert boundary is not None
    found: dict[str, bytes] = {}
    for part in body.split(b"--" + boundary.group(1).encode()):
        if b"\r\n\r\n" not in part:
            continue
        head, content = part.split(b"\r\n\r\n", 1)
        name = re.search(rb'name="([^"]+)"', head)
        filename = re.search(rb'filename="([^"]+)"', head)
        if name is not None:
            found[name.group(1).decode()] = content.rsplit(b"\r\n", 1)[0]
            if filename is not None:
                found[name.group(1).decode() + ".filename"] = filename.group(1)
    return found


class BmcCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.old_cert, self.old_key = make_pair(self.directory, "old")
        self.new_cert, self.new_key = make_pair(self.directory, "new")
        self.chain_cert, _ = make_pair(self.directory, "issuer")
        self.bmc = FakeBmc(self.directory, self.old_cert, self.old_key)
        self.addCleanup(self.bmc.stop)
        self.old = bmc_redfish.pem_fingerprint(self.old_cert)
        self.new = bmc_redfish.pem_fingerprint(self.new_cert)
        self.clock = 0.0

    def tick(self, seconds: float) -> None:
        self.clock += seconds

    def install(self, **overrides: Any) -> bmc_redfish.Installed:
        arguments: dict[str, Any] = {
            "trusted": {self.old},
            "username": USER,
            "password": PASSWORD,
            "fullchain": self.new_cert + self.chain_cert,
            "key_pem": self.new_key,
            "wait": 30.0,
            "interval": 10.0,
            "clock": lambda: self.clock,
            "sleep": self.tick,
        }
        arguments.update(overrides)
        return bmc_redfish.install("127.0.0.1", self.bmc.port, **arguments)


class Installing(BmcCase):
    def test_the_leaf_and_key_are_uploaded_the_bmc_restarted_and_the_socket_is_the_receipt(
        self,
    ) -> None:
        installed = self.install()

        self.assertEqual(installed.fingerprint_sha256, self.new)
        self.assertEqual(
            (installed.firmware.model, installed.firmware.version), ("X13SCL-IF", "01.09.06")
        )
        self.assertIn("successfully uploaded", installed.upload_said)
        uploaded = self.bmc.uploaded
        self.assertEqual(uploaded["cert_file"].decode().count("BEGIN CERTIFICATE"), 1)
        self.assertEqual(bmc_redfish.pem_fingerprint(uploaded["cert_file"].decode()), self.new)
        self.assertEqual(uploaded["key_file"].decode(), self.new_key)
        self.assertEqual(
            (uploaded["cert_file.filename"], uploaded["key_file.filename"]),
            (b"cert.pem", b"key.pem"),
        )
        self.assertEqual(self.bmc.reset_body, {"ResetType": "GracefulRestart"})
        self.assertEqual(
            bmc_redfish.served("127.0.0.1", self.bmc.port).fingerprint_sha256, self.new
        )
        self.assertEqual(self.bmc.deleted, [], "the restart ends the session")

    def test_a_bmc_away_while_it_restarts_is_asked_again(self) -> None:
        self.bmc.away_after_reset = 2

        self.assertEqual(self.install().fingerprint_sha256, self.new)
        self.assertEqual(self.clock, 20.0)

    def test_a_bmc_that_keeps_the_old_certificate_has_not_installed_it(self) -> None:
        self.bmc.keep_old_after_reset = True

        with self.assertRaises(BmcError) as failed:
            self.install()
        self.assertEqual(failed.exception.code, "not_served")
        self.assertIn(self.old, str(failed.exception))

    def test_an_upload_the_bmc_refuses_is_said_in_its_words_and_nothing_restarts(self) -> None:
        self.bmc.upload_answer = (
            400,
            {
                "error": {
                    "code": "Base.v1_10_3.GeneralError",
                    "@Message.ExtendedInfo": [{"Message": "SSL certificate validation failed."}],
                }
            },
        )
        with self.assertRaises(BmcError) as failed:
            self.install()
        self.assertEqual(failed.exception.code, "refused")
        self.assertIn("SSL certificate validation failed.", str(failed.exception))
        self.assertIsNone(self.bmc.reset_body)
        self.assertEqual(self.bmc.deleted, ["token-0"])


class Trust(BmcCase):
    def test_a_bmc_serving_an_unconfirmed_certificate_is_sent_nothing(self) -> None:
        with self.assertRaises(BmcError) as failed:
            self.install(trusted={"0" * 64})
        self.assertEqual(failed.exception.code, "untrusted")
        self.assertIn(self.old, str(failed.exception))
        self.assertEqual(self.bmc.requests, [])

    def test_an_account_the_bmc_refuses_is_said_as_such(self) -> None:
        with self.assertRaises(BmcError) as failed:
            self.install(password=WRONG)
        self.assertEqual(failed.exception.code, "login_refused")
        self.assertEqual(self.bmc.uploaded, {})


class Reading(BmcCase):
    def test_served_reads_the_handshake_and_sends_nothing(self) -> None:
        now = bmc_redfish.served("127.0.0.1", self.bmc.port)
        self.assertEqual(now.fingerprint_sha256, self.old)
        self.assertEqual(self.bmc.requests, [])

    def test_nothing_listening_is_unreachable_and_quick(self) -> None:
        with self.assertRaises(BmcError) as failed:
            bmc_redfish.served("127.0.0.1", free_port(), timeout=2.0)
        self.assertEqual(failed.exception.code, "unreachable")

    def test_check_shows_what_is_served_and_that_the_account_is_let_in(self) -> None:
        checked = bmc_redfish.check("127.0.0.1", self.bmc.port, username=USER, password=PASSWORD)
        self.assertEqual(checked.served.fingerprint_sha256, self.old)
        self.assertEqual(checked.firmware.version, "01.09.06")
        self.assertIs(checked.may_upload, True)
        self.assertEqual(self.bmc.deleted, ["token-0"])
        self.assertEqual(self.bmc.uploaded, {})
        with self.assertRaises(BmcError) as failed:
            bmc_redfish.check("127.0.0.1", self.bmc.port, username=USER, password=WRONG)
        self.assertEqual(failed.exception.code, "login_refused")

    def test_check_says_an_account_that_may_not_upload_before_anything_is_saved(self) -> None:
        """26-11-26: an Operator signs in, and is refused the upload with 403."""

        for allowed, said in ((False, False), (None, None)):
            with self.subTest(allowed=allowed):
                self.bmc.may_upload = allowed
                checked = bmc_redfish.check(
                    "127.0.0.1", self.bmc.port, username=USER, password=PASSWORD
                )
                self.assertIs(checked.may_upload, said)
        self.assertEqual(self.bmc.uploaded, {})

    def test_a_path_the_bmc_names_is_held_to_its_own_tree(self) -> None:
        for value, held in (
            ("/redfish/v1/Managers/1", "/redfish/v1/Managers/1"),
            (
                "https://192.0.2.7/redfish/v1/SessionService/Sessions/9",
                "/redfish/v1/SessionService/Sessions/9",
            ),
            ("/redfish/v1/../../etc", None),
            ("/somewhere/else", None),
            (None, None),
        ):
            with self.subTest(value=value):
                self.assertEqual(bmc_redfish._path(value), held)


if __name__ == "__main__":
    unittest.main()
