"""NDES servers confirmed from their CA, and written into the policy's ndes block (B383, B385)."""

from __future__ import annotations

import fcntl
import hashlib
import http.server
import io
import json
import multiprocessing
import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import uuid
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import exit_codes, helper_socket, ndes_server_socket, ndes_servers, safe_yaml
from haprion.cli import ndes_server, ndes_server_helper
from haprion.config import SYSTEM_TRUST, ConfigError, load_policy
from tests.contract_schema import assert_contract
from tests.test_cert_import import OPENSSL, Pki

ENDPOINT = "https://ca.example.com/certsrv/mscep/mscep.dll"
OTHER = "https://ca2.example.com/certsrv/mscep/mscep.dll"
POLICY = """\
# Runtime policy, rendered by the installation.
schema_version: 1
cluster_file: {root}/clusters.yaml
config_root: {root}/config
publish_root: {root}/publish
validation_certs_root: {root}/validation
acme:
  dns_profiles:
    directory: {root}/dns-profiles
    private_keys:
    - {root}/keys/0123456789abcdef.key
"""


class Answer:
    """GetCACert as an AD CS NDES answers it: the CAs and the RA certificate, PKCS#7 DER."""

    def __init__(self, root: Path) -> None:
        # The intermediate plays the issuing CA, the leaf its RA certificate.
        self.pki = Pki(root / "pki", names=("ndes-ra.example.com",))
        bundle = root / "bundle.pem"
        bundle.write_text(
            self.pki.intermediate.read_text()
            + self.pki.root.read_text()
            + self.pki.leaf.read_text()
        )
        self.der = subprocess.run(
            [OPENSSL, "crl2pkcs7", "-nocrl", "-certfile", str(bundle), "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout
        self.asked: list[str] = []
        self.trusted: list[Path] = []

    def __call__(self, endpoint: str, trust: Path) -> bytes:
        self.asked.append(endpoint)
        self.trusted.append(trust)
        return self.der

    def digest(self, path: Path, algorithm: str) -> str:
        """The certificate's DER digest as openssl's own `dgst` gives it."""

        der = subprocess.run(
            [OPENSSL, "x509", "-in", str(path), "-outform", "DER"], capture_output=True, check=True
        ).stdout
        said = subprocess.run(
            [OPENSSL, "dgst", algorithm, "-r"], input=der, capture_output=True, check=True
        ).stdout
        return said.split()[0].decode()

    def sha256(self, path: Path) -> str:
        der = subprocess.run(
            [OPENSSL, "x509", "-in", str(path), "-outform", "DER"], capture_output=True, check=True
        ).stdout
        return hashlib.sha256(der).hexdigest()


class Served:
    """A local HTTP server whose one handler answers as a test says (no NDES server is asked)."""

    def __init__(self, answer: Any) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                answer(self)

            def log_message(self, *_: Any) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/certsrv/mscep/mscep.dll"

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class ServedOverTls(Served):
    """The same server over HTTPS, with the certificate chain a test gives it."""

    def __init__(self, chain: Path, key: Path) -> None:
        def answer(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "2")
            handler.end_headers()
            handler.wfile.write(b"ca")

        super().__init__(answer)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)

    def __enter__(self) -> str:
        self.thread.start()
        return f"https://localhost:{self.server.server_address[1]}/certsrv/mscep/mscep.dll"


class TheFetch(unittest.TestCase):
    """`get_ca_cert` against a local server, through urllib as it runs."""

    def fetch(self, answer: Any) -> ndes_servers.NdesServerError:
        with Served(answer) as url, self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.get_ca_cert(url)
        return caught.exception

    def test_a_redirect_is_said_not_followed(self) -> None:
        """Review 2026-10-29, B07: a redirect to http was followed, and the CA read in the clear."""

        asked: list[str] = []

        def answer(handler: http.server.BaseHTTPRequestHandler) -> None:
            asked.append(handler.path)
            if handler.path.startswith("/elsewhere"):
                handler.send_response(200)
                handler.send_header("Content-Length", "2")
                handler.end_headers()
                handler.wfile.write(b"ca")
                return
            handler.send_response(302)
            handler.send_header("Location", f"http://{handler.headers['Host']}/elsewhere")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        refused = self.fetch(answer)
        self.assertEqual(refused.code, "redirected")
        self.assertRegex(str(refused), r"redirected to http://127\.0\.0\.1:\d+/elsewhere;")
        self.assertEqual(len(asked), 1)

    def test_a_proxy_in_the_environment_is_not_taken(self) -> None:
        def answer(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "2")
            handler.end_headers()
            handler.wfile.write(b"ca")

        unused = "http://192.0.2.1:9"
        with (
            mock.patch.dict(
                os.environ,
                {"http_proxy": unused, "https_proxy": unused, "HTTP_PROXY": unused},
            ),
            Served(answer) as url,
        ):
            self.assertEqual(ndes_servers.get_ca_cert(url), b"ca")

    def test_a_broken_answer_is_no_answer(self) -> None:
        """Review 2026-10-29, C01: a body cut short or a status line that is none escaped raw."""

        def cut(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "100")
            handler.end_headers()
            handler.wfile.write(b"short")
            handler.close_connection = True

        def garbled(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.wfile.write(b"not a status line\r\n\r\n")
            handler.close_connection = True

        for answer in (cut, garbled):
            with self.subTest(answer=answer.__name__):
                refused = self.fetch(answer)
                self.assertEqual(refused.code, "unreachable")
                self.assertEqual(refused.exit_code, exit_codes.UNAVAILABLE)

    def test_a_server_that_answers_a_byte_at_a_time_is_given_up_on_in_time(self) -> None:
        """Review 2026-10-29, B08: the bound was per read, so a drip held the socket for all."""

        def drip(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "30")
            handler.end_headers()
            try:
                for _ in range(30):
                    handler.wfile.write(b"x")
                    handler.wfile.flush()
                    time.sleep(0.2)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the fetch gave up, as it should

        started = time.monotonic()
        with (
            mock.patch.object(ndes_servers, "TIMEOUT", 1.0),
            mock.patch.object(ndes_servers, "DEADLINE", 1.0),
        ):
            refused = self.fetch(drip)
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(refused.code, "unreachable")
        self.assertIn("longer than", str(refused))

    def test_an_error_answer_is_said_and_closed_on_the_wire(self) -> None:
        def answer(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(404)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        refused = self.fetch(answer)
        self.assertEqual(refused.code, "unreachable")
        self.assertIn("HTTP 404", str(refused))


class TheSocketClient(unittest.TestCase):
    def test_a_service_asked_and_then_silent_is_told_from_one_never_asked(self) -> None:
        """Review 2026-10-29 again: both were `unavailable`, and both left an `unknown` row."""

        for error, code in (
            (helper_socket.HelperUnavailable("not running"), "unavailable"),
            (helper_socket.HelperBusy("busy"), "unavailable"),
            (helper_socket.HelperSilent("did not answer"), "unanswered"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(helper_socket, "ask", side_effect=error),
                self.assertRaises(ndes_servers.NdesServerError) as caught,
            ):
                ndes_server_socket.ask("add", endpoint=ENDPOINT)
            self.assertEqual(caught.exception.code, code)


class TheHelperUnit(unittest.TestCase):
    def test_systemd_ends_the_helper_before_the_web_stops_waiting(self) -> None:
        """Review 2026-10-29, B08: no RuntimeMaxSec, and a drip held the socket past the web."""

        unit = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haprion-ndes-server-helper@.service.example"
        ).read_text()
        self.assertIn("Type=exec", unit)
        seconds = int(unit.split("\nRuntimeMaxSec=", 1)[1].split("\n", 1)[0])
        self.assertLess(seconds, ndes_server_socket.TIMEOUT_SECONDS)
        self.assertGreater(seconds, ndes_servers.DEADLINE + ndes_servers.TIMEOUT)


def pkcs7(*pems: Path) -> bytes:
    """GetCACert's answer: these certificates, PKCS#7 DER."""

    with tempfile.TemporaryDirectory() as raw:
        bundle = Path(raw) / "bundle.pem"
        bundle.write_text("".join(each.read_text() for each in pems))
        return subprocess.run(
            [OPENSSL, "crl2pkcs7", "-nocrl", "-certfile", str(bundle), "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout


class AChainWithoutItsRoot(unittest.TestCase):
    """Review 2026-10-29, B09 (B388): a chain short of its root was confirmed, and failed at issue."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.answer = Answer(self.root)
        pki = self.answer.pki
        self.short = pkcs7(pki.intermediate, pki.leaf)
        other = Pki(self.root / "other", names=("other.example.com",))
        self.store = self.root / "store.pem"
        self.store.write_text(other.root.read_text() + pki.root.read_text())

    def test_a_chain_with_its_root_is_not_completed(self) -> None:
        found = ndes_servers.authorities(
            ENDPOINT, fetch=self.answer, trust=self.root / "no-store.pem"
        )
        self.assertEqual([a.from_store for a in found], [False, False])

    def test_the_root_is_taken_from_the_store_and_confirmed_with_the_rest(self) -> None:
        found = ndes_servers.authorities(ENDPOINT, fetch=lambda *_: self.short, trust=self.store)
        root = self.answer.sha256(self.answer.pki.root)
        self.assertEqual(
            [(a.subject, a.from_store) for a in found],
            [("CN=Test Issuing CA", False), ("CN=Test Root", True)],
        )
        self.assertEqual(found[1].sha256, root)
        self.assertTrue(found[1].summary()["from_store"])

    def test_a_root_the_store_does_not_have_is_refused(self) -> None:
        self.store.write_text(Pki(self.root / "third", names=("x.example.com",)).root.read_text())
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.authorities(ENDPOINT, fetch=lambda *_: self.short, trust=self.store)
        self.assertEqual(caught.exception.code, "no_root")
        self.assertIn("gives no root CA", str(caught.exception))
        # The store it was completed from, not always the manager's (round 2, cosmetic).
        self.assertIn(f"none in the server's tls_ca {self.store} issues", str(caught.exception))

    def test_a_name_alone_does_not_make_a_root(self) -> None:
        # Another CA under the same name, not the one that signed the chain.
        (self.root / "impostor").mkdir()
        impostor = Pki(self.root / "impostor" / "pki", names=("x.example.com",))
        self.store.write_text(impostor.root.read_text())
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.authorities(ENDPOINT, fetch=lambda *_: self.short, trust=self.store)
        self.assertEqual(caught.exception.code, "no_root")

    def test_a_chain_that_does_not_verify_is_refused_as_issuance_would(self) -> None:
        """Review 2026-10-29 again, BB04: the server's own chain was judged by its names.

        A root renewed with a new key keeps its name, and a CA past its
        date keeps both; each was confirmed and every issue failed after.
        """

        pki = self.answer.pki
        (self.root / "impostor").mkdir()
        impostor = Pki(self.root / "impostor" / "pki", names=("x.example.com",))
        expired = pki.directory / "expired-issuing.pem"
        subprocess.run(
            [
                OPENSSL,
                "x509",
                "-req",
                "-in",
                str(pki.directory / "Test Issuing CA.csr"),
                "-CA",
                str(pki.root),
                "-CAkey",
                str(pki.root_key),
                "-not_before",
                "20200101000000Z",
                "-not_after",
                "20200201000000Z",
                "-extfile",
                str(pki.directory / "Test Issuing CA.ext"),
                "-out",
                str(expired),
            ],
            capture_output=True,
            check=True,
        )
        for name, answer in (
            (
                "a root of the same name and another key",
                pkcs7(pki.intermediate, impostor.root, pki.leaf),
            ),
            ("an issuing CA past its date", pkcs7(expired, pki.root, pki.leaf)),
        ):
            with (
                self.subTest(name),
                self.assertRaises(ndes_servers.NdesServerError) as caught,
            ):
                ndes_servers.authorities(
                    ENDPOINT, fetch=lambda *_, given=answer: given, trust=self.store
                )
            self.assertEqual(caught.exception.code, "bad_chain")
            self.assertIn("do not verify as a chain", str(caught.exception))
            self.assertIn("CN=Test Issuing CA", str(caught.exception))


class EcPki:
    """Small EC PKIs, each CA built to one shape, for the confirmation against issuance."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.serial = 0

    def make(
        self,
        name: str,
        extensions: str,
        issuer: tuple[Path, Path] | None = None,
        *,
        dates: tuple[str, str] | None = None,
    ) -> tuple[Path, Path]:
        self.serial += 1
        key, certificate = self.root / f"{name}.key", self.root / f"{name}.pem"
        config, request = self.root / f"{name}.ext", self.root / f"{name}.csr"
        run = [OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
        subprocess.run([*run, "-out", str(key)], capture_output=True, check=True)
        config.write_text(
            "[v]\n"
            + extensions
            + "\nsubjectKeyIdentifier=hash\n"
            + ("authorityKeyIdentifier=keyid\n" if issuer else "")
        )
        subprocess.run(
            [
                OPENSSL,
                "req",
                "-new",
                "-key",
                str(key),
                "-subj",
                f"/CN={name}",
                "-out",
                str(request),
            ],
            capture_output=True,
            check=True,
        )
        signing = (
            ["-CA", str(issuer[0]), "-CAkey", str(issuer[1])] if issuer else ["-key", str(key)]
        )
        subprocess.run(
            [OPENSSL, "x509", "-req", "-in", str(request), "-out", str(certificate)]
            + ["-extfile", str(config), "-extensions", "v", "-days", "3650"]
            + ["-set_serial", str(self.serial), *signing]
            + (["-not_before", dates[0], "-not_after", dates[1]] if dates else []),
            capture_output=True,
            check=True,
        )
        return certificate, key


CA = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign"
# An RA certificate is no server's: its own usage is never one issuance asks for.
RA = "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth"


class TheConfirmationChecksWhatIssuanceChecks(unittest.TestCase):
    """Review 2026-10-29, round 2, BBB04: issuance is the answer key.

    The check judged each CA certificate as the end of a chain, while
    issuance verifies a server certificate under the issuing CA. A
    constraint that bites only below the issuing CA was confirmed and failed
    every issue; a CA beside the path refused a server issuance would use.
    Each shape is put to both, and they must agree.
    """

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def issued(self, pki: EcPki, issuing: tuple[Path, Path], found: Any) -> bool:
        """What `ndes.validate_certificate` does with a server certificate from the issuing CA."""

        from haprion import ndes
        from haprion.cert_import import assemble

        leaf, key = pki.make(
            "web.example.com",
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:web.example.com",
            issuing,
        )
        directory = pki.root / "staging"
        directory.mkdir()
        saved = "".join(authority.pem for authority in found)
        (directory / "issuing-ca.pem").write_text(saved)
        material = assemble(
            [leaf.read_text(), *[authority.pem for authority in found]], [key.read_text()]
        )
        try:
            ndes.validate_certificate(material, ["web.example.com"], directory)
        except ndes.NdesError as exc:
            self.assertEqual(exc.code, "untrusted_certificate", str(exc))
            return False
        return True

    def test_the_confirmation_and_issuance_agree(self) -> None:
        old = ("20200101000000Z", "20210101000000Z")
        names = (
            "a root that issues, as AD CS's one level",
            "a root with pathlen:0 over the issuing CA",
            "an issuing CA for clients only",
            "an issuing CA for any purpose by name",
            "an issuing CA for servers and clients",
            "a CA past its date beside the path",
        )
        # name: (the confirmation's refusal or None, whether issuance issues)
        shapes: dict[str, tuple[str | None, bool]] = {}
        for number, name in enumerate(names):
            pki = EcPki(self.root / str(number))
            pki.root.mkdir()
            if number == 0:
                root = pki.make("Root", CA)
                issuing, chain = root, [root]
            else:
                root = pki.make(
                    "Root", CA.replace("CA:TRUE", "CA:TRUE,pathlen:0") if number == 1 else CA
                )
                eku = {
                    2: "\nextendedKeyUsage=clientAuth",
                    3: "\nextendedKeyUsage=anyExtendedKeyUsage",
                    4: "\nextendedKeyUsage=serverAuth,clientAuth",
                }.get(number, "")
                issuing = pki.make("Issuing", CA + eku, root)
                chain = [issuing, root]
                if number == 5:
                    chain.append(pki.make("Old Issuing", CA, root, dates=old))
            ra = pki.make("RA", RA, issuing)
            answer = pkcs7(*[each[0] for each in chain], ra[0])
            refused: str | None = None
            try:
                found = ndes_servers.authorities(
                    ENDPOINT, fetch=lambda *_, given=answer: given, trust=self.root / "none.pem"
                )
            except ndes_servers.NdesServerError as exc:
                self.assertEqual(exc.code, "bad_chain", str(exc))
                refused = str(exc)
                found = tuple(
                    ndes_servers.Authority(
                        subject="", sha256="", sha1="", pem=each[0].read_text(), issues_ra=False
                    )
                    for each in chain
                )
            shapes[name] = (refused, self.issued(pki, issuing, found))
        for name, (refused, issued) in shapes.items():
            with self.subTest(name):
                self.assertEqual(refused is None, issued, refused)
        self.assertEqual(
            [name for name, (_refused, issued) in shapes.items() if issued],
            [
                "a root that issues, as AD CS's one level",
                "an issuing CA for servers and clients",
                "a CA past its date beside the path",
            ],
        )
        said = {name: refused for name, (refused, _issued) in shapes.items() if refused}
        self.assertIn(
            "CN=Root: path length constraint exceeded",
            said["a root with pathlen:0 over the issuing CA"],
        )
        self.assertIn(
            "CN=Issuing: unsuitable certificate purpose", said["an issuing CA for clients only"]
        )


class TheNamesAreCheckedAsIssuanceChecksThem(unittest.TestCase):
    """Review 2026-10-29, round 3, B3-04: a name outside the CA's constraints.

    The confirmation cannot judge names - a server is confirmed before any
    certificate is asked for - so the enrollment asks before the request is
    sent, and issuance stays the answer key: for each shape, the check
    before and the verification after must agree, and both say it is the
    names, not a CA renewed.
    """

    def test_the_check_before_the_request_and_issuance_agree(self) -> None:
        from haprion import ndes
        from haprion.cert_import import assemble

        permitted_org = "\nnameConstraints=critical,permitted;DNS:example.org"
        permitted_com = "\nnameConstraints=critical,permitted;DNS:example.com"
        excluded_com = "\nnameConstraints=critical,excluded;DNS:example.com"
        # name: (root's constraint, issuing CA's, the names, whether issuance issues)
        shapes = {
            "no constraints": ("", "", ("web.example.com",), True),
            "the issuing CA's cover the name": ("", permitted_com, ("web.example.com",), True),
            "the issuing CA's do not": ("", permitted_org, ("web.example.com",), False),
            "the root's do not": (permitted_org, "", ("web.example.com",), False),
            "one name of two is excluded": (
                "",
                excluded_com,
                ("web.example.org", "web.example.com"),
                False,
            ),
            "a wildcard inside them": (
                "",
                permitted_org,
                ("web.example.org", "*.example.org"),
                True,
            ),
        }
        with tempfile.TemporaryDirectory() as raw:
            for number, (name, (above, below, names, issues)) in enumerate(shapes.items()):
                pki = EcPki(Path(raw) / str(number))
                pki.root.mkdir()
                root = pki.make("Root", CA + above)
                issuing = pki.make("Issuing", CA + below, root)
                ra = pki.make("RA", RA, issuing)
                answer = pkcs7(issuing[0], root[0], ra[0])
                found = ndes_servers.authorities(
                    ENDPOINT,
                    fetch=lambda *_, given=answer: given,
                    trust=pki.root / "none.pem",
                )
                leaf, key = pki.make(
                    names[0],
                    "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\nsubjectAltName="
                    + ",".join(f"DNS:{each}" for each in names),
                    issuing,
                )
                saved = "".join(authority.pem for authority in found)
                directory = pki.root / "staging"
                directory.mkdir()
                (directory / "issuing-ca.pem").write_text(saved)
                material = assemble(
                    [leaf.read_text(), *[authority.pem for authority in found]], [key.read_text()]
                )
                with self.subTest(name):
                    issued: str | None = None
                    try:
                        ndes.validate_certificate(material, names, directory)
                    except ndes.NdesError as exc:
                        issued = str(exc)
                    self.assertEqual(issued is None, issues, issued)
                    if not issues:
                        self.assertNotIn("if the CA was renewed", str(issued))
                        self.assertIn("names asked for are outside", str(issued))
                        self.assertIn("subtree violation", str(issued))
                    before = ndes_servers.names_problem(saved, names)
                    self.assertEqual(before is None, issues, before)
                    if not issues:
                        self.assertIn("subtree violation", str(before))

    def test_a_set_it_cannot_read_leaves_it_to_issuance(self) -> None:
        self.assertIsNone(ndes_servers.names_problem("example CA material", ["web.example.com"]))
        self.assertIsNone(ndes_servers.names_problem("", ["web.example.com"]))


class TheAuthorities(unittest.TestCase):
    def test_the_cas_the_issuing_one_first_and_never_the_ra(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            answer = Answer(Path(raw))
            found = ndes_servers.authorities(ENDPOINT, fetch=answer)
            issuing = answer.sha256(answer.pki.intermediate)
            thumbprint = answer.digest(answer.pki.intermediate, "-sha1")

        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].issues_ra)
        self.assertEqual(found[0].subject, "CN=Test Issuing CA")
        self.assertFalse(found[1].issues_ra)
        self.assertEqual(found[0].sha256, issuing)
        self.assertEqual(found[0].sha1, thumbprint)
        self.assertEqual(answer.asked, [ENDPOINT])

    def test_an_error_answer_is_said_and_closed(self) -> None:
        """Review 2026-10-28, F04: an HTTP error is a response, and was left open."""

        stream = io.BytesIO(b"not here")
        error = urllib.error.HTTPError(ENDPOINT, 404, "", Message(), stream)
        opener = mock.Mock(open=mock.Mock(side_effect=error))
        with (
            mock.patch.object(ndes_servers, "_opener", return_value=opener),
            self.assertRaises(ndes_servers.NdesServerError) as caught,
        ):
            ndes_servers.get_ca_cert(ENDPOINT)
        self.assertEqual(caught.exception.code, "unreachable")
        self.assertIn("HTTP 404", str(caught.exception))
        self.assertTrue(stream.closed)

    def test_https_is_checked_against_the_store_it_is_given(self) -> None:
        """Review 2026-10-29 again, BB07: always the system's, while Certmonger used `tls_ca`."""

        opener = mock.Mock(open=mock.Mock(side_effect=OSError("stop")))
        own = Path("/nonexistent/tls.pem")
        with (
            mock.patch.object(ndes_servers, "_opener", return_value=opener) as built,
            self.assertRaises(ndes_servers.NdesServerError),
        ):
            ndes_servers.get_ca_cert(ENDPOINT, own)
        built.assert_called_once_with(own)

    def test_an_https_certificate_not_trusted_is_said_as_such(self) -> None:
        """Review 2026-10-29 again, BB07: it was "did not answer"."""

        untrusted = urllib.error.URLError(
            ssl.SSLCertVerificationError(
                1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
            )
        )
        for trust, store in (
            (SYSTEM_TRUST, "this manager's certificate store"),
            (Path("/nonexistent/tls.pem"), "the server's tls_ca /nonexistent/tls.pem"),
        ):
            opener = mock.Mock(open=mock.Mock(side_effect=untrusted))
            with (
                self.subTest(trust=trust),
                mock.patch.object(ndes_servers, "_opener", return_value=opener),
                self.assertRaises(ndes_servers.NdesServerError) as caught,
            ):
                ndes_servers.get_ca_cert(ENDPOINT, trust)
            self.assertEqual(caught.exception.code, "tls")
            self.assertIn(f"its HTTPS certificate is not trusted by {store}", str(caught.exception))
            self.assertNotIn("did not answer", str(caught.exception))
        opener = mock.Mock(open=mock.Mock(side_effect=ssl.SSLError(1, "handshake failure")))
        with (
            mock.patch.object(ndes_servers, "_opener", return_value=opener),
            self.assertRaises(ndes_servers.NdesServerError) as caught,
        ):
            ndes_servers.get_ca_cert(ENDPOINT, SYSTEM_TRUST)
        self.assertEqual(caught.exception.code, "tls")
        self.assertIn("TLS failed", str(caught.exception))

    def test_each_https_failure_is_given_its_own_way_out(self) -> None:
        """Review 2026-10-29, round 2, BBB05: every failure was told to add a CA to the store.

        Over real HTTPS on this host. A certificate for another name, one past
        its date and one from a CA the store does not hold each say what is
        wrong; and a CA that Python's strict mode alone refuses - this test
        PKI's root has no key usage - is accepted, as the enrollment's
        libcurl accepts it.
        """

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            here = Pki(root / "here", names=("localhost",))
            other = Pki(root / "other", names=("other.example.com",))
            stranger = Pki(root / "stranger", names=("localhost",))
            expired = here.directory / "expired.pem"
            subprocess.run(
                [OPENSSL, "x509", "-req", "-in", str(here.directory / "localhost.csr")]
                + ["-CA", str(here.intermediate), "-CAkey", str(here.intermediate_key)]
                + ["-not_before", "20200101000000Z", "-not_after", "20200201000000Z"]
                + ["-extfile", str(here.directory / "localhost.ext"), "-out", str(expired)],
                capture_output=True,
                check=True,
            )
            #
            # The issuing CA past its date, with the same key, under a valid
            # leaf: OpenSSL's code is the leaf's, and it says nothing of
            # which one (review 2026-10-29, round 3, B3-03).
            #
            lapsed = here.directory / "lapsed-ca.pem"
            subprocess.run(
                [OPENSSL, "x509", "-req", "-in", str(here.directory / "Test Issuing CA.csr")]
                + ["-CA", str(here.root), "-CAkey", str(here.root_key)]
                + ["-not_before", "20200101000000Z", "-not_after", "20210101000000Z"]
                + ["-extfile", str(here.directory / "Test Issuing CA.ext"), "-out", str(lapsed)],
                capture_output=True,
                check=True,
            )
            chains = {}
            for name, leaf, key, pki, issuer in (
                ("here", here.leaf, here.leaf_key, here, here.intermediate),
                ("other", other.leaf, other.leaf_key, other, other.intermediate),
                ("expired", expired, here.leaf_key, here, here.intermediate),
                ("lapsed CA", here.leaf, here.leaf_key, here, lapsed),
            ):
                chain = root / f"{name}-chain.pem"
                chain.write_text(leaf.read_text() + issuer.read_text())
                chains[name] = (chain, key, pki.root)
            for name, trust, words in (
                (
                    "other",
                    other.root,
                    "its HTTPS certificate is not for localhost; give the address its certificate names",
                ),
                ("expired", here.root, "a certificate in its HTTPS chain has expired"),
                ("lapsed CA", here.root, "a certificate in its HTTPS chain has expired"),
                ("here", stranger.root, "add the CA that issued it to the store"),
            ):
                chain, key, _ = chains[name]
                with (
                    self.subTest(name),
                    ServedOverTls(chain, key) as url,
                    self.assertRaises(ndes_servers.NdesServerError) as caught,
                ):
                    ndes_servers.get_ca_cert(url, trust)
                self.assertEqual(caught.exception.code, "tls")
                self.assertIn(words, str(caught.exception))
                if name != "here":
                    self.assertNotIn("add the CA", str(caught.exception))
                self.assertNotIn("its HTTPS certificate has expired", str(caught.exception))
            chain, key, trust = chains["here"]
            with ServedOverTls(chain, key) as url:
                self.assertEqual(ndes_servers.get_ca_cert(url, trust), b"ca")

    def test_an_address_that_is_not_https_is_refused_before_anything_is_asked(self) -> None:
        asked: list[str] = []
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.authorities("http://ca.example.com/", fetch=asked.append)  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "bad_input")
        self.assertEqual(asked, [])

    def test_an_answer_without_a_ca_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            leaf = Answer(Path(raw)).pki.leaf.read_bytes()
            with self.assertRaises(ndes_servers.NdesServerError) as caught:
                ndes_servers.authorities(ENDPOINT, fetch=lambda *_: leaf)
        self.assertEqual(caught.exception.code, "bad_answer")


class TheSavedChainsExpiry(unittest.TestCase):
    """B389: the server list says when the confirmed CA runs out, before renewals fail on it."""

    def test_the_first_certificate_to_expire_is_the_chain_s_end(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            pki = Pki(root)
            short = root / "short.pem"
            subprocess.run(
                [
                    str(OPENSSL),
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(root / "short.key"),
                    "-out",
                    str(short),
                    "-subj",
                    "/CN=Short Root",
                    "-days",
                    "5",
                ],
                check=True,
                capture_output=True,
            )
            bundle = root / "bundle.pem"
            bundle.write_text(pki.intermediate.read_text() + short.read_text())
            expires = ndes_servers.ca_expires(bundle)
        assert expires is not None
        left = datetime.fromisoformat(expires.replace("Z", "+00:00")) - datetime.now(UTC)
        self.assertGreater(left, timedelta(days=4))
        self.assertLess(left, timedelta(days=6))

    def test_a_file_that_cannot_be_read_has_no_date(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.assertIsNone(ndes_servers.ca_expires(root / "missing.pem"))
            (root / "empty.pem").write_text("")
            self.assertIsNone(ndes_servers.ca_expires(root / "empty.pem"))
            #
            # Assembled, as the node status assembles its pattern: a literal
            # header is what the secret scanner exists to catch.
            #
            dashes = "-" * 5
            (root / "broken.pem").write_text(
                f"{dashes}BEGIN CERTIFICATE{dashes}\nAAAA\n{dashes}END CERTIFICATE{dashes}\n"
            )
            self.assertIsNone(ndes_servers.ca_expires(root / "broken.pem"))


class ThePolicy(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "runtime-policy.yaml"
        self.policy.write_text(POLICY.format(root=self.root))
        self.policy.chmod(0o644)
        self.cas = self.root / "ndes-ca"
        self.answer = Answer(self.root)
        self.issuing = self.answer.sha256(self.answer.pki.intermediate)
        self.chain = [self.issuing, self.answer.sha256(self.answer.pki.root)]
        self.lock = self.root / "locks" / "ndes-policy.lock"
        patch = mock.patch.object(ndes_servers, "LOCK_PATH", self.lock)
        patch.start()
        self.addCleanup(patch.stop)

    def add(
        self, endpoint: str = ENDPOINT, fingerprints: list[str] | None = None
    ) -> dict[str, object]:
        return ndes_servers.add(
            endpoint,
            self.chain if fingerprints is None else fingerprints,
            policy_path=self.policy,
            ca_directory=self.cas,
            fetch=self.answer,
        )

    def servers(self) -> list[str]:
        ndes = load_policy(self.policy, require_secure=False).ndes
        assert ndes is not None
        return [server.endpoint for server in ndes.servers]

    def test_a_first_server_makes_the_block_and_keeps_the_rest_of_the_file(self) -> None:
        added = self.add()

        text = self.policy.read_text()
        self.assertTrue(text.startswith("# Runtime policy, rendered by the installation.\n"))
        self.assertEqual(self.servers(), [ENDPOINT])
        ndes = yaml.safe_load(text)["ndes"]
        self.assertEqual(ndes["client_root"], "/opt/haprion-scep/current")
        self.assertEqual(ndes["profiles"], {"directory": "/etc/haprion/ndes-profiles"})
        written = Path(str(added["issuing_ca"]))
        self.assertEqual(written.parent, self.cas)
        self.assertIn(self.answer.pki.intermediate.read_text(), written.read_text())
        self.assertNotIn(self.answer.pki.leaf.read_text(), written.read_text())
        self.assertEqual(written.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.policy.stat().st_mode & 0o777, 0o644)

    def test_a_second_server_is_added_and_the_form_before_it_becomes_the_first(self) -> None:
        with self.policy.open("a") as policy:
            policy.write(
                "ndes:\n"
                f"  endpoint: {ENDPOINT}\n"
                f"  tls_ca: {self.root}/tls.pem\n"
                f"  issuing_ca: {self.root}/ca.pem\n"
                "  client_root: /opt/haprion-scep/current\n"
                "  state_root: /etc/haprion/ndes-requests\n"
                "  profiles:\n"
                "    directory: /etc/haprion/ndes-profiles\n"
                "    private_keys: [/etc/haprion/keys/0123456789abcdef.key]\n"
                f"backup_root: {self.root}/backup\n"
            )
        self.add(OTHER)

        self.assertEqual(self.servers(), [ENDPOINT, OTHER])
        data = yaml.safe_load(self.policy.read_text())
        self.assertEqual(data["ndes"]["servers"][0]["tls_ca"], f"{self.root}/tls.pem")
        self.assertEqual(data["backup_root"], f"{self.root}/backup")

    def test_the_profile_keys_are_the_dns_profiles_own(self) -> None:
        """Review 2026-10-29, B05: a copy of the keys did not follow a rotation."""

        self.add()
        text = self.policy.read_text()
        rotated = f"    - {self.root}/keys/fedcba9876543210.key\n"
        anchor = f"    - {self.root}/keys/0123456789abcdef.key\n"
        self.policy.write_text(text.replace(anchor, anchor + rotated, 1))
        ndes = load_policy(self.policy, require_secure=False).ndes
        assert ndes is not None
        self.assertEqual(
            [str(key) for key in ndes.profiles.private_keys],
            [f"{self.root}/keys/0123456789abcdef.key", f"{self.root}/keys/fedcba9876543210.key"],
        )

    def test_a_block_with_keys_of_its_own_keeps_them(self) -> None:
        own = f"{self.root}/keys/aaaaaaaaaaaaaaaa.key"
        with self.policy.open("a") as policy:
            policy.write(
                "ndes:\n"
                "  servers: []\n"
                "  client_root: /opt/haprion-scep/current\n"
                "  state_root: /etc/haprion/ndes-requests\n"
                "  profiles:\n"
                "    directory: /etc/haprion/ndes-profiles\n"
                f"    private_keys: [{own}]\n"
            )
        self.add()
        ndes = load_policy(self.policy, require_secure=False).ndes
        assert ndes is not None
        self.assertEqual([str(key) for key in ndes.profiles.private_keys], [own])

    def test_without_a_profile_key_nothing_is_asked(self) -> None:
        self.policy.write_text(POLICY.format(root=self.root).partition("acme:")[0])
        before = self.policy.read_text()
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            self.add()
        self.assertEqual(caught.exception.code, "no_profile_key")
        self.assertIn("no profile key", str(caught.exception))
        self.assertEqual(self.answer.asked, [])
        self.assertEqual(self.policy.read_text(), before)

    def test_the_comments_after_the_block_stay(self) -> None:
        """Review 2026-10-29, B04: a comment before the next key was taken as the block's."""

        self.add()
        with self.policy.open("a") as policy:
            policy.write(f"# The backup settings\nbackup_root: {self.root}/backup\n")
        self.add(OTHER)
        self.assertIn("\n# The backup settings\nbackup_root:", self.policy.read_text())
        ndes_servers.remove(OTHER, used_by=lambda: (), policy_path=self.policy)
        self.assertIn("\n# The backup settings\nbackup_root:", self.policy.read_text())
        ndes_servers.remove(ENDPOINT, used_by=lambda: (), policy_path=self.policy)
        text = self.policy.read_text()
        self.assertIn("\n# The backup settings\nbackup_root:", text)
        self.assertNotIn("ndes", yaml.safe_load(text))

    def test_a_comment_inside_the_block_goes_with_it_and_one_at_the_end_stays(self) -> None:
        with self.policy.open("a") as policy:
            policy.write(
                "ndes:\n"
                "# confirmed by hand\n"
                f"  endpoint: {ENDPOINT}\n"
                f"  issuing_ca: {self.root}/ca.pem\n"
                "  client_root: /opt/haprion-scep/current\n"
                "  state_root: /etc/haprion/ndes-requests\n"
                "  profiles:\n"
                "    directory: /etc/haprion/ndes-profiles\n"
                "    private_keys: [/etc/haprion/keys/0123456789abcdef.key]\n"
                "\n# The end of the policy\n"
            )
        self.add(OTHER)
        text = self.policy.read_text()
        self.assertEqual(self.servers(), [ENDPOINT, OTHER])
        self.assertNotIn("confirmed by hand", text)
        self.assertTrue(text.endswith("\n\n# The end of the policy\n"), text)
        self.add(OTHER)
        self.assertEqual(self.policy.read_text(), text)

    def test_a_server_confirmed_again_keeps_its_tls_ca(self) -> None:
        """Review 2026-10-29, B02: the entry was written anew, and HTTPS fell back to the system's store."""

        self.add()
        data = yaml.safe_load(self.policy.read_text())
        data["ndes"]["servers"][0]["tls_ca"] = f"{self.root}/tls.pem"
        self.policy.write_text(yaml.safe_dump(data, sort_keys=False))
        self.add()
        ndes = load_policy(self.policy, require_secure=False).ndes
        assert ndes is not None
        self.assertEqual(str(ndes.servers[0].tls_ca), f"{self.root}/tls.pem")

    def test_a_refused_policy_leaves_the_server_s_ca_as_it_was(self) -> None:
        """Review 2026-10-29, B03: the CA file was replaced before the policy was read back."""

        saved = Path(str(self.add()["issuing_ca"]))
        before = saved.read_bytes()
        (self.root / "renewed").mkdir()
        self.answer = Answer(self.root / "renewed")
        chain = [
            self.answer.sha256(self.answer.pki.intermediate),
            self.answer.sha256(self.answer.pki.root),
        ]
        with (
            mock.patch.object(ndes_servers, "load_policy", side_effect=ConfigError("refused")),
            self.assertRaises(ndes_servers.NdesServerError),
        ):
            self.add(fingerprints=chain)
        self.assertEqual(saved.read_bytes(), before)
        self.assertEqual(list(self.cas.iterdir()), [saved])

    def test_a_ca_replaced_or_removed_takes_its_file_with_it(self) -> None:
        first = Path(str(self.add()["issuing_ca"]))
        (self.root / "renewed").mkdir()
        self.answer = Answer(self.root / "renewed")
        second = Path(
            str(
                self.add(
                    fingerprints=[
                        self.answer.sha256(self.answer.pki.intermediate),
                        self.answer.sha256(self.answer.pki.root),
                    ]
                )["issuing_ca"]
            )
        )
        self.assertNotEqual(first, second)
        self.assertEqual(list(self.cas.iterdir()), [second])
        ndes_servers.remove(
            ENDPOINT, used_by=lambda: (), policy_path=self.policy, ca_directory=self.cas
        )
        self.assertEqual(list(self.cas.iterdir()), [])

    def test_a_ca_file_a_server_trusts_for_its_https_stays(self) -> None:
        """Review 2026-10-29 again, BB05: only `issuing_ca` was counted as a reference.

        Written the way a hand edit may name it (`./`), which the comparison
        of the policy's string missed too.
        """

        first = Path(str(self.add()["issuing_ca"]))
        data = yaml.safe_load(self.policy.read_text())
        data["ndes"]["servers"][0]["tls_ca"] = f"{first.parent}/./{first.name}"
        self.policy.write_text(yaml.safe_dump(data, sort_keys=False))
        (self.root / "renewed").mkdir()
        self.answer = Answer(self.root / "renewed")
        renewed = [
            self.answer.sha256(self.answer.pki.intermediate),
            self.answer.sha256(self.answer.pki.root),
        ]
        second = Path(str(self.add(fingerprints=renewed)["issuing_ca"]))
        self.assertTrue(first.exists())
        # Another server that borrows the file keeps it past this one's removal.
        data = yaml.safe_load(self.policy.read_text())
        del data["ndes"]["servers"][0]["tls_ca"]
        data["ndes"]["servers"].append(
            {"endpoint": OTHER, "issuing_ca": str(second), "tls_ca": str(first)}
        )
        self.policy.write_text(yaml.safe_dump(data, sort_keys=False))
        data["ndes"]["servers"][0]["issuing_ca"] = str(first)
        self.policy.write_text(yaml.safe_dump(data, sort_keys=False))
        ndes_servers.remove(
            ENDPOINT, used_by=lambda: (), policy_path=self.policy, ca_directory=self.cas
        )
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_a_ca_file_a_server_trusts_through_a_link_stays(self) -> None:
        """Review 2026-10-29, round 2, cosmetic: a `tls_ca` linked to the file did not hold it."""

        first = Path(str(self.add()["issuing_ca"]))
        link = self.root / "tls-link.pem"
        link.symlink_to(first)
        data = yaml.safe_load(self.policy.read_text())
        data["ndes"]["servers"][0]["tls_ca"] = str(link)
        self.policy.write_text(yaml.safe_dump(data, sort_keys=False))
        (self.root / "renewed").mkdir()
        self.answer = Answer(self.root / "renewed")
        renewed = [
            self.answer.sha256(self.answer.pki.intermediate),
            self.answer.sha256(self.answer.pki.root),
        ]
        self.add(fingerprints=renewed)
        self.assertTrue(first.exists())

    def test_a_ca_file_outside_the_manager_s_directory_is_never_removed(self) -> None:
        # A policy from before B385 names its CA file where the installation put it.
        own = self.root / "issuing-ca.pem"
        own.write_text(self.answer.pki.intermediate.read_text())
        with self.policy.open("a") as policy:
            policy.write(
                "ndes:\n"
                f"  endpoint: {ENDPOINT}\n"
                f"  issuing_ca: {own}\n"
                "  client_root: /opt/haprion-scep/current\n"
                "  state_root: /etc/haprion/ndes-requests\n"
                "  profiles:\n"
                "    directory: /etc/haprion/ndes-profiles\n"
                "    private_keys: [/etc/haprion/keys/0123456789abcdef.key]\n"
            )
        self.add()
        self.assertTrue(own.exists())
        ndes_servers.remove(
            ENDPOINT, used_by=lambda: (), policy_path=self.policy, ca_directory=self.cas
        )
        self.assertTrue(own.exists())

    def test_a_fingerprint_the_server_no_longer_gives_changes_nothing(self) -> None:
        before = self.policy.read_text()
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            self.add(fingerprints=["0" * 64])
        self.assertEqual(caught.exception.code, "changed")
        self.assertEqual(self.policy.read_text(), before)
        self.assertFalse(self.cas.exists())

    def test_every_ca_certificate_saved_is_one_confirmed(self) -> None:
        # Review 2026-10-28, U02: the server's whole chain is saved, so the
        # issuing CA alone, or the chain with one more, confirms nothing.
        before = self.policy.read_text()
        for fingerprints in ([self.issuing], [*self.chain, "0" * 64], []):
            with self.assertRaises(ndes_servers.NdesServerError):
                self.add(fingerprints=fingerprints)
        self.assertEqual(self.policy.read_text(), before)
        added = self.add(fingerprints=list(reversed(self.chain)))
        self.assertEqual(added["sha256"], self.chain)

    def test_a_server_in_use_stays_and_the_last_one_takes_the_block(self) -> None:
        self.add()
        self.add(OTHER)
        with self.assertRaises(ndes_servers.NdesServerError) as caught:
            ndes_servers.remove(OTHER, used_by=lambda: ("internal-ca",), policy_path=self.policy)
        self.assertEqual(caught.exception.code, "in_use")

        ndes_servers.remove(OTHER, used_by=lambda: (), policy_path=self.policy)
        self.assertEqual(self.servers(), [ENDPOINT])
        ndes_servers.remove(ENDPOINT, used_by=lambda: (), policy_path=self.policy)
        self.assertNotIn("ndes", yaml.safe_load(self.policy.read_text()))
        self.assertIsNone(load_policy(self.policy, require_secure=False).ndes)

    def test_the_profiles_using_a_server_are_read_from_their_records(self) -> None:
        records = self.root / "ndes-profiles"
        records.mkdir()
        (records / "internal-ca.json").write_text(
            f'{{"profile_id": "internal-ca", "endpoint": "{ENDPOINT}"}}'
        )
        (records / "other.json").write_text(f'{{"profile_id": "other", "endpoint": "{OTHER}"}}')
        self.assertEqual(ndes_servers.profiles_using(records, ENDPOINT), ("internal-ca",))

    def test_a_profile_record_that_cannot_be_read_holds_every_server(self) -> None:
        """Review 2026-10-29, B10: it was skipped, where pending_requests counts one as bound."""

        records = self.root / "ndes-profiles"
        records.mkdir()
        (records / "broken.json").write_text("{not json")
        (records / "listed.json").write_text("[]")
        (records / "other.json").write_text(f'{{"profile_id": "other", "endpoint": "{OTHER}"}}')
        self.assertEqual(ndes_servers.profiles_using(records, ENDPOINT), ("broken", "listed"))

    def test_the_profiles_using_a_server_are_asked_under_the_lock(self) -> None:
        self.add()
        held = []

        def used_by() -> tuple[str, ...]:
            handle = os.open(self.lock, os.O_RDWR)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(False)
            except BlockingIOError:
                held.append(True)
            finally:
                os.close(handle)
            return ()

        ndes_servers.remove(ENDPOINT, used_by=used_by, policy_path=self.policy)
        self.assertEqual(held, [True])

    def test_two_processes_adding_servers_at_once_keep_both(self) -> None:
        # Review 2026-10-28, F05: the command and the web's helper are two
        # processes. The first reads the policy and waits for the second to
        # read it too; the second writes only after the first has. Without the
        # lock both read the same file and the second write loses the first
        # server; with it the second cannot read until the first has written.
        context = multiprocessing.get_context("fork")
        first_read, second_read, first_written = (context.Event() for _ in range(3))
        real_load, real_write = safe_yaml.load, ndes_servers._write_policy

        def first() -> None:
            def load(text: str) -> Any:
                first_read.set()
                second_read.wait(2)
                return real_load(text)

            def write(policy_path: Path, text: str) -> None:
                real_write(policy_path, text)
                first_written.set()

            with (
                mock.patch.object(safe_yaml, "load", load),
                mock.patch.object(ndes_servers, "_write_policy", write),
            ):
                self.add(ENDPOINT)

        def second() -> None:
            def load(text: str) -> Any:
                second_read.set()
                first_written.wait(10)
                return real_load(text)

            with mock.patch.object(safe_yaml, "load", load):
                self.add(OTHER)

        def run(work: Any) -> None:
            status = 1
            try:
                work()
                status = 0
            finally:
                os._exit(status)

        one = context.Process(target=run, args=(first,))
        one.start()
        self.assertTrue(first_read.wait(30))
        two = context.Process(target=run, args=(second,))
        two.start()
        one.join(30)
        two.join(30)
        self.assertEqual((one.exitcode, two.exitcode), (0, 0))
        self.assertEqual(sorted(self.servers()), sorted([ENDPOINT, OTHER]))


class TheHelperAndTheCommand(unittest.TestCase):
    """The web's socket and the operator's command: one module, one contract (CLI parity)."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "runtime-policy.yaml"
        self.policy.write_text(POLICY.format(root=self.root))
        self.answer = Answer(self.root)
        self.issuing = self.answer.sha256(self.answer.pki.intermediate)
        self.chain = [self.issuing, self.answer.sha256(self.answer.pki.root)]
        for patch in (
            mock.patch.object(
                ndes_server_helper,
                "load_policy",
                side_effect=lambda path: load_policy(path, require_secure=False),
            ),
            mock.patch.object(ndes_servers, "CA_DIRECTORY", self.root / "ndes-ca"),
            mock.patch.object(ndes_servers, "LOCK_PATH", self.root / "ndes-policy.lock"),
            #
            # A first server makes the block with the product's directories,
            # which a removal then reads: here, the test's own (review
            # 26-10-29, A09 - it read this machine's profile records).
            #
            mock.patch.object(ndes_servers, "PROFILE_DIRECTORY", str(self.root / "ndes-profiles")),
            mock.patch.object(ndes_servers, "STATE_ROOT", str(self.root / "ndes-requests")),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def ask(self, **parameters: object) -> tuple[int, dict[str, Any]]:
        request = {
            "schema_version": 1,
            "operation": "ndes_server",
            "cluster": None,
            "request_id": str(uuid.uuid4()),
            "parameters": parameters,
        }
        out, err = io.StringIO(), io.StringIO()
        code = ndes_server_helper.main(
            [],
            input_stream=io.BytesIO(json.dumps(request).encode() + b"\n"),
            output_stream=out,
            error_stream=err,
            policy_path=self.policy,
            fetch=self.answer,
            require_root=False,
        )
        self.journal = err.getvalue()
        return code, assert_contract("haprion-ndes-server", out.getvalue())

    def test_a_known_server_is_asked_over_the_https_its_tls_ca_trusts(self) -> None:
        """Review 2026-10-29 again, BB07: the fetch and the completion use one store."""

        self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        self.assertEqual(self.answer.trusted[-1], SYSTEM_TRUST)
        data = yaml.safe_load(self.policy.read_text())
        own = self.root / "tls.pem"
        own.write_text(self.answer.pki.root.read_text())
        data["ndes"]["servers"][0]["tls_ca"] = str(own)
        self.policy.write_text(yaml.safe_dump(data, sort_keys=False))
        code, _ = self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertEqual(code, 0)
        self.assertEqual(self.answer.trusted[-1], own)

    def test_fetch_shows_the_cas_and_add_confirms_one(self) -> None:
        code, fetched = self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertEqual(code, 0)
        self.assertEqual(fetched["result"]["state"], "new")
        self.assertEqual(fetched["result"]["authorities"][0]["sha256"], self.issuing)

        code, added = self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        self.assertEqual((code, added["outcome"]), (0, "done"))
        _code, again = self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertEqual(again["result"]["state"], "confirmed")

    def test_the_list_says_when_each_server_s_ca_expires(self) -> None:
        """B389: the list the interface draws its server table from."""

        self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        code, listed = self.ask(action="list")
        self.assertEqual(code, 0)
        (server,) = listed["result"]["servers"]
        self.assertEqual(server["endpoint"], ENDPOINT)
        self.assertEqual(server["expires"], ndes_servers.ca_expires(Path(server["issuing_ca"])))
        self.assertIsNotNone(server["expires"])

    def test_a_change_of_the_policy_is_written_to_the_journal(self) -> None:
        """Review 2026-10-29, B12: root changed the policy and said nothing of it."""

        self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertEqual(self.journal, "")
        self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        self.assertIn(f"added {ENDPOINT}", self.journal)
        for each in self.chain:
            self.assertIn(each, self.journal)
        self.ask(action="remove", endpoint=ENDPOINT)
        self.assertIn(f"removed {ENDPOINT}", self.journal)

    def test_a_chain_completed_from_the_store_is_confirmed_and_saved_whole(self) -> None:
        pki = self.answer.pki
        short = pkcs7(pki.intermediate, pki.leaf)
        store = self.root / "store.pem"
        store.write_text(pki.root.read_text())
        with mock.patch.object(ndes_server_helper, "SYSTEM_TRUST", store):
            self.answer.der = short
            _code, fetched = self.ask(action="fetch", endpoint=ENDPOINT)
            self.assertEqual(
                [a["from_store"] for a in fetched["result"]["authorities"]], [False, True]
            )
            said = self.command("add", ENDPOINT, root=False)[1]
            self.assertIn("CN=Test Root (CA, from this manager's certificate store)", said)
            code, added = self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        self.assertEqual(code, 0, added)
        self.assertIn(pki.root.read_text(), Path(added["result"]["issuing_ca"]).read_text())

    def renewed(self) -> list[str]:
        """The server's CA renewed with a new key: another chain at the same address."""

        (self.root / "renewed").mkdir()
        self.answer = Answer(self.root / "renewed")
        return [
            self.answer.sha256(self.answer.pki.intermediate),
            self.answer.sha256(self.answer.pki.root),
        ]

    def test_a_confirmed_server_whose_ca_changed_is_confirmed_again(self) -> None:
        """Review 2026-10-29, B01: the fetch said "confirmed" for any chain, so none could replace it."""

        self.assertEqual(self.ask(action="fetch", endpoint=ENDPOINT)[1]["result"]["state"], "new")
        self.ask(action="add", endpoint=ENDPOINT, sha256=self.chain)
        records = self.root / "ndes-profiles"
        records.mkdir()
        (records / "internal-ca.json").write_text(
            json.dumps({"profile_id": "internal-ca", "endpoint": ENDPOINT})
        )
        chain = self.renewed()

        _code, fetched = self.ask(action="fetch", endpoint=ENDPOINT)
        self.assertEqual(fetched["result"]["state"], "changed")
        self.assertEqual(fetched["result"]["authorities"][0]["sha256"], chain[0])
        code, added = self.ask(action="add", endpoint=ENDPOINT, sha256=chain)
        self.assertEqual((code, added["result"]["sha256"]), (0, chain))
        saved = Path(added["result"]["issuing_ca"]).read_text()
        self.assertIn(self.answer.pki.intermediate.read_text(), saved)
        self.assertEqual(
            self.ask(action="fetch", endpoint=ENDPOINT)[1]["result"]["state"], "confirmed"
        )

    def test_a_changed_ca_and_a_bad_action_are_refused_by_the_contract(self) -> None:
        code, refused = self.ask(action="add", endpoint=ENDPOINT, sha256=["0" * 64])
        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(refused["error"]["code"], "changed")
        code, refused = self.ask(action="add", endpoint=ENDPOINT, sha256=self.issuing)
        self.assertEqual((code, refused["error"]["code"]), (exit_codes.REFUSED, "bad_input"))
        code, refused = self.ask(action="drop", endpoint=ENDPOINT)
        self.assertEqual((code, refused["error"]["code"]), (exit_codes.REFUSED, "bad_input"))

    def command(self, *argv: str, root: bool = True) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("os.geteuid", return_value=0 if root else 1000):
            code = ndes_server.main(
                list(argv),
                stream_out=out,
                stream_err=err,
                fetch=self.answer,
                policy_path=self.policy,
            )
        return code, out.getvalue() + err.getvalue()

    def test_the_command_shows_without_changing_and_confirms_only_as_root(self) -> None:
        before = self.policy.read_text()
        code, said = self.command("add", ENDPOINT, root=False)
        self.assertEqual(code, 0)
        self.assertIn(f"SHA-256  {self.issuing}", said)
        self.assertIn("Nothing was changed", said)
        confirm = " ".join(f"--sha256 {each}" for each in self.chain)
        self.assertIn(f"add {ENDPOINT} {confirm}", said)
        self.assertEqual(self.policy.read_text(), before)

        code, said = self.command("add", ENDPOINT, *confirm.split(), root=False)
        self.assertEqual(code, exit_codes.NOT_ROOT)
        code, said = self.command("add", ENDPOINT, "--sha256", self.issuing)
        self.assertEqual(code, exit_codes.REFUSED, said)
        code, said = self.command(
            "add", ENDPOINT, *confirm.upper().replace("--SHA256", "--sha256").split()
        )
        self.assertEqual(code, 0, said)
        code, said = self.command("list")
        self.assertIn(ENDPOINT, said)
        code, said = self.command("remove", ENDPOINT)
        self.assertEqual(code, 0, said)
        self.assertIn("No NDES server", self.command("list")[1])

    def test_the_command_offers_to_confirm_a_changed_ca_again(self) -> None:
        confirm = [arg for each in self.chain for arg in ("--sha256", each)]
        self.assertEqual(self.command("add", ENDPOINT, *confirm)[0], 0)
        self.assertIn("confirmed already", self.command("add", ENDPOINT, root=False)[1])
        chain = self.renewed()

        code, said = self.command("add", ENDPOINT, root=False)
        self.assertEqual(code, 0)
        self.assertNotIn("confirmed already", said)
        self.assertIn("confirmed with other CA certificates", said)
        renewed = " ".join(f"--sha256 {each}" for each in chain)
        self.assertIn(f"add {ENDPOINT} {renewed}", said)
        self.assertEqual(self.command("add", ENDPOINT, *renewed.split())[0], 0)
        self.assertIn("confirmed already", self.command("add", ENDPOINT, root=False)[1])

    def test_the_command_takes_as_many_fingerprints_as_the_helper(self) -> None:
        """Review 2026-10-29: past 16 the helper's refusal escaped the command as a traceback."""

        many = [arg for _ in range(17) for arg in ("--sha256", "0" * 64)]
        code, said = self.command("add", ENDPOINT, *many)
        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("ERROR: parameters.sha256", said)

    def test_the_command_answers_in_the_helper_s_contract(self) -> None:
        code, said = self.command("add", ENDPOINT, "--json", root=False)
        self.assertEqual(code, 0)
        document = assert_contract("haprion-ndes-server", said)
        self.assertEqual(document["result"]["authorities"][0]["sha256"], self.issuing)
        code, said = self.command("remove", ENDPOINT, "--json", root=False)
        self.assertEqual(code, exit_codes.NOT_ROOT)
        self.assertEqual(assert_contract("haprion-ndes-server", said)["error"]["code"], "not_root")


if __name__ == "__main__":
    unittest.main()
