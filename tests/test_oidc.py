"""The OIDC helper's logic against a provider of the test's own making (O3, B196-B199).

The provider is real HTTPS on the loopback, with a certificate authority made
for the run, so the checks that matter - TLS verified against the added CA, no
redirect followed, the size bound - are exercised the way they run, not
patched. Each refusal in the plan's §16.6 gate has a test here: `alg: none`,
HS256 signed with the public key, the wrong issuer, audience, azp or nonce, an
expired token, userinfo about someone else or failing, a group overage, a
redirect, an answer too large and the wrong CA.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import shutil
import ssl
import tempfile
import threading
import time
import unittest
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import parse_qs

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from haprion import oidc
from haprion.cli import oidc_helper
from haprion.dns_profile_keys import write_key_pair
from tests.contract_schema import assert_contract

CLIENT_ID = "haprion"
SECRET = "a client secret long enough for HS256"  # noqa: S105 - the fake provider's own
NONCE = "n" * 43
VERIFIER = "v" * 43
REDIRECT = "https://mgr.example.com/login/oidc/callback"
# What the fake provider hands out and then expects back at userinfo.
BEARER = "fixture"


def _certificate_authority() -> tuple[str, ssl.SSLContext]:
    """A CA and a loopback server certificate it signed, both made now."""

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test oidc CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # The chain is read once; the key file is not left behind.
    with tempfile.TemporaryDirectory(prefix="oidc-test-") as name:
        pem = Path(name) / "server.pem"
        pem.write_bytes(
            server.public_bytes(serialization.Encoding.PEM)
            + server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context.load_cert_chain(pem)
    return ca.public_bytes(serialization.Encoding.PEM).decode("ascii"), context


CA_PEM, SERVER_CONTEXT = _certificate_authority()
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def _jwk(key: Any, kid: str) -> dict[str, Any]:
    algorithm: Any = (
        jwt.algorithms.RSAAlgorithm
        if isinstance(key, rsa.RSAPrivateKey)
        else (jwt.algorithms.ECAlgorithm)
    )
    document: dict[str, Any] = json.loads(algorithm.to_jwk(key.public_key()))
    document["kid"] = kid
    return document


class Provider:
    """A provider whose every answer a test can replace."""

    def __init__(self) -> None:
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                return None

            def do_GET(self) -> None:
                provider.handle(self, None)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                provider.handle(self, self.rfile.read(length).decode("ascii"))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = SERVER_CONTEXT.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.issuer = f"https://localhost:{self.port}/application/o/app/"
        self.routes: dict[str, Callable[[BaseHTTPRequestHandler, str | None], tuple[int, Any]]] = {}
        self.token_requests: list[tuple[dict[str, list[str]], str | None]] = []
        self.claims: dict[str, Any] = {}
        self.userinfo: dict[str, Any] | None = {"sub": "subject-1", "groups": ["haproxy-admins"]}
        self.signing: tuple[str, Any, str | None] = ("RS256", RSA_KEY, "rsa-1")
        self.discovery_extra: dict[str, Any] = {}
        self.token_answer: tuple[int, Any] | None = None
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def url(self, path: str) -> str:
        return f"https://localhost:{self.port}{path}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.url("/authorize"),
            "token_endpoint": self.url("/token"),
            "jwks_uri": self.url("/jwks"),
            "userinfo_endpoint": self.url("/userinfo"),
            "end_session_endpoint": self.url("/end-session"),
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            **self.discovery_extra,
        }

    def id_token(self, **overrides: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "sub": "subject-1",
            "iat": now,
            "exp": now + 300,
            "nonce": NONCE,
            "preferred_username": "alice",
            **self.claims,
            **overrides,
        }
        algorithm, key, kid = self.signing
        headers = {} if kid is None else {"kid": kid}
        return jwt.encode(claims, key, algorithm=algorithm, headers=headers)

    def handle(self, handler: BaseHTTPRequestHandler, body: str | None) -> None:
        path = handler.path.split("?", 1)[0]
        if path in self.routes:
            status, document = self.routes[path](handler, body)
        elif path == "/application/o/app/.well-known/openid-configuration":
            status, document = 200, self.discovery()
        elif path == "/jwks":
            status, document = 200, {"keys": [_jwk(RSA_KEY, "rsa-1"), _jwk(EC_KEY, "ec-1")]}
        elif path == "/token":
            self.token_requests.append((parse_qs(body or ""), handler.headers.get("Authorization")))
            status, document = self.token_answer or (
                200,
                {"id_token": self.id_token(), "access_token": BEARER, "token_type": "Bearer"},
            )
        elif path == "/userinfo":
            if handler.headers.get("Authorization") != f"Bearer {BEARER}":
                status, document = 401, {"error": "invalid_token"}
            elif self.userinfo is None:
                status, document = 500, {}
            else:
                status, document = 200, self.userinfo
        else:
            status, document = 404, {"error": "not_found"}
        raw = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
        handler.send_response(status)
        if status in (301, 302):
            handler.send_header("Location", self.url("/elsewhere"))
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)


class ProviderTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = Provider()
        self.addCleanup(self.provider.close)
        self.client = oidc.Client(ca_pem=CA_PEM)

    def discovery(self) -> oidc.Discovery:
        return oidc.discover(self.client, self.provider.issuer)

    def sign_in(self, **fields: Any) -> oidc.SignedIn:
        discovery = self.discovery()
        return oidc.exchange(
            self.client,
            discovery,
            oidc.signing_keys(self.client, discovery),
            client_id=CLIENT_ID,
            secret=SECRET,
            method=fields.pop("method", "client_secret_basic"),
            code="code-1",
            verifier=VERIFIER,
            redirect_uri=REDIRECT,
            nonce=fields.pop("nonce", NONCE),
            username_claim=fields.pop("username_claim", "preferred_username"),
            groups_claim=fields.pop("groups_claim", "groups"),
        )

    def refused(self, code: str, **fields: Any) -> oidc.OidcError:
        with self.assertRaises(oidc.OidcError) as caught:
            self.sign_in(**fields)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return caught.exception


class Discovery(ProviderTestCase):
    def test_the_provider_s_endpoints_are_read_from_its_own_document(self) -> None:
        discovery = self.discovery()
        self.assertEqual(discovery.issuer, self.provider.issuer)
        self.assertEqual(discovery.token_endpoint, self.provider.url("/token"))
        self.assertEqual(discovery.end_session_endpoint, self.provider.url("/end-session"))

    def test_an_issuer_that_differs_by_a_slash_is_named_in_full(self) -> None:
        self.provider.discovery_extra = {"issuer": self.provider.issuer.rstrip("/")}
        with self.assertRaises(oidc.OidcError) as caught:
            self.discovery()
        self.assertEqual(caught.exception.code, "issuer_mismatch")
        self.assertIn(self.provider.issuer.rstrip("/") + "'", str(caught.exception))

    def test_an_endpoint_that_is_not_https_is_refused(self) -> None:
        self.provider.discovery_extra = {"token_endpoint": "http://localhost/token"}
        with self.assertRaises(oidc.OidcError) as caught:
            self.discovery()
        self.assertEqual(caught.exception.code, "bad_discovery")

    def test_the_system_s_authorities_alone_do_not_trust_the_test_ca(self) -> None:
        with self.assertRaises(oidc.OidcError) as caught:
            oidc.discover(oidc.Client(), self.provider.issuer)
        self.assertEqual(caught.exception.code, "tls")

    def test_a_redirect_is_refused_not_followed(self) -> None:
        self.provider.routes["/application/o/app/.well-known/openid-configuration"] = lambda *_: (
            302,
            {},
        )
        with self.assertRaises(oidc.OidcError) as caught:
            self.discovery()
        self.assertEqual(caught.exception.code, "redirected")

    def test_an_answer_over_the_bound_is_refused(self) -> None:
        self.provider.routes["/application/o/app/.well-known/openid-configuration"] = lambda *_: (
            200,
            b"x" * (oidc.MAX_RESPONSE_BYTES + 1),
        )
        with self.assertRaises(oidc.OidcError) as caught:
            self.discovery()
        self.assertEqual(caught.exception.code, "too_large")

    def test_a_proxy_in_the_environment_is_not_used(self) -> None:
        # Port 9 on the loopback answers nothing; a client that honoured the
        # variable would fail here instead of reaching the provider.
        with mock.patch.dict(
            os.environ, {"https_proxy": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9"}
        ):
            for name in ("no_proxy", "NO_PROXY"):
                os.environ.pop(name, None)
            self.assertEqual(
                oidc.discover(oidc.Client(ca_pem=CA_PEM), self.provider.issuer).issuer,
                self.provider.issuer,
            )

    def test_an_issuer_with_a_query_or_without_https_is_refused(self) -> None:
        for issuer in ("http://localhost/", "https://localhost/?a=b", "https:///x"):
            with self.subTest(issuer=issuer), self.assertRaises(oidc.OidcError):
                oidc.issuer_url(issuer)


class SigningIn(ProviderTestCase):
    def test_a_sign_in_reads_the_subject_the_name_and_the_groups(self) -> None:
        signed_in = self.sign_in()

        self.assertEqual(
            (signed_in.subject, signed_in.username, signed_in.groups),
            ("subject-1", "alice", ("haproxy-admins",)),
        )
        self.assertEqual(signed_in.userinfo, "userinfo used")
        fields, authorization = self.provider.token_requests[-1]
        self.assertEqual(fields["code_verifier"], [VERIFIER])
        self.assertEqual(fields["redirect_uri"], [REDIRECT])
        self.assertNotIn("client_secret", fields)
        expected = base64.b64encode(b"haprion:a%20client%20secret%20long%20enough%20for%20HS256")
        self.assertEqual(authorization, f"Basic {expected.decode()}")

    def test_client_secret_post_sends_the_secret_in_the_form(self) -> None:
        self.sign_in(method="client_secret_post")
        fields, authorization = self.provider.token_requests[-1]
        self.assertEqual(fields["client_secret"], [SECRET])
        self.assertIsNone(authorization)

    def test_es256_and_hs256_are_verified_too(self) -> None:
        for signing in (("ES256", EC_KEY, "ec-1"), ("HS256", SECRET.encode(), None)):
            with self.subTest(algorithm=signing[0]):
                self.provider.signing = signing
                self.assertEqual(self.sign_in().subject, "subject-1")

    def test_an_unsigned_token_is_refused(self) -> None:
        self.provider.signing = ("none", None, None)
        self.assertIn("'none'", str(self.refused("bad_token")))

    def test_hs256_signed_with_the_public_key_is_refused(self) -> None:
        """The algorithm-confusion attack, built by hand as an attacker would.

        PyJWT will not sign HMAC with a PEM key, which is the library's own
        guard; the helper must not depend on the attacker using the library.
        """

        public_pem = RSA_KEY.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

        def part(document: dict[str, Any]) -> bytes:
            return base64.urlsafe_b64encode(json.dumps(document).encode()).rstrip(b"=")

        now = int(time.time())
        signing_input = (
            part({"alg": "HS256", "typ": "JWT", "kid": "rsa-1"})
            + b"."
            + part(
                {
                    "iss": self.provider.issuer,
                    "aud": CLIENT_ID,
                    "sub": "subject-1",
                    "iat": now,
                    "exp": now + 300,
                    "nonce": NONCE,
                }
            )
        )
        signature = base64.urlsafe_b64encode(
            hmac.new(public_pem, signing_input, hashlib.sha256).digest()
        ).rstrip(b"=")
        forged = (signing_input + b"." + signature).decode("ascii")
        self.provider.token_answer = (200, {"id_token": forged, "access_token": BEARER})
        self.refused("bad_token")

    def test_each_claim_that_binds_the_token_is_checked(self) -> None:
        now = int(time.time())
        for claims, sentence in (
            ({"iss": "https://other.example/"}, "another issuer"),
            ({"aud": "another-client"}, "another client"),
            ({"aud": [CLIENT_ID, "other"]}, "no azp"),
            ({"azp": "other"}, "another party"),
            ({"nonce": "m" * 43}, "nonce"),
            # CR-05: outside ASCII made the comparison raise rather than refuse.
            ({"nonce": "å" * 43}, "nonce"),
            ({"exp": now - 3600, "iat": now - 7200}, "expired"),
        ):
            with self.subTest(claims=claims):
                self.provider.token_answer = (
                    200,
                    {"id_token": self.provider.id_token(**claims), "access_token": BEARER},
                )
                self.assertIn(sentence, str(self.refused("bad_token")))

    def test_an_unknown_key_id_is_refused(self) -> None:
        self.provider.signing = ("RS256", RSA_KEY, "rotated-away")
        self.assertIn("rotated-away", str(self.refused("bad_token")))

    def test_the_provider_s_refusal_of_the_code_is_its_own_sentence(self) -> None:
        self.provider.token_answer = (
            400,
            {"error": "invalid_grant", "error_description": "The code has expired"},
        )
        self.assertIn("The code has expired", str(self.refused("token_refused")))


class Userinfo(ProviderTestCase):
    def test_userinfo_about_someone_else_is_not_used(self) -> None:
        self.provider.userinfo = {"sub": "subject-2", "groups": ["haproxy-admins"]}
        signed_in = self.sign_in()
        self.assertEqual(signed_in.groups, ())
        self.assertEqual(signed_in.userinfo, "userinfo named another subject and was not used")

    def test_a_failing_userinfo_leaves_the_id_token_to_stand_alone(self) -> None:
        self.provider.userinfo = None
        self.provider.claims = {"groups": ["haproxy-readers"]}
        signed_in = self.sign_in()
        self.assertEqual(signed_in.groups, ("haproxy-readers",))
        self.assertIn("not used", signed_in.userinfo)

    def test_the_id_token_wins_where_both_say_something(self) -> None:
        self.provider.claims = {"preferred_username": "alice"}
        self.provider.userinfo = {"sub": "subject-1", "preferred_username": "mallory"}
        self.assertEqual(self.sign_in().username, "alice")

    def test_a_name_only_in_userinfo_is_found_there(self) -> None:
        # Authelia's default: the id_token carries nothing but the protocol's claims.
        self.provider.token_answer = (
            200,
            {"id_token": self.provider.id_token(preferred_username=None), "access_token": BEARER},
        )
        self.provider.userinfo = {"sub": "subject-1", "preferred_username": "bob", "groups": ["g"]}
        signed_in = self.sign_in()
        self.assertEqual((signed_in.username, signed_in.groups), ("bob", ("g",)))


class Claims(ProviderTestCase):
    def test_a_claim_by_path_by_whole_name_and_as_an_object_s_keys(self) -> None:
        claims = {
            "realm_access": {"roles": ["haproxy-admins", "offline_access"]},
            "urn:zitadel:iam:org:project:roles": {"admin": {"1": "example.com"}},
            "groups": "/haproxy-readers",
        }
        self.assertEqual(
            oidc.claim_values(claims, "realm_access.roles"), ["haproxy-admins", "offline_access"]
        )
        self.assertEqual(oidc.claim_values(claims, "urn:zitadel:iam:org:project:roles"), ["admin"])
        self.assertEqual(oidc.claim_values(claims, "groups"), ["/haproxy-readers"])
        self.assertEqual(oidc.claim_values(claims, "missing.path"), [])

    def test_a_group_overage_is_a_sentence_about_app_roles(self) -> None:
        self.provider.userinfo = {"sub": "subject-1"}
        self.provider.claims = {"_claim_names": {"groups": "src1"}}
        self.assertIn("app roles", str(self.refused("group_overage")))

    def test_no_name_is_refused(self) -> None:
        self.provider.userinfo = {"sub": "subject-1"}
        self.provider.token_answer = (
            200,
            {"id_token": self.provider.id_token(preferred_username=None), "access_token": BEARER},
        )
        self.refused("no_username")


class TheClientCheck(ProviderTestCase):
    def check(self) -> tuple[bool, str]:
        return oidc.check_client(
            self.client,
            self.discovery(),
            client_id=CLIENT_ID,
            secret=SECRET,
            method="client_secret_basic",
            redirect_uri=REDIRECT,
        )

    def test_invalid_grant_means_the_client_was_accepted(self) -> None:
        self.provider.token_answer = (400, {"error": "invalid_grant"})
        self.assertEqual(self.check()[0], True)

    def test_invalid_client_means_it_was_not(self) -> None:
        self.provider.token_answer = (
            401,
            {"error": "invalid_client", "error_description": "Client authentication failed"},
        )
        accepted, message = self.check()
        self.assertFalse(accepted)
        self.assertIn("Client authentication failed", message)


class TheSealedSecret(unittest.TestCase):
    def setUp(self) -> None:
        directory = Path(tempfile.mkdtemp(prefix="oidc-keys-"))
        self.addCleanup(shutil.rmtree, directory, True)
        self.public = write_key_pair(directory / "k.key", directory / "k.pub")
        from haprion.dns_profile_keys import read_private_key

        self.private = read_private_key(directory / "k.key", require_secure=False)

    def test_it_opens_only_for_the_issuer_and_client_it_was_sealed_for(self) -> None:
        sealed = oidc.seal_client_secret(
            self.public,
            issuer="https://a.example/",
            client_id="c",
            secret="s3cret",  # noqa: S106 - sealed and opened within the test
        )
        self.assertEqual(
            oidc.open_client_secret(
                self.private, sealed, issuer="https://a.example/", client_id="c"
            ),
            "s3cret",
        )
        for issuer, client_id in (("https://evil.example/", "c"), ("https://a.example/", "d")):
            with self.subTest(issuer=issuer, client_id=client_id):
                with self.assertRaises(oidc.OidcError) as caught:
                    oidc.open_client_secret(
                        self.private, sealed, issuer=issuer, client_id=client_id
                    )
                self.assertEqual(caught.exception.code, "secret_for_another_client")


class TheHelper(ProviderTestCase):
    """`haprion-oidc-helper` end to end: the request in, the envelope out."""

    def setUp(self) -> None:
        super().setUp()
        self.keys = Path(tempfile.mkdtemp(prefix="oidc-helper-keys-"))
        self.addCleanup(shutil.rmtree, self.keys, True)
        public = write_key_pair(self.keys / "tmp.key", self.keys / "tmp.pub")
        (self.keys / "tmp.key").rename(self.keys / f"{public.key_id}.key")
        self.key_id = public.key_id
        self.sealed = base64.b64encode(
            oidc.seal_client_secret(
                public, issuer=self.provider.issuer, client_id=CLIENT_ID, secret=SECRET
            )
        ).decode("ascii")

    def run_helper(self, action: str, **parameters: Any) -> tuple[int, dict[str, Any]]:
        request = {
            "schema_version": 1,
            "operation": "oidc",
            "cluster": None,
            "request_id": str(uuid.uuid4()),
            "parameters": {
                "action": action,
                "issuer": self.provider.issuer,
                "ca_pem": CA_PEM,
                **parameters,
            },
        }
        out, err = io.StringIO(), io.StringIO()
        code = oidc_helper.main(
            [],
            input_stream=io.BytesIO(json.dumps(request).encode() + b"\n"),
            output_stream=out,
            error_stream=err,
            key_directory=self.keys,
            owner=Path(self.keys / f"{self.key_id}.key").stat().st_uid,
        )
        document = assert_contract("haprion-oidc", out.getvalue())
        return code, document

    def client_fields(self) -> dict[str, Any]:
        return {
            "client_id": CLIENT_ID,
            "client_secret_sealed": self.sealed,
            "key_id": self.key_id,
            "auth_method": "client_secret_basic",
            "redirect_uri": REDIRECT,
        }

    def test_discover_answers_the_endpoints(self) -> None:
        code, document = self.run_helper("discover")
        self.assertEqual(code, 0)
        self.assertEqual(
            document["result"]["authorization_endpoint"], self.provider.url("/authorize")
        )

    def test_verify_lists_each_check(self) -> None:
        self.provider.token_answer = (400, {"error": "invalid_grant"})
        code, document = self.run_helper("verify", **self.client_fields())
        self.assertEqual(code, 0)
        result = document["result"]
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            [check["name"] for check in result["checks"]],
            ["discovery", "keys", "method", "algorithm", "client"],
        )

    def test_verify_says_which_check_failed(self) -> None:
        self.provider.discovery_extra = {
            "token_endpoint_auth_methods_supported": ["private_key_jwt"]
        }
        self.provider.token_answer = (401, {"error": "invalid_client"})
        result = self.run_helper("verify", **self.client_fields())[1]["result"]
        self.assertFalse(result["ok"])
        failed = {check["name"] for check in result["checks"] if not check["ok"]}
        self.assertEqual(failed, {"method", "client"})

    def test_exchange_answers_who_signed_in_and_the_claims_only_when_asked(self) -> None:
        fields = {
            **self.client_fields(),
            "code": "code-1",
            "verifier": VERIFIER,
            "nonce": NONCE,
            "username_claim": "preferred_username",
            "groups_claim": "groups",
        }
        code, document = self.run_helper("exchange", **fields)
        self.assertEqual(code, 0, document)
        result = document["result"]
        self.assertEqual((result["username"], result["groups"]), ("alice", ["haproxy-admins"]))
        self.assertNotIn("claims", result)
        self.assertIn("claims", self.run_helper("exchange", **fields, claims=True)[1]["result"])

    def test_a_refusal_is_an_envelope_with_the_code(self) -> None:
        self.provider.discovery_extra = {"issuer": "https://other.example/"}
        code, document = self.run_helper("discover")
        self.assertEqual(code, 64)
        self.assertEqual(document["error"]["code"], "issuer_mismatch")

    def test_an_unknown_action_is_refused(self) -> None:
        code, document = self.run_helper("fetch-anything")
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "bad_input")


if __name__ == "__main__":
    unittest.main()
