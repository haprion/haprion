"""The HTTP-01 challenge reaches the manager through a real HAProxy (PL17).

A site that redirects http to https, is reachable from one network only and
sits behind a blocklist is the case the generator's rules are for: the
certificate authority's validation servers are none of its clients, and the
challenge has to get through all three. A small server plays the manager.

The control runs the same cluster without the setting and shows what the rules
guard against: the challenge refused, or sent to https.
"""

from __future__ import annotations

import dataclasses
import shutil
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from haprion.cluster_settings import AcmeChallenge, ClusterSettings
from haprion.config import Vip
from haprion.generate import BLOCKLISTS_DIRECTORY, generate
from haprion.proxy_model import load_proxy
from tests import spawned
from tests.spawned import start_haproxy, wait_for
from tests.test_generate_behaviour import (
    echo_server,
    free_port,
    self_signed,
    write_release,
)

CHALLENGE = "/.well-known/acme-challenge/token"
HAPROXY = shutil.which("haproxy")
#
# Each VIP's source address, which the challenge has to leave from as the
# pools do (26-11-15). The whole of 127.0.0.0/8 is this host's on Linux.
#
SOURCES = {"main": "127.0.0.3", "other": "127.0.0.4"}


def manager_server(port: int, seen: list[str]) -> ThreadingHTTPServer:
    """The manager: answers like the echo server, and notes the address each request came from."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # the name is the library's
            seen.append(self.client_address[0])
            body = f"manager {self.path}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            """Silence. The test's own output is the interesting one."""

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


SITE = """
schema: 1
name: {name}
hostnames: [{name}.example.com]
listen:
  protocol: https
  certificate: site
  redirect_http: {redirect}
  vip: {vip}
{extra}routes:
  - path: /
    backend: {name}-pool
backends:
  {name}-pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 127.0.0.1
        port: {pool}
"""


@unittest.skipUnless(HAPROXY and shutil.which("openssl"), "haproxy is not installed here")
class _Cluster(unittest.TestCase):
    send: bool = True
    directory: tempfile.TemporaryDirectory[str]
    servers: list[ThreadingHTTPServer]
    running: list[object]
    http: int
    seen: list[str]

    @classmethod
    @spawned.retry_on_taken_port
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        manager, pool = free_port(), free_port()
        cls.seen = []
        cls.servers = [manager_server(manager, cls.seen), echo_server("site", pool)]
        wait_for(manager)
        wait_for(pool)
        certificates = root / "certs"
        certificates.mkdir()
        certificate, key = self_signed(root, "site", expired=False)
        (certificates / "site.pem").write_text(key.read_text() + certificate.read_text())
        (root / "blocklists").mkdir()
        (root / "blocklists" / "crowdsec.lst").write_text("127.0.0.1\n")
        cls.http = free_port()
        settings = ClusterSettings(
            acme_challenge=AcmeChallenge("127.0.0.1", manager) if cls.send else None
        )
        layer = generate(
            [
                # Reachable from another network only, and a blocklist, and a redirect.
                load_proxy(
                    "locked",
                    SITE.format(
                        name="locked",
                        redirect="true",
                        vip="main",
                        pool=pool,
                        extra="allow_from: [office]\ndeny_from:\n  sources: [crowdsec]\n",
                    ).encode(),
                ),
                load_proxy(
                    "open",
                    SITE.format(
                        name="open", redirect="true", vip="main", pool=pool, extra=""
                    ).encode(),
                ),
                # An address with https and nothing on port 80.
                load_proxy(
                    "secure",
                    SITE.format(
                        name="secure", redirect="false", vip="other", pool=pool, extra=""
                    ).encode(),
                ),
            ],
            vips={
                "main": Vip(name="main", address="127.0.0.1", source=SOURCES["main"]),
                "other": Vip(name="other", address="127.0.0.2", source=SOURCES["other"]),
            },
            default_vip="main",
            ports={"http": cls.http, "https": free_port()},
            certificates=("site",),
            networks={"office": ("198.51.100.0/24",)},
            blocklists=("crowdsec",),
            settings=settings,
        )
        layer = dataclasses.replace(
            layer,
            configuration={
                name: content.replace(BLOCKLISTS_DIRECTORY, str(root / "blocklists"))
                for name, content in layer.configuration.items()
            },
        )
        release = root / "release"
        release.mkdir()
        assert HAPROXY is not None
        cls.running = [
            start_haproxy(HAPROXY, write_release(release, layer, certificates), cls.http)
        ]

    @classmethod
    def tearDownClass(cls) -> None:
        for process in cls.running:
            process.terminate()  # type: ignore[attr-defined]
            process.wait(timeout=5)  # type: ignore[attr-defined]
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        cls.directory.cleanup()

    def get(
        self, host: str, path: str, address: str = "127.0.0.1", method: str = "GET"
    ) -> tuple[int, str, str]:
        connection = HTTPConnection(address, self.http, timeout=5)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host)
            connection.endheaders()
            response = connection.getresponse()
            return response.status, response.read().decode(), response.getheader("location") or ""
        finally:
            connection.close()


class TheChallengeReachesTheManager(_Cluster):
    def test_a_restricted_site_that_redirects_still_answers_the_challenge(self) -> None:
        self.assertEqual(
            self.get("locked.example.com", CHALLENGE)[:2], (200, f"manager {CHALLENGE}")
        )

    def test_the_restrictions_still_hold_for_everything_else(self) -> None:
        self.assertEqual(self.get("locked.example.com", "/")[0], 403)

    def test_an_open_site_redirects_everything_but_the_challenge(self) -> None:
        status, _, location = self.get("open.example.com", "/")
        self.assertEqual((status, location), (301, "https://open.example.com/"))
        self.assertEqual(self.get("open.example.com", CHALLENGE)[:2], (200, f"manager {CHALLENGE}"))

    def test_a_name_no_site_claims_is_answered_for_the_challenge_too(self) -> None:
        self.assertEqual(
            self.get("nobody.example.com", CHALLENGE)[:2], (200, f"manager {CHALLENGE}")
        )
        self.assertEqual(self.get("nobody.example.com", "/")[0], 503)

    def test_an_address_without_a_site_on_port_80_answers_only_the_challenge(self) -> None:
        self.assertEqual(
            self.get("secure.example.com", CHALLENGE, "127.0.0.2")[:2],
            (200, f"manager {CHALLENGE}"),
        )
        self.assertEqual(self.get("secure.example.com", "/", "127.0.0.2")[0], 404)

    def test_the_challenge_leaves_from_the_vips_source_address(self) -> None:
        # A firewall in front of the manager is written for the source address;
        # the node's own address is never in it (26-11-15, found in production).
        for host, address, vip in (
            ("locked.example.com", "127.0.0.1", "main"),
            ("secure.example.com", "127.0.0.2", "other"),
        ):
            with self.subTest(vip=vip):
                self.assertEqual(self.get(host, CHALLENGE, address)[0], 200)
                self.assertEqual(self.seen[-1], SOURCES[vip])


class OnlyARealChallengeReachesTheManager(_Cluster):
    def test_a_path_that_only_starts_like_one_takes_the_way_any_request_takes(self) -> None:
        prefix = "/.well-known/acme-challenge/"
        for path in (
            prefix + "../../etc/passwd",
            prefix + "%2e%2e/x",
            prefix + "a/b",
            prefix + "%2e%2e%2fx",
            prefix,
        ):
            with self.subTest(path=path):
                self.assertEqual(self.get("locked.example.com", path)[0], 403)
                self.assertEqual(self.get("open.example.com", path)[0], 301)
                self.assertEqual(self.get("secure.example.com", path, "127.0.0.2")[0], 404)

    def test_only_get_and_head_are_a_challenge(self) -> None:
        self.assertEqual(self.get("locked.example.com", CHALLENGE, method="POST")[0], 403)
        self.assertEqual(self.get("open.example.com", CHALLENGE, method="POST")[0], 301)
        # The stand-in manager has no HEAD; 501 is its answer, so the request got there.
        self.assertEqual(self.get("locked.example.com", CHALLENGE, method="HEAD")[0], 501)

    def test_a_token_of_the_base64url_characters_is_one(self) -> None:
        path = "/.well-known/acme-challenge/Ab-9_zZ"
        self.assertEqual(self.get("locked.example.com", path)[:2], (200, f"manager {path}"))


class WithoutTheSettingTheChallengeIsRefused(_Cluster):
    send = False

    def test_the_restricted_site_refuses_it(self) -> None:
        self.assertEqual(self.get("locked.example.com", CHALLENGE)[0], 403)

    def test_the_open_site_sends_it_to_https(self) -> None:
        self.assertEqual(self.get("open.example.com", CHALLENGE)[0], 301)


if __name__ == "__main__":
    unittest.main()
