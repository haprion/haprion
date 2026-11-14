"""The HTTP-01 challenge goes to the manager, whatever else the frontend decides (PL17).

An object that redirects http to https, restricts who may reach it or sits
behind a blocklist would otherwise refuse the certificate authority, whose
validation servers are nobody's clients. The rules held here are the order
HAProxy runs them in: every `http-request` rule before `redirect`, and both
before `use_backend`, wherever they are written.
"""

from __future__ import annotations

import re
import unittest

from haprion.cluster_settings import AcmeChallenge, ClusterSettings, dump_document, load_document
from haprion.config import ConfigError
from haprion.generate import ACME_CHALLENGE, GeneratorError, generate
from haprion.golden import GOLDEN, arguments, objects
from haprion.proxy_model import load_proxy
from haprion.reservations import load_reservations

CASE = GOLDEN / "acme-challenge"
SETTINGS = ClusterSettings(acme_challenge=AcmeChallenge("192.0.2.5", 8080))
CONDITION = f"{ACME_CHALLENGE}-path"


def frontend(text: str, name: str) -> list[str]:
    """One frontend's lines, from its header to the next section."""

    block = re.search(rf"^frontend {name}\n(.*?)(?=^(?:frontend|backend) |\Z)", text, re.S | re.M)
    if block is None:
        raise AssertionError(f"no frontend {name}")
    return [line for line in block.group(1).splitlines() if line]


def layer(settings: ClusterSettings = SETTINGS, reservations: bytes = b"{}") -> str:
    options = arguments(CASE)
    options["settings"] = settings
    return generate(
        objects(CASE), reservations=load_reservations(reservations), **options
    ).configuration["1000-frontends.cfg"]


class TheChallengeIsLetThroughBeforeAnythingRefusesIt(unittest.TestCase):
    def test_nothing_is_written_without_the_setting(self) -> None:
        text = layer(ClusterSettings())
        self.assertNotIn("acme", text)
        self.assertNotIn("well-known", text)

    def test_the_first_deciding_rule_of_every_http_frontend_lets_it_through(self) -> None:
        text = layer()
        for name in ("mgd-internal-http", "mgd-plain-http"):
            with self.subTest(frontend=name):
                rules = [
                    line.strip()
                    for line in frontend(text, name)
                    if line.strip().startswith("http-request") and "set-var(txn.traffic" not in line
                ]
                self.assertEqual(rules[0], f"http-request allow if {CONDITION}")
                self.assertIn(
                    f"    acl {CONDITION} path_beg /.well-known/acme-challenge/",
                    frontend(text, name),
                )

    def test_the_redirect_leaves_the_path_alone(self) -> None:
        lines = frontend(layer(), "mgd-internal-http")
        redirect = [line for line in lines if "redirect scheme" in line]
        self.assertEqual(
            redirect, [f"    redirect scheme https code 301 if mgd-app-host !{CONDITION}"]
        )

    def test_the_challenge_is_routed_before_any_site(self) -> None:
        for name in ("mgd-internal-http", "mgd-plain-http"):
            with self.subTest(frontend=name):
                routes = [line for line in frontend(layer(), name) if "use_backend" in line]
                self.assertEqual(routes[0], f"    use_backend {ACME_CHALLENGE} if {CONDITION}")
                self.assertEqual(len(routes) - len(set(routes)), 0)

    def test_https_frontends_are_not_touched(self) -> None:
        for name in ("mgd-internal-https", "mgd-dmz-https"):
            with self.subTest(frontend=name):
                self.assertNotIn("acme", "\n".join(frontend(layer(), name)))

    def test_the_backend_is_the_manager_without_a_check(self) -> None:
        self.assertIn(
            f"\nbackend {ACME_CHALLENGE}\n    mode http\n    server manager 192.0.2.5:8080\n",
            layer(),
        )

    def test_an_address_with_https_only_gets_a_frontend_for_the_challenge_alone(self) -> None:
        lines = frontend(layer(), "mgd-dmz-http")
        self.assertIn("    bind 198.51.100.20:80 guid-prefix li:dmz-http.0a8854d019d4672e", lines)
        self.assertEqual(
            lines[-2:],
            [
                f"    http-request return status 404 if !{CONDITION}",
                f"    use_backend {ACME_CHALLENGE} if {CONDITION}",
            ],
        )
        self.assertNotIn("redirect", "\n".join(lines))

    def test_it_follows_the_clusters_http_port(self) -> None:
        options = arguments(CASE)
        options["settings"] = SETTINGS
        options["ports"] = {"http": 8081, "https": 8443}
        text = generate(objects(CASE), **options).configuration["1000-frontends.cfg"]
        self.assertIn("bind 198.51.100.20:8081 ", "\n".join(frontend(text, "mgd-dmz-http")))

    def test_an_ipv6_manager_is_bracketed(self) -> None:
        text = layer(ClusterSettings(acme_challenge=AcmeChallenge("2001:db8::5", 80)))
        self.assertIn("    server manager [2001:db8::5]:80\n", text)


class WhatTakesThePortRefusesItByName(unittest.TestCase):
    def refused(self, reservations: bytes = b"{}") -> str:
        with self.assertRaises(GeneratorError) as caught:
            layer(reservations=reservations)
        return str(caught.exception)

    def test_a_reservation_on_the_address_and_port(self) -> None:
        said = self.refused(b"tcp_ports: ['198.51.100.20:80']\n")
        self.assertIn("HTTP-01 challenge", said)
        self.assertIn("dmz port 80", said)
        self.assertIn("manual/reservations.yaml", said)

    def test_a_reservation_of_the_port_on_every_address(self) -> None:
        self.assertIn("manual/reservations.yaml", self.refused(b"tcp_ports: [80]\n"))

    def test_a_tcp_object_on_the_port_names_the_object(self) -> None:
        options = arguments(CASE)
        options["settings"] = SETTINGS
        proxies = [
            *objects(CASE),
            load_proxy(
                "ssh",
                b"""schema: 1
name: ssh
listen:
  protocol: tcp
  vip: dmz
  port: 80
backend: ssh-pool
backends:
  ssh-pool:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 198.51.100.13
        port: 22
""",
            ),
        ]
        with self.assertRaisesRegex(GeneratorError, "ssh listens on dmz port 80"):
            generate(proxies, **options)

    def test_nothing_is_refused_without_the_setting(self) -> None:
        layer(ClusterSettings(), reservations=b"tcp_ports: ['198.51.100.20:80']\n")


class TheSettingInTheFile(unittest.TestCase):
    def test_the_port_is_80_unless_written(self) -> None:
        settings = load_document(b"acme_challenge: {address: 192.0.2.5}\n")
        self.assertEqual(settings.acme_challenge, AcmeChallenge("192.0.2.5", 80))
        self.assertEqual(load_document(dump_document(settings)), settings)
        self.assertIn(b"port: 80", dump_document(settings))

    def test_a_name_is_not_an_address(self) -> None:
        for document in (
            b"acme_challenge: {address: manager.example.com}",
            b"acme_challenge: {port: 80}",
            b"acme_challenge: {address: 192.0.2.5, port: 0}",
            b"acme_challenge: {address: 192.0.2.5, host: x}",
            b"acme_challenge: 192.0.2.5",
        ):
            with self.subTest(document=document), self.assertRaises(ConfigError):
                load_document(document)

    def test_without_it_the_file_says_nothing(self) -> None:
        self.assertNotIn(b"acme", dump_document(ClusterSettings()))


if __name__ == "__main__":
    unittest.main()
