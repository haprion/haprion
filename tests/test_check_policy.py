"""What a check does, decided in one place.

The rules were written twice: the generator read the model and wrote HAProxy's
words, and the interface's probe read the form's fields and built a request. A
question with two derivations drifts, and this pair had drifted already - B92
found the probe reading the wrong field in four places, so ticking the check's
own TLS box changed the configuration and changed nothing about what was run.

These hold the rules themselves. The generator's own output is held to the byte
by the golden files, and this module is what both of them now ask.
"""

from __future__ import annotations

import unittest

from haprion.check_policy import EffectiveCheck, effective_check, effective_checks, tls_mismatches
from haprion.proxy_model import Proxy, load_proxy

DOCUMENT = """schema: 1
name: shop
hostnames: [shop.example.com]
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    balance: roundrobin
{pool}
    health:
      type: {type}
{health}
    servers:
    - host: {host}
      port: 8080
"""


def proxy(
    *,
    type: str = "http",
    health: str = "",
    pool: str = "",
    host: str = "198.51.100.10",
) -> Proxy:
    #
    # An http check needs a path and the other kinds refuse one, so the fixture
    # supplies it where it belongs rather than every case repeating it.
    #
    path = "      path: /healthz\n" if type == "http" else ""
    document = DOCUMENT.format(type=type, health=path + health, pool=pool, host=host)
    return load_proxy("shop", document.encode())


def check(
    *, type: str = "http", health: str = "", pool: str = "", host: str = "198.51.100.10"
) -> EffectiveCheck:
    built = proxy(type=type, health=health, pool=pool, host=host)
    return effective_check(built.backends["web"], built.backends["web"].servers[0])


TLS_POOL = "    tls:\n      verify: none\n"
VERIFIED_POOL = "    tls:\n      verify: system\n"


class WhetherTheCheckSpeaksTls(unittest.TestCase):
    """Three answers from two fields, and the middle one is the one people get wrong."""

    def test_saying_nothing_follows_the_pool(self) -> None:
        self.assertFalse(check().encrypted)
        self.assertTrue(check(pool=TLS_POOL).encrypted)

    def test_a_check_of_its_own_overrules_the_pool_in_both_directions(self) -> None:
        """The two combinations that could not be expressed at all before B92."""

        self.assertTrue(check(health="      tls: true\n").encrypted)
        self.assertFalse(check(pool=TLS_POOL, health="      tls: false\n").encrypted)

    def test_a_check_port_does_not_change_the_answer(self) -> None:
        """Only how the generator spells it: inheritance stops at another port.

        A TLS pool checked on a different port is still a TLS check - the
        configuration says `check-ssl` there rather than relying on what it
        would otherwise inherit.
        """

        self.assertTrue(check(pool=TLS_POOL, health="      port: 9443\n").encrypted)


class WhereTheCheckIsSent(unittest.TestCase):
    def test_the_traffic_port_unless_the_check_names_its_own(self) -> None:
        self.assertEqual(check().port, 8080)
        self.assertEqual(check(health="      port: 9443\n").port, 9443)

    def test_the_server_is_the_pool_member_itself(self) -> None:
        self.assertEqual(check().host, "198.51.100.10")


class WhatTheConnectionIsHeldTo(unittest.TestCase):
    def test_a_plain_pool_verifies_nothing(self) -> None:
        self.assertFalse(check().verify)

    def test_a_pool_that_trusts_nobody_verifies_nothing_either(self) -> None:
        self.assertFalse(check(pool=TLS_POOL).verify)

    def test_a_verified_pool_says_so(self) -> None:
        """Named servers, because verification checks a certificate against a name."""

        self.assertTrue(check(pool=VERIFIED_POOL, host="pool-a.example.net").verify)

    def test_a_pool_verified_against_its_own_ca_names_it(self) -> None:
        """The probe trusts the file HAProxy's `ca-file` does (B276, 26-10-12)."""

        own = check(
            pool="    tls:\n      verify: ca\n      ca: example-ca\n", host="pool-a.example.net"
        )

        self.assertTrue(own.verify)
        self.assertEqual(own.authority, "example-ca")
        self.assertIsNone(check(pool=VERIFIED_POOL, host="pool-a.example.net").authority)
        self.assertIsNone(check(pool=TLS_POOL).authority)

    def test_the_floor_is_the_pools_own_and_not_the_readers(self) -> None:
        lax = check(pool="    tls:\n      verify: none\n      policy: legacy\n")

        self.assertEqual(lax.min_version, "TLSv1.1")
        self.assertEqual(check().min_version, "TLSv1.2")


class WhatCannotBeReproducedWithoutHaproxy(unittest.TestCase):
    """Carried so that whoever stands in for the check can say what they skipped."""

    def test_a_body_condition_is_named(self) -> None:
        self.assertEqual(check(health='      expect_body: "ok"\n').expect_body, "ok")

    def test_a_tcp_exchange_is_named(self) -> None:
        exchange = check(type="tcp", health='      send: "PING"\n      expect: "PONG"\n')

        self.assertEqual((exchange.send, exchange.expect), ("PING", "PONG"))


class EveryCheckAnObjectRuns(unittest.TestCase):
    def test_a_disabled_check_is_left_out_rather_than_returned_silent(self) -> None:
        self.assertEqual(effective_checks(proxy(type="disabled")), ())

    def test_one_per_server(self) -> None:
        self.assertEqual(len(effective_checks(proxy())), 1)


class WhereTheCheckAndTheTrafficDisagree(unittest.TestCase):
    """26-11-03: a plain check passed while TLS traffic to the same port failed."""

    def test_a_plain_check_on_a_tls_pool_is_said(self) -> None:
        said = tls_mismatches(proxy(pool=TLS_POOL, health="      tls: false\n"))

        self.assertEqual(
            said,
            [
                "The health check connects to port 8080 without TLS and the traffic with;"
                " one of the two will fail"
            ],
        )

    def test_a_tls_check_on_a_plain_pool_is_said(self) -> None:
        for type, health in (
            ("http", "      tls: true\n"),
            ("tcp", "      tls: true\n"),
            ("tcp", '      tls: true\n      send: "PING"\n      expect: "PONG"\n'),
        ):
            with self.subTest(type=type, health=health):
                said = tls_mismatches(proxy(type=type, health=health))

                self.assertEqual(len(said), 1)
                self.assertIn("with TLS and the traffic without", said[0])

    def test_a_plain_exchange_on_a_tls_pool_is_said(self) -> None:
        exchange = '      tls: false\n      send: "PING"\n      expect: "PONG"\n'

        self.assertEqual(len(tls_mismatches(proxy(type="tcp", pool=TLS_POOL, health=exchange))), 1)

    def test_agreement_says_nothing(self) -> None:
        self.assertEqual(tls_mismatches(proxy()), [])
        self.assertEqual(tls_mismatches(proxy(pool=TLS_POOL)), [])
        self.assertEqual(tls_mismatches(proxy(health="      tls: false\n")), [])
        self.assertEqual(tls_mismatches(proxy(pool=TLS_POOL, health="      tls: true\n")), [])

    def test_a_check_port_of_its_own_says_nothing(self) -> None:
        """Another port is another service; the check owes the traffic nothing there."""

        said = tls_mismatches(proxy(pool=TLS_POOL, health="      tls: false\n      port: 9000\n"))

        self.assertEqual(said, [])

    def test_a_plain_connect_says_nothing(self) -> None:
        """It speaks neither, so it disagrees with nothing."""

        self.assertEqual(
            tls_mismatches(proxy(type="tcp", pool=TLS_POOL, health="      tls: false\n")), []
        )

    def test_a_disabled_check_says_nothing(self) -> None:
        self.assertEqual(tls_mismatches(proxy(type="disabled", pool=TLS_POOL)), [])


if __name__ == "__main__":
    unittest.main()
