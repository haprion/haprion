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

from haprion.check_policy import EffectiveCheck, effective_check, effective_checks
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


if __name__ == "__main__":
    unittest.main()
