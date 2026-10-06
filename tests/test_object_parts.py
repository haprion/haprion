"""Each object's own share of a shared file.

The generated layer is not one file per object: routing goes into a frontend
every object on the address shares, and only the backends get a file of their
own. So "has this object changed" cannot be answered by hashing files, and
these tests hold the split that lets it be answered at all.

The property that matters is the one a naive split gets wrong: adding a second
site to a listener must not report the first one as changed. It is the reason
`listener` is kept apart from `routing` rather than both being read off the
frontend file.
"""

from __future__ import annotations

import unittest
from typing import Any

from haproxy_mgmt.config import Vip
from haproxy_mgmt.generate import generate
from haproxy_mgmt.golden import CERTIFICATES, DEFAULT_VIPS
from haproxy_mgmt.proxy_model import load_proxy

SHOP = b"""
schema: 1
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
    health:
      type: disabled
    servers:
      - host: 198.51.100.10
        port: 8080
"""

INTRANET = b"""
schema: 1
name: intranet
hostnames: [intranet.example.com]
listen:
  protocol: http
routes:
  - path: /
    backend: portal
backends:
  portal:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 198.51.100.11
        port: 8080
"""

SECURE = b"""
schema: 1
name: secure
hostnames: [secure.example.com]
listen:
  protocol: https
  certificate: example.com
routes:
  - path: /
    backend: secure-web
backends:
  secure-web:
    balance: roundrobin
    health:
      type: disabled
    servers:
      - host: 198.51.100.12
        port: 8443
"""


def parts(documents: list[tuple[str, bytes]], **overrides: object) -> dict[str, dict[str, str]]:
    proxies = [load_proxy(name, document) for name, document in documents]
    arguments: dict[str, Any] = {
        "vips": dict(DEFAULT_VIPS),
        "default_vip": "main",
        "certificates": CERTIFICATES,
    }
    arguments.update(overrides)
    return generate(proxies, **arguments).object_parts


class AnObjectCarriesItsOwnLinesAndNobodyElses(unittest.TestCase):
    def test_a_neighbour_arriving_leaves_an_object_untouched(self) -> None:
        """The whole reason the parts are split the way they are.

        Both sites sit in one frontend, so the file changes. If that file were
        the unit of comparison, publishing `intranet` would report `shop` as
        waiting for a deploy - which is the false claim this replaces.
        """

        alone = parts([("shop", SHOP)])
        crowded = parts([("shop", SHOP), ("intranet", INTRANET)])
        self.assertEqual(alone["shop"], crowded["shop"])

    def test_an_objects_own_change_shows_in_its_routing(self) -> None:
        restricted = SHOP.replace(b"listen:", b"allow_from: [203.0.113.0/24]\nlisten:")
        before = parts([("shop", SHOP)])
        after = parts([("shop", restricted)], networks={"office": ["203.0.113.0/24"]})
        self.assertNotEqual(before["shop"]["routing"], after["shop"]["routing"])
        self.assertEqual(before["shop"]["backends"], after["shop"]["backends"])

    def test_moving_the_address_shows_in_every_object_on_it(self) -> None:
        """A change nobody made to the object, which the object still feels.

        The VIP is not named in the object's document, so a comparison that
        read only the object's own bytes would call this no change at all.
        """

        moved = {"main": Vip(name="main", address="192.0.2.30")}
        before = parts([("shop", SHOP), ("intranet", INTRANET)])
        after = parts([("shop", SHOP), ("intranet", INTRANET)], vips=moved)
        for name in ("shop", "intranet"):
            self.assertNotEqual(before[name]["listener"], after[name]["listener"])
            self.assertEqual(before[name]["routing"], after[name]["routing"])

    def test_a_listener_policy_change_shows_without_touching_the_object(self) -> None:
        strict = {"main": Vip(name="main", address="192.0.2.20", tls_policy="modern")}
        before = parts([("secure", SECURE)])
        after = parts([("secure", SECURE)], vips=strict)
        self.assertNotEqual(before["secure"]["listener"], after["secure"]["listener"])

    def test_the_certificate_part_carries_the_objects_own_terms(self) -> None:
        strict = SECURE.replace(
            b"certificate: example.com", b"certificate: example.com\n  tls: modern"
        )
        before = parts([("secure", SECURE)])
        after = parts([("secure", strict)])
        self.assertIn("/example.com.pem", before["secure"]["certificate"])
        self.assertNotEqual(before["secure"]["certificate"], after["secure"]["certificate"])

    def test_an_object_serving_no_tls_has_no_certificate_line(self) -> None:
        self.assertEqual(parts([("shop", SHOP)])["shop"]["certificate"], "")

    def test_every_object_is_described_exactly_once(self) -> None:
        produced = parts([("shop", SHOP), ("intranet", INTRANET), ("secure", SECURE)])
        self.assertEqual(sorted(produced), ["intranet", "secure", "shop"])
        for name, entry in produced.items():
            self.assertEqual(
                sorted(entry), ["backends", "certificate", "listener", "routing"], name
            )


if __name__ == "__main__":
    unittest.main()
