"""What HAProxy calls an object's backends (B250, 2026-10-06).

The name is the `proxy` label HAProxy's exporter puts on every metric, so it is
what a dashboard shows - and the exporter carries nothing else that could:
`description` is not exported (measured on 3.4.6). A pool is therefore named
by itself, and the cluster has to keep that name unique.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from haprion import generate as generator
from haprion import golden
from haprion.generate import (
    GeneratorError,
    backend_name,
    generate,
    runtime_backends,
)
from haprion.objects import objects_result
from haprion.proxy_model import GENERATED_PREFIX, ModelError, Proxy, load_proxy

COMMIT = "a" * 40


def site(name: str, pools: str = "web", *, redirect: str = "", advanced: str = "") -> Proxy:
    """An http object; the first pool takes `/`, each other one a path of its own."""

    names = pools.split()
    routes = f"  - path: /\n    backend: {names[0]}\n" + "".join(
        f"  - path: /to-{pool}\n    backend: {pool}\n" for pool in names[1:]
    )
    if redirect:
        routes += f"  - path: {redirect}\n    redirect:\n      location: https://example.net/\n"
    backends = "".join(
        f"  {pool}:\n    balance: roundrobin\n    servers:\n"
        f"      - host: 198.51.100.10\n        port: 8080\n"
        for pool in names
    )
    text = (
        f"schema: 1\nname: {name}\nhostnames: [{name.replace('_', '-')}.example.com]\n"
        f"listen:\n  protocol: http\n"
        f"routes:\n{routes}backends:\n{backends}"
    )
    if advanced:
        text += "advanced: |\n" + "".join(f"  {line}\n" for line in advanced.splitlines())
    return load_proxy(name, text.encode())


def layer(*proxies: Proxy) -> dict[str, str]:
    arguments: dict[str, Any] = golden.arguments(Path("/nonexistent"))
    return generate(list(proxies), **arguments).configuration


class APoolIsNamedByItself(unittest.TestCase):
    def test_the_pool_is_the_backend_and_every_reference_says_so(self) -> None:
        proxy = site("monitor-server_admin-web", "admin-web_80")
        files = layer(proxy)

        self.assertEqual(backend_name(proxy, "admin-web_80"), "admin-web_80")
        self.assertIn("\nbackend admin-web_80\n", files["1001-monitor-server_admin-web.cfg"])
        self.assertIn("use_backend admin-web_80 if", files["1000-frontends.cfg"])
        self.assertNotIn("mgd-monitor-server_admin-web-admin-web_80", "".join(files.values()))

    def test_a_redirect_keeps_its_object_in_front(self) -> None:
        proxy = site("ftp-server_admin-web", "ftp-server", redirect="/old")

        self.assertEqual(runtime_backends(proxy), ["ftp-server", "ftp-server_admin-web-redirect-old"])
        self.assertIn(
            "\nbackend ftp-server_admin-web-redirect-old\n", layer(proxy)["1001-ftp-server_admin-web.cfg"]
        )

    def test_the_generators_own_prefix_is_held_in_one_place(self) -> None:
        self.assertEqual(GENERATED_PREFIX, f"{generator.PREFIX}-")


class ThePoolNameIsTheClusters(unittest.TestCase):
    def test_two_objects_may_not_both_call_a_pool_web(self) -> None:
        with self.assertRaisesRegex(GeneratorError, r"unique in the cluster.*web \(shop, store\)"):
            layer(site("shop"), site("store"))

    def test_a_pool_may_not_take_another_objects_redirect_name(self) -> None:
        with self.assertRaisesRegex(GeneratorError, r"shop-redirect-old \(other, shop\)"):
            layer(site("shop", redirect="/old"), site("other", "other-web shop-redirect-old"))

    def test_a_pool_may_not_begin_like_the_generators_names(self) -> None:
        with self.assertRaisesRegex(ModelError, "mgd-metrics begins with mgd-"):
            site("shop", "mgd-metrics")

    def test_an_added_section_may_not_take_another_objects_pool_name(self) -> None:
        added = site("a", "a-web", advanced="backend a-cache\n    mode tcp")
        with self.assertRaisesRegex(GeneratorError, "a-cache has the name of a backend of b"):
            layer(added, site("b", "a-cache"))

    def test_distinct_pools_on_several_objects_are_fine(self) -> None:
        files = layer(site("shop", "shop-web"), site("store", "store-web"))

        self.assertIn("\nbackend shop-web\n", files["1001-shop.cfg"])
        self.assertIn("\nbackend store-web\n", files["1001-store.cfg"])


class TheObjectsHelperSaysTheNames(unittest.TestCase):
    """The interface finds an object's backends here, never by splitting a name."""

    def test_every_backend_of_the_object_is_listed(self) -> None:
        text = (
            b"schema: 1\nname: ftp-server_admin-web\nhostnames: [ftp.example.com]\n"
            b"listen:\n  protocol: http\nroutes:\n  - path: /\n    backend: ftp-server\n"
            b"  - path: /old\n    redirect:\n      location: https://example.net/\n"
            b"backends:\n  ftp-server:\n    balance: roundrobin\n    servers:\n"
            b"      - host: 198.51.100.10\n        port: 8080\n"
        )
        result: dict[str, Any] = objects_result(
            {"managed/proxies/ftp-server_admin-web.yaml": text}, COMMIT
        )

        self.assertEqual(
            result["objects"][0]["runtime_backends"], ["ftp-server", "ftp-server_admin-web-redirect-old"]
        )

    def test_an_unreadable_object_says_nothing(self) -> None:
        result: dict[str, Any] = objects_result(
            {"managed/proxies/shop.yaml": b"schema: 1\nname: shop\n"}, COMMIT
        )

        self.assertIsNone(result["objects"][0]["runtime_backends"])


if __name__ == "__main__":
    unittest.main()
