"""The generator writes no control character from the model into a file (B450, X01).

Validation is each field's job and a field can be wrong; what the generator
writes is a line-based format, so a value holding a line break is more
configuration. The check behind the fields holds every value the generator is
given, so a field added later with the same gap is stopped too.
"""

from __future__ import annotations

import dataclasses
import unittest

from haprion.config import Vip
from haprion.generate import GeneratorError, generate
from haprion.proxy_model import Proxy, load_proxy
from tests.test_proxy_model import MINIMAL

VIPS = {"main": Vip(name="main", address="192.0.2.1")}


def run(proxy: Proxy, **more: object) -> None:
    generate([proxy], vips=VIPS, default_vip="main", **more)  # type: ignore[arg-type]


def with_host(host: str) -> Proxy:
    proxy = load_proxy("shop", MINIMAL)
    backend = proxy.backends["web"]
    server = dataclasses.replace(backend.servers[0], host=host)
    backends = {"web": dataclasses.replace(backend, servers=(server,))}
    return dataclasses.replace(proxy, backends=backends)


class TheGuardBehindTheFields(unittest.TestCase):
    def test_an_unchanged_object_is_generated(self) -> None:
        run(load_proxy("shop", MINIMAL))

    def test_every_control_character_in_a_modelled_value_is_refused(self) -> None:
        for character in ("\n", "\r", "\x00", "\x0b", "\x1b", "\x7f", "\t"):
            with self.subTest(character=character), self.assertRaises(GeneratorError) as caught:
                run(with_host(f"::1{character}global"))
            self.assertIn("control character", str(caught.exception))

    def test_a_value_in_the_cluster_inputs_is_held_to_it_too(self) -> None:
        proxy = load_proxy("shop", MINIMAL)
        with self.assertRaises(GeneratorError):
            run(proxy, trusted_proxies=["192.0.2.0/24\nglobal"])
        with self.assertRaises(GeneratorError):
            run(proxy, networks={"office": ["192.0.2.0/24\nglobal"]})


if __name__ == "__main__":
    unittest.main()
