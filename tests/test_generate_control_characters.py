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


class AdvancedConfigAgreesWithTheModel(unittest.TestCase):
    """Review 26-11-05, XX01: the model keeps a tab in advanced config and the guard refused it.

    A refusal at publish stopped every object of the cluster for one pasted tab.
    """

    def advanced(self, text: str) -> Proxy:
        return load_proxy("shop", MINIMAL + f"advanced: {text}\n".encode())

    def test_a_tab_between_words_or_inside_a_quoted_value_is_written(self) -> None:
        for text in (
            '"http-request\\tset-header X-A b\\n"',
            '"http-request set-header X-A \\"a\\tb\\"\\n"',
            '"# a note\\there\\nhttp-request set-header X-A b\\n"',
        ):
            with self.subTest(text=text):
                out = generate([self.advanced(text)], vips=VIPS, default_vip="main")

                self.assertIn("X-A", "".join(out.configuration.values()))

    def test_a_refusal_names_the_object_and_the_field_and_not_the_input(self) -> None:
        proxy = self.advanced('"http-request set-header X-A b\\n"')
        placement = dataclasses.replace(
            proxy.advanced.placement,  # type: ignore[union-attr]
            lines=tuple(
                dataclasses.replace(line, text=line.text.replace("b", "b\x0bc"))
                for line in proxy.advanced.placement.lines  # type: ignore[union-attr]
            ),
        )
        proxy = dataclasses.replace(
            proxy,
            advanced=dataclasses.replace(proxy.advanced, placement=placement),  # type: ignore[type-var]
        )

        with self.assertRaises(GeneratorError) as caught:
            run(proxy)

        message = str(caught.exception)
        self.assertTrue(message.startswith("shop.advanced holds a control character"), message)
        self.assertNotIn("input[", message)
        self.assertNotIn("placement", message)


if __name__ == "__main__":
    unittest.main()
