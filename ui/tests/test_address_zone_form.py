"""The form refuses an address with a zone ID, as every other way in does (B450, X01)."""

from __future__ import annotations

import unittest

from haprion.proxy_model import ModelError, load_proxy

from haprion_ui.preview import DEFAULTS, build_document

ZONED = ("2001:db8::1%x\nglobal", "fe80::1%eth0", "2001:db8::1%a b")


class TheFormWritesWhatTheModelRefuses(unittest.TestCase):
    def test_a_server_address_and_an_allowed_range(self) -> None:
        for value in ZONED:
            with self.subTest(value=value):
                for fields in (
                    {"servers": f"{value}:8080"},
                    {"servers": "198.51.100.10:8080", "allow_ranges": value},
                ):
                    with self.assertRaises((ModelError, ValueError)):
                        load_proxy(
                            "app",
                            build_document(
                                dict(
                                    DEFAULTS,
                                    name="app",
                                    hostnames="app.example.com",
                                    protocol="http",
                                    **fields,
                                )
                            ).encode(),
                        )


if __name__ == "__main__":
    unittest.main()
