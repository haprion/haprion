"""A subdomain object's page names the exact names other objects answer under it (B278)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any, cast

from haprion_ui.objects import ObjectView, answered_elsewhere


def view(name: str, *hostnames: str) -> ObjectView:
    return cast(ObjectView, SimpleNamespace(name=name, hostnames=hostnames))


class TheNamesASubdomainYields(unittest.TestCase):
    def test_exact_names_under_it_are_listed_with_their_object(self) -> None:
        views: list[Any] = [
            view("apps", "*.apps.example.com"),
            view("grafana", "grafana.apps.example.com"),
            view("deep", "a.b.apps.example.com"),
            view("shop", "shop.example.com"),
        ]

        self.assertEqual(
            answered_elsewhere("apps", ("*.apps.example.com",), views),
            (("grafana.apps.example.com", "grafana"),),
        )

    def test_an_object_without_a_subdomain_lists_nothing(self) -> None:
        self.assertEqual(
            answered_elsewhere("shop", ("shop.example.com",), [view("grafana", "x.example.com")]),
            (),
        )


if __name__ == "__main__":
    unittest.main()
