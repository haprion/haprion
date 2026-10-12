"""A subdomain object's page names the exact names other objects answer under it (B278)."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any, cast

from haprion_ui.objects import ObjectView, answered_elsewhere


def view(
    name: str, *hostnames: str, vip: str | None = None, ports: tuple[int, ...] = ()
) -> ObjectView:
    addresses = None if vip is None else SimpleNamespace(vip_name=vip)
    return cast(
        ObjectView,
        SimpleNamespace(name=name, hostnames=hostnames, addresses=addresses, ports=ports),
    )


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

    def test_an_object_on_another_listener_takes_no_name(self) -> None:
        #
        # As seen on a cluster (26-10-12): monitor lives on another VIP, so
        # on the default VIP the subdomain object answers it, and the page
        # must not say otherwise.
        #
        views: list[Any] = [
            view("wildcard-probe", "*.apps.example.com", vip="vip-int", ports=(80, 443)),
            view("grafana", "grafana.apps.example.com", vip="vip-int", ports=(80, 443)),
            view("monitor", "monitor.apps.example.com", vip="vip-second", ports=(80, 443)),
            view("dns", "ns.apps.example.com", vip="vip-int", ports=(53,)),
        ]

        self.assertEqual(
            answered_elsewhere("wildcard-probe", ("*.apps.example.com",), views),
            (("grafana.apps.example.com", "grafana"),),
        )


if __name__ == "__main__":
    unittest.main()
