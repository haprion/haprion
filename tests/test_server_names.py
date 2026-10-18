"""Server names the manager cannot resolve: said where they are typed and published (finding 72)."""

from __future__ import annotations

import io
import unittest

from haprion import server_names
from haprion.cli import objects_apply
from haprion.proxy_model import Proxy, load_proxy


def site(name: str, *hosts: str) -> Proxy:
    servers = "".join(f"      - host: {host}\n        port: 8080\n" for host in hosts)
    text = (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
        "listen:\n  protocol: http\n"
        "routes:\n  - path: /\n    backend: web\n"
        f"backends:\n  web:\n    balance: roundrobin\n    servers:\n{servers}"
    )
    return load_proxy(name, text.encode())


def known(*names: str) -> server_names.Resolves:
    return lambda host: host in names


class WhichNamesAreAsked(unittest.TestCase):
    def test_names_once_each_and_never_an_address(self) -> None:
        proxies = [
            site("shop", "app-1.example.com", "198.51.100.10"),
            site("blog", "app-1.example.com", "app-2.example.com", "2001:db8::10"),
        ]

        self.assertEqual(server_names.names(proxies), ["app-1.example.com", "app-2.example.com"])

    def test_only_the_names_that_do_not_resolve(self) -> None:
        proxies = [site("shop", "app-1.example.com", "typo.example.com")]

        self.assertEqual(
            server_names.unresolved(proxies, known("app-1.example.com")), ["typo.example.com"]
        )

    def test_the_sentence_names_the_server_and_the_consequence(self) -> None:
        said = server_names.warning("typo.example.com")

        self.assertIn("typo.example.com is not in DNS as the manager sees it", said)
        self.assertIn("the deploy stops", said)


class TheTerminalSaysIt(unittest.TestCase):
    def test_each_publish_s_names_are_a_warning_once(self) -> None:
        plan = objects_apply.Plan(
            documents={"shop": "x"},
            added=("shop",),
            changed=(),
            removed=(),
            unchanged=(),
            diffs={},
        )
        versions = [
            {"version": 4, "hash": "a" * 40, "changed": True, "unresolved_servers": ["typo.x"]},
            {"version": 5, "hash": "b" * 40, "changed": True, "unresolved_servers": ["typo.x"]},
        ]
        summary = objects_apply._summary(plan, check=False, versions=versions)
        out = io.StringIO()

        objects_apply._render("alpha", plan, summary, out)

        self.assertEqual(summary["unresolved_servers"], ["typo.x"])
        self.assertEqual(out.getvalue().count("WARNING: typo.x is not in DNS"), 1)
