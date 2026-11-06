"""Server names the manager cannot resolve: said where they are typed and published (finding 72)."""

from __future__ import annotations

import io
import threading
import time
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
            server_names.lookups(proxies, known("app-1.example.com")).unresolved,
            ["typo.example.com"],
        )

    def test_a_resolver_that_fails_leaves_the_name_unresolved_not_unasked(self) -> None:
        def broken(host: str) -> bool:
            raise OSError("boom")

        found = server_names.lookups([site("shop", "app-1.example.com")], broken)

        self.assertEqual((found.unresolved, found.unasked), (["app-1.example.com"], []))

    def test_many_unresolved_names_are_a_few_sentences_and_a_count(self) -> None:
        names = [f"app-{number}.example.com" for number in range(40)]

        said = server_names.warnings(names)

        self.assertEqual(len(said), server_names.SAID_ONE_BY_ONE + 1)
        self.assertEqual(said[0], server_names.warning(names[0]))
        self.assertTrue(said[-1].startswith("35 more server names are not in DNS"))
        self.assertIn("app-5.example.com", said[-1])
        self.assertNotIn("app-39.example.com", said[-1])
        self.assertEqual(
            server_names.warnings(names[:2]), [server_names.warning(n) for n in names[:2]]
        )
        self.assertEqual(server_names.warnings([]), [])

    def test_the_lookups_stop_when_their_time_is_spent(self) -> None:
        """B483: a resolver that does not answer costs seconds a name, under the lock."""

        now = [0.0]
        asked: list[str] = []

        def slow(host: str) -> bool:
            asked.append(host)
            now[0] += 4.0
            return host != "typo.example.com"

        proxies = [site("shop", *(f"app-{number}.example.com" for number in range(5)))]
        proxies.append(site("blog", "typo.example.com"))

        found = server_names.lookups(proxies, slow, seconds=10.0, clock=lambda: now[0], threads=1)

        self.assertEqual(asked, ["app-0.example.com", "app-1.example.com", "app-2.example.com"])
        self.assertEqual(found.unresolved, [])
        self.assertEqual(
            found.unasked, ["app-3.example.com", "app-4.example.com", "typo.example.com"]
        )
        self.assertEqual(server_names.lookups(proxies, known("app-0.example.com")).unasked, [])

    def test_the_names_are_asked_several_at_a_time(self) -> None:
        """B483: 11.5 ms a name the cache does not hold; one at a time would not reach thousands."""

        def slow(host: str) -> bool:
            time.sleep(0.05)
            return host != "typo-7.example.com"

        hosts = [f"typo-{number}.example.com" for number in range(64)]
        proxies = [site(f"s{number}", host) for number, host in enumerate(hosts)]
        started = time.monotonic()

        found = server_names.lookups(proxies, slow, seconds=5.0)

        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(found, server_names.Lookups(["typo-7.example.com"], []))

    def test_a_lookup_that_never_returns_holds_nothing_past_the_time(self) -> None:
        stuck = threading.Event()
        started = time.monotonic()

        found = server_names.lookups(
            [site("shop", "a.example.com", "b.example.com")],
            lambda host: stuck.wait(30) or True,
            seconds=0.3,
        )

        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(found, server_names.Lookups([], ["a.example.com", "b.example.com"]))
        stuck.set()

    def test_the_names_not_looked_up_are_one_sentence(self) -> None:
        said = server_names.unasked_warning([f"app-{number}.example.com" for number in range(7)])

        self.assertIn("7 server names were not looked up (app-0.example.com,", said)
        self.assertIn("app-4.example.com, ...)", said)
        self.assertIn("the deploy stops", said)
        self.assertIn(
            "1 server name was not looked up", server_names.unasked_warning(["a.example"])
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
        self.assertNotIn("not looked up", out.getvalue())

    def test_the_names_not_looked_up_are_a_warning_once(self) -> None:
        plan = objects_apply.Plan(
            documents={"shop": "x"}, added=("shop",), changed=(), removed=(), unchanged=()
        )
        versions = [
            {"version": 4, "hash": "a" * 40, "changed": True, "unasked_servers": ["late.x"]},
            {"version": 5, "hash": "b" * 40, "changed": True, "unasked_servers": ["late.x"]},
        ]
        summary = objects_apply._summary(plan, check=False, versions=versions)
        out = io.StringIO()

        objects_apply._render("alpha", plan, summary, out)

        self.assertEqual(summary["unasked_servers"], ["late.x"])
        self.assertEqual(out.getvalue().count("WARNING: 1 server name was not looked up"), 1)
