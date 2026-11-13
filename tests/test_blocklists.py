"""Blocklists: the format, the limits, the exceptions and the fetch (B496 nr 13, B500)."""

from __future__ import annotations

import base64
import ipaddress
import random
import ssl
import threading
import time
import tracemalloc
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from haprion import blocklists
from haprion.blocklists import BlocklistError
from tests.test_oidc import CA_PEM, SERVER_CONTEXT

SPAMHAUS = b"""; Spamhaus DROP List 2026/11/10 - (c) 2026 The Spamhaus Project
; Last-Modified: Tue, 10 Nov 2026 06:00:00 GMT
192.0.2.0/24 ; SBL000001
198.51.100.0/25 ; SBL000002
"""
FIREHOL = b"""#
# firehol_level1
#
203.0.113.0/24
2001:db8::/32
"""
RAW = b"192.0.2.7\n198.51.100.200\n# the end\n"


def quad(*octets: int) -> str:
    """An address from its octets; the private ones are the subject here and not written out."""

    return ".".join(str(octet) for octet in octets)


def _networks(*values: str) -> tuple[blocklists.Network, ...]:
    return tuple(ipaddress.ip_network(value) for value in values)


class TheFormatIsOneAddressToALine(unittest.TestCase):
    def test_the_three_known_lists_read(self) -> None:
        self.assertEqual(
            blocklists.parse(SPAMHAUS).networks, _networks("192.0.2.0/24", "198.51.100.0/25")
        )
        self.assertEqual(
            blocklists.parse(FIREHOL).networks, _networks("203.0.113.0/24", "2001:db8::/32")
        )
        self.assertEqual(
            blocklists.parse(RAW).networks, _networks("192.0.2.7/32", "198.51.100.200/32")
        )

    def test_a_line_that_is_not_an_address_is_skipped_and_counted(self) -> None:
        parsed = blocklists.parse(b"192.0.2.1\nnot an address\n<html>\n198.51.100.1\n")
        self.assertEqual(parsed.skipped, 2)
        self.assertEqual(len(parsed.networks), 2)

    def test_an_entire_address_family_is_skipped(self) -> None:
        parsed = blocklists.parse(b"0.0.0.0/0\n::/0\n192.0.2.1\n")
        self.assertEqual(parsed.skipped, 2)
        self.assertEqual(parsed.networks, _networks("192.0.2.1/32"))

    def test_host_bits_are_read_as_the_network_the_list_named(self) -> None:
        self.assertEqual(blocklists.parse(b"192.0.2.9/24\n").networks, _networks("192.0.2.0/24"))

    def test_a_mapped_address_is_read_as_ipv4(self) -> None:
        self.assertEqual(
            blocklists.parse(b"::ffff:192.0.2.5\n").networks, _networks("192.0.2.5/32")
        )

    def test_a_zone_id_is_not_an_address(self) -> None:
        self.assertEqual(blocklists.parse(b"fe80::1%eth0\n192.0.2.1\n").skipped, 1)

    def test_private_networks_are_always_taken_out(self) -> None:
        private = (
            f"{quad(10, 0, 0, 0)}/8",
            quad(192, 168, 1, 5),
            f"{quad(172, 16, 0, 0)}/12",
            quad(127, 0, 0, 1),
            quad(169, 254, 1, 1),
            f"{quad(100, 64, 0, 0)}/10",
            "fd00::/8",
            "fe80::/10",
            "::1",
            f"::ffff:{quad(10, 1, 2, 3)}",
        )
        parsed = blocklists.parse(("\n".join((*private, "192.0.2.1")) + "\n").encode())
        self.assertEqual(parsed.networks, _networks("192.0.2.1/32"))
        self.assertEqual(parsed.skipped, 10)

    def test_an_entry_over_a_private_network_keeps_its_public_part(self) -> None:
        parsed = blocklists.parse(f"{quad(192, 0, 0, 0)}/8\n".encode())
        self.assertIsNone(blocklists.contains(parsed.networks, quad(192, 168, 4, 4)))
        self.assertIsNotNone(blocklists.contains(parsed.networks, "192.0.2.1"))
        self.assertIsNotNone(blocklists.contains(parsed.networks, quad(192, 169, 0, 1)))
        self.assertEqual(parsed.skipped, 1)

    def test_an_entry_shorter_than_a_slash_8_or_16_is_skipped(self) -> None:
        broad = (
            f"{quad(0, 0, 0, 0)}/1",
            f"{quad(128, 0, 0, 0)}/1",
            f"{quad(64, 0, 0, 0)}/7",
            "8000::/1",
            "2000::/15",
        )
        parsed = blocklists.parse(("\n".join((*broad, "198.51.100.0/24")) + "\n").encode())
        self.assertEqual(parsed.networks, _networks("198.51.100.0/24"))
        self.assertEqual(parsed.skipped, 5)
        narrow = f"{quad(64, 0, 0, 0)}/8"
        kept = blocklists.parse(f"{narrow}\n2001::/16\n".encode())
        self.assertEqual(kept.networks, _networks(narrow, "2001::/16"))
        self.assertEqual(kept.skipped, 0)

    def test_a_list_of_nothing_public_is_refused(self) -> None:
        body = f"{quad(10, 0, 0, 0)}/8\n{quad(192, 168, 0, 0)}/16\n".encode()
        with self.assertRaises(BlocklistError) as caught:
            blocklists.parse(body)
        self.assertEqual(caught.exception.code, "empty")

    def test_overlaps_and_duplicates_collapse(self) -> None:
        parsed = blocklists.parse(b"192.0.2.0/24\n192.0.2.7\n192.0.2.0/24\n")
        self.assertEqual(parsed.networks, _networks("192.0.2.0/24"))

    def test_a_list_with_no_address_is_refused(self) -> None:
        for body in (b"", b"# only a comment\n", b"<html>Not found</html>\n"):
            with self.subTest(body=body), self.assertRaises(BlocklistError) as caught:
                blocklists.parse(body)
            self.assertEqual(caught.exception.code, "empty")

    def test_the_limits_refuse_the_list(self) -> None:
        with self.assertRaises(BlocklistError) as caught:
            blocklists.parse(b"#" * (blocklists.MAX_BYTES + 1))
        self.assertEqual(caught.exception.code, "too_large")
        many = "\n".join(
            str(ipaddress.ip_address("2001:db8::") + 2 * n)
            for n in range(blocklists.MAX_ENTRIES + 1)
        )
        with self.assertRaises(BlocklistError) as caught:
            blocklists.parse(many.encode())
        self.assertEqual(caught.exception.code, "too_many")
        self.assertIn("100 000", str(caught.exception))

    def test_the_file_is_one_network_to_a_line_a_single_address_bare(self) -> None:
        networks = _networks("192.0.2.0/24", "198.51.100.7/32", "2001:db8::1/128")
        self.assertEqual(blocklists.render(networks), b"192.0.2.0/24\n198.51.100.7\n2001:db8::1\n")
        self.assertEqual(blocklists.render(()), b"")


class CollapsedAsTheStandardLibraryDoes(unittest.TestCase):
    """The list's networks merged without an object per address (26-11-11).

    `ipaddress.collapse_addresses` made an address object for every entry and
    cached more on each network: 100 000 entries, a list of 1.4 MB, took the
    reading to 194 MB and a test with exceptions in four clusters to 299 MB.
    The merge is now done on integers, and must answer exactly as it did.
    """

    def random_list(self, seed: int) -> bytes:
        rng = random.Random(seed)  # noqa: S311 - the same lists every run, not a secret
        lines = []
        for _ in range(3000):
            if rng.random() < 0.8:
                base = rng.randrange(0, 1 << 12) << 4
                prefix = rng.choice((28, 29, 30, 31, 32, 32, 32))
                lines.append(f"{ipaddress.IPv4Address((198 << 24) + (51 << 16) + base)}/{prefix}")
            else:
                base = rng.randrange(0, 1 << 12) << 8
                prefix = rng.choice((120, 124, 127, 128, 128))
                lines.append(f"{ipaddress.IPv6Address((0x20010DB8 << 96) + base)}/{prefix}")
        return ("\n".join(lines) + "\n").encode()

    def test_the_same_networks_in_the_same_order(self) -> None:
        for seed in range(20):
            with self.subTest(seed=seed):
                body = self.random_list(seed)
                read = [ipaddress.ip_network(line, strict=False) for line in body.decode().split()]
                expected = (
                    *ipaddress.collapse_addresses(n for n in read if n.version == 4),
                    *ipaddress.collapse_addresses(n for n in read if n.version == 6),
                )
                self.assertEqual(blocklists.parse(body).networks, expected)

    def test_a_large_list_is_read_in_little_memory(self) -> None:
        rng = random.Random(1)  # noqa: S311 - the same list every run, not a secret
        body = (
            "\n".join(
                str(ipaddress.IPv4Address(rng.randrange(1 << 24, 223 << 24)))
                for _ in range(blocklists.MAX_ENTRIES)
            )
            + "\n"
        ).encode()
        tracemalloc.start()
        try:
            parsed = blocklists.parse(body)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # The private networks in the random addresses are cut out.
        self.assertGreater(len(parsed.networks), 95_000)
        self.assertLess(peak, 80 * 1024 * 1024, f"{peak // (1024 * 1024)} MB")


class AnExceptionIsTakenOut(unittest.TestCase):
    def test_an_address_inside_a_network_splits_it(self) -> None:
        result = blocklists.subtract(_networks("192.0.2.0/30"), ("192.0.2.1",), {})
        self.assertEqual(result.networks, _networks("192.0.2.0/32", "192.0.2.2/31"))
        self.assertEqual(result.excepted, 1)

    def test_a_group_is_taken_out_by_its_members(self) -> None:
        result = blocklists.subtract(
            _networks("192.0.2.7/32", "198.51.100.0/24", "203.0.113.9/32"),
            ("partner-sites", "203.0.113.9"),
            {"partner-sites": ("198.51.100.0/24",)},
        )
        self.assertEqual(result.networks, _networks("192.0.2.7/32"))
        self.assertEqual(result.excepted, 2)

    def test_a_group_the_cluster_does_not_define_is_said(self) -> None:
        result = blocklists.subtract(_networks("192.0.2.7/32"), ("gone",), {})
        self.assertEqual(result.unknown_groups, ("gone",))
        self.assertEqual(result.networks, _networks("192.0.2.7/32"))

    def test_another_family_is_left_alone(self) -> None:
        result = blocklists.subtract(_networks("2001:db8::/32"), ("192.0.2.0/24",), {})
        self.assertEqual((result.networks, result.excepted), (_networks("2001:db8::/32"), 0))

    def test_counting_alone_counts_what_subtract_counts(self) -> None:
        networks = blocklists.parse(
            b"192.0.2.0/24\n198.51.100.0/24\n203.0.113.7\n2001:db8::/32\n"
        ).networks
        groups = {"partners": ["198.51.100.128/25", "2001:db8::1"]}
        excepts = ("192.0.2.9", "partners", "elsewhere")

        done = blocklists.subtract(networks, excepts, groups)

        self.assertEqual(
            blocklists.excepted(networks, excepts, groups), (done.excepted, done.unknown_groups)
        )
        self.assertEqual(done.excepted, 3)

    def test_contains_names_the_network(self) -> None:
        networks = _networks("192.0.2.0/24", "2001:db8::/32")
        self.assertEqual(blocklists.contains(networks, "192.0.2.9"), networks[0])
        self.assertIsNone(blocklists.contains(networks, "198.51.100.1"))


class TheDefinitionIsChecked(unittest.TestCase):
    def _definition(self, **fields: Any) -> blocklists.Definition:
        base: dict[str, Any] = {
            "name": "crowdsec",
            "url": "https://example.com/list.txt",
            "every_hours": 24,
        }
        return blocklists.definition(**{**base, **fields})

    def test_a_plain_definition_reads(self) -> None:
        self.assertEqual(self._definition().name, "crowdsec")

    def test_the_name_is_one_an_object_can_name(self) -> None:
        for name in ("Crowdsec", "1list", "a_b", "a" * 41, ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self._definition(name=name)
        self._definition(name="a" * 40)

    def test_the_url_is_https_without_credentials(self) -> None:
        for url in (
            "http://example.com/x",
            "https://user:pw@example.com/x",
            "https:///x",
            "https://example.com/x#y",
            "https://example.com/a b",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self._definition(url=url)

    def test_fetch_every_is_one_of_four(self) -> None:
        for every in (0, 2, True, "24", 48):
            with self.subTest(every=every), self.assertRaises(ValueError):
                self._definition(every_hours=every)

    def test_basic_needs_a_username_and_only_basic_takes_one(self) -> None:
        with self.assertRaises(ValueError):
            self._definition(authorization="basic")
        with self.assertRaises(ValueError):
            self._definition(authorization="bearer", username="admin")
        with self.assertRaises(ValueError):
            self._definition(authorization="basic", username="a:b")
        self._definition(authorization="basic", username="admin")

    def test_except_takes_addresses_networks_and_groups_once(self) -> None:
        item = self._definition(excepts=["192.0.2.10", " partner-sites ", "", "198.51.100.0/24"])
        self.assertEqual(item.excepts, ("192.0.2.10/32", "partner-sites", "198.51.100.0/24"))
        for bad in (["192.0.2.1/24"], ["0.0.0.0/0"], ["a b"], ["office", "office"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self._definition(excepts=bad)

    def test_except_holds_at_most_what_the_database_holds(self) -> None:
        many = [f"198.51.{n // 256}.{n % 256}" for n in range(blocklists.EXCEPT_MAX)]
        self.assertEqual(len(self._definition(excepts=many).excepts), blocklists.EXCEPT_MAX)
        with self.assertRaisesRegex(ValueError, "at most 256 entries"):
            self._definition(excepts=[*many, "203.0.113.1"])


class Source:
    """An https server whose answer a test sets."""

    def __init__(self) -> None:
        source = self
        self.answer: tuple[int, dict[str, str], bytes] = (200, {}, RAW)
        self.seen: list[dict[str, str]] = []
        self.drip = False

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                return None

            def do_GET(self) -> None:
                source.seen.append(dict(self.headers.items()))
                if source.drip:
                    # A header sent a byte at a time, each well inside the socket's timeout.
                    try:
                        self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                        for _ in range(200):
                            time.sleep(0.1)
                            self.wfile.write(b"x")
                            self.wfile.flush()
                    except OSError:
                        pass  # the client gave up, as it should
                    return
                status, headers, body = source.answer
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = SERVER_CONTEXT.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://localhost:{self.server.server_address[1]}/list.txt"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class TheFetchIsHttpsAndNothingElse(unittest.TestCase):
    def setUp(self) -> None:
        self.source = Source()
        self.addCleanup(self.source.close)
        self.context = ssl.create_default_context(cadata=CA_PEM)

    def _item(self, **fields: Any) -> blocklists.Definition:
        return blocklists.definition(name="crowdsec", url=self.source.url, every_hours=1, **fields)

    def test_the_body_comes_back(self) -> None:
        self.assertEqual(blocklists.fetch(self._item(), context=self.context), RAW)

    def test_basic_and_bearer_are_sent(self) -> None:
        blocklists.fetch(
            self._item(authorization="basic", username="admin"), "pw", context=self.context
        )
        expected = "Basic " + base64.b64encode(b"admin:pw").decode()
        self.assertEqual(self.source.seen[-1]["Authorization"], expected)
        blocklists.fetch(self._item(authorization="bearer"), "tok", context=self.context)
        self.assertEqual(self.source.seen[-1]["Authorization"], "Bearer tok")

    def test_a_missing_or_unsendable_secret_is_refused_before_any_request(self) -> None:
        for secret in ("", "a\nb"):
            with self.subTest(secret=secret), self.assertRaises(BlocklistError) as caught:
                blocklists.fetch(self._item(authorization="bearer"), secret, context=self.context)
            self.assertEqual(caught.exception.code, "no_secret")
        self.assertEqual(self.source.seen, [])

    def test_the_system_cas_alone_do_not_trust_the_test_ca(self) -> None:
        with self.assertRaises(BlocklistError) as caught:
            blocklists.fetch(self._item())
        self.assertEqual(caught.exception.code, "tls")

    def test_a_redirect_is_not_followed(self) -> None:
        self.source.answer = (302, {"Location": "https://example.com/"}, b"")
        with self.assertRaises(BlocklistError) as caught:
            blocklists.fetch(self._item(), context=self.context)
        self.assertEqual(caught.exception.code, "redirected")

    def test_an_error_status_is_refused(self) -> None:
        self.source.answer = (401, {}, b"no")
        with self.assertRaises(BlocklistError) as caught:
            blocklists.fetch(self._item(), context=self.context)
        self.assertEqual(
            (caught.exception.code, str(caught.exception)), ("refused", "localhost answered 401")
        )

    def test_an_answer_over_the_limit_is_refused(self) -> None:
        self.source.answer = (200, {}, b"#" * (blocklists.MAX_BYTES + 1))
        with self.assertRaises(BlocklistError) as caught:
            blocklists.fetch(self._item(), context=self.context)
        self.assertEqual(caught.exception.code, "too_large")

    def test_an_answer_that_drips_its_header_ends_at_the_total_limit(self) -> None:
        self.source.drip = True
        started = time.monotonic()
        with self.assertRaises(BlocklistError) as caught:
            blocklists.fetch(self._item(), context=self.context, timeout=1)
        self.assertEqual(caught.exception.code, "unreachable")
        self.assertLess(time.monotonic() - started, 2.5)


if __name__ == "__main__":
    unittest.main()
