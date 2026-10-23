"""What a person writes down about the handwritten half of the configuration.

Every refusal here is read by somebody who has just been told their site will
not publish, so each one names the file and the thing in it.
"""

from __future__ import annotations

import unittest

from haprion.reservations import (
    ReservationError,
    Reservations,
    fragment_digest,
    load_reservations,
    review_fragments,
)


class TheFileBothClustersActuallyCarry(unittest.TestCase):
    """Three bytes: `{}`. It has to stay valid, and reserve nothing."""

    def test_an_empty_mapping_reserves_nothing(self) -> None:
        self.assertEqual(load_reservations(b"{}\n"), Reservations())

    def test_an_empty_file_reserves_nothing_either(self) -> None:
        self.assertEqual(load_reservations(b""), Reservations())


class WhatMayBeReserved(unittest.TestCase):
    def test_hostnames_and_ports_are_read(self) -> None:
        reservations = load_reservations(b"hostnames: [legacy.example.com]\ntcp_ports: [8443]\n")

        self.assertEqual(reservations.hostnames, frozenset({"legacy.example.com"}))
        self.assertEqual(reservations.tcp_ports, frozenset({8443}))

    def test_a_hostname_is_lowercased_the_way_a_host_header_is_compared(self) -> None:
        """Mixed case would otherwise reserve nothing while looking like it did."""

        reservations = load_reservations(b"hostnames: [Legacy.Example.COM]\n")

        self.assertIn("legacy.example.com", reservations.hostnames)

    def test_something_that_is_not_a_hostname_is_refused(self) -> None:
        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"hostnames: ['https://legacy.example.com']\n")

        self.assertIn("not a hostname", str(raised.exception))

    def test_something_that_is_not_a_port_is_refused(self) -> None:
        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"tcp_ports: [70000]\n")

        self.assertIn("not a port number", str(raised.exception))

    def test_a_key_nobody_expected_is_refused(self) -> None:
        """A typo here reserves nothing and looks like it reserved something."""

        with self.assertRaises(ReservationError):
            load_reservations(b"hostname: [legacy.example.com]\n")

    def test_something_that_is_not_a_mapping_is_refused(self) -> None:
        with self.assertRaises(ReservationError):
            load_reservations(b"- legacy.example.com\n")


if __name__ == "__main__":
    unittest.main()


class APortIsClaimedOnAnAddressOrOnAllOfThem(unittest.TestCase):
    """The distinction the file exists for once a cluster has several VIPs."""

    def test_a_bare_number_claims_the_port_everywhere(self) -> None:
        reservations = load_reservations(b"tcp_ports: [8404]\n")

        self.assertEqual(reservations.tcp_ports, frozenset({8404}))
        self.assertEqual(reservations.tcp_listeners, frozenset())
        self.assertTrue(reservations.claims("192.0.2.10", 8404))
        self.assertTrue(reservations.claims("198.51.100.10", 8404))

    def test_a_bind_line_without_an_address_reads_the_same_way(self) -> None:
        """`bind :8404` really does take the port on every address the host has."""

        self.assertEqual(
            load_reservations(b"tcp_ports: [':8404']\n"),
            load_reservations(b"tcp_ports: [8404]\n"),
        )

    def test_an_address_claims_the_port_only_there(self) -> None:
        reservations = load_reservations(b"tcp_ports: ['192.0.2.10:443']\n")

        self.assertEqual(reservations.tcp_listeners, frozenset({("192.0.2.10", 443)}))
        self.assertEqual(reservations.tcp_ports, frozenset())
        self.assertTrue(reservations.claims("192.0.2.10", 443))
        self.assertFalse(reservations.claims("198.51.100.10", 443))

    def test_both_forms_live_in_one_list(self) -> None:
        reservations = load_reservations(b"tcp_ports: [8404, '192.0.2.10:443']\n")

        self.assertTrue(reservations.claims("198.51.100.10", 8404))
        self.assertTrue(reservations.claims("192.0.2.10", 443))
        self.assertFalse(reservations.claims("198.51.100.10", 443))

    def test_an_ipv6_address_is_bracketed_as_a_bind_line_requires(self) -> None:
        reservations = load_reservations(b"tcp_ports: ['[2001:db8::1]:443']\n")

        self.assertEqual(reservations.tcp_listeners, frozenset({("2001:db8::1", 443)}))

    def test_an_ipv6_address_is_kept_in_its_one_spelling(self) -> None:
        """1A-5: a VIP spelled `2001:db8::1` was not the reservation `2001:DB8:0::1`."""

        reservations = load_reservations(b"tcp_ports: ['[2001:DB8:0::1]:443']\n")

        self.assertTrue(reservations.claims("2001:db8::1", 443))

    def test_an_unbracketed_ipv6_address_is_refused_rather_than_guessed_at(self) -> None:
        """Without brackets the last colon is not distinguishable from the address."""

        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"tcp_ports: ['2001:db8::1:443']\n")

        self.assertIn("[address]:port", str(raised.exception))

    def test_something_that_is_not_an_address_is_refused(self) -> None:
        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"tcp_ports: ['node-a:443']\n")

        self.assertIn("must be an IP address", str(raised.exception))

    def test_a_yaml_boolean_does_not_become_port_one(self) -> None:
        """`- yes` is a bool in YAML, and a bool is an int in Python."""

        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"tcp_ports: [yes]\n")

        self.assertIn("not a port", str(raised.exception))

    def test_a_port_out_of_range_is_refused_in_the_address_form_too(self) -> None:
        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"tcp_ports: ['192.0.2.10:70000']\n")

        self.assertIn("not a port number", str(raised.exception))


class HandwrittenFragmentsTheePromiseDoesNotCover(unittest.TestCase):
    """L8: an old promise must not look exactly like a current one."""

    STATS = b"listen stats\n"
    LEGACY = b"frontend legacy\n"

    FILES = {
        "core/haproxy.cfg": b"global\n",
        "core/conf.d/0010-stats.cfg": STATS,
        "manual/conf.d/0050-legacy.cfg": LEGACY,
        "manual/reservations.yaml": b"{}\n",
    }

    def _reviewed(self, **paths: bytes) -> bytes:
        lines = "".join(
            f"  {path.replace('__', '/').replace('_cfg', '.cfg')}: {fragment_digest(data)}\n"
            for path, data in paths.items()
        )
        return f"reviewed:\n{lines}".encode()

    ALL_REVIEWED = (
        b"reviewed:\n"
        b"  core/conf.d/0010-stats.cfg: " + fragment_digest(STATS).encode() + b"\n"
        b"  manual/conf.d/0050-legacy.cfg: " + fragment_digest(LEGACY).encode() + b"\n"
    )

    def test_fragments_are_named_when_nothing_has_been_confirmed(self) -> None:
        review = review_fragments(self.FILES, load_reservations(b"{}\n"))

        self.assertEqual(
            review.unreviewed,
            ("core/conf.d/0010-stats.cfg", "manual/conf.d/0050-legacy.cfg"),
        )

    def test_both_handwritten_bands_are_watched_not_only_manual(self) -> None:
        """The collision that made this necessary came from a file in `core/`."""

        review = review_fragments(self.FILES, Reservations())

        self.assertIn("core/conf.d/0010-stats.cfg", review.unreviewed)

    def test_reserving_something_no_longer_silences_the_rest(self) -> None:
        """B86's rule went quiet here, which is the whole reason for L8."""

        review = review_fragments(self.FILES, load_reservations(b"tcp_ports: [80]\n"))

        self.assertEqual(len(review.unreviewed), 2)

    def test_a_confirmed_fragment_is_quiet(self) -> None:
        review = review_fragments(self.FILES, load_reservations(self.ALL_REVIEWED))

        self.assertFalse(review)

    def test_a_fragment_edited_after_confirmation_is_named(self) -> None:
        """The failure the whole point rests on: a listener added afterwards."""

        edited = dict(self.FILES)
        edited["manual/conf.d/0050-legacy.cfg"] = b"frontend legacy\n  bind :8404\n"

        review = review_fragments(edited, load_reservations(self.ALL_REVIEWED))

        self.assertEqual(review.changed, ("manual/conf.d/0050-legacy.cfg",))
        self.assertEqual(review.unreviewed, ())

    def test_it_stays_loud_even_when_the_promise_is_not_empty(self) -> None:
        """A filled-in reservations file must not hide a stale confirmation."""

        edited = dict(self.FILES)
        edited["core/conf.d/0010-stats.cfg"] = b"listen stats\n  bind :8405\n"
        promise = b"tcp_ports: [8404]\n" + self.ALL_REVIEWED

        self.assertEqual(
            review_fragments(edited, load_reservations(promise)).changed,
            ("core/conf.d/0010-stats.cfg",),
        )

    def test_a_confirmation_about_a_removed_fragment_is_named(self) -> None:
        remaining = {"core/haproxy.cfg": b"global\n"}

        review = review_fragments(remaining, load_reservations(self.ALL_REVIEWED))

        self.assertEqual(
            review.vanished,
            ("core/conf.d/0010-stats.cfg", "manual/conf.d/0050-legacy.cfg"),
        )
        self.assertEqual(review.unreviewed, ())

    def test_a_cluster_with_no_fragments_says_nothing(self) -> None:
        """`core/haproxy.cfg` exists everywhere; counting it would fire every time."""

        self.assertFalse(review_fragments({"core/haproxy.cfg": b"global\n"}, Reservations()))

    def test_a_confirmation_outside_the_fragment_directories_is_refused(self) -> None:
        """A line that silences nothing must not read as though it did."""

        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"reviewed:\n  core/haproxy.cfg: " + b"a" * 64 + b"\n")

        self.assertIn("not a fragment", str(raised.exception))

    def test_a_digest_that_is_not_a_sha256_is_refused(self) -> None:
        with self.assertRaises(ReservationError) as raised:
            load_reservations(b"reviewed:\n  manual/conf.d/a.cfg: notadigest\n")

        self.assertIn("SHA-256", str(raised.exception))

    def test_an_uppercase_digest_is_read_as_the_same_digest(self) -> None:
        """`sha256sum` prints lowercase, but a person may paste either."""

        promise = b"reviewed:\n  core/conf.d/a.cfg: " + fragment_digest(b"x").upper().encode()

        self.assertFalse(review_fragments({"core/conf.d/a.cfg": b"x"}, load_reservations(promise)))
