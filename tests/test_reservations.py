"""What a person writes down about the handwritten half of the configuration.

Every refusal here is read by somebody who has just been told their site will
not publish, so each one names the file and the thing in it.
"""

from __future__ import annotations

import unittest

from haproxy_mgmt.reservations import ReservationError, Reservations, load_reservations


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
