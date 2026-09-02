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
