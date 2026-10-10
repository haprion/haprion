"""The address list a node's keepalived carries, rendered from one document.

What matters here is not the formatting but the properties an operator and a
diff depend on: that both kinds of address are present, that the order is a
function of the names rather than of insertion, and that nothing outside the
address list can be written from here.
"""

from __future__ import annotations

import unittest

from haprion.config import Vip
from haprion.keepalived_fragment import FRAGMENT, render


def vips(**entries: tuple[str, str | None]) -> dict[str, Vip]:
    return {
        name: Vip(name=name, address=address, source=source)
        for name, (address, source) in entries.items()
    }


class TheAddressList(unittest.TestCase):
    def addresses(self, text: str) -> list[str]:
        return [
            line.split("#")[0].strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def test_every_kind_of_address_a_node_must_hold_is_listed(self) -> None:
        #
        # A VIP nobody carries answers nothing; a source address nobody carries
        # sends replies to a node that is not expecting them. Both are on the
        # interface or neither works.
        #
        text = render(
            vips(public=("192.0.2.20", "192.0.2.25"), partner=("192.0.2.21", None)),
            {"egress": "192.0.2.35"},
        )

        self.assertEqual(
            self.addresses(text), ["192.0.2.21", "192.0.2.20", "192.0.2.25", "192.0.2.35"]
        )

    def test_the_order_follows_the_names_and_not_the_document(self) -> None:
        # Otherwise a version diff shows a reordering and hides the change.
        first = render(vips(b=("192.0.2.21", None), a=("192.0.2.20", None)), {})
        second = render(vips(a=("192.0.2.20", None), b=("192.0.2.21", None)), {})

        self.assertEqual(first, second)

    def test_one_address_named_twice_is_carried_once(self) -> None:
        #
        # Legal in the document - a named source may repeat a VIP's own address
        # - and wrong in keepalived, which would be told to add it twice.
        #
        text = render(vips(public=("192.0.2.20", "192.0.2.25")), {"same": "192.0.2.25"})

        self.assertEqual(self.addresses(text), ["192.0.2.20", "192.0.2.25"])

    def test_each_line_says_why_the_address_is_there(self) -> None:
        # The question asked in front of this file on a node is never "what is
        # this address called" but "what is it for".
        text = render(vips(public=("192.0.2.20", "192.0.2.25")), {"egress": "192.0.2.35"})

        self.assertIn("# vip public", text)
        self.assertIn("# default source for vip public", text)
        self.assertIn("# source egress", text)

    def test_nothing_that_decides_vrrp_ownership_can_be_written_from_here(self) -> None:
        #
        # The boundary B57 rests on. Two masters or none come from these
        # fields, and none of them is derived from the network document.
        #
        # The header names them, in prose, as the fields this file does not
        # touch. The check is therefore about the lines keepalived acts on.
        text = render(vips(public=("192.0.2.20", "192.0.2.25")), {"egress": "192.0.2.35"})
        acted_on = "\n".join(
            line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
        )

        for field in ("priority", "virtual_router_id", "auth_pass", "unicast", "notify", "{"):
            self.assertNotIn(field, acted_on)

    def test_the_addresses_are_written_the_way_the_nodes_carry_them(self) -> None:
        #
        # Measured on a running node, 2026-09-01: the pair carried its
        # addresses as `<address>/24 dev eth0`, and a bare address is not the
        # same address. keepalived reads one without a prefix as /32, which carries
        # no subnet route and is not chosen as a source for the segment - so
        # moving the list into this file would have changed the network while
        # claiming to change only where the list is written.
        #
        text = render(vips(public=("192.0.2.20", "192.0.2.25")), {}, prefix=24, interface="eth0")

        self.assertEqual(self.addresses(text), ["192.0.2.20/24 dev eth0", "192.0.2.25/24 dev eth0"])

    def test_a_cluster_that_states_neither_gets_what_keepalived_defaults_to(self) -> None:
        # A bare address, which is right for a cluster written that way and
        # wrong for one written any other way. Stated in clusters.yaml rather
        # than guessed at from the address.
        text = render(vips(public=("192.0.2.20", None)), {})

        self.assertEqual(self.addresses(text), ["192.0.2.20"])

    def test_the_file_is_named_once_for_both_sides_of_the_release(self) -> None:
        self.assertEqual(FRAGMENT, "keepalived/addresses.conf")
