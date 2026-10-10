from __future__ import annotations

import unittest

from haprion_ui import objects
from haprion_ui.proxies import ProxyView


def listed(*names: str) -> tuple[objects.ListedObject, ...]:
    return tuple(
        objects.ListedObject(
            name=name,
            protocol="https",
            hostnames=(f"{name}.example.com",),
            ports=(443,),
            backend_count=1,
            redirect_http=True,
            readable=True,
            problem=None,
            serving=True,
        )
        for name in names
    )


def frontend(name: str, *, managed: bool) -> ProxyView:
    return ProxyView(
        name=name,
        protocol="https",
        managed=managed,
        enabled=True,
        hostnames=(),
        ports=(443,),
        backend_count=1,
    )


class TheSummaryAgreesWithTheTable(unittest.TestCase):
    """The three cards count the rows below them, and nothing else.

    They used to count published frontends, which is not what the table lists
    and not what anybody wrote. The generator names a frontend after the
    address and protocol it binds, so an https object that redirects plain HTTP
    is two frontends and was counted twice - and every object sharing one
    address goes through one frontend, so a busy VIP counted them all as one.
    """

    def test_an_object_that_redirects_plain_http_is_one_proxy_and_not_two(self) -> None:
        counts = objects.counted({"alpha": listed("shop")}, {"alpha": ()})

        self.assertEqual((counts.published, counts.managed, counts.unmanaged), (1, 1, 0))

    def test_unmanaged_frontends_are_counted_as_frontends(self) -> None:
        #
        # For configuration this platform does not own there is no object to
        # count: the frontend really is all there is.
        #
        counts = objects.counted(
            {"alpha": listed("shop", "console")},
            {"alpha": (frontend("legacy", managed=False), frontend("old", managed=False))},
        )

        self.assertEqual((counts.published, counts.managed, counts.unmanaged), (4, 2, 2))

    def test_every_cluster_on_the_page_is_added_up(self) -> None:
        counts = objects.counted(
            {"alpha": listed("shop"), "beta": listed("console", "api")},
            {"alpha": (frontend("legacy", managed=False),), "beta": ()},
        )

        self.assertEqual((counts.published, counts.managed, counts.unmanaged), (4, 3, 1))

    def test_a_page_with_nothing_on_it_counts_nothing(self) -> None:
        counts = objects.counted({}, {})

        self.assertEqual((counts.published, counts.managed, counts.unmanaged), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
