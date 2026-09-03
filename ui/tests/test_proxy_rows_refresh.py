from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest import mock

from haproxy_ui.db import ClusterInventory, ClusterObjects
from tests.test_login import LoginTestCase, configuration

OBSERVED = datetime(2026, 9, 3, 9, 0, tzinfo=UTC)

DOCUMENT = """schema: 1
name: {name}
hostnames:
- {name}.example.com
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    servers:
    - host: 192.0.2.10
      port: 8080
"""


def objects_reading(*names: str) -> ClusterObjects:
    return ClusterObjects(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "commit": "a" * 40,
            "objects": [
                {
                    "name": name,
                    "document": DOCUMENT.format(name=name),
                    "readable": True,
                    "protocol": "http",
                    "hostnames": [f"{name}.example.com"],
                }
                for name in names
            ],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


def inventory(*served: str) -> ClusterInventory:
    """The published frontends, naming the hostnames the nodes answer for."""

    return ClusterInventory(
        cluster="alpha",
        observed_at=OBSERVED,
        outcome="done",
        result={
            "version": "v9",
            "proxies": [
                {
                    "name": "mgd-main-http",
                    "protocol": "http",
                    "managed": True,
                    "enabled": True,
                    "hostnames": [f"{name}.example.com" for name in served],
                    "ports": [80],
                    "backend_count": len(served),
                }
            ]
            if served
            else [],
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


class TheRowsCatchUpWithoutTheWholePageBeingDrawn(LoginTestCase):
    """A row moves for reasons that happen elsewhere, and it has to move here.

    An object waiting for a deploy sits at the top so nobody misses it, and it
    joins the alphabetical order the moment the nodes are serving it. That
    moment arrives while somebody is looking at the page, and until the rows
    could be replaced on their own the only way to see it was to reload.
    """

    def rows(self, *, served: tuple[str, ...]) -> Any:
        client = self.client(replace(configuration(), clusters=("alpha",)))
        self.sign_in(client)
        with (
            mock.patch(
                "haproxy_ui.db.cluster_objects",
                return_value=[objects_reading("zeta", "alpha-site", "middle")],
            ),
            mock.patch("haproxy_ui.db.cluster_inventories", return_value=[inventory(*served)]),
        ):
            return client.get("/proxies/rows")

    def order(self, markup: str) -> list[str]:
        return [
            part.split("</strong>")[0]
            for part in markup.split('data-label="Proxy"')[1:]
            if "<strong>" in part
            for part in [part.split("<strong>")[1]]
        ]

    def test_nothing_deployed_puts_them_all_first_in_alphabetical_order(self) -> None:
        answer = self.rows(served=())

        self.assertEqual(answer.status_code, 200)
        self.assertEqual(
            self.order(answer.json()["clusters"]["alpha"]), ["alpha-site", "middle", "zeta"]
        )

    def test_a_deployed_object_leaves_the_top_and_joins_the_list(self) -> None:
        #
        # `alpha-site` is first alphabetically, so an ordering that ignored the
        # deploy state would look identical. It is served here, which must put
        # it below the two that are still waiting.
        #
        answer = self.rows(served=("alpha-site",))

        self.assertEqual(
            self.order(answer.json()["clusters"]["alpha"]), ["middle", "zeta", "alpha-site"]
        )

    def test_the_counts_come_back_with_the_rows(self) -> None:
        counts = self.rows(served=()).json()["counts"]

        self.assertEqual(counts, {"published": 3, "managed": 3, "unmanaged": 0})

    def test_the_rows_are_not_served_to_somebody_who_is_not_signed_in(self) -> None:
        client = self.client(replace(configuration(), clusters=("alpha",)))

        self.assertEqual(client.get("/proxies/rows").status_code, 401)

    def test_the_listing_no_longer_repeats_the_redirect_on_every_row(self) -> None:
        #
        # A property of the object, answered on its own page. In a list of
        # sites it is a line of noise under a name.
        #
        self.assertNotIn("Redirects HTTP", self.rows(served=()).json()["clusters"]["alpha"])


if __name__ == "__main__":
    unittest.main()
