"""The interface after a pool began to be named by itself (B250, 2026-10-06).

A backend's name no longer says whose it is, so the interface asks the objects
- and a removal's own bookkeeping, for an object whose document is gone - and
understands the older `mgd-<object>-<pool>` names that history and nodes on an
older release still carry.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from haproxy_mgmt.proxy_model import load_proxy

from haproxy_ui import health, metrics, objects, operations, traffic_logs
from haproxy_ui.db import Job


@dataclass
class Reading:
    cluster: str
    result: dict[str, Any]


@dataclass(frozen=True)
class View:
    name: str
    runtime_backends: tuple[str, ...] | None


def nodes(*members: tuple[str, str, str]) -> list[Reading]:
    servers = [
        {"backend": backend, "server": server, "status": state}
        for backend, server, state in members
    ]
    return [Reading("alpha", {"nodes": [{"name": "node-a", "status": {"servers": servers}}]})]


def publish_job(payload: dict[str, Any]) -> Job:
    moment = datetime(2026, 10, 6, 12, tzinfo=UTC)
    return Job(
        id=1,
        request_id=UUID("3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f"),
        operation="objects_publish",
        cluster="alpha",
        payload=payload,
        state="done",
        created_at=moment,
        started_at=moment,
        finished_at=moment,
        exit_code=0,
        outcome="done",
        result=None,
        stderr_excerpt=None,
        idempotency_key=None,
        attempts=1,
    )


class WhoseABackendIs(unittest.TestCase):
    def test_a_pool_named_by_itself_is_found_through_its_object(self) -> None:
        owners = health.backend_owners([View("monitor-server_admin-web", ("admin-web_80",))])
        lamps = health.object_healths(
            nodes(("admin-web_80", "s1", "UP")),
            cluster="alpha",
            objects={"monitor-server_admin-web": (True, False)},
            owners=owners,
        )

        self.assertEqual(lamps["monitor-server_admin-web"].tone, "healthy")

    def test_without_the_objects_account_a_bare_pool_is_nobodys(self) -> None:
        """Nothing is guessed from the name: it is the pool's, not the object's."""

        served = health.served_objects(
            nodes(("admin-web_80", "s1", "UP")), cluster="alpha", names=["monitor-server_admin-web"]
        )

        self.assertEqual(served, frozenset())

    def test_a_node_on_an_older_release_still_answers_for_its_object(self) -> None:
        served = health.served_objects(
            nodes(("mgd-shop-web", "s1", "UP")), cluster="alpha", names=["shop"], owners={}
        )

        self.assertEqual(served, frozenset({"shop"}))

    def test_a_removed_object_is_found_through_its_removal(self) -> None:
        removal = publish_job(
            {"objects": {"gone": None}, "removed_backends": {"gone": ["gone-web"]}}
        )
        owners = health.backend_owners([], objects.removed_backends([removal]))

        served = health.served_objects(
            nodes(("gone-web", "s1", "UP")), cluster="alpha", names=["gone"], owners=owners
        )

        self.assertEqual(served, frozenset({"gone"}))

    def test_an_object_page_reads_its_pool_under_either_name(self) -> None:
        for reported in ("web", "mgd-shop-web"):
            with self.subTest(reported=reported):
                found = health.backend_health(
                    nodes((reported, "s1", "UP")), cluster="alpha", obj="shop", backend="web"
                )

                self.assertEqual(found.backend, "web")
                self.assertEqual([member.server for member in found.nodes[0].members], ["s1"])


class TheObjectsHelperIsRead(unittest.TestCase):
    def test_the_backends_come_from_the_envelope(self) -> None:
        view = objects.object_view(
            {"name": "shop", "document": "x", "runtime_backends": ["web", "shop-redirect"]}
        )

        self.assertEqual(
            view.runtime_backends if view is not None else None, ("web", "shop-redirect")
        )

    def test_an_older_helper_said_nothing(self) -> None:
        view = objects.object_view({"name": "shop", "document": "x"})

        self.assertIsNotNone(view)
        self.assertIsNone(view.runtime_backends if view is not None else None)


class ARemovalWritesItDown(unittest.TestCase):
    def prepare(self, **payload: object) -> operations.Prepared:
        return operations.prepare(
            operation="objects_publish",
            cluster="alpha",
            request_id=UUID("3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f"),
            payload={
                "objects": {"gone": None},
                "expected_head": "abc123",
                "comment": "Remove gone",
                **payload,
            },
        )

    def test_it_is_checked_and_never_forwarded(self) -> None:
        prepared = self.prepare(removed_backends={"gone": ["gone-web"]})

        self.assertNotIn("removed_backends", prepared.request)
        self.assertNotIn("gone-web", prepared.request)

    def test_only_a_removed_object_may_be_named(self) -> None:
        refused: tuple[object, ...] = (
            {"kept": ["web"]},
            {"gone": []},
            {"gone": "gone-web"},
            {"gone": [""]},
            {"gone": ["x" * 129]},
            {},
            ["gone-web"],
        )
        for value in refused:
            with self.subTest(value=value), self.assertRaises(operations.BadPayload):
                self.prepare(removed_backends=value)

    def test_the_listing_reads_it_back(self) -> None:
        jobs = [
            publish_job({"objects": {"gone": None}, "removed_backends": {"gone": ["gone-web"]}}),
            publish_job({"objects": {"older": None}}),
        ]

        self.assertEqual(objects.removed_backends(jobs), {"gone": ("gone-web",)})


class TheTrafficLogNamesAServerUnderEitherName(unittest.TestCase):
    def test_a_row_from_before_and_after_finds_its_address(self) -> None:
        proxy = load_proxy(
            "shop",
            b"schema: 1\nname: shop\nhostnames: [shop.example.com]\nlisten:\n  protocol: http\n"
            b"routes:\n  - path: /\n    backend: web\nbackends:\n  web:\n"
            b"    balance: roundrobin\n    servers:\n      - host: 198.51.100.10\n        port: 8080\n",
        )
        found = traffic_logs.configured_server_addresses("alpha", [proxy])

        self.assertEqual(found[("alpha", "web", "s1")], "198.51.100.10:8080")
        self.assertEqual(found[("alpha", "mgd-shop-web", "s1")], "198.51.100.10:8080")


class TheFormSaysWhatTheNameIsFor(unittest.TestCase):
    def test_unique_per_cluster_and_used_by_metrics(self) -> None:
        template = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "haproxy_ui"
            / "templates"
            / "_object-form.html"
        ).read_text()
        field = template.split('<input name="backend"', 1)[1].split("</label>", 1)[0]

        self.assertIn("Unique per cluster. Default: the object's name.", field)
        self.assertIn("This name is used by metrics.", field)


if __name__ == "__main__":
    unittest.main()


def site(name: str, pools: str = "web", redirect: str = "") -> Any:
    """An http object; the first pool takes `/`, each other one a path of its own."""

    names = pools.split()
    routes = f"  - path: /\n    backend: {names[0]}\n" + "".join(
        f"  - path: /to-{pool}\n    backend: {pool}\n" for pool in names[1:]
    )
    if redirect:
        routes += f"  - path: {redirect}\n    redirect:\n      location: https://example.net/\n"
    backends = "".join(
        f"  {pool}:\n    balance: roundrobin\n    servers:\n"
        f"      - host: 198.51.100.10\n        port: 8080\n"
        for pool in names
    )
    return load_proxy(
        name,
        (
            f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
            f"listen:\n  protocol: http\nroutes:\n{routes}backends:\n{backends}"
        ).encode(),
    )


class WhatAPublishRenames(unittest.TestCase):
    """The history follows a rename only where the publish says which became which."""

    def test_one_pool_for_another_is_a_rename_under_both_older_forms(self) -> None:
        renamed, introduced = metrics.renamed_backends(
            site("monitor", "admin-web_80"), site("monitor", "monitor-web")
        )

        self.assertEqual(
            renamed,
            {"admin-web_80": "monitor-web", "mgd-monitor-admin-web_80": "monitor-web"},
        )
        self.assertEqual(introduced, ["monitor-web"])

    def test_two_pools_changed_at_once_are_not_guessed_at(self) -> None:
        renamed, introduced = metrics.renamed_backends(
            site("shop", "web api"), site("shop", "front back")
        )

        self.assertEqual(renamed, {})
        self.assertEqual(introduced, ["back", "front"])

    def test_a_renamed_object_takes_its_redirects_history_along(self) -> None:
        renamed, _introduced = metrics.renamed_backends(
            site("shop", "web", redirect="/old"), site("store", "web", redirect="/old")
        )

        self.assertEqual(renamed["shop-redirect-old"], "store-redirect-old")
        self.assertNotIn("web", renamed)

    def test_a_new_object_renames_nothing(self) -> None:
        self.assertEqual(metrics.renamed_backends(None, site("shop")), ({}, ["web"]))
