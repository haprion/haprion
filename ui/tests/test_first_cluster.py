"""The guide through the first cluster (B315, mock approved 26-10-15).

Held here: which step is shown is read from the installation - no cluster, a
cluster being created, one node or two and nothing deployed, a deploy that ran
from the guide - and each step does what the operation it stands for does: the
first node creates the cluster with its block, the second is *Add node*, both
read and shown before anything is queued.
"""

from __future__ import annotations

import copy
import json
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import node_enrollment

from haprion_ui import demo, first_cluster
from haprion_ui.cluster_nodes import Creating
from tests.test_login import configuration
from tests.test_settings_nodes import NOW, NodesPage, block, key


def reading(nodes: int = 2, *, deployed: bool = False, owner: str = "edge-a") -> Any:
    row = next(row for row in demo.status_rows(NOW) if row.cluster == "edge-demo")
    result = copy.deepcopy(dict(row.result))
    result["nodes"] = result["nodes"][:nodes]
    for node in result["nodes"]:
        if not deployed:
            node["status"]["release"] = {"version": None, "hash": None}
        node["status"]["vip"]["owner"] = node["name"] == owner
    return replace(row, result=result)


def guide(**facts: Any) -> first_cluster.Guide | None:
    arguments: dict[str, Any] = {
        "clusters": ("edge-demo",),
        "reading": reading(),
        "creations": (),
        "busy": {},
        "vip": "203.0.113.10",
        "phase": "",
        "deployed_recently": False,
    }
    arguments.update(facts)
    return first_cluster.guide(**arguments)


def step(found: first_cluster.Guide | None) -> int | None:
    return None if found is None else found.step


class WhichStep(NodesPage):
    def test_from_the_installation_as_it_is(self) -> None:
        creating = Creating("gamma", "Creating cluster", None, None, 41)
        failed = Creating("gamma", None, "Creation failed", "gamma-a did not answer", 41)
        cases: dict[str, tuple[dict[str, Any], int, str | None]] = {
            "no cluster": (dict(clusters=(), reading=None), 1, None),
            "being created": (
                dict(clusters=(), reading=None, creations=(creating,)),
                2,
                "Creating cluster",
            ),
            "one node": (dict(reading=reading(1)), 3, None),
            "second skipped": (dict(reading=reading(1), phase="skip"), 4, None),
            "two nodes": (dict(), 4, None),
            "second joining": (dict(busy={"edge-demo": "Adding node"}), 3, "Adding node"),
            "deploying": (dict(busy={"edge-demo": "Deploying"}, phase="deploying"), 4, "Deploying"),
            "deployed, not read yet": (
                dict(phase="deploying", deployed_recently=True),
                4,
                "Reading the nodes",
            ),
            "done": (
                dict(reading=reading(deployed=True), phase="deploying", deployed_recently=True),
                5,
                None,
            ),
        }
        for name, (facts, expected, busy) in cases.items():
            with self.subTest(name):
                found = guide(**facts)
                self.assertEqual(step(found), expected)
                assert found is not None  # noqa: S101 - narrowed for the next line
                self.assertEqual(found.busy, busy)
        refused = guide(clusters=(), reading=None, creations=(failed,))
        self.assertEqual(refused.problem if refused else None, "gamma-a did not answer")

    def test_the_dashboard_once_a_cluster_is_deployed_or_there_are_two(self) -> None:
        self.assertIsNone(guide(reading=reading(deployed=True)))
        self.assertIsNone(guide(clusters=("edge-demo", "service-demo")))
        self.assertIsNone(guide(reading=None))

    def test_done_names_where_the_address_landed(self) -> None:
        done = guide(reading=reading(deployed=True), phase="deploying", deployed_recently=True)
        assert done is not None  # noqa: S101 - narrowed for the next line
        self.assertEqual((done.owner, done.standby), ("edge-a", ("edge-b",)))


class TheSteps(NodesPage):
    def first(self, **fields: Any) -> Any:
        form = {"cluster": "gamma", "display_name": "Gamma", "vip": "198.51.100.30"}
        form.update(fields)
        return form

    def test_name_and_address_are_checked_as_create_cluster_checks_them(self) -> None:
        client = self.client_for()
        refused = self.post_to(client, "/first-cluster/name", **self.first(vip="not-an-address"))
        self.assertEqual(refused.status_code, 400)
        self.assertIn("The VIP must be an IP address", refused.text)
        taken = self.post_to(client, "/first-cluster/name", **self.first(cluster="edge-demo"))
        self.assertIn("There is already a cluster edge-demo.", taken.text)

        page = self.post_to(client, "/first-cluster/name", **self.first())
        self.assertEqual(page.status_code, 200)
        self.assertIn("Run this on the first node", page.text)
        self.assertIn("sudo apt install ./haprion-node_", page.text)
        self.assertIn('name="vip" value="198.51.100.30"', page.text)
        self.assertEqual(self.queued, [])

    def test_the_first_node_is_shown_and_then_creates_the_cluster(self) -> None:
        client = self.client_for()
        pasted = block("gamma", "gamma-a")
        shown = self.post_to(client, "/first-cluster/first-node", **self.first(block=pasted))
        self.assertEqual(shown.status_code, 200)
        self.assertIn("gamma-a.example.com", shown.text)
        self.assertIn(node_enrollment.fingerprint(key(1)), shown.text)
        self.assertIn(">Add gamma-a</button>", shown.text)
        self.assertEqual(self.queued, [])

        queued = self.post_to(
            client, "/first-cluster/first-node", **self.first(block=pasted, confirm="gamma-a")
        )
        self.assertEqual((queued.status_code, queued.headers["location"]), (303, "/"))
        (job,) = self.queued
        self.assertEqual((job["operation"], job["cluster"]), ("cluster_define", "gamma"))
        self.assertEqual(job["payload"]["vip"], "198.51.100.30")
        self.assertEqual(job["payload"]["blocks"], [pasted])

    def test_back_keeps_what_was_typed(self) -> None:
        page = self.post_to(
            self.client_for(), "/first-cluster/first-node", **self.first(action="back")
        )
        self.assertIn('value="Gamma"', page.text)
        self.assertIn(">Continue</button>", page.text)

    def test_the_second_node_is_add_node(self) -> None:
        client = self.client_for()
        pasted = block("edge-demo", "edge-c")
        shown = self.post_to(
            client, "/first-cluster/second-node", cluster="edge-demo", block=pasted
        )
        self.assertIn(">Add edge-c</button>", shown.text)
        self.assertEqual(self.queued, [])

        queued = self.post_to(
            client,
            "/first-cluster/second-node",
            cluster="edge-demo",
            block=pasted,
            confirm="edge-c",
        )
        self.assertEqual((queued.status_code, queued.headers["location"]), (303, "/"))
        (job,) = self.queued
        self.assertEqual((job["operation"], job["payload"]["action"]), ("cluster_node", "add"))
        self.assertIs(job["payload"]["deploy"], True)

    def test_the_steps_are_an_admin_s(self) -> None:
        reader = self.client_for(role="reader")
        self.assertEqual(
            self.post_to(reader, "/first-cluster/name", **self.first()).status_code, 403
        )

    def test_the_node_package_downloads_under_its_versioned_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            release = Path(raw)
            (release / "haprion-node.deb").write_bytes(b"!<arch>\n")
            (release / "INSTALLATION.json").write_text(
                json.dumps({"node_package": {"version": "0.8.0+git1.abc"}})
            )
            with (
                mock.patch.object(first_cluster, "RELEASE", release),
                mock.patch.object(first_cluster, "NODE_PACKAGE", release / "haprion-node.deb"),
            ):
                client = self.client_for()
                answer = client.get("/first-cluster/haprion-node_0.8.0+git1.abc_all.deb")
                missing = client.get("/first-cluster/haprion-node_9_all.deb")
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.content, b"!<arch>\n")
        self.assertEqual(missing.status_code, 404)


class OnTheDashboard(NodesPage):
    def test_a_new_installation_s_dashboard_is_the_guide(self) -> None:
        with mock.patch("haprion_ui.db.cluster_statuses", return_value=[]):
            client = self.client(replace(configuration(), management_writes=True, clusters=()))
            self.sign_in(client)
            page = client.get("/").text
        self.assertIn("Set up your first cluster", page)
        self.assertIn('action="/first-cluster/name"', page)
