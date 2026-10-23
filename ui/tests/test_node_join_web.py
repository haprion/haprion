"""The web's part in joining a new node (B317).

Held here: a v2 block's one-time key is sealed for root when the job is
queued, bound to the cluster and the node, and the job keeps the block without
it; without a sealing key the page says so instead of queueing; and the queue
refuses a block that carries its key in the clear, so no path can put it in
the job table.
"""

from __future__ import annotations

import base64
import json
import unittest
from uuid import uuid4

from haprion import node_enrollment, node_join
from haprion.dns_profile_keys import generate
from haprion.node_enrollment import Enrollment

from haprion_ui import cluster_nodes, operations
from tests.test_settings_nodes import key

# A made-up key in the key's armour; the armour named apart, as nothing real is.
ARMOUR = "OPENSSH PRIVATE KEY"
PRIVATE = (
    f"-----BEGIN {ARMOUR}-----\n"
    + "\n".join(["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"] * 5)
    + f"\n-----END {ARMOUR}-----\n"
)


def v2_block(join_key: str | None = PRIVATE) -> str:
    return node_enrollment.render(
        Enrollment(
            cluster=None,
            name="gamma-a",
            host="gamma-a.example.com",
            host_key=key(1),
            config_pull_key=key(2),
            cert_pull_key=key(3),
            join_key=join_key,
        )
    )


class TheSeal(unittest.TestCase):
    def test_the_job_keeps_the_block_and_the_key_goes_sealed(self) -> None:
        private, public = generate()
        stored, sealed = cluster_nodes.sealed_block(v2_block(), cluster="gamma", public_key=public)
        self.assertEqual(stored, v2_block(join_key=None))
        if sealed is None:
            self.fail("a v2 block went without its sealed key")
        self.assertEqual(sealed["key_id"], public.key_id)
        box = base64.b64decode(sealed["ciphertext"])
        self.assertEqual(
            node_join.open_join_key(private, box, cluster="gamma", node="gamma-a"), PRIVATE
        )
        self.assertNotIn("PRIVATE", json.dumps([stored, sealed]))

    def test_a_v1_block_goes_as_it_is_and_no_key_is_said(self) -> None:
        v1 = v2_block(join_key=None).replace("haprion-node-v2:", "x")  # not a block
        with self.assertRaises(cluster_nodes.FormProblem):
            cluster_nodes.sealed_block(v1, cluster="gamma", public_key=None)
        with self.assertRaisesRegex(cluster_nodes.FormProblem, "no key to seal"):
            cluster_nodes.sealed_block(v2_block(), cluster="gamma", public_key=None)


class TheQueue(unittest.TestCase):
    def test_a_key_in_the_clear_is_refused(self) -> None:
        for operation, payload in (
            ("cluster_node", {"action": "add", "block": v2_block(), "host": "gamma-a.example.com"}),
            (
                "cluster_define",
                {
                    "action": "add",
                    "display_name": "Gamma",
                    "vip": "198.51.100.30",
                    "node_path": "gamma",
                    "blocks": [v2_block()],
                    "hosts": ["gamma-a.example.com"],
                },
            ),
        ):
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(operations.BadPayload, "sealed"),
            ):
                operations.prepare(
                    operation=operation, cluster="gamma", request_id=uuid4(), payload=payload
                )

    def test_a_sealed_key_reaches_the_helper_request(self) -> None:
        sealed = {"key_id": "k1", "ciphertext": "Ym94"}
        prepared = operations.prepare(
            operation="cluster_node",
            cluster="gamma",
            request_id=uuid4(),
            payload={
                "action": "add",
                "block": v2_block(join_key=None),
                "host": "gamma-a.example.com",
                "join_key": sealed,
            },
        )
        self.assertEqual(json.loads(prepared.request)["parameters"]["join_key"], sealed)
        defined = operations.prepare(
            operation="cluster_define",
            cluster="gamma",
            request_id=uuid4(),
            payload={
                "action": "add",
                "display_name": "Gamma",
                "vip": "198.51.100.30",
                "node_path": "gamma",
                "blocks": [v2_block(join_key=None)],
                "hosts": ["gamma-a.example.com"],
                "join_keys": [sealed],
            },
        )
        self.assertEqual(json.loads(defined.request)["parameters"]["join_keys"], [sealed])


if __name__ == "__main__":
    unittest.main()
