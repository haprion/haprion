"""What a queued payload is allowed to say, and what it becomes.

The payload comes from a form and has been sitting in a table since. By the time
a worker reads it the only honest assumption is that it may say anything, so
these tests are mostly about refusals - and about the envelope being the engine's
own, not a second copy built here.
"""

from __future__ import annotations

import json
import unittest
from uuid import uuid4

from haproxy_mgmt.cli import deploy, managed_network_publish

from haproxy_ui import operations

REQUEST = uuid4()


class TheCommandComesFromTheEngine(unittest.TestCase):
    def test_a_deploy_sends_the_engines_own_envelope(self) -> None:
        prepared = operations.prepare(
            operation="deploy", cluster="alpha", request_id=REQUEST, payload={}
        )
        envelope = json.loads(prepared.request)

        self.assertEqual(
            envelope,
            json.loads(
                deploy.build_request(
                    "alpha",
                    str(REQUEST),
                    allow_vip_unknown=False,
                    json_mode=True,
                    lifeline=True,
                )
            ),
        )

    def test_the_worker_declares_a_lifeline(self) -> None:
        """The worker holds stdin open; the command line does not.

        The worker has a lease it can lose and no way to signal a helper running
        as root. A person at a terminal has Ctrl-C and no lease, so the engine's
        own default stays False and nothing about the command line changes.
        """

        for operation in ("deploy", "cert_deploy"):
            with self.subTest(operation=operation):
                prepared = operations.prepare(
                    operation=operation, cluster="alpha", request_id=REQUEST, payload={}
                )
                self.assertIs(json.loads(prepared.request)["lifeline"], True)

    def test_the_queued_request_id_is_the_one_that_is_sent(self) -> None:
        #
        # This is what makes "did this operation take effect?" answerable after a
        # crash: the ID in the job row is the ID the helper saw.
        #
        prepared = operations.prepare(
            operation="deploy", cluster="alpha", request_id=REQUEST, payload={}
        )

        self.assertEqual(json.loads(prepared.request)["request_id"], str(REQUEST))

    def test_the_worker_always_asks_for_a_machine_readable_answer(self) -> None:
        prepared = operations.prepare(
            operation="cert_deploy", cluster="alpha", request_id=REQUEST, payload={}
        )

        self.assertIs(json.loads(prepared.request)["parameters"]["json"], True)

    def test_sudo_runs_without_a_terminal_and_ends_its_options(self) -> None:
        prepared = operations.prepare(
            operation="deploy", cluster="alpha", request_id=REQUEST, payload={}
        )

        self.assertEqual(prepared.argv[1:3], ("-n", "--"))

    def test_a_revert_carries_the_version_and_the_expected_commit(self) -> None:
        prepared = operations.prepare(
            operation="revert",
            cluster="alpha",
            request_id=REQUEST,
            payload={"version": 12, "expected_commit": "a" * 40},
        )
        parameters = json.loads(prepared.request)["parameters"]

        self.assertEqual(parameters["version"], 12)
        self.assertEqual(parameters["expected_commit"], "a" * 40)

    def test_a_network_publish_sends_the_engines_own_envelope(self) -> None:
        prepared = operations.prepare(
            operation="network_publish",
            cluster="alpha",
            request_id=REQUEST,
            payload={
                "network": "vips: {}\n",
                "expected_head": "a" * 40,
                "comment": "Add a source",
            },
        )

        self.assertEqual(
            json.loads(prepared.request),
            json.loads(
                managed_network_publish.build_request(
                    "alpha",
                    str(REQUEST),
                    network="vips: {}\n",
                    expected_head="a" * 40,
                    comment="Add a source",
                )
            ),
        )


class PayloadsAreRefusedRatherThanTrimmed(unittest.TestCase):
    def test_an_unknown_operation_is_refused(self) -> None:
        with self.assertRaises(operations.UnknownOperation):
            operations.prepare(operation="publish", cluster="alpha", request_id=REQUEST, payload={})

    def test_an_unexpected_parameter_is_refused_rather_than_ignored(self) -> None:
        #
        # Ignoring it would run a different operation from the one that was
        # asked for, and the row would say the asked-for one had been done.
        #
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="deploy",
                cluster="alpha",
                request_id=REQUEST,
                payload={"allow_vip_unknown": True, "force": True},
            )

    def test_a_flag_that_is_not_a_boolean_is_refused(self) -> None:
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="deploy",
                cluster="alpha",
                request_id=REQUEST,
                payload={"allow_vip_unknown": "yes"},
            )

    def test_a_boolean_version_is_not_version_one(self) -> None:
        #
        # True is an int in Python, so `version: true` would otherwise revert the
        # cluster to version 1 - a real operation, silently, from a payload that
        # meant nothing of the sort.
        #
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="revert",
                cluster="alpha",
                request_id=REQUEST,
                payload={"version": True, "expected_commit": "a" * 40},
            )

    def test_a_revert_without_an_expected_commit_is_refused(self) -> None:
        #
        # The expected commit is the fencing that makes a revert safe: without it
        # a stale request reverts whatever the cluster happens to hold now.
        #
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="revert", cluster="alpha", request_id=REQUEST, payload={"version": 3}
            )


if __name__ == "__main__":
    unittest.main()
