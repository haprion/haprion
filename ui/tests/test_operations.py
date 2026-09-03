"""What a queued payload is allowed to say, and what it becomes.

The payload comes from a form and has been sitting in a table since. By the time
a worker reads it the only honest assumption is that it may say anything, so
these tests are mostly about refusals - and about the envelope being the engine's
own, not a second copy built here.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from uuid import UUID, uuid4

from haproxy_mgmt.cli import deploy, managed_network_publish, managed_objects_publish

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


class PublishingObjects(unittest.TestCase):
    """The operation behind "Save and publish".

    The payload is built from a form, so every field is checked here rather
    than trusted to the helper - a helper's refusal arrives as a failed job
    instead of as a page saying what was wrong.
    """

    def prepare(self, **payload: object):
        return operations.prepare(
            operation="objects_publish",
            cluster="alpha",
            request_id=UUID("3f1c2b64-6f3f-4f3a-9c6e-1d2b3c4d5e6f"),
            payload={
                "objects": {"shop": "schema: 1"},
                "expected_head": "abc123",
                "comment": "Publish shop",
                **payload,
            },
        )

    def test_the_helper_is_named_by_the_engine_and_not_written_again(self) -> None:
        prepared = self.prepare()

        self.assertEqual(prepared.argv[-1], managed_objects_publish.HELPER)
        self.assertIn("objects_publish", prepared.request)

    def test_a_removal_is_a_null_document(self) -> None:
        prepared = self.prepare(objects={"gone": None})

        self.assertIn('"gone":null', prepared.request)

    def test_a_name_the_model_would_refuse_never_reaches_the_helper(self) -> None:
        with self.assertRaises(operations.BadPayload):
            self.prepare(objects={"Not A Name": "schema: 1"})

    def test_an_empty_set_of_objects_is_refused(self) -> None:
        with self.assertRaises(operations.BadPayload):
            self.prepare(objects={})

    def test_the_override_must_be_a_real_boolean(self) -> None:
        """A string "false" arriving as true is how an override turns itself on."""

        with self.assertRaises(operations.BadPayload):
            self.prepare(allow_certificate_mismatch="false")

    def test_it_is_off_unless_asked_for(self) -> None:
        self.assertIn('"allow_certificate_mismatch":false', self.prepare().request)


class TheQueueMustAcceptWhatTheCodeBuilds(unittest.TestCase):
    """Every operation `prepare` knows has to be one the job table permits.

    Nothing makes them agree by construction, and deliberately so: the check
    constraint is the database's own opinion of what may be queued, and a job
    row is what the worker will later run as root. Deriving it from an import
    would let code widen it.

    So a test holds them together, and this one exists because they came apart:
    the editor's publish button reached a working helper, a granted sudoers rule
    and a prepared payload, and then met a constraint nobody had widened - a 500
    at the last step of a chain whose every other link had been built.
    """

    def operations_prepare_accepts(self) -> set[str]:
        source = Path(operations.__file__).read_text(encoding="utf-8")
        return set(re.findall(r'if operation == "([a-z_]+)"', source))

    def constraint(self) -> str:
        versions = Path(__file__).resolve().parents[1] / "migrations" / "versions"
        speaking = [
            path
            for path in sorted(versions.glob("[0-9]*.py"))
            if "job_operation_allowed" in path.read_text(encoding="utf-8")
        ]
        self.assertTrue(speaking, "no migration constrains the job operation")
        #
        # The last migration to speak, and its `upgrade` half only: the
        # downgrade below it names the previous, narrower set.
        #
        text = speaking[-1].read_text(encoding="utf-8")
        return text[: text.index("def downgrade")]

    def test_every_operation_the_code_prepares_may_be_queued(self) -> None:
        permitted = self.constraint()
        accepted = self.operations_prepare_accepts()

        self.assertTrue(accepted)
        for operation in sorted(accepted):
            with self.subTest(operation=operation):
                self.assertIn(f"'{operation}'", permitted)
