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

from haproxy_mgmt.cli import (
    cert_deploy,
    deploy,
    managed_network_publish,
    managed_objects_publish,
    revert,
)

from haproxy_ui import operations, worker

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

    def test_certificate_issue_forwards_only_the_profile_id_to_the_helper(self) -> None:
        prepared = operations.prepare(
            operation="cert_issue",
            cluster=None,
            request_id=REQUEST,
            payload={
                "domain": "app.example.com",
                "method": "dns-01",
                "dns_profile": "cf-main",
                "clusters": ["alpha"],
                "receivers": [],
            },
        )

        parameters = json.loads(prepared.request)["parameters"]
        self.assertEqual(parameters["dns_profile"], "cf-main")
        self.assertNotIn("provider", parameters)

    def test_profile_removal_is_bound_to_the_exact_stored_revision(self) -> None:
        row = operations.SealedProfileRow(
            id="cf-main",
            provider_id="cloudflare",
            schema_version=1,
            key_id="0123456789abcdef",
            revision=3,
            ciphertext=b"x" * 48,
        )
        prepared = operations.prepare(
            operation="dns_profile_apply",
            cluster=None,
            request_id=REQUEST,
            payload={"profile": "cf-main", "revision": 3, "remove": True},
            profile_lookup=lambda _profile: row,
        )
        self.assertIs(json.loads(prepared.request)["parameters"]["remove"], True)

        with self.assertRaisesRegex(operations.BadPayload, "revision 3, not 2"):
            operations.prepare(
                operation="dns_profile_apply",
                cluster=None,
                request_id=REQUEST,
                payload={"profile": "cf-main", "revision": 2, "remove": True},
                profile_lookup=lambda _profile: row,
            )


class DeletingCertificates(unittest.TestCase):
    def test_the_request_carries_the_ids_and_nothing_else(self) -> None:
        prepared = operations.prepare(
            operation="cert_delete",
            cluster=None,
            request_id=REQUEST,
            payload={"certificates": ["old.example.com", "older.example.net"]},
        )
        self.assertEqual(
            prepared.argv[-1], "/opt/haproxy-mgmt/current/bin/haproxy-cert-delete-helper"
        )
        request = json.loads(prepared.request)
        self.assertIsNone(request["cluster"])
        self.assertEqual(
            request["parameters"], {"certificates": ["old.example.com", "older.example.net"]}
        )

    def test_the_list_is_held_to_shape_and_size(self) -> None:
        for payload in (
            {"certificates": []},
            {"certificates": "old.example.com"},
            {"certificates": ["../etc/passwd"]},
            {"certificates": ["a.example", "a.example"]},
            {"certificates": [f"c{i}.example" for i in range(33)]},
            {"certificates": ["a.example"], "force": True},
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_delete", cluster=None, request_id=REQUEST, payload=payload
                )

    def test_a_draft_that_names_a_certificate_refuses_the_job(self) -> None:
        """The check the web makes as it queues; the worker holds no grant on
        drafts and passes nothing here."""

        with self.assertRaisesRegex(operations.BadPayload, "alpha/shop"):
            operations.prepare(
                operation="cert_delete",
                cluster=None,
                request_id=REQUEST,
                payload={"certificates": ["old.example.com"]},
                draft_references=lambda ids: {"old.example.com": ("alpha/shop",)},
            )
        operations.prepare(
            operation="cert_delete",
            cluster=None,
            request_id=REQUEST,
            payload={"certificates": ["old.example.com"]},
            draft_references=lambda ids: {},
        )

    def test_a_cluster_is_refused(self) -> None:
        with self.assertRaises(operations.BadPayload):
            operations.prepare(
                operation="cert_delete",
                cluster="alpha",
                request_id=REQUEST,
                payload={"certificates": ["old.example.com"]},
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

    def test_the_draft_it_came_from_is_checked_and_never_forwarded(self) -> None:
        #
        # Which draft row this publish came from, so the row can be recognised
        # as published rather than guessed at from its text. Checked like every
        # other field - a job is what the worker runs as root - and deliberately
        # absent from the helper's request, whose parameters are named one at a
        # time.
        #
        prepared = self.prepare(draft={"id": "11111111-2222-3333-4444-555555555555", "revision": 4})

        self.assertNotIn("draft", prepared.request)
        self.assertNotIn("11111111", prepared.request)

    def test_a_draft_that_is_not_an_id_and_a_revision_is_refused(self) -> None:
        for value in (
            {"id": "", "revision": 1},
            {"id": "11111111-2222-3333-4444-555555555555"},
            {"id": "11111111-2222-3333-4444-555555555555", "revision": "4"},
            {"id": "11111111-2222-3333-4444-555555555555", "revision": True},
            {"id": "11111111-2222-3333-4444-555555555555", "revision": 4, "extra": 1},
            "not a mapping",
        ):
            with self.subTest(draft=value), self.assertRaises(operations.BadPayload):
                self.prepare(draft=value)

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


class TheWorkerMustBeAllowedToRunWhatItIsGiven(unittest.TestCase):
    """Every helper the worker is prepared to run needs a rule naming it.

    The rule is a file outside this repository, written from an example inside
    it, and neither follows a release - so a helper added here reaches sudo's
    refusal on its first use, as `haproxy-objects-publish-helper` did. The
    example is what an installation renders, so it is the thing to hold in step.

    It also has to be rendered rather than copied. It was installed as
    /etc/sudoers.d/${WORKER_USER} while naming one fixed account in every line,
    so a platform whose worker is called something else got a file visudo
    accepts and sudo ignores.
    """

    def example(self) -> str:
        path = (
            Path(__file__).resolve().parents[2]
            / "install"
            / "platform"
            / "examples"
            / "haproxy-ui-worker.sudoers.example"
        )
        return path.read_text(encoding="utf-8")

    def rules(self) -> list[str]:
        return [line for line in self.example().splitlines() if "ALL=(root)" in line]

    def test_every_helper_the_worker_may_run_has_a_rule(self) -> None:
        helpers = {
            deploy.HELPER,
            cert_deploy.HELPER,
            revert.HELPER,
            managed_network_publish.HELPER,
            managed_objects_publish.HELPER,
        }
        granted = self.example()

        for helper in sorted(helpers):
            with self.subTest(helper=helper):
                self.assertIn(f'{helper} ""', granted)

    def test_no_rule_names_an_account_the_installation_did_not_choose(self) -> None:
        self.assertTrue(self.rules(), "the example grants nothing")
        for rule in self.rules():
            with self.subTest(rule=rule):
                self.assertTrue(rule.startswith("WORKER_USER "), rule)


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

    def test_every_operation_has_an_answer_the_worker_will_accept(self) -> None:
        """Otherwise the operation runs, takes effect, and is recorded as unknown.

        The worker judges a helper's envelope against the outcomes that
        operation may produce, and an operation missing from that table has an
        empty set - so every answer it gives is rejected. The command still ran.
        `objects_publish` did exactly this: the commit was written and the job
        said nobody could tell.
        """

        for operation in sorted(self.operations_prepare_accepts()):
            with self.subTest(operation=operation):
                self.assertIn(operation, worker._OPERATION_OUTCOMES)
                self.assertTrue(worker._OPERATION_OUTCOMES[operation])

    def test_the_accepted_outcomes_are_the_schema_s_own(self) -> None:
        """The contract says which answers exist; the worker must not invent more."""

        #
        # From this file rather than from the installed package: a release
        # carries the interface, not the engine's schema directory, and the
        # contract these are held against lives in the repository.
        #
        schemas = Path(__file__).resolve().parents[2] / "schemas" / "v1"
        for name, path in (
            ("network_publish", "haproxy-network-publish.schema.json"),
            ("objects_publish", "haproxy-objects-publish.schema.json"),
            ("cert_issue", "haproxy-cert-issue.schema.json"),
            ("dns_profile_apply", "haproxy-dns-profile-apply.schema.json"),
            ("ndes_profile_apply", "haproxy-ndes-profile-apply.schema.json"),
            ("cert_publish", "haproxy-cert-publish.schema.json"),
            ("cert_target", "haproxy-cert-target.schema.json"),
            ("cert_delete", "haproxy-cert-delete.schema.json"),
        ):
            with self.subTest(operation=name):
                document = json.loads((schemas / path).read_text(encoding="utf-8"))
                #
                # The envelope's shared fields come in by `$ref`, so the branch
                # that names this operation's own outcomes is the one carrying
                # `properties`. Found rather than indexed by position: the order
                # of an `allOf` is not part of the contract.
                #
                declared = next(
                    set(branch["properties"]["outcome"]["enum"])
                    for branch in document["allOf"]
                    if "properties" in branch and "outcome" in branch["properties"]
                )
                self.assertEqual(worker._OPERATION_OUTCOMES[name], declared)

    def test_every_operation_the_code_prepares_may_be_queued(self) -> None:
        permitted = self.constraint()
        accepted = self.operations_prepare_accepts()

        self.assertTrue(accepted)
        for operation in sorted(accepted):
            with self.subTest(operation=operation):
                self.assertIn(f"'{operation}'", permitted)
