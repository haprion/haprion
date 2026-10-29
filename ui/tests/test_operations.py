"""What a queued payload is allowed to say, and what it becomes.

The payload comes from a form and has been sitting in a table since. By the time
a worker reads it the only honest assumption is that it may say anything, so
these tests are mostly about refusals - and about the envelope being the engine's
own, not a second copy built here.
"""

from __future__ import annotations

import io
import json
import os
import re
import unittest
from pathlib import Path
from unittest import mock
from uuid import UUID, uuid4

from haprion import (
    accounts,
    cert_issue,
    cert_receiver,
    helper_protocol,
    server_state,
    state_backup,
)
from haprion import cert_publish as cert_publish_model
from haprion.cli import (
    backup_job_helper,
    cert_publish,
    cert_receiver_helper,
    changes_publish,
    deploy,
    deploy_helper,
    node_ask,
    server_state_helper,
    socket_ask,
)
from haprion.status_collect import STATUS_TIMEOUT_SECONDS

from haprion_ui import answers, operations, worker

REQUEST = uuid4()


class TheCommandComesFromTheEngine(unittest.TestCase):
    def test_a_backup_schedule_is_bounded_before_it_is_queued(self) -> None:
        prepared = operations.prepare(
            operation="backup_schedule",
            cluster="alpha",
            request_id=REQUEST,
            payload={
                "time": "22:30",
                "frequency": "weekly",
                "weekdays": ["Fri", "Mon"],
                "day_of_month": "",
                "retention": 30,
                "enabled": True,
            },
        )
        parameters = json.loads(prepared.request)["parameters"]
        self.assertEqual(parameters["weekdays"], ["Mon", "Fri"])
        self.assertIsNone(parameters["day_of_month"])
        self.assertEqual(parameters["retention"], 30)

        for payload in (
            {"time": "5:00", "enabled": True},
            {"time": "05:00", "frequency": "weekly", "weekdays": [], "enabled": True},
            {"time": "05:00", "frequency": "monthly", "day_of_month": "x", "enabled": True},
            {"time": "05:00", "retention": "30", "enabled": True},
            {"time": "05:00", "enabled": True, "unit": "x.timer"},
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="backup_schedule",
                    cluster="alpha",
                    request_id=REQUEST,
                    payload=payload,
                )

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

    def test_a_deploy_carries_the_version_the_page_showed(self) -> None:
        prepared = operations.prepare(
            operation="deploy",
            cluster="alpha",
            request_id=REQUEST,
            payload={"expected_version": 12},
        )
        self.assertEqual(json.loads(prepared.request)["parameters"]["expected_version"], 12)

        for value in ("12", True, 0, -1, 1.5):
            with self.subTest(value=value), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="deploy",
                    cluster="alpha",
                    request_id=REQUEST,
                    payload={"expected_version": value},
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
        self.assertNotIn("expected_head", parameters)

    def test_a_revert_carries_the_head_its_page_listed(self) -> None:
        """CR-09: the helper refuses once anything was recorded after it."""

        prepared = operations.prepare(
            operation="revert",
            cluster="alpha",
            request_id=REQUEST,
            payload={"version": 12, "expected_commit": "a" * 40, "expected_head": "b" * 40},
        )

        self.assertEqual(json.loads(prepared.request)["parameters"]["expected_head"], "b" * 40)

    def test_who_asked_goes_to_every_helper_that_records_a_version(self) -> None:
        #
        # B207: the signed-in person, carried by the job and checked here the
        # way the helper checks it, so a refusal comes before the lock.
        #
        for operation, payload in (
            ("revert", {"version": 12, "expected_commit": "a" * 40}),
            (
                "changes_publish",
                {"objects": {"shop": "x"}, "expected_head": "a" * 40, "comment": "c"},
            ),
        ):
            with self.subTest(operation=operation):
                named = operations.prepare(
                    operation=operation,
                    cluster="alpha",
                    request_id=REQUEST,
                    payload={**payload, "requested_by": "Ada Admin"},
                )
                unnamed = operations.prepare(
                    operation=operation, cluster="alpha", request_id=REQUEST, payload=payload
                )
                self.assertEqual(
                    json.loads(named.request)["parameters"]["requested_by"], "Ada Admin"
                )
                self.assertNotIn("requested_by", json.loads(unnamed.request)["parameters"])
                with self.assertRaises(operations.BadPayload):
                    operations.prepare(
                        operation=operation,
                        cluster="alpha",
                        request_id=REQUEST,
                        payload={**payload, "requested_by": "ada\nRun-By: root"},
                    )

    def test_a_network_publish_sends_the_engines_own_envelope(self) -> None:
        prepared = operations.prepare(
            operation="changes_publish",
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
                changes_publish.build_request(
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

    def test_a_certificate_job_outlasts_the_slowest_provider_s_certbot_run(self) -> None:
        issue = operations.prepare(
            operation="cert_issue",
            cluster=None,
            request_id=REQUEST,
            payload={"domain": "app.example.com", "method": "dns-01", "clusters": ["alpha"]},
        )
        renew = operations.prepare(
            operation="cert_issue",
            cluster=None,
            request_id=REQUEST,
            payload={"domain": "app.example.com", "renew": True},
        )
        deploy = operations.prepare(
            operation="deploy", cluster="alpha", request_id=REQUEST, payload={}
        )

        slowest = cert_issue.longest_certbot_timeout()
        for prepared in (issue, renew):
            self.assertGreaterEqual(prepared.timeout_seconds - slowest, operations.TIMEOUT_SECONDS)
        self.assertEqual(deploy.timeout_seconds, operations.TIMEOUT_SECONDS)

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


class ImportingACaCertificate(unittest.TestCase):
    """B276: a CA through `cert_import`, from an upload or from the NDES CA with no file."""

    def test_the_ndes_ca_carries_no_box(self) -> None:
        prepared = operations.prepare(
            operation="cert_import",
            cluster=None,
            request_id=REQUEST,
            payload={"id": "corp-root", "authority": "ndes", "clusters": ["alpha"]},
        )

        parameters = json.loads(prepared.request)["parameters"]
        self.assertEqual(
            parameters,
            {
                "certificate": "corp-root",
                "clusters": ["alpha"],
                "receivers": [],
                "authority": "ndes",
            },
        )

    def test_an_upload_carries_its_box_and_the_mark(self) -> None:
        prepared = operations.prepare(
            operation="cert_import",
            cluster=None,
            request_id=REQUEST,
            payload={
                "id": "corp-root",
                "key_id": "0123456789abcdef",
                "ciphertext": "AAAA",
                "clusters": ["alpha"],
                "receivers": [],
                "authority": "upload",
            },
        )

        parameters = json.loads(prepared.request)["parameters"]
        self.assertEqual(parameters["authority"], "upload")
        self.assertEqual(parameters["ciphertext"], "AAAA")

    def test_what_a_ca_payload_may_not_carry(self) -> None:
        for payload in (
            {"id": "corp-root", "authority": "ndes", "clusters": ["alpha"], "ciphertext": "AA=="},
            {"id": "corp-root", "authority": "ndes", "clusters": [], "receivers": ["lb-01"]},
            {"id": "corp-root", "authority": "ndes", "clusters": []},
            {"id": "corp-root", "authority": "elsewhere", "clusters": ["alpha"]},
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_import", cluster=None, request_id=REQUEST, payload=payload
                )


class DeletingCertificates(unittest.TestCase):
    def test_the_request_carries_the_ids_and_nothing_else(self) -> None:
        prepared = operations.prepare(
            operation="cert_delete",
            cluster=None,
            request_id=REQUEST,
            payload={"certificates": ["old.example.com", "older.example.net"]},
        )
        self.assertEqual(prepared.argv[-1], "/opt/haprion/current/bin/haprion-cert-delete-helper")
        request = json.loads(prepared.request)
        self.assertIsNone(request["cluster"])
        self.assertEqual(
            request["parameters"], {"certificates": ["old.example.com", "older.example.net"]}
        )

    def test_the_list_is_held_to_shape_and_size(self) -> None:
        payloads: tuple[dict[str, object], ...] = (
            {"certificates": []},
            {"certificates": "old.example.com"},
            {"certificates": ["../etc/passwd"]},
            {"certificates": ["a.example", "a.example"]},
            {"certificates": [f"c{i}.example" for i in range(33)]},
            {"certificates": ["a.example"], "force": True},
        )
        for payload in payloads:
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


class RetargetingCertificates(unittest.TestCase):
    """Publish to… and Remove from… (2026-09-15): a list of IDs and one delta."""

    def test_a_receiver_s_format_rides_in_the_delta_and_is_checked_here(self) -> None:
        prepared = operations.prepare(
            operation="cert_target",
            cluster=None,
            request_id=REQUEST,
            payload={
                "certificates": ["a.example"],
                "action": "add",
                "receivers": ["lb-01"],
                "formats": {"lb-01": "pkcs12"},
            },
        )
        self.assertEqual(
            json.loads(prepared.request)["parameters"]["add"],
            {"clusters": [], "receivers": ["lb-01"], "formats": {"lb-01": "pkcs12"}},
        )
        for payload in (
            {
                "certificates": ["a.example"],
                "action": "add",
                "receivers": ["lb-01"],
                "formats": {"lb-02": "pkcs12"},
            },
            {
                "certificates": ["a.example"],
                "action": "add",
                "receivers": ["lb-01"],
                "formats": {"lb-01": "der"},
            },
            {
                "certificates": ["a.example"],
                "action": "add",
                "receivers": ["lb-01"],
                "formats": ["lb-01"],
            },
            {
                "certificates": ["a.example"],
                "action": "remove",
                "receivers": ["lb-01"],
                "formats": {"lb-01": "pkcs12"},
            },
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_target", cluster=None, request_id=REQUEST, payload=payload
                )

    def test_the_request_carries_the_ids_and_the_delta(self) -> None:
        prepared = operations.prepare(
            operation="cert_target",
            cluster=None,
            request_id=REQUEST,
            payload={
                "certificates": ["a.example", "b.example"],
                "action": "add",
                "clusters": ["beta"],
            },
        )
        self.assertEqual(prepared.argv[-1], "/opt/haprion/current/bin/haprion-cert-target-helper")
        request = json.loads(prepared.request)
        self.assertIsNone(request["cluster"])
        self.assertEqual(
            request["parameters"],
            {
                "certificates": ["a.example", "b.example"],
                "add": {"clusters": ["beta"], "receivers": []},
                "deploy": True,
            },
        )
        prepared = operations.prepare(
            operation="cert_target",
            cluster=None,
            request_id=REQUEST,
            payload={"certificates": ["a.example"], "action": "remove", "receivers": ["lb-01"]},
        )
        self.assertEqual(
            json.loads(prepared.request)["parameters"]["remove"],
            {"clusters": [], "receivers": ["lb-01"]},
        )

    def test_the_payload_is_held_to_shape(self) -> None:
        for payload in (
            {"certificates": [], "action": "add", "clusters": ["beta"]},
            {"certificates": ["a.example"], "action": "replace", "clusters": ["beta"]},
            {"certificates": ["a.example"], "action": "add"},
            {"certificates": ["a.example"], "action": "add", "clusters": ["beta"], "extra": 1},
            {"certificates": ["a.example", "a.example"], "action": "add", "clusters": ["beta"]},
            {"certificate": "a.example", "clusters": ["beta"]},
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_target", cluster=None, request_id=REQUEST, payload=payload
                )

    def test_a_draft_in_the_dropped_cluster_refuses_a_remove_and_nothing_else(self) -> None:
        references = {"a.example": ("alpha/shop", "beta/shop")}
        with self.assertRaisesRegex(operations.BadPayload, "beta/shop"):
            operations.prepare(
                operation="cert_target",
                cluster=None,
                request_id=REQUEST,
                payload={"certificates": ["a.example"], "action": "remove", "clusters": ["beta"]},
                draft_references=lambda ids: references,
            )
        # A draft in another cluster, or an add, is not held by it.
        for payload in (
            {"certificates": ["a.example"], "action": "remove", "clusters": ["gamma"]},
            {"certificates": ["a.example"], "action": "add", "clusters": ["beta"]},
            {"certificates": ["a.example"], "action": "remove", "receivers": ["lb-01"]},
        ):
            operations.prepare(
                operation="cert_target",
                cluster=None,
                request_id=REQUEST,
                payload=payload,
                draft_references=lambda ids: references,
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


class PublishingSavedChanges(unittest.TestCase):
    """The operation behind *Publish* on Versions (B257).

    The payload is built from a form, so every field is checked here rather
    than trusted to the helper - a helper's refusal arrives as a failed job
    instead of as a page saying what was wrong.
    """

    def prepare(self, **payload: object) -> operations.Prepared:
        return operations.prepare(
            operation="changes_publish",
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

        self.assertEqual(prepared.argv[-1], changes_publish.HELPER)
        self.assertIn("changes_publish", prepared.request)

    def test_the_rows_it_came_from_are_checked_and_never_forwarded(self) -> None:
        #
        # Which saved rows this publish carries, so each can be recognised as
        # published rather than guessed at from its text. Checked like every
        # other field - a job is what the worker runs as root - and deliberately
        # absent from the helper's request, whose parameters are named one at a
        # time.
        #
        row = {"id": "11111111-2222-3333-4444-555555555555", "revision": 4}
        prepared = self.prepare(drafts=[row], changes=[{**row, "id": "22222222"}])

        self.assertNotIn("drafts", prepared.request)
        self.assertNotIn('changes"', prepared.request)
        self.assertNotIn("11111111", prepared.request)
        self.assertNotIn("22222222", prepared.request)

    def test_a_row_that_is_not_an_id_and_a_revision_is_refused(self) -> None:
        for value in (
            {"id": "", "revision": 1},
            {"id": "11111111-2222-3333-4444-555555555555"},
            {"id": "11111111-2222-3333-4444-555555555555", "revision": "4"},
            {"id": "11111111-2222-3333-4444-555555555555", "revision": True},
            {"id": "11111111-2222-3333-4444-555555555555", "revision": 4, "extra": 1},
            "not a mapping",
        ):
            for key in ("drafts", "changes"):
                with self.subTest(key=key, row=value), self.assertRaises(operations.BadPayload):
                    self.prepare(**{key: [value]})

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


class AServerStateJob(unittest.TestCase):
    """B263: the worker sends the command line's request, and refuses a shape it never could."""

    PAYLOAD = {"object": "shop", "servers": ["web/198.51.100.10:8080"], "state": "drain"}

    def test_it_is_the_engines_own_request_through_sudo(self) -> None:
        prepared = operations.prepare(
            operation="server_state", cluster="alpha", request_id=REQUEST, payload=self.PAYLOAD
        )

        self.assertEqual(prepared.argv[-1], server_state_helper.HELPER)
        self.assertEqual(
            json.loads(prepared.request),
            json.loads(
                server_state_helper.build_request(
                    "alpha",
                    str(REQUEST),
                    object_name="shop",
                    servers=["web/198.51.100.10:8080"],
                    state="drain",
                )
            ),
        )

    def test_a_payload_that_could_never_be_right_is_refused_before_sudo(self) -> None:
        changes: tuple[dict[str, object], ...] = (
            {"state": "down"},
            {"servers": []},
            {"servers": "web/198.51.100.10:8080"},
            {"servers": ["198.51.100.10:8080"] * 65},
            {"object": "Shop;id"},
            {"force": True},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="server_state",
                    cluster="alpha",
                    request_id=REQUEST,
                    payload={**self.PAYLOAD, **change},
                )


class ADynamicUnblockJob(unittest.TestCase):
    """B271: the command line's unblock request, and a shape it never could be refused."""

    PAYLOAD = {"object": "shop", "addresses": ["203.0.113.7", "2001:db8::7"]}

    def test_it_is_the_engines_own_request_through_sudo(self) -> None:
        prepared = operations.prepare(
            operation="dynamic_unblock", cluster="alpha", request_id=REQUEST, payload=self.PAYLOAD
        )

        self.assertEqual(prepared.argv[-1], server_state_helper.HELPER)
        self.assertEqual(
            json.loads(prepared.request),
            json.loads(
                server_state_helper.build_unblock_request(
                    "alpha",
                    str(REQUEST),
                    object_name="shop",
                    addresses=["203.0.113.7", "2001:db8::7"],
                )
            ),
        )

    def test_a_payload_that_could_never_be_right_is_refused_before_sudo(self) -> None:
        changes: tuple[dict[str, object], ...] = (
            {"addresses": []},
            {"addresses": "203.0.113.7"},
            {"addresses": ["203.0.113.7"] * 65},
            {"addresses": [""]},
            {"object": "Shop;id"},
            {"state": "drain"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="dynamic_unblock",
                    cluster="alpha",
                    request_id=REQUEST,
                    payload={**self.PAYLOAD, **change},
                )


class TheWorkerMustBeAllowedToRunWhatItIsGiven(unittest.TestCase):
    """Every helper the worker is prepared to run needs a rule naming it.

    The rule is a file outside this repository, written from an example inside
    it, and neither follows a release - so a helper added here reaches sudo's
    refusal on its first use, as the first objects publish helper did. The
    example is what an installation installs, so it is the thing to hold in step.
    """

    def example(self) -> str:
        path = (
            Path(__file__).resolve().parents[2]
            / "install"
            / "platform"
            / "examples"
            / "haprion-worker.sudoers.example"
        )
        return path.read_text(encoding="utf-8")

    def rules(self) -> list[str]:
        return [line for line in self.example().splitlines() if "ALL=(root)" in line]

    def test_every_helper_the_worker_may_run_has_a_rule(self) -> None:
        #
        # Read off the module rather than listed here: until 2026-10-09 this
        # named four helpers by hand while the worker ran thirteen, so a new
        # one could miss its rule and still pass.
        #
        source = Path(operations.__file__).read_text(encoding="utf-8")
        modules = re.findall(r"argv=\(\w+\.SUDO, \*SUDO_FLAGS, (\w+)\.HELPER\)", source)
        helpers = {getattr(operations, module).HELPER for module in modules}
        self.assertIn(server_state_helper.HELPER, helpers)
        granted = self.example()

        for helper in sorted(helpers):
            with self.subTest(helper=helper):
                self.assertIn(f'{helper} ""', granted)

    def test_every_rule_names_the_worker_and_no_other_account(self) -> None:
        self.assertTrue(self.rules(), "the example grants nothing")
        for rule in self.rules():
            with self.subTest(rule=rule):
                self.assertTrue(rule.startswith(f"{accounts.WORKER} "), rule)


class TheReceiverHelperIsNotReachedThroughSudo(unittest.TestCase):
    """B163: the one helper that writes /etc answers on a socket instead.

    A sudoers rule for it would be worse than none: the worker's unit keeps
    /etc read-only for everything it starts, so the rule would grant a helper
    that fails at its first write while saying in /etc/sudoers.d that it may
    run. What the worker runs is its own client, as itself.
    """

    def test_the_prepared_command_is_the_client_and_not_sudo(self) -> None:
        for payload in (
            {"receiver": "lb-02.example.net", "action": "remove"},
            {
                "receiver": "lb-02.example.net",
                "action": "add",
                "transport": "sftp",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample lb-02",
            },
            {
                "receiver": "lb-02.example.net",
                "action": "key",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewOne lb-02",
            },
        ):
            with self.subTest(action=payload["action"]):
                prepared = operations.prepare(
                    operation="cert_receiver",
                    cluster=None,
                    request_id=uuid4(),
                    payload=payload,
                )

                self.assertEqual(prepared.argv, operations.RECEIVER_CLIENT)
                self.assertNotIn("/usr/bin/sudo", prepared.argv)
                self.assertEqual(prepared.argv[1:], ("-m", "haprion.cli.cert_receiver_ask"))
                self.assertEqual(json.loads(prepared.request)["operation"], "cert_receiver")

    def test_a_new_key_takes_the_key_and_nothing_else(self) -> None:
        """26-10-18: the lock it was registered with is the helper's to keep."""

        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewOne lb-02"
        for extra in (
            {},
            {"public_key": key, "transport": "rsync"},
            {"public_key": key, "allow": ["192.0.2.0/24"]},
            {"public_key": "   "},
        ):
            with self.subTest(extra=extra), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_receiver",
                    cluster=None,
                    request_id=uuid4(),
                    payload={"receiver": "lb-02.example.net", "action": "key", **extra},
                )

    def test_the_sudoers_example_grants_it_nothing(self) -> None:
        granted = TheWorkerMustBeAllowedToRunWhatItIsGiven().example()

        self.assertNotIn(cert_receiver_helper.HELPER, granted)


class DefiningClusters(unittest.TestCase):
    """B211: a whole cluster created or removed through the node helper's socket."""

    CREATION = {
        "action": "add",
        "display_name": "Gamma",
        "vip": "198.51.100.30",
        "node_path": "gamma",
        "default_certificate": "example.net",
        "blocks": ["block-one", "block-two"],
        "hosts": ["node-c.example.com", "node-d.example.com"],
        "address_prefix": 24,
    }

    def prepare(self, payload: dict[str, object]) -> operations.Prepared:
        return operations.prepare(
            operation="cluster_define", cluster="gamma", request_id=REQUEST, payload=payload
        )

    def test_a_creation_is_the_request_haproxy_cluster_sends(self) -> None:
        prepared = self.prepare(self.CREATION)

        self.assertEqual(prepared.argv, operations.NODE_CLIENT)
        request = json.loads(prepared.request)
        self.assertEqual((request["operation"], request["cluster"]), ("cluster_define", "gamma"))
        self.assertEqual(request["parameters"], self.CREATION)

    def test_the_client_carries_every_request_built_for_it_to_the_helper(self) -> None:
        built = [
            self.prepare(self.CREATION),
            self.prepare({"action": "remove"}),
            operations.prepare(
                operation="cluster_node",
                cluster="gamma",
                request_id=REQUEST,
                payload={"action": "add", "block": "block-one", "host": "node-c.example.com"},
            ),
        ]
        for prepared in built:
            with self.subTest(request=prepared.request[:60]):
                self.assertEqual(prepared.argv, operations.NODE_CLIENT)
                carried = socket_ask._read(io.BytesIO(prepared.request.encode()))
                self.assertEqual(carried, json.loads(prepared.request))
                self.assertIn(
                    json.loads(prepared.request)["operation"], node_ask.SERVICE.operations or ()
                )

    def test_a_removal_carries_nothing_but_its_action(self) -> None:
        request = json.loads(self.prepare({"action": "remove"}).request)

        self.assertEqual(request["parameters"], {"action": "remove"})
        with self.assertRaisesRegex(operations.BadPayload, "nothing else"):
            self.prepare({"action": "remove", "vip": "198.51.100.30"})

    def test_a_node_change_asked_to_deploy_tells_the_helper_nothing_of_it(self) -> None:
        """B321: `deploy` is the worker's to act on; the helper's request is as before."""

        def node(payload: dict[str, object]) -> operations.Prepared:
            return operations.prepare(
                operation="cluster_node", cluster="gamma", request_id=REQUEST, payload=payload
            )

        removal = json.loads(node({"action": "remove", "node": "node-b", "deploy": True}).request)
        self.assertEqual(removal["parameters"], {"action": "remove", "node": "node-b"})
        addition = json.loads(
            node(
                {
                    "action": "add",
                    "block": "block-one",
                    "host": "node-c.example.com",
                    "deploy": True,
                }
            ).request
        )
        self.assertNotIn("deploy", addition["parameters"])
        refused: tuple[tuple[dict[str, object], str], ...] = (
            ({"action": "remove", "node": "node-b", "deploy": "yes"}, "true or false"),
            ({"action": "host", "node": "node-b", "host": "lb-02", "deploy": True}, "only an"),
        )
        for payload, message in refused:
            with self.subTest(payload), self.assertRaisesRegex(operations.BadPayload, message):
                node(payload)

    def test_a_creation_short_of_its_shape_is_refused(self) -> None:
        for change, message in (
            ({"hosts": ["node-c.example.com"]}, "pair up"),
            ({"hosts": []}, "one or two hosts"),
            ({"blocks": ["one", "two", "three"]}, "one or two blocks"),
            ({"blocks": ["one", " "]}, "one or two blocks"),
            ({"default_certificate": ""}, "default certificate must be a name"),
            ({"vip": ""}, "its vip"),
            ({"address_prefix": "24"}, "prefix must be a number"),
            ({"address_prefix": True}, "prefix must be a number"),
            ({"root": "/"}, "unexpected parameters: root"),
            ({"action": "rename"}, "add or remove"),
        ):
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(operations.BadPayload, message),
            ):
                self.prepare({**self.CREATION, **change})


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
        return set(operations.OPERATIONS)

    def test_the_registry_is_what_prepare_accepts(self) -> None:
        """Asked of `prepare` itself: the regular expression these tests read the
        file with did not see `dynamic_unblock`, which compares with a constant
        (review 2026-10-22, 6-6)."""

        for operation in sorted(operations.OPERATIONS):
            with self.subTest(operation=operation):
                try:
                    operations.prepare(
                        operation=operation,
                        cluster=None if operation in operations.CERTIFICATE_OPERATIONS else "alpha",
                        request_id=uuid4(),
                        payload={},
                    )
                except operations.UnknownOperation:
                    self.fail(f"{operation} is in OPERATIONS and prepare does not know it")
                except operations.BadPayload:
                    pass
        for retired in ("publish", "x"):
            with self.subTest(operation=retired), self.assertRaises(operations.UnknownOperation):
                operations.prepare(
                    operation=retired, cluster="alpha", request_id=uuid4(), payload={}
                )
        source = Path(operations.__file__).read_text(encoding="utf-8")
        named = set(re.findall(r'if operation == "([a-z_]+)"', source))
        self.assertLessEqual(named, operations.OPERATIONS)

    def constraint(self) -> str:
        """The operations `job_operation_allowed` names, as the newest migration to speak says it.

        From the constraint's name to the end of its definition: the baseline
        writes it inside `create table` as pg_dump does, a later migration as
        an `alter table ... add constraint` of its own.
        """

        versions = Path(__file__).resolve().parents[1] / "migrations" / "versions"
        speaking = [
            path
            for path in sorted(versions.glob("[0-9]*.py"))
            if "job_operation_allowed" in path.read_text(encoding="utf-8")
        ]
        self.assertTrue(speaking, "no migration constrains the job operation")
        text = speaking[-1].read_text(encoding="utf-8")
        start = text.rindex("job_operation_allowed")
        ends = [end for end in (text.find(";", start), text.find("CONSTRAINT", start)) if end > 0]
        return text[start : min(ends)]

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
        """The contract says which answers exist; the worker must not invent more.

        Each operation's schema is found by the operation it names, for every
        operation in the registry: the list here was written by hand and left
        out deploy, cert_deploy and revert (review 2026-10-22, 6-6).
        """

        #
        # From this file rather than from the installed package: a release
        # carries the interface, not the engine's schema directory, and the
        # contract these are held against lives in the repository.
        #
        schemas = Path(__file__).resolve().parents[2] / "schemas" / "v1"
        declared: dict[str, set[str]] = {}
        for path in sorted(schemas.glob("haprion-*.schema.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            #
            # A schema is either flat or the shared envelope plus one branch of
            # its own; the branch that names the operation names its outcomes.
            #
            for branch in (document, *document.get("allOf", ())):
                properties = branch.get("properties", {})
                if "operation" not in properties or "outcome" not in properties:
                    continue
                named = properties["operation"]
                names = named.get("enum") or [named["const"]]
                for name in names:
                    declared[name] = set(properties["outcome"]["enum"])
        for name in sorted(operations.OPERATIONS):
            with self.subTest(operation=name):
                self.assertIn(name, declared, "no schema names this operation")
                self.assertEqual(worker._OPERATION_OUTCOMES[name], declared[name])

    def test_every_sudo_helper_is_one_the_release_declares(self) -> None:
        """What `check-compatibility` holds the sudo rules to is what the worker runs."""

        source = Path(operations.__file__).read_text(encoding="utf-8")
        modules = re.findall(r"argv=\(\w+\.SUDO, \*SUDO_FLAGS, (\w+)\.HELPER\)", source)
        helpers = {Path(getattr(operations, module).HELPER).name for module in modules}
        requirements = json.loads(
            (Path(operations.__file__).with_name("compatibility.json")).read_text()
        )["requires"]
        self.assertEqual(helpers, set(requirements["worker_helpers"]))

    def test_every_operation_the_code_prepares_may_be_queued(self) -> None:
        permitted = self.constraint()
        accepted = self.operations_prepare_accepts()

        self.assertTrue(accepted)
        for operation in sorted(accepted):
            with self.subTest(operation=operation):
                self.assertIn(f"'{operation}'", permitted)

    def test_the_queue_permits_nothing_the_code_does_not_prepare(self) -> None:
        """A job row is what the worker runs as root; three retired operations stayed permitted."""

        self.assertEqual(set(re.findall(r"'([a-z_]+)'", self.constraint())), operations.OPERATIONS)


class EnrollingOverNdes(unittest.TestCase):
    def test_a_request_carries_the_names_and_targets_and_never_a_secret(self) -> None:
        prepared = operations.prepare(
            operation="cert_scep",
            cluster=None,
            request_id=uuid4(),
            payload={
                "id": "example.com",
                "profile": "certserver1",
                "domains": ["example.com", "*.example.com"],
                "clusters": ["alpha"],
                "receivers": [],
            },
        )
        self.assertTrue(prepared.argv[-1].endswith("haprion-cert-scep-helper"))
        request = json.loads(prepared.request)
        self.assertIsNone(request["cluster"])
        self.assertEqual(
            request["parameters"],
            {
                "id": "example.com",
                "profile": "certserver1",
                "domains": ["example.com", "*.example.com"],
                "clusters": ["alpha"],
                "receivers": [],
                "resume": False,
            },
        )

    def test_an_abandon_names_only_the_certificate(self) -> None:
        """B388: the interface's Abandon request is the command's --abandon."""

        prepared = operations.prepare(
            operation="cert_scep",
            cluster=None,
            request_id=uuid4(),
            payload={"id": "example.com", "action": "abandon"},
        )
        self.assertEqual(
            json.loads(prepared.request)["parameters"], {"id": "example.com", "abandon": True}
        )
        for payload in (
            {"id": "example.com", "action": "remove"},
            {"id": "example.com", "action": "abandon", "resume": True},
            {"id": "example.com", "action": "abandon", "profile": "certserver1"},
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_scep", cluster=None, request_id=uuid4(), payload=payload
                )

    def test_a_resume_names_only_the_certificate(self) -> None:
        prepared = operations.prepare(
            operation="cert_scep",
            cluster=None,
            request_id=uuid4(),
            payload={"id": "example.com", "resume": True},
        )
        parameters = json.loads(prepared.request)["parameters"]
        self.assertEqual((parameters["id"], parameters["resume"]), ("example.com", True))
        self.assertEqual(parameters["domains"], [])
        for payload in (
            {"id": "example.com", "resume": True, "domains": ["example.com"]},
            {
                "id": "example.com",
                "profile": "certserver1",
                "domains": ["*.example.com"],
                "clusters": ["alpha"],
            },
            {"id": "example.com", "profile": "certserver1", "domains": ["example.com"]},
            {
                "id": "../x",
                "profile": "certserver1",
                "domains": ["example.com"],
                "clusters": ["alpha"],
            },
        ):
            with self.subTest(payload=payload), self.assertRaises(operations.BadPayload):
                operations.prepare(
                    operation="cert_scep", cluster=None, request_id=uuid4(), payload=payload
                )


class EveryOutcomeABuilderGivesIsTaken(unittest.TestCase):
    """Review 26-10-24, 13-07: a builder that works its outcome out wrote one nothing took.

    The table above is held to the schema; this holds the builders that decide
    their outcome from what happened to the table and the envelope at once.
    Each outcome such a builder can give is written as the helper writes it -
    `write_document`, strict as the suites run it - and read back as the worker
    reads it. The backup run's partial and the receiver's partial both crashed
    in the envelope and were stored `unknown` (13-01, 13-02).
    """

    REQUEST = "ffffffff-ffff-4fff-8fff-ffffffffffff"

    def taken(self, document: dict[str, object], exit_code: int, *, cluster: str | None) -> None:
        written = io.StringIO()
        with mock.patch.dict(os.environ, {helper_protocol.STRICT_VARIABLE: "1"}):
            helper_protocol.write_document(written, document, exit_code)
        operation = str(document["operation"])
        self.assertIsNotNone(
            answers.accepted(
                written.getvalue(),
                operation=operation,
                cluster=cluster,
                request_id=self.REQUEST,
                outcomes=worker._OPERATION_OUTCOMES[operation],
            ),
            f"{operation} {document['outcome']} is not an answer the worker takes",
        )

    def test_a_backup_run_as_many_nodes_as_answered(self) -> None:
        def node(name: str, outcome: str) -> state_backup.NodeResult:
            done = outcome == "done"
            return state_backup.NodeResult(
                name=name,
                outcome=outcome,
                version="1" if done else None,
                size_bytes=10 if done else None,
                error=None if done else "unreachable",
            )

        seen = set()
        for outcomes in (("done", "done"), ("done", "failed"), ("failed", "failed")):
            report = state_backup.BackupResult(
                cluster="alpha",
                version="1",
                nodes=tuple(node(f"node-{i}", o) for i, o in enumerate(outcomes)),
            )
            with self.subTest(report.outcome):
                document, exit_code = backup_job_helper.run_document(
                    report, cluster="alpha", request_id=self.REQUEST
                )
                self.taken(document, exit_code, cluster="alpha")
                seen.add(report.outcome)
        self.assertEqual(seen, {"done", "partial", "failed"})

    def test_a_receiver_with_and_without_a_layer_left_behind(self) -> None:
        seen = set()
        for states in (("removed", "removed"), ("removed", "failed")):
            result = cert_receiver.Result(
                receiver_id="svc-app",
                action="remove",
                layers=tuple(
                    cert_receiver.Layer(name=f"layer{i}", state=state, detail="x")
                    for i, state in enumerate(states)
                ),
            )
            document, exit_code = cert_receiver.answer(result, request_id=self.REQUEST)
            with self.subTest(document["outcome"]):
                self.taken(document, exit_code, cluster=None)
                seen.add(str(document["outcome"]))
        self.assertEqual(seen, {"done", "partial"})

    def test_a_certificate_publish_with_and_without_warnings_and_a_deploy_left(self) -> None:
        """Review 26-10-25, 13-07: the test held only the two builders that had crashed."""

        seen = set()
        for report in (
            cert_publish_model.Report(certificates=(), changed_clusters=()),
            cert_publish_model.Report(
                certificates=(), changed_clusters=(), warnings=(("pending", "still to roll"),)
            ),
            cert_publish_model.Report(
                certificates=(),
                changed_clusters=("alpha",),
                deployments=(cert_publish_model.DeployResult(cluster="alpha", exit_code=1),),
            ),
        ):
            document, exit_code = cert_publish.result_envelope(report, request_id=self.REQUEST)
            with self.subTest(document["outcome"]):
                self.taken(document, exit_code, cluster=None)
                seen.add(str(document["outcome"]))
        self.assertEqual(seen, {"done", "partial", "failed"})

    def test_an_unblock_on_every_node_some_and_none(self) -> None:
        seen = set()
        for outcomes in (("done", "done"), ("done", "failed"), ("refused", "failed")):
            nodes = tuple(
                server_state.Unblocked(node=f"node-{i}", outcome=outcome, message="m")
                for i, outcome in enumerate(outcomes)
            )
            written = io.StringIO()
            with mock.patch.dict(os.environ, {helper_protocol.STRICT_VARIABLE: "1"}):
                server_state_helper._write_unblocked(written, "alpha", self.REQUEST, "shop", nodes)
            stated = json.loads(written.getvalue())
            with self.subTest(stated["outcome"]):
                self.assertIsNotNone(
                    answers.accepted(
                        written.getvalue(),
                        operation=server_state.UNBLOCK_OPERATION,
                        cluster="alpha",
                        request_id=self.REQUEST,
                        outcomes=worker._OPERATION_OUTCOMES[server_state.UNBLOCK_OPERATION],
                    )
                )
                seen.add(stated["outcome"])
        self.assertEqual(seen, {"done", "partial", "failed"})


if __name__ == "__main__":
    unittest.main()


class TheDeployAnswersBeforeTheWorkerStopsIt(unittest.TestCase):
    """Review 2026-10-22, 6-9: a deploy within every step's limit went past the job's."""

    def test_the_helper_s_budget_ends_before_the_job_s_timeout(self) -> None:
        for operation in ("deploy", "cert_deploy"):
            with self.subTest(operation=operation):
                prepared = operations.prepare(
                    operation=operation,
                    cluster="alpha",
                    request_id=uuid4(),
                    payload={"allow_vip_unknown": False},
                )
                self.assertLessEqual(
                    deploy_helper.RUN_BUDGET_SECONDS + STATUS_TIMEOUT_SECONDS,
                    prepared.timeout_seconds,
                )
        self.assertGreaterEqual(
            deploy_helper.BUDGET.node_step,
            deploy_helper.TRIGGER_TIMEOUT_SECONDS + STATUS_TIMEOUT_SECONDS,
        )
