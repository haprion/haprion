"""Publishing the objects somebody saved crosses the same boundary as the rest.

The objects part of a saved-changes publish (B257); what the package adds to
it - a network and settings in the same version - is in `test_changes_publish`.
"""

from __future__ import annotations

import grp
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haproxy_mgmt import tls_policy
from haproxy_mgmt.candidate_validation import ValidationResult
from haproxy_mgmt.cli import changes_publish
from haproxy_mgmt.version_history import count_versions, recent_versions, request_id_of
from tests.contract_schema import assert_contract
from tests.test_publish_helper import PublishFixture, Recorder, git

REQUEST_ID = "55555555-5555-4555-8555-555555555555"
NETWORK = """vips:
  main:
    address: 192.0.2.20
    source: 192.0.2.25
default_vip: main
sources:
  outbound: 192.0.2.35
networks:
  office:
  - 198.51.100.0/24
"""


def proxy(name: str, host: str, *, address: str = "198.51.100.10") -> str:
    return f"""schema: 1
name: {name}
hostnames: [{host}]
listen:
  protocol: http
routes:
- path: /
  backend: web
backends:
  web:
    balance: roundrobin
    health:
      type: disabled
    servers:
    - host: {address}
      port: 8080
"""


class ObjectsPublishFixture(PublishFixture):
    def seed(self, **objects: str) -> None:
        """Commit the base a draft is made against: a network, and some objects.

        The published objects have to already exist for the interesting cases -
        a removal, a hostname collision with an object nobody touched - to be
        reachable at all.
        """

        (self.repo / "managed").mkdir(exist_ok=True)
        (self.repo / "managed/network.yaml").write_text(NETWORK, encoding="utf-8")
        for name, document in objects.items():
            path = self.repo / "managed/proxies" / f"{name}.yaml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(document, encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "Seed the managed layer")

    def request(self, **overrides: object) -> io.BytesIO:
        parameters: dict[str, object] = {
            "objects": {"shop": proxy("shop", "shop.example.com")},
            "expected_head": git(self.repo, "rev-parse", "HEAD"),
            "comment": "Publish the shop",
        }
        parameters.update(overrides)
        return io.BytesIO(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation": "changes_publish",
                    "cluster": "alpha",
                    "request_id": REQUEST_ID,
                    "parameters": parameters,
                }
            ).encode()
        )

    def publish_objects(
        self,
        policy_path: Path,
        request: io.BytesIO,
        *,
        valid: bool = True,
        warn_on: str | None = None,
    ) -> tuple[int, Any, str]:
        out, err = io.StringIO(), io.StringIO()
        self.recorder = Recorder()

        def validator(candidate: Path, _request_id: str) -> ValidationResult:
            #
            # `warn_on` is a line of the candidate HAProxy warns about, as
            # 3.4.6 words a keyword a section does not take.
            #
            diagnostics = "candidate output"
            if warn_on is not None:
                for path in sorted(candidate.rglob("*.cfg")):
                    lines = path.read_text().split("\n")
                    if warn_on in lines:
                        number = lines.index(warn_on) + 1
                        diagnostics = (
                            f"[WARNING]  (1) : config : parsing [/candidate/conf.d/{path.name}:"
                            f"{number}] : 'x' ignored because backend 'y' has no frontend capability."
                        )
            return ValidationResult(valid=valid, diagnostics=diagnostics)

        code = changes_publish.main(
            [],
            policy_path=policy_path,
            run_root=self.run_root,
            lock_root=self.lock_root,
            input_stream=request,
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            validator=validator,
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=self.recorder,
        )
        #
        # A request rejected before its own fields are trusted has no envelope
        # to write: the failure document names the operation and request it is
        # answering, and there is no such thing yet.  `None` says that, rather
        # than a decoder error covering it up.
        #
        printed = out.getvalue()
        return code, json.loads(printed) if printed else None, err.getvalue()


class ObjectPublicationTests(ObjectsPublishFixture):
    def test_an_object_is_stored_and_generated_without_touching_human_layers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before_core = (self.repo / "core/haproxy.cfg").read_bytes()

            code, document, err = self.publish_objects(policy, self.request())

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            self.assertEqual(document["operation"], "changes_publish")
            self.assertTrue(document["result"]["changed"])
            self.assertEqual(document["result"]["objects"], ["shop"])
            self.assertEqual(document["result"]["removed"], [])
            self.assertEqual(
                (self.repo / "managed/proxies/shop.yaml").read_text(),
                proxy("shop", "shop.example.com"),
            )
            self.assertIn("managed/generated/1001-shop.cfg", git(self.repo, "ls-files"))
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), before_core)
            self.assertEqual(
                request_id_of(self.repo, git(self.repo, "rev-parse", "HEAD")), REQUEST_ID
            )
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_the_version_names_who_asked_and_which_account_ran_it(self) -> None:
        #
        # B207: the person the interface's worker names, and the account sudo
        # proves. Anyone else - an operator at the terminal, or any caller when
        # the policy names no worker - is recorded as themselves, whatever the
        # request says.
        #
        for worker, sudo_user, named, expected in (
            ("svc-app", "svc-app", "Ada Admin", "Ada Admin"),
            ("svc-app", "operator", "Ada Admin", "operator"),
            (None, "svc-app", "Ada Admin", "svc-app"),
            ("svc-app", "operator", None, "operator"),
        ):
            with (
                self.subTest(worker=worker, sudo_user=sudo_user, named=named),
                tempfile.TemporaryDirectory() as raw,
            ):
                policy = self.runtime(Path(raw), interface_account=worker)
                self.seed()
                extra = {} if named is None else {"requested_by": named}
                with mock.patch.dict(os.environ, {"SUDO_USER": sudo_user}):
                    code, _document, err = self.publish_objects(policy, self.request(**extra))

                self.assertEqual((code, err), (0, ""))
                lines = git(self.repo, "log", "-1", "--format=%B").splitlines()
                self.assertIn(f"Requested-By: {expected}", lines)
                self.assertIn(f"Run-By: {sudo_user}", lines)
                self.assertEqual(recent_versions(self.repo)[0].requested_by, expected)

    def test_a_name_that_could_forge_a_trailer_is_refused_before_anything_is_written(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            head = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_objects(
                policy, self.request(requested_by="ada\nRequest-Id: forged")
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "bad_input")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), head)

    def test_a_name_with_an_underscore_publishes_and_fits_its_own_contract(self) -> None:
        #
        # The model was widened to allow an underscore and the frozen schema
        # was not, so the envelope this command emits failed the contract it is
        # published under. Nothing refused it at runtime - only a fixture
        # without an underscore in it kept the two looking agreed.
        #
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, err = self.publish_objects(
                policy,
                self.request(objects={"web_app": proxy("web_app", "web-app.example.com")}),
            )

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            self.assertEqual(document["result"]["objects"], ["web_app"])

    def test_publishing_before_a_network_exists_is_refused_rather_than_invented(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "network_missing")
            self.assertIn("network_missing", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_dirty_human_worktree_is_blocked_without_touching_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")
            (self.repo / "core/haproxy.cfg").write_bytes(b"human draft\n")

            code, document, err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["outcome"], "blocked")
            self.assertIn("dirty_worktree", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), b"human draft\n")

    def test_a_stale_draft_cannot_publish_over_a_newer_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")
            (self.repo / "manual/reservations.yaml").write_text("hostnames: [legacy.example.com]\n")
            git(self.repo, "add", "manual/reservations.yaml")
            git(self.repo, "commit", "-qm", "Human update")

            code, document, err = self.publish_objects(policy, self.request(expected_head=before))

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "expected_target_changed")
            self.assertIn("expected_target_changed", err)
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Human update")

    def test_an_invalid_candidate_never_records_a_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_objects(policy, self.request(), valid=False)

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "candidate_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/proxies/shop.yaml").exists())

    def test_a_warning_on_a_pasted_line_refuses_the_publish_and_names_the_line(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")
            document = proxy("shop", "shop.example.com") + (
                "advanced: |\n  # note\n  http-request deny if { path /x }\n"
            )

            code, answer, _err = self.publish_objects(
                policy,
                self.request(objects={"shop": document}),
                warn_on="    http-request deny if { path /x }",
            )

            self.assertEqual(code, 65)
            self.assertEqual(answer["error"]["code"], "advanced_ignored")
            self.assertIn(
                "(advanced config of shop, line 2)", answer["error"]["details"]["diagnostics"]
            )
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_warning_elsewhere_does_not_refuse_the_publish(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            document = proxy("shop", "shop.example.com") + (
                "advanced: |\n  http-request deny if { path /x }\n"
            )

            code, _answer, _err = self.publish_objects(
                policy, self.request(objects={"shop": document}), warn_on="    option forwardfor"
            )

            self.assertEqual(code, 0)

    def stale_core(self) -> None:
        """A human commit that drops the line the TLS policy requires."""

        core = self.repo / "core/haproxy.cfg"
        core.write_text(
            core.read_text().replace(f"  {tls_policy.DEFAULT_PATH_LINE}\n", ""), encoding="utf-8"
        )
        git(self.repo, "commit", "-qam", "Human edit to core")

    def test_a_stale_core_is_refused_before_a_version_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            self.stale_core()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "tls_defaults_stale")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/proxies/shop.yaml").exists())

            again, document, _err = self.publish_objects(policy, self.request())
            self.assertEqual(again, 75)
            self.assertEqual(document["error"]["code"], "tls_defaults_stale")

    def test_an_unchanged_retry_is_held_to_the_same_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            first, _document, _err = self.publish_objects(policy, self.request())
            self.assertEqual(first, 0)
            self.stale_core()
            releases_before = sorted(self.publish_path.rglob("*"))

            code, document, _err = self.publish_objects(policy, self.request())

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "tls_defaults_stale")
            self.assertEqual(sorted(self.publish_path.rglob("*")), releases_before)

    def test_a_retry_after_the_commit_repairs_the_release_from_that_version(self) -> None:
        """What a requeued job sends: the same request, fenced on the old head.

        The first run recorded its version and stopped before the release was
        installed. The retry must recognise its own version rather than refuse
        it as a moved target, and write the release from that commit.
        """

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            sent = self.request().getvalue()
            self.publish_objects(policy, io.BytesIO(sent))
            head = git(self.repo, "rev-parse", "HEAD")
            versions = count_versions(self.repo)
            shutil.rmtree(self.publish_path / "releases" / head)
            (self.publish_path / "current").unlink()

            code, document, err = self.publish_objects(policy, io.BytesIO(sent))

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            self.assertFalse(document["result"]["changed"])
            self.assertEqual(document["result"]["hash"], head)
            self.assertEqual(count_versions(self.repo), versions)
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{head}")

    def test_a_retried_removal_is_not_refused_as_a_removal_of_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(shop=proxy("shop", "shop.example.com"))
            sent = self.request(objects={"shop": None}).getvalue()
            self.publish_objects(policy, io.BytesIO(sent))
            head = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.publish_objects(policy, io.BytesIO(sent))

            self.assertEqual((code, err), (0, ""))
            self.assertEqual(document["result"]["hash"], head)
            self.assertEqual(document["result"]["removed"], ["shop"])

    def test_a_version_stacked_on_the_request_s_own_is_still_a_moved_target(self) -> None:
        """Only the request's own version, directly on its base, is a retry."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            sent = self.request().getvalue()
            self.publish_objects(policy, io.BytesIO(sent))
            (self.repo / "manual/reservations.yaml").write_text("hostnames: [legacy.example.com]\n")
            git(self.repo, "add", "manual/reservations.yaml")
            git(self.repo, "commit", "-qm", "Human update")

            code, document, _err = self.publish_objects(policy, io.BytesIO(sent))

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "expected_target_changed")
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Human update")

    def test_removing_an_object_takes_its_generated_configuration_with_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(shop=proxy("shop", "shop.example.com"))

            code, document, err = self.publish_objects(policy, self.request(objects={"shop": None}))

            self.assertEqual((code, err), (0, ""))
            self.assertEqual(document["result"]["removed"], ["shop"])
            self.assertEqual(document["result"]["objects"], [])
            self.assertFalse((self.repo / "managed/proxies/shop.yaml").exists())
            self.assertNotIn("managed/generated/1001-shop.cfg", git(self.repo, "ls-files"))

    def test_removing_something_this_version_does_not_have_is_a_refusal(self) -> None:
        """Silently succeeding would report a site taken down when nothing was."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.publish_objects(policy, self.request(objects={"gone": None}))

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "changes_invalid")
            self.assertIn("cannot be removed", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_new_object_may_not_take_an_untouched_object_s_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(shop=proxy("shop", "shop.example.com"))
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish_objects(
                policy, self.request(objects={"mirror": proxy("mirror", "shop.example.com")})
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "changes_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/proxies/mirror.yaml").exists())

    def test_a_name_that_is_a_path_never_reaches_the_candidate_builder(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.publish_objects(
                policy,
                self.request(objects={"../../core/haproxy": proxy("shop", "shop.example.com")}),
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "bad_input")
            self.assertIn("usable object name", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_the_request_the_worker_builds_is_the_request_the_helper_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            request = changes_publish.build_request(
                "alpha",
                REQUEST_ID,
                objects={"shop": proxy("shop", "shop.example.com")},
                expected_head=git(self.repo, "rev-parse", "HEAD"),
                comment="Publish the shop",
            )

            code, document, err = self.publish_objects(policy, io.BytesIO(request.encode()))

            self.assertEqual((code, err), (0, ""))
            self.assertTrue(document["result"]["changed"])
            self.assertFalse(document["result"]["already_current"])


if __name__ == "__main__":
    unittest.main()
