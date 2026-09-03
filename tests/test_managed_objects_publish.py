"""Publishing the objects somebody edited crosses the same boundary as the rest."""

from __future__ import annotations

import grp
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from haproxy_mgmt.candidate_validation import ValidationResult
from haproxy_mgmt.cli import managed_objects_publish
from haproxy_mgmt.version_history import request_id_of
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
                    "operation": "objects_publish",
                    "cluster": "alpha",
                    "request_id": REQUEST_ID,
                    "parameters": parameters,
                }
            ).encode()
        )

    def run_publish(self, policy_path: Path, request: io.BytesIO, *, valid: bool = True):
        out, err = io.StringIO(), io.StringIO()
        self.recorder = Recorder()

        def validator(_candidate: Path, _request_id: str) -> ValidationResult:
            return ValidationResult(valid=valid, diagnostics="candidate output")

        code = managed_objects_publish.main(
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

            code, document, err = self.run_publish(policy, self.request())

            self.assertEqual((code, err), (0, ""))
            assert_contract("haproxy-objects-publish", json.dumps(document))
            self.assertEqual(document["operation"], "objects_publish")
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

            code, document, err = self.run_publish(
                policy,
                self.request(objects={"web_app": proxy("web_app", "web-app.example.com")}),
            )

            self.assertEqual((code, err), (0, ""))
            assert_contract("haproxy-objects-publish", json.dumps(document))
            self.assertEqual(document["result"]["objects"], ["web_app"])

    def test_the_network_description_is_read_from_the_base_and_never_from_the_caller(self) -> None:
        """A stale tab may not undo an address change through the object path."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, err = self.run_publish(
                policy, self.request(network="vips: {}\ndefault_vip: main\n")
            )

            self.assertEqual(code, 65)
            self.assertIsNone(document)
            self.assertIn("unknown", err)
            self.assertEqual((self.repo / "managed/network.yaml").read_text(), NETWORK)

    def test_publishing_before_a_network_exists_is_refused_rather_than_invented(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.run_publish(policy, self.request())

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

            code, document, err = self.run_publish(policy, self.request())

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

            code, document, err = self.run_publish(policy, self.request(expected_head=before))

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "expected_target_changed")
            self.assertIn("expected_target_changed", err)
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Human update")

    def test_an_invalid_candidate_never_records_a_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.run_publish(policy, self.request(), valid=False)

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "candidate_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/proxies/shop.yaml").exists())

    def test_removing_an_object_takes_its_generated_configuration_with_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(shop=proxy("shop", "shop.example.com"))

            code, document, err = self.run_publish(policy, self.request(objects={"shop": None}))

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

            code, document, err = self.run_publish(policy, self.request(objects={"gone": None}))

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "objects_invalid")
            self.assertIn("cannot be removed", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_new_object_may_not_take_an_untouched_object_s_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(shop=proxy("shop", "shop.example.com"))
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.run_publish(
                policy, self.request(objects={"mirror": proxy("mirror", "shop.example.com")})
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "objects_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/proxies/mirror.yaml").exists())

    def test_a_name_that_is_a_path_never_reaches_the_candidate_builder(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.run_publish(
                policy,
                self.request(objects={"../../core/haproxy": proxy("shop", "shop.example.com")}),
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "bad_input")
            self.assertIn("usable object name", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_more_objects_than_one_publish_carries_are_refused_before_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            objects = {
                f"site-{index}": proxy(f"site-{index}", f"site{index}.example.com")
                for index in range(managed_objects_publish.MAX_OBJECTS + 1)
            }

            code, document, _err = self.run_publish(policy, self.request(objects=objects))

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "bad_input")

    def test_the_request_the_worker_builds_is_the_request_the_helper_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            request = managed_objects_publish.build_request(
                "alpha",
                REQUEST_ID,
                objects={"shop": proxy("shop", "shop.example.com")},
                expected_head=git(self.repo, "rev-parse", "HEAD"),
                comment="Publish the shop",
            )

            code, document, err = self.run_publish(policy, io.BytesIO(request.encode()))

            self.assertEqual((code, err), (0, ""))
            self.assertTrue(document["result"]["changed"])
            self.assertFalse(document["result"]["already_current"])


if __name__ == "__main__":
    unittest.main()
