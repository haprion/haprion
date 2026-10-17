"""Saved changes are published as one version, whichever parts they touch (B257)."""

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

import yaml

from haprion.candidate_validation import ValidationResult
from haprion.cli import changes_publish
from haprion.cluster_settings import LOCATION as SETTINGS_LOCATION
from haprion.version_history import count_versions, recent_versions, request_id_of
from tests.contract_schema import assert_contract
from tests.test_changes_publish_objects import NETWORK, ObjectsPublishFixture, proxy
from tests.test_publish_helper import Recorder, git

REQUEST_ID = "77777777-7777-4777-8777-777777777777"
#
# The base's network with a second VIP, the kind of change an object saved in
# the same package depends on.
#
WIDER_NETWORK = NETWORK.replace(
    "default_vip: main\n",
    "  shop:\n    address: 192.0.2.21\n    source: 192.0.2.26\ndefault_vip: main\n",
)
SETTINGS = "metrics: {port: 8405, sources: [192.0.2.0/24]}\n"


def on_vip(document: str, vip: str) -> str:
    return document.replace("  protocol: http\n", f"  protocol: http\n  vip: {vip}\n")


class ChangesPublishTests(ObjectsPublishFixture):
    def changes(self, **parts: Any) -> io.BytesIO:
        parts.setdefault("expected_head", git(self.repo, "rev-parse", "HEAD"))
        parts.setdefault("comment", "Publish the saved changes")
        return io.BytesIO(changes_publish.build_request("alpha", REQUEST_ID, **parts).encode())

    def publish(self, policy_path: Path, request: io.BytesIO) -> tuple[int, Any, str]:
        out, err = io.StringIO(), io.StringIO()
        self.recorder = Recorder()
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
            validator=lambda _candidate, _request_id: ValidationResult(valid=True, diagnostics=""),
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=self.recorder,
        )
        printed = out.getvalue()
        return code, json.loads(printed) if printed else None, err.getvalue()

    def test_objects_network_and_settings_are_one_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(staging=proxy("staging", "staging.example.com"))
            versions = count_versions(self.repo)

            code, document, err = self.publish(
                policy,
                self.changes(
                    objects={
                        "shop": on_vip(proxy("shop", "shop.example.com"), "shop"),
                        "staging": None,
                    },
                    network=WIDER_NETWORK,
                    settings=SETTINGS,
                ),
            )

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            result = document["result"]
            self.assertEqual(
                (result["objects"], result["removed"], result["network"], result["settings"]),
                (["shop"], ["staging"], True, True),
            )
            self.assertEqual(count_versions(self.repo), versions + 1)
            self.assertEqual((self.repo / "managed/network.yaml").read_text(), WIDER_NETWORK)
            self.assertIn("8405", (self.repo / SETTINGS_LOCATION).read_text())
            self.assertTrue((self.repo / "managed/proxies/shop.yaml").exists())
            self.assertFalse((self.repo / "managed/proxies/staging.yaml").exists())
            #
            # The object's backend leaves from the new VIP's source address.
            #
            self.assertIn(
                "source 192.0.2.26", (self.repo / "managed/generated/1001-shop.cfg").read_text()
            )
            self.assertEqual(
                git(self.repo, "log", "-1", "--format=%s"),
                "Publish changes: Publish the saved changes",
            )
            self.assertEqual(
                request_id_of(self.repo, git(self.repo, "rev-parse", "HEAD")), REQUEST_ID
            )
            self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_a_server_name_the_manager_cannot_resolve_is_said_not_refused(self) -> None:
        """Finding 72: found where it is published, not first by a node's deploy."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            document = proxy("shop", "shop.example.com", address="typo.example.com")
            with mock.patch(
                "haprion.server_names.resolves", side_effect=lambda host: host != "typo.example.com"
            ):
                code, published, err = self.publish(
                    policy, self.changes(objects={"shop": document})
                )

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(published))
            self.assertEqual(published["result"]["unresolved_servers"], ["typo.example.com"])
            self.assertTrue((self.repo / "managed/proxies/shop.yaml").exists())

    def test_an_object_on_a_vip_the_package_does_not_add_is_refused(self) -> None:
        """The other half of the case above: the network is read from the base."""

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish(
                policy,
                self.changes(objects={"shop": on_vip(proxy("shop", "shop.example.com"), "shop")}),
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "changes_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_network_alone_is_a_version_and_keeps_the_objects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(shop=proxy("shop", "shop.example.com"))

            code, document, err = self.publish(policy, self.changes(network=WIDER_NETWORK))

            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            result = document["result"]
            self.assertEqual(
                (result["changed"], result["objects"], result["network"], result["settings"]),
                (True, [], True, False),
            )
            self.assertTrue((self.repo / "managed/proxies/shop.yaml").exists())

    def test_settings_alone_are_stored_canonically(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()

            code, document, err = self.publish(policy, self.changes(settings=SETTINGS))

            self.assertEqual((code, err), (0, ""))
            self.assertTrue(document["result"]["settings"])
            self.assertEqual(
                (self.repo / SETTINGS_LOCATION).read_text(),
                "metrics:\n  port: 8405\n  sources:\n  - 192.0.2.0/24\n",
            )
            self.assertEqual((self.repo / "managed/network.yaml").read_text(), NETWORK)

    def test_coverage_is_asked_for_objects_and_network_and_not_for_settings_alone(self) -> None:
        #
        # Settings alone never ask: an object published with the mismatch
        # override would otherwise block every change of log target.
        #
        for parts, asked in (
            ({"settings": SETTINGS}, False),
            ({"network": WIDER_NETWORK}, True),
            ({"objects": {"shop": proxy("shop", "shop.example.com")}}, True),
        ):
            with self.subTest(parts=sorted(parts)), tempfile.TemporaryDirectory() as raw:
                policy = self.runtime(Path(raw))
                certificates = Path(raw) / "certdist"
                certificates.mkdir()
                document = yaml.safe_load(policy.read_text())
                document["certificate_root"] = str(certificates)
                policy.write_text(yaml.safe_dump(document))
                self.seed()
                with mock.patch.object(changes_publish, "coverage", return_value={}) as coverage:
                    code, _document, err = self.publish(policy, self.changes(**parts))

                self.assertEqual((code, err), (0, ""))
                self.assertEqual(coverage.called, asked)

    def test_an_empty_package_is_refused_before_anything_is_opened(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, err = self.publish(policy, self.changes())

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "bad_input")
            self.assertIn("at least one", err)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_a_network_that_cannot_stand_is_named_as_the_network(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish(
                policy,
                self.changes(
                    objects={"shop": proxy("shop", "shop.example.com")},
                    network="vips: {}\ndefault_vip: main\n",
                ),
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "network_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

    def test_settings_that_cannot_stand_are_named_as_the_settings(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish(
                policy,
                self.changes(
                    objects={"shop": proxy("shop", "shop.example.com")},
                    settings="log_targets:\n  graylog: {address: logs.example.com, port: 514}\n",
                ),
            )

            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "settings_invalid")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)
            self.assertFalse((self.repo / "managed/proxies/shop.yaml").exists())

    def test_sixty_four_objects_publish_and_sixty_five_are_refused(self) -> None:
        def sites(count: int) -> dict[str, str | None]:
            return {
                #
                # A backend's name is unique in the cluster, so each its own.
                #
                f"site-{index}": proxy(f"site-{index}", f"site{index}.example.com").replace(
                    "web", f"web{index}"
                )
                for index in range(count)
            }

        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")

            code, document, _err = self.publish(
                policy, self.changes(objects=sites(changes_publish.MAX_OBJECTS + 1))
            )
            self.assertEqual(code, 65)
            self.assertEqual(document["error"]["code"], "bad_input")
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), before)

            code, document, err = self.publish(
                policy, self.changes(objects=sites(changes_publish.MAX_OBJECTS))
            )
            self.assertEqual((code, err), (0, ""))
            assert_contract("haprion-changes-publish", json.dumps(document))
            self.assertEqual(len(document["result"]["objects"]), 64)

    def test_a_request_over_the_ceiling_is_refused_before_it_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            padding = "#" + "x" * (changes_publish.MAX_REQUEST_BYTES) + "\n"

            code, document, err = self.publish(
                policy,
                self.changes(objects={"shop": proxy("shop", "shop.example.com") + padding}),
            )

            self.assertEqual(code, 65)
            self.assertIsNone(document)
            self.assertIn("ERROR", err)

    def test_a_package_saved_against_an_older_version_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            before = git(self.repo, "rev-parse", "HEAD")
            (self.repo / "manual/reservations.yaml").write_text("hostnames: [legacy.example.com]\n")
            git(self.repo, "add", "manual/reservations.yaml")
            git(self.repo, "commit", "-qm", "Human update")

            code, document, _err = self.publish(
                policy, self.changes(network=WIDER_NETWORK, expected_head=before)
            )

            self.assertEqual(code, 75)
            self.assertEqual(document["error"]["code"], "expected_target_changed")
            self.assertEqual(git(self.repo, "log", "-1", "--format=%s"), "Human update")

    def test_a_retry_after_the_commit_repairs_the_release_from_that_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed(staging=proxy("staging", "staging.example.com"))
            sent = self.changes(objects={"staging": None}, network=WIDER_NETWORK).getvalue()
            self.publish(policy, io.BytesIO(sent))
            head = git(self.repo, "rev-parse", "HEAD")
            versions = count_versions(self.repo)
            shutil.rmtree(self.publish_path / "releases" / head)
            (self.publish_path / "current").unlink()

            code, document, err = self.publish(policy, io.BytesIO(sent))

            self.assertEqual((code, err), (0, ""))
            self.assertFalse(document["result"]["changed"])
            self.assertEqual(document["result"]["removed"], ["staging"])
            self.assertEqual(count_versions(self.repo), versions)
            self.assertEqual(os.readlink(self.publish_path / "current"), f"releases/{head}")

    def test_the_version_names_the_person_the_worker_acts_for(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = self.runtime(Path(raw))
            self.seed()
            with mock.patch.dict(os.environ, {"SUDO_USER": "_haprion-worker"}):
                code, _document, err = self.publish(
                    policy, self.changes(settings=SETTINGS, requested_by="Ada Admin")
                )

            self.assertEqual((code, err), (0, ""))
            self.assertEqual(recent_versions(self.repo)[0].requested_by, "Ada Admin")

    def test_the_request_leaves_out_the_parts_that_are_not_changed(self) -> None:
        request = json.loads(
            changes_publish.build_request(
                "alpha", REQUEST_ID, expected_head="a" * 40, comment="c", settings=SETTINGS
            )
        )

        self.assertEqual(
            sorted(request["parameters"]),
            ["allow_certificate_mismatch", "comment", "expected_head", "settings"],
        )


if __name__ == "__main__":
    unittest.main()
