"""A change to the node list is published as a version (B318, 26-10-16)."""

from __future__ import annotations

import grp
import io
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import crs, exit_codes, held_ports, node_publish
from haprion.candidate_validation import ValidationResult
from haprion.cli import revert, revert_helper
from haprion.config import Cluster, load_policy, load_runtime_config
from haprion.held_ports import HeldPorts
from haprion.helper_protocol import HelperRequest
from haprion.repo_snapshot import read_tree_files, resolve_head
from haprion.version_history import count_versions
from tests.test_changes_publish_objects import ObjectsPublishFixture, proxy
from tests.test_publish_helper import HAPROXY_CFG, Recorder, git

REQUEST = HelperRequest(
    operation="cluster_node",
    cluster="alpha",
    request_id="88888888-8888-4888-8888-888888888888",
    parameters={},
)


def addresses(cluster: Cluster) -> tuple[tuple[str, str], ...]:
    return tuple((node.name, node.mgmt_host) for node in cluster.nodes)


class PublishingTheNodeList(ObjectsPublishFixture):
    def site(self, root: Path) -> Path:
        policy_path = self.runtime(root)
        self.seed()
        clusters_path = root / "clusters.yaml"
        clusters = yaml.safe_load(clusters_path.read_text())
        clusters["clusters"]["alpha"]["vrrp_router_id"] = 7
        clusters_path.write_text(yaml.safe_dump(clusters))
        self.clusters_path = clusters_path
        self.validated = 0
        return policy_path

    def cluster(self, policy_path: Path) -> Cluster:
        policy = load_policy(policy_path, require_secure=False)
        return load_runtime_config(policy, require_secure=False).cluster("alpha")

    def add_node(self, name: str, host: str) -> None:
        clusters = yaml.safe_load(self.clusters_path.read_text())
        clusters["clusters"]["alpha"]["nodes"].append({"name": name, "mgmt_host": host})
        self.clusters_path.write_text(yaml.safe_dump(clusters))

    def publish(self, cluster: Cluster, *, valid: bool = True) -> dict[str, object]:
        def validator(_candidate: Path, _request_id: str) -> ValidationResult:
            self.validated += 1
            return ValidationResult(valid=valid, diagnostics="candidate output")

        return node_publish.publish(
            REQUEST,
            cluster,
            comment="node-c added",
            require_secure=False,
            run_root=self.run_root,
            validator=validator,
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=Recorder(),
            addresses=addresses,
        )

    def revert(self, policy_path: Path, version: int, commit: str) -> tuple[int, dict[str, Any]]:
        """The revert helper's answer, made against the newest version."""

        request = revert.build_request(
            "alpha",
            "99999999-9999-4999-8999-999999999999",
            version=version,
            expected_commit=commit,
            expected_head=git(self.repo, "rev-parse", "HEAD").strip(),
        )
        output = io.StringIO()
        code = revert_helper.main(
            [],
            policy_path=policy_path,
            run_root=self.run_root,
            lock_root=self.lock_root,
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=io.StringIO(),
            require_secure=False,
            require_root=False,
            validator=lambda _candidate, _request_id: ValidationResult(
                valid=True, diagnostics="candidate output"
            ),
            group=grp.getgrgid(os.getgid()).gr_name,
            change_owner=Recorder(),
        )
        return code, json.loads(output.getvalue())

    def released(self, name: str) -> list[Path]:
        return sorted((self.publish_path / "current").rglob(f"node-{name}.conf"))

    def test_an_added_node_is_in_the_next_version_and_its_release(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            before = count_versions(self.repo)
            self.add_node("node-c", "192.0.2.3")

            published = self.publish(self.cluster(policy_path))

            self.assertEqual(published["version"], before + 1)
            self.assertTrue(published["changed"])
            self.assertEqual(len(self.released("node-c")), 1)
            self.assertIn("node-c added", git(self.repo, "log", "-1", "--format=%B"))
            self.assertEqual(self.validated, 1)

    def test_an_unchanged_list_is_no_new_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            first = self.publish(self.cluster(policy_path))

            again = self.publish(self.cluster(policy_path))

            self.assertEqual(again["version"], first["version"])
            self.assertFalse(again["changed"])
            self.assertEqual(self.validated, 1)

    def test_a_first_version_never_installed_is_checked_before_it_goes_out(self) -> None:
        """A new cluster's version 1 carries its generated files; it is still validated."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            cluster = self.cluster(policy_path)
            _branch, head = resolve_head(self.repo)
            files = node_publish.seed(
                read_tree_files(self.repo, head), cluster, addresses=addresses
            )
            # The tree exactly, as the cluster's creation writes it.
            git(self.repo, "rm", "-rq", "managed")
            for path, content in files.items():
                (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
                (self.repo / path).write_bytes(content)
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", "Cluster alpha created")
            version = count_versions(self.repo)

            published = self.publish(cluster)

            self.assertEqual((published["version"], published["changed"]), (version, False))
            self.assertEqual(self.validated, 1)
            self.assertEqual(len(self.released("node-a")), 1)

    def test_a_list_that_does_not_validate_is_said_and_not_published(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            before = count_versions(self.repo)
            self.add_node("node-c", "192.0.2.3")

            published = self.publish(self.cluster(policy_path), valid=False)

            self.assertEqual(published["error"]["code"], "candidate_invalid")  # type: ignore[index]
            self.assertEqual(count_versions(self.repo), before)
            self.assertEqual(self.released("node-c"), [])

    def test_a_revert_keeps_the_node_list_it_is_made_on(self) -> None:
        """A revert restores configuration, never the node list (B360, review 26-10-24 01-01)."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            two_nodes = self.publish(self.cluster(policy_path))
            commit = git(self.repo, "rev-parse", "HEAD").strip()
            (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # later\n")
            git(self.repo, "commit", "-qam", "A later change")
            self.add_node("node-c", "192.0.2.3")
            self.publish(self.cluster(policy_path))

            code, answer = self.revert(policy_path, int(str(two_nodes["version"])), commit)

            self.assertEqual(code, 0, answer)
            self.assertTrue(answer["result"]["changed"])
            self.assertEqual((self.repo / "core/haproxy.cfg").read_bytes(), HAPROXY_CFG)
            self.assertEqual(len(self.released("node-c")), 1)
            self.assertIn("192.0.2.3", self.released("node-a")[0].read_text())

    def test_a_revert_is_held_to_the_certificates_a_publish_is_held_to(self) -> None:
        """Review 26-10-30, D6: the version was valid once; the certificate is today's."""

        secure = proxy("shop", "shop.example.com").replace(
            "protocol: http", "protocol: https\n  certificate: example.com"
        )
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            self.seed(shop=secure)
            self.publish(self.cluster(policy_path))
            commit = git(self.repo, "rev-parse", "HEAD").strip()
            version = count_versions(self.repo)
            (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # later\n")
            git(self.repo, "commit", "-qam", "A later change")

            with mock.patch.object(
                revert_helper, "coverage_for", return_value={"example.com": ("other.example.org",)}
            ):
                code, answer = self.revert(policy_path, version, commit)

            self.assertEqual(code, exit_codes.REFUSED, answer)
            self.assertEqual(answer["error"]["code"], "changes_invalid")
            self.assertIn("does not answer for that name", answer["error"]["message"])
            self.assertEqual(count_versions(self.repo), version + 1)

            with mock.patch.object(
                revert_helper, "coverage_for", return_value={"example.com": ("shop.example.com",)}
            ):
                code, answer = self.revert(policy_path, version, commit)

            self.assertEqual(code, 0, answer)

    def test_a_revert_asks_the_nodes_for_held_ports_only_when_the_version_has_objects(self) -> None:
        for objects, asked in (({}, False), ({"shop": proxy("shop", "shop.example.com")}, True)):
            with self.subTest(objects=sorted(objects)), tempfile.TemporaryDirectory() as raw:
                policy_path = self.site(Path(raw))
                if objects:
                    self.seed(**objects)
                self.publish(self.cluster(policy_path))
                commit = git(self.repo, "rev-parse", "HEAD").strip()
                version = count_versions(self.repo)
                (self.repo / "core/haproxy.cfg").write_bytes(HAPROXY_CFG + b"  # later\n")
                git(self.repo, "commit", "-qam", "A later change")

                with mock.patch.object(held_ports, "read", return_value=HeldPorts()) as read:
                    code, answer = self.revert(policy_path, version, commit)

                self.assertEqual(code, 0, answer)
                self.assertEqual(read.called, asked)

    def test_a_revert_over_only_a_node_change_changes_nothing(self) -> None:
        """The node list is not configuration, so there is nothing to go back to."""

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            two_nodes = self.publish(self.cluster(policy_path))
            commit = git(self.repo, "rev-parse", "HEAD").strip()
            self.add_node("node-c", "192.0.2.3")
            self.publish(self.cluster(policy_path))
            before = count_versions(self.repo)

            code, answer = self.revert(policy_path, int(str(two_nodes["version"])), commit)

            self.assertEqual(code, 0, answer)
            self.assertFalse(answer["result"]["changed"])
            self.assertEqual(count_versions(self.repo), before)
            self.assertEqual(len(self.released("node-c")), 1)

    def test_a_revert_gives_back_the_rule_set_the_version_ran(self) -> None:
        """The rule set is configuration; today's installed one is not (B366, review 26-10-25 1-01).

        Version A ran rule set 1.0.0. The package was upgraded and the next
        publish carried 2.0.0 and nothing else. Going back to A is a new
        version with A's rules - not "already holds the content" made from
        today's.
        """

        def rules(version: str) -> crs.RuleSet:
            return crs.RuleSet(
                version=version,
                files={
                    "VERSION": f"{version}\n".encode(),
                    "crs-setup.conf": b"# setup\n",
                    "rules/REQUEST-901-INITIALIZATION.conf": f"# {version}\n".encode(),
                },
            )

        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.site(Path(raw))
            shop = self.repo / "managed/proxies/shop.yaml"
            shop.parent.mkdir(parents=True, exist_ok=True)
            shop.write_text(
                proxy("shop", "shop.example.com").replace("routes:", "waf: {mode: block}\nroutes:")
            )
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", "The shop with the engine")
            with mock.patch.object(crs, "installed", lambda: rules("1.0.0")):
                first = self.publish(self.cluster(policy_path))
            commit = git(self.repo, "rev-parse", "HEAD").strip()
            with mock.patch.object(crs, "installed", lambda: rules("2.0.0")):
                upgraded = self.publish(self.cluster(policy_path))
                self.assertTrue(upgraded["changed"])

                code, answer = self.revert(policy_path, int(str(first["version"])), commit)

            self.assertEqual(code, 0, answer)
            self.assertTrue(answer["result"]["changed"])
            self.assertEqual((self.repo / "managed/waf/crs/VERSION").read_bytes(), b"1.0.0\n")
            (released,) = (self.publish_path / "current").rglob("REQUEST-901-INITIALIZATION.conf")
            self.assertEqual(released.read_bytes(), b"# 1.0.0\n")
