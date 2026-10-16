"""A change to the node list is published as a version (B318, 26-10-16)."""

from __future__ import annotations

import grp
import os
import tempfile
from pathlib import Path

import yaml

from haprion import node_publish
from haprion.candidate_validation import ValidationResult
from haprion.config import Cluster, load_policy, load_runtime_config
from haprion.helper_protocol import HelperRequest
from haprion.repo_snapshot import read_tree_files, resolve_head
from haprion.version_history import count_versions
from tests.test_changes_publish_objects import ObjectsPublishFixture
from tests.test_publish_helper import Recorder, git

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
