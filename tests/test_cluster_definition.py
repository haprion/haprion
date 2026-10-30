"""Creating and removing a cluster, as one change or none (B211)."""

from __future__ import annotations

import io
import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from haprion import candidate_validation, change_journal, cluster_definition, node_enrollment
from haprion.cli import cluster as cluster_command
from haprion.cli import node_helper
from haprion.cluster_definition import Places, Tools
from haprion.config import ConfigError, RuntimeConfig, load_policy, load_runtime_config
from haprion.git_command import GIT
from haprion.node_enrollment import AskNode, Enrollment, EnrollmentError, Locations
from haprion.status_collect import NodeResponse
from haprion.version_history import count_versions
from tests.contract_schema import assert_contract, published
from tests.test_node_enrollment import key

BASE = Path(__file__).resolve().parents[1]
SUDOERS = """# Installed by install/02-manager-config. Do not edit by hand.
User_Alias HAPROXY_EDITORS = operator

Cmnd_Alias HAPROXY_EDIT = \\
    sudoedit {root}/alpha/core/haproxy.cfg, \\
    sudoedit {root}/alpha/manual/reservations.yaml

HAPROXY_EDITORS ALL = (root) HAPROXY_EDIT
"""


def block(name: str, seed: int, cluster: str = "gamma") -> str:
    return node_enrollment.render(
        Enrollment(
            cluster=cluster,
            name=name,
            host=f"{name}.example.com",
            host_key=key(seed),
            config_pull_key=key(seed + 1),
            cert_pull_key=key(seed + 2),
        )
    )


def answering_as(cluster: str) -> AskNode:
    def ask(node: Any) -> NodeResponse:
        return NodeResponse(0, json.dumps({"node": node.name, "cluster": cluster}))

    return ask


def silent(_node: Any) -> NodeResponse:
    return NodeResponse(255, "")


def resolving(name: str) -> tuple[str, ...]:
    """A resolver that answers every name but `unresolved.example.com`, one documentation address each."""

    if name == "unresolved.example.com":
        return ()
    return (f"192.0.2.{sum(name.encode()) % 200 + 1}",)


class Site:
    """An installation with one cluster, `alpha`, in a directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.config_root = root / "config"
        self.publish_root = root / "published"
        self.backup_root = root / "backups"
        for directory in (
            self.config_root,
            self.publish_root,
            self.backup_root,
            root / "validation/certs",
        ):
            directory.mkdir(parents=True)
        for path in (
            self.config_root / "alpha",
            self.config_root / "alpha.git",
            self.publish_root / "alpha",
        ):
            path.mkdir()
            (path / "marker").write_text("alpha\n")
        for node in ("node-a", "node-b"):
            (self.backup_root / node).mkdir()
        self.cluster_file = root / "clusters.yaml"
        self.cluster_file.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "clusters": {
                        "alpha": {
                            "display_name": "Alpha",
                            "vip": "192.0.2.20",
                            "config_path": str(self.config_root / "alpha"),
                            "publish_path": str(self.publish_root / "alpha"),
                            "node_path": "alpha",
                            "nodes": [
                                {"name": "node-a", "mgmt_host": "node-a.example.com"},
                                {"name": "node-b", "mgmt_host": "node-b.example.com"},
                            ],
                            "validation_certs": str(root / "validation/certs"),
                            "default_certificate": "example.com",
                        }
                    },
                },
                sort_keys=False,
            )
        )
        self.registry = root / "certificates.yaml"
        self.registry.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "certificates": {
                        "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                        "example.net": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                    },
                },
                sort_keys=False,
            )
        )
        policy = {
            "schema_version": 1,
            "cluster_file": str(self.cluster_file),
            "config_root": str(self.config_root),
            "publish_root": str(self.publish_root),
            "validation_certs_root": str(root / "validation"),
            "certificate_root": str(root / "certdist"),
            "certificate_registry": str(self.registry),
            "backup_root": str(self.backup_root),
        }
        self.policy_file = root / "runtime-policy.yaml"
        self.policy_file.write_text(yaml.safe_dump(policy))
        self.policy = load_policy(self.policy_file, require_secure=False)
        for account in ("_haprion-pull", "_haprion-cert-pull"):
            (root / account / ".ssh").mkdir(parents=True)
            (root / account / ".ssh/authorized_keys").write_text(
                f'restrict,command="x" {key(90)} node-a config pull\n'
            )
        self.known_hosts = root / "known_hosts"
        self.known_hosts.write_text(
            node_enrollment.hashed_host_line("node-a.example.com", key(91)) + "\n"
        )
        self.collector = root / "collector.json"
        self.collector.write_text(
            json.dumps(
                {"nodes": [{"cluster": "alpha", "node": "node-a", "host": "node-a.example.com"}]}
            )
        )
        self.collector_known = root / "collector_known_hosts"
        self.collector_known.write_text("")
        self.locations = Locations(
            root_known_hosts=self.known_hosts,
            collector_config=self.collector,
            collector_known_hosts=self.collector_known,
            journal=root / ".journal" / "change-journal.json",
            home=lambda account: root / account,
            forward=resolving,
        )
        (root / ".journal").mkdir()
        self.sudoers = root / "haprion-config-edit"
        self.sudoers.write_text(SUDOERS.format(root=self.config_root))
        self.gitconfig = root / "gitconfig"
        self.gitconfig.write_text("")
        self.retention = root / "retention"
        self.retention.mkdir()
        (self.retention / "alpha.json").write_text('{"keep": 14}\n')
        self.places = Places(
            sudoers=self.sudoers, gitconfig=self.gitconfig, retention=self.retention
        )
        self.ran: list[list[str]] = []
        self.visudo_refuses = False
        self.tools = Tools(run=self.run, owner=lambda *_: None, clock=lambda: 1_790_000_000.0)

    def run(
        self, argv: Sequence[str], *, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.ran.append(list(argv))
        if argv[0] == cluster_definition.VISUDO:
            return subprocess.CompletedProcess(
                list(argv), 1 if self.visudo_refuses else 0, "", "parse error"
            )
        if argv[0] == cluster_definition.SYSTEMCTL:
            return subprocess.CompletedProcess(list(argv), 0, "", "")
        return subprocess.run(
            list(argv), input=input_text, capture_output=True, text=True, check=False
        )

    def runtime(self) -> RuntimeConfig:
        return load_runtime_config(self.policy, require_secure=False)

    def snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if path.is_file()
        }

    def spec(self, **overrides: Any) -> cluster_definition.Definition:
        fields: dict[str, Any] = {
            "display_name": "Gamma",
            "vip": "198.51.100.30",
            "node_path": "gamma",
            "default_certificate": "example.net",
            "blocks": [block("node-c", 10), block("node-d", 20)],
            "hosts": ["node-c.example.com", "node-d.example.com"],
            "address_prefix": 24,
        }
        fields.update(overrides)
        return cluster_definition.definition("gamma", **fields)

    def add(
        self,
        spec: cluster_definition.Definition | None = None,
        ask: AskNode | None = None,
        addresses: Any = None,
        join_node: Any = None,
    ) -> Any:
        return cluster_definition.add(
            self.policy,
            self.runtime(),
            spec or self.spec(),
            ask=ask or answering_as("gamma"),
            join_node=join_node,
            locations=self.locations,
            places=self.places,
            tools=self.tools,
            require_secure=False,
            addresses=addresses,
        )

    def remove(self, cluster: str = "alpha") -> Any:
        return cluster_definition.remove(
            self.policy,
            self.runtime(),
            cluster=cluster,
            locations=self.locations,
            places=self.places,
            tools=self.tools,
            require_secure=False,
        )


@unittest.skipUnless(Path(GIT).exists(), "git is not installed where the tests run")
class CreatingACluster(unittest.TestCase):
    def test_two_new_nodes_with_one_host_key_are_said_and_the_cluster_stands(self) -> None:
        """Fynd 43 (B335): a cluster created from two clones of one machine."""

        clone = node_enrollment.render(
            Enrollment(
                cluster="gamma",
                name="node-d",
                host="node-d.example.com",
                host_key=key(10),
                config_pull_key=key(21),
                cert_pull_key=key(22),
            )
        )
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            outcome = site.add(site.spec(blocks=[block("node-c", 10), clone]))

            self.assertEqual(
                outcome.warnings, (node_enrollment.shared_key_warning("node-d", ["node-c"]),)
            )
            self.assertIn("gamma", site.runtime().clusters)

    def test_the_first_cluster_on_an_empty_manager_with_one_node_and_no_certificate(self) -> None:
        """B302: installed without clusters, the first is created with its first node."""

        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            site.remove("alpha")
            registry_before = site.registry.read_bytes()

            site.add(
                site.spec(
                    default_certificate=None,
                    blocks=[block("node-c", 10)],
                    hosts=["node-c.example.com"],
                )
            )

            gamma = site.runtime().cluster("gamma")
            self.assertEqual([node.name for node in gamma.nodes], ["node-c"])
            self.assertIsNone(gamma.default_certificate)
            self.assertEqual(gamma.certificate_ids, ())
            self.assertEqual(gamma.validation_certs, site.root / "validation/certs")
            self.assertEqual(site.registry.read_bytes(), registry_before)
            sudoers = site.sudoers.read_text()
            self.assertIn(f"sudoedit {site.config_root}/gamma/core/haproxy.cfg, \\", sudoers)
            self.assertTrue(sudoers.rstrip().endswith("HAPROXY_EDITORS ALL = (root) HAPROXY_EDIT"))

    def test_each_new_cluster_gets_the_lowest_router_id_none_has(self) -> None:
        """B313: the product writes keepalived.conf for clusters it created."""

        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            self.assertIsNone(site.runtime().cluster("alpha").vrrp_router_id)

            site.add()
            site.add(
                cluster_definition.definition(
                    "delta",
                    display_name="Delta",
                    vip="198.51.100.40",
                    node_path="delta",
                    default_certificate=None,
                    blocks=[block("node-e", 30, cluster="delta")],
                    hosts=["node-e.example.com"],
                ),
                ask=answering_as("delta"),
            )

            runtime = site.runtime()
            self.assertEqual(runtime.cluster("gamma").vrrp_router_id, 1)
            self.assertEqual(runtime.cluster("delta").vrrp_router_id, 2)

    def test_the_cluster_its_repository_and_its_nodes_exist_as_one(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            outcome = site.add()

            runtime = site.runtime()
            gamma = runtime.cluster("gamma")
            self.assertEqual([node.name for node in gamma.nodes], ["node-c", "node-d"])
            self.assertEqual(gamma.default_certificate, "example.net")
            self.assertEqual(gamma.address_prefix, 24)
            self.assertIn("gamma", runtime.registry.certificates["example.net"].clusters)  # type: ignore[union-attr]
            work = site.config_root / "gamma"
            self.assertIn("ssl-default-bind-ciphers", (work / "core/haproxy.cfg").read_text())
            self.assertIn("198.51.100.30", (work / "managed/network.yaml").read_text())
            self.assertTrue((work / "manual/conf.d/.gitkeep").exists())
            log = subprocess.run(
                [GIT, "-C", str(work), "log", "--format=%s"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertEqual(log.strip(), "Cluster gamma created")
            # A publish refuses a repository without its own identity (Fas 18, 26-10-15).
            for setting, value in cluster_definition.REPOSITORY_IDENTITY:
                kept = subprocess.run(
                    [GIT, "-C", str(site.config_root / "gamma.git"), "config", "--get", setting],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
                self.assertEqual(kept, value)
            self.assertTrue((site.publish_root / "gamma/releases").is_dir())
            sudoers = site.sudoers.read_text()
            self.assertIn(f"sudoedit {site.config_root}/gamma/core/haproxy.cfg", sudoers)
            self.assertIn(
                f"sudoedit {site.config_root}/alpha/manual/reservations.yaml, \\", sudoers
            )
            self.assertTrue(sudoers.rstrip().endswith("HAPROXY_EDITORS ALL = (root) HAPROXY_EDIT"))
            safe = subprocess.run(
                [GIT, "config", "--file", str(site.gitconfig), "--get-all", "safe.directory"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()
            self.assertEqual(safe, [f"{site.config_root}/gamma.git", f"{site.config_root}/gamma"])
            #
            # Each new node's keys read the new cluster's tree and its own
            # certificate directory, from the node's address (B358).
            #
            for account, root, purpose in (
                ("_haprion-pull", site.publish_root / "gamma", "config pull"),
                ("_haprion-cert-pull", site.root / "certdist" / "gamma", "certificate pull"),
            ):
                lines = (site.root / account / ".ssh/authorized_keys").read_text().splitlines()
                line = next(line for line in lines if line.endswith(f" node-d {purpose}"))
                self.assertTrue(line.startswith('from="'), line)
                self.assertIn(f'command="/usr/bin/rrsync -ro {root}" ', line)
            self.assertEqual(len(outcome.fingerprints), 2)

    def test_the_first_version_carries_the_files_its_nodes_need(self) -> None:
        """B318: version 1 is the cluster being made, keepalived for each node included."""

        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            site.add(
                addresses=lambda cluster: tuple(
                    (node.name, f"198.51.100.{number}")
                    for number, node in enumerate(cluster.nodes, start=1)
                )
            )

            work = site.config_root / "gamma"
            tracked = subprocess.run(
                [GIT, "-C", str(work), "ls-files"], capture_output=True, text=True, check=True
            ).stdout.split()
            self.assertIn("managed/keepalived/node-node-c.conf", tracked)
            self.assertIn("managed/keepalived/node-node-d.conf", tracked)
            self.assertEqual(count_versions(work), 1)

    def test_nodes_that_cannot_be_looked_up_leave_the_layout_alone(self) -> None:
        def unresolved(_cluster: Any) -> tuple[tuple[str, str], ...]:
            raise ConfigError("node-c.example.com does not resolve")

        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            site.add(addresses=unresolved)

            work = site.config_root / "gamma"
            self.assertFalse((work / "managed/keepalived").exists())
            self.assertTrue((work / "managed/network.yaml").exists())

    def test_each_node_gets_an_empty_backup_directory(self) -> None:
        """Fas 18 (26-10-16): a new node's backups read as none yet, not as unreadable."""

        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            site.add()

            directory = site.backup_root / "node-c"
            self.assertTrue(directory.is_dir())
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(list(directory.iterdir()), [])

    def test_a_node_that_does_not_answer_leaves_the_installation_as_it_was(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            before = site.snapshot()

            with self.assertRaises(EnrollmentError) as caught:
                site.add(ask=silent)

            self.assertEqual(caught.exception.code, "node_unverified")
            self.assertEqual(site.snapshot(), before)
            self.assertFalse((site.config_root / "gamma").exists())
            self.assertFalse((site.publish_root / "gamma").exists())
            self.assertFalse((site.backup_root / "node-c").exists())

    def test_nodes_a_rolled_back_create_joined_are_not_joined_again(self) -> None:
        """Review 26-10-30, E2: node-c joined, node-d failed, the block of node-c is used up."""

        from tests.test_node_join_manager import PRIVATE

        blocks = [
            node_enrollment.render(
                Enrollment(
                    cluster=None,
                    name=name,
                    host=f"{name}.example.com",
                    host_key=key(seed),
                    config_pull_key=key(seed + 1),
                    cert_pull_key=key(seed + 2),
                    join_key=PRIVATE,
                )
            )
            for name, seed in (("node-c", 10), ("node-d", 20))
        ]
        document = {"version": 1, "cluster": "gamma"}
        for joined_before in ((), ("node-c",)):
            with (
                self.subTest(joined_before=joined_before),
                tempfile.TemporaryDirectory() as raw,
                mock.patch.object(node_enrollment, "join_document", return_value=document),
            ):
                site = Site(Path(raw))
                before = site.snapshot()
                joins: list[str] = []
                joined = set(joined_before)

                def join(
                    node: Any,
                    _private: str,
                    _document: Any,
                    joins: list[str] = joins,
                    joined: set[str] = joined,
                ) -> Any:
                    joins.append(node.name)
                    if node.name == "node-d":
                        return NodeResponse(75, "", "preparing this node stopped")
                    if node.name in joined:
                        return NodeResponse(255, "", "Permission denied")
                    joined.add(node.name)
                    return NodeResponse(0, "")

                def ask(node: Any, joined: set[str] = joined) -> Any:
                    if node.name not in joined:
                        return NodeResponse(255, "")
                    return NodeResponse(0, json.dumps({"node": node.name, "cluster": "gamma"}))

                spec = site.spec(blocks=blocks, hosts=["node-c.example.com", "node-d.example.com"])
                with self.assertRaises(EnrollmentError) as caught:
                    site.add(spec, ask=ask, join_node=join)
                self.assertEqual(site.snapshot(), before)
                self.assertEqual(joins, ["node-c", "node-d"])
                if not joined_before:
                    self.assertIn("node-c", str(caught.exception))
                    self.assertIn("rolled back on the manager", str(caught.exception))

    def test_a_block_without_the_certificate_key_is_refused_as_an_added_node_is(self) -> None:
        """Review 26-10-30, E4: one rule for creating a cluster and adding a node."""

        bare = node_enrollment.render(
            Enrollment(
                cluster="gamma",
                name="node-c",
                host="node-c.example.com",
                host_key=key(10),
                config_pull_key=key(11),
                cert_pull_key=None,
            )
        )
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            before = site.snapshot()
            spec = site.spec(blocks=[bare], hosts=["node-c.example.com"])
            with self.assertRaises(EnrollmentError) as caught:
                site.add(spec)
            self.assertEqual(caught.exception.code, "enrollment_invalid")
            self.assertIn("certificate pull key", str(caught.exception))
            self.assertEqual(site.snapshot(), before)

    def test_an_ipv6_vip_is_refused_before_anything_is_joined(self) -> None:
        """Review 26-10-30, E3: the node side is IPv4 only."""

        with self.assertRaises(EnrollmentError) as caught:
            cluster_definition.check_name("alpha", display_name="Alpha", vip="2001:db8::10")
        self.assertEqual(caught.exception.code, "cluster_invalid")
        self.assertIn("not an IPv4 address", str(caught.exception))

    def test_an_editing_policy_visudo_refuses_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            site.visudo_refuses = True
            before = site.snapshot()

            with self.assertRaisesRegex(EnrollmentError, "would not parse"):
                site.add()

            self.assertEqual(site.snapshot(), before)

    def test_a_block_for_another_cluster_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            with self.assertRaisesRegex(EnrollmentError, "was made for 'alpha'"):
                site.spec(blocks=[block("node-c", 10, "alpha"), block("node-d", 20)])

    def test_a_taken_name_node_path_or_node_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            with self.assertRaisesRegex(EnrollmentError, "node path"):
                site.add(site.spec(node_path="alpha"))
            with self.assertRaisesRegex(EnrollmentError, "already in alpha"):
                site.add(site.spec(hosts=["node-a.example.com", "node-d.example.com"]))
            with self.assertRaisesRegex(EnrollmentError, "no certificate"):
                site.add(site.spec(default_certificate="example.org"))

    def test_step_one_asks_the_engine_for_the_layout(self) -> None:
        """One template: step 1 once kept a copy, and the copy drifted (finding 53)."""

        script = (BASE / "install/01-manager-prepare").read_text()
        self.assertIn('"$CLUSTER_CONFIG" --seed "$seed"', script)
        self.assertNotIn("<<'CORE'", script)
        self.assertNotIn("<<'RESERVATIONS'", script)
        self.assertNotIn("vips:", script)

    def test_a_new_cluster_opens_the_socket_node_status_reads(self) -> None:
        """Without it every node of the cluster read *Stats unavailable* (finding 53)."""

        node_status = (BASE / "install/node/haprion-node-status").read_text()
        self.assertIn(f'RUNTIME_SOCKET = "{cluster_definition.STATUS_SOCKET}"', node_status)
        core = cluster_definition.seed_files("192.0.2.1")["core/haproxy.cfg"].decode()
        self.assertIn(
            f"    stats socket {cluster_definition.STATUS_SOCKET} mode 660 level user",
            core.splitlines(),
        )

    def test_the_seed_carries_a_source_address_and_needs_no_vip(self) -> None:
        with_source = cluster_definition.seed_files("192.0.2.1", "192.0.2.2")
        network = yaml.safe_load(with_source["managed/network.yaml"])
        self.assertEqual(
            network,
            {
                "vips": {"main": {"address": "192.0.2.1", "source": "192.0.2.2"}},
                "default_vip": "main",
            },
        )
        plain = yaml.safe_load(cluster_definition.seed_files("192.0.2.1")["managed/network.yaml"])
        self.assertEqual(plain, {"vips": {"main": {"address": "192.0.2.1"}}, "default_vip": "main"})
        self.assertNotIn("managed/network.yaml", cluster_definition.seed_files(None))

    def test_a_new_cluster_keeps_its_counters_where_the_check_can_open_them(self) -> None:
        """The core names the file; the validation sandbox makes its directory (N3)."""

        ours = cluster_definition.seed_files("192.0.2.1")["core/haproxy.cfg"].decode()
        wanted = f"    shm-stats-file {cluster_definition.SHM_STATS_FILE}"

        self.assertIn(wanted, ours.splitlines())
        self.assertEqual(
            str(Path(cluster_definition.SHM_STATS_FILE).parent),
            candidate_validation.SHM_STATS_DIRECTORY,
        )
        self.assertIn(
            f"    stats socket {cluster_definition.MANAGER_SOCKET} mode 600 level admin",
            ours.splitlines(),
        )
        self.assertIn(
            f"TemporaryFileSystem={candidate_validation.SHM_STATS_DIRECTORY}",
            candidate_validation.sandbox_command(Path("/tmp/candidate"), "request-1"),
        )


@unittest.skipUnless(Path(GIT).exists(), "git is not installed where the tests run")
class RemovingACluster(unittest.TestCase):
    def added(self, raw: str) -> Site:
        site = Site(Path(raw))
        site.add()
        return site

    def test_removal_archives_and_forgets_the_cluster(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)

            outcome = site.remove("alpha")

            self.assertNotIn("alpha", site.runtime().clusters)
            archive = site.config_root / ".removed" / outcome.archive
            self.assertEqual((archive / "alpha/marker").read_text(), "alpha\n")
            self.assertTrue((archive / "alpha.git").is_dir())
            self.assertTrue((site.publish_root / ".removed" / outcome.archive / "alpha").is_dir())
            self.assertTrue((site.backup_root / ".removed" / outcome.archive / "node-a").is_dir())
            self.assertFalse((site.backup_root / "node-a").exists())
            self.assertFalse((site.retention / "alpha.json").exists())
            self.assertNotIn("alpha", site.sudoers.read_text())
            self.assertNotIn(
                "node-a", (site.root / "_haprion-pull/.ssh/authorized_keys").read_text()
            )
            self.assertNotIn("alpha", site.registry.read_text())
            self.assertIn(
                [
                    cluster_definition.SYSTEMCTL,
                    "disable",
                    "--now",
                    "haprion-state-backup@alpha.timer",
                ],
                site.ran,
            )

    def test_removal_takes_its_repositories_out_of_safe_directory(self) -> None:
        """Review 2026-09-30 F4: the entries go, and a cluster that had none is no error."""

        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            site.remove("gamma")
            listed = subprocess.run(
                [GIT, "config", "--file", str(site.gitconfig), "--get-all", "safe.directory"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.split()
            self.assertEqual(listed, [])

    def test_a_git_config_that_fails_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            before = site.snapshot()
            real = site.run

            def refusing(
                argv: Sequence[str], *, input_text: str | None = None
            ) -> subprocess.CompletedProcess[str]:
                if "--add" in argv and "safe.directory" in argv:
                    return subprocess.CompletedProcess(
                        list(argv), 1, "", "could not lock config file"
                    )
                return real(argv, input_text=input_text)

            site.tools = Tools(run=refusing, owner=lambda *_: None, clock=lambda: 1_790_000_000.0)
            with self.assertRaisesRegex(EnrollmentError, "could not lock config file"):
                site.add()
            self.assertEqual(site.snapshot(), before)
            self.assertFalse((site.config_root / "gamma").exists())

    def test_an_archived_name_cannot_be_used_again(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            site.remove("gamma")

            with self.assertRaisesRegex(EnrollmentError, "is archived"):
                site.add()

    def test_the_last_cluster_can_go_and_its_editing_rule_with_it(self) -> None:
        """B302: no clusters is a manager's state; the editing policy keeps no empty alias."""

        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            site.remove("alpha")
            self.assertEqual(dict(site.runtime().clusters), {})
            self.assertNotIn("HAPROXY_EDIT =", site.sudoers.read_text())

    def test_a_failure_puts_back_what_was_moved(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            before = site.snapshot()
            real = change_journal.write_like

            def failing(path: Path, content: bytes) -> None:
                if path == site.registry:
                    raise OSError("disk full")
                real(path, content)

            change_journal.write_like = failing
            try:
                with self.assertRaises(OSError):
                    site.remove("alpha")
            finally:
                change_journal.write_like = real

            self.assertEqual(site.snapshot(), before)
            self.assertFalse(
                (site.config_root / ".removed").exists()
                and any((site.config_root / ".removed").iterdir())
            )


REQUEST_ID = "77777777-7777-4777-8777-777777777777"


@unittest.skipUnless(Path(GIT).exists(), "git is not installed where the tests run")
class TheHelper(unittest.TestCase):
    """The request the worker and `haprion-cluster` send, answered in the contract's envelope."""

    def run_helper(
        self, site: Site, request: str, *, ask: AskNode | None = None
    ) -> tuple[int, dict[str, Any]]:
        out, err = io.StringIO(), io.StringIO()
        # The locks outside the installation, whose snapshot they would change.
        locks = Path(self.enterContext(tempfile.TemporaryDirectory()))
        code = node_helper.main(
            [],
            policy_path=site.policy_file,
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=locks,
            registry_lock=locks / "registry.lock",
            locations=site.locations,
            places=site.places,
            tools=site.tools,
            ask=ask or answering_as("gamma"),
            publish=published,
        )
        return code, assert_contract("haprion-cluster-define", out.getvalue())

    def creation(self, **overrides: Any) -> str:
        fields: dict[str, Any] = {
            "action": "add",
            "display_name": "Gamma",
            "vip": "198.51.100.30",
            "node_path": "gamma",
            "default_certificate": "example.net",
            "blocks": [block("node-c", 10), block("node-d", 20)],
            "hosts": ["node-c.example.com", "node-d.example.com"],
            "address_prefix": 24,
        }
        fields.update(overrides)
        return node_helper.build_define_request("gamma", REQUEST_ID, **fields)

    def test_a_creation_answers_with_its_nodes_and_their_host_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))

            code, document = self.run_helper(site, self.creation())

            self.assertEqual((code, document["outcome"]), (0, "done"))
            result = document["result"]
            self.assertEqual(result["action"], "added")
            self.assertEqual([node["name"] for node in result["nodes"]], ["node-c", "node-d"])
            self.assertEqual(
                result["host_key_fingerprints"],
                [node_enrollment.fingerprint(key(10)), node_enrollment.fingerprint(key(20))],
            )
            self.assertIsNone(result["archive"])
            self.assertIn("gamma", site.runtime().clusters)

    def test_a_node_that_does_not_answer_is_blocked_and_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            before = site.snapshot()

            code, document = self.run_helper(site, self.creation(), ask=silent)

            self.assertEqual((code, document["outcome"]), (75, "blocked"))
            self.assertEqual(document["error"]["code"], "node_unverified")
            self.assertEqual(site.snapshot(), before)

    def test_a_removal_answers_with_its_archive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            self.run_helper(site, self.creation())

            code, document = self.run_helper(
                site, node_helper.build_define_request("alpha", REQUEST_ID, action="remove")
            )

            self.assertEqual((code, document["outcome"]), (0, "done"))
            result = document["result"]
            self.assertEqual(result["action"], "removed")
            self.assertTrue(result["archive"].startswith("alpha-"))
            self.assertEqual(result["host_key_fingerprints"], [])
            self.assertNotIn("alpha", site.runtime().clusters)

    def test_a_removal_takes_no_definition(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            request = json.loads(
                node_helper.build_define_request("alpha", REQUEST_ID, action="remove")
            )
            request["parameters"]["vip"] = "198.51.100.30"

            code, document = self.run_helper(site, json.dumps(request))

            self.assertEqual((code, document["outcome"]), (65, "failed"))
            self.assertIn("takes no vip", document["error"]["message"])
            self.assertIn("alpha", site.runtime().clusters)


class TheCommand(unittest.TestCase):
    def test_add_sends_both_blocks_in_the_order_of_the_hosts(self) -> None:
        sent: list[str] = []

        def run(request: str) -> subprocess.CompletedProcess[str]:
            sent.append(request)
            answer = {
                "operation": "cluster_define",
                "result": {
                    "action": "added",
                    "nodes": [{"name": "node-c"}, {"name": "node-d"}],
                    "files": ["clusters.yaml"],
                    "host_key_fingerprints": ["SHA256:x", "SHA256:y"],
                    "publication": {"version": 1, "hash": "c" * 40, "changed": False},
                },
            }
            return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

        # Folded by a terminal, as a pasted pair arrives.
        pasted = block("node-c", 10)[:40] + "\n" + block("node-c", 10)[40:] + "\n\n"
        pasted += block("node-d", 20) + "\n"
        out = io.StringIO()
        code = cluster_command.main(
            [
                "add",
                "-c",
                "gamma",
                "--display-name",
                "Gamma",
                "--vip",
                "198.51.100.30",
                "--node-path",
                "gamma",
                "--certificate",
                "example.net",
                "--host",
                "node-c.example.com",
                "--host",
                "node-d.example.com",
                "--prefix",
                "24",
            ],
            stdin=io.StringIO(pasted),
            stdout=out,
            run=run,
        )

        self.assertEqual(code, 0)
        parameters = json.loads(sent[0])["parameters"]
        self.assertEqual(parameters["blocks"], [block("node-c", 10), block("node-d", 20)])
        self.assertEqual(parameters["hosts"], ["node-c.example.com", "node-d.example.com"])
        self.assertEqual(parameters["address_prefix"], 24)
        self.assertNotIn("address_interface", parameters)
        self.assertIn("Created gamma with node-c, node-d.", out.getvalue())
        self.assertIn("no certificates yet: haprion-cert-deploy -c gamma", out.getvalue())
        self.assertIn("Published as version 1; haprion-deploy -c gamma", out.getvalue())
        self.assertEqual(parameters["display_name"], "Gamma")

    def test_without_a_display_name_the_cluster_is_named_by_its_id(self) -> None:
        """Review 2026-10-22, 7-16: a required name no page shows; the form takes the same default."""

        sent: list[str] = []

        def run(request: str) -> subprocess.CompletedProcess[str]:
            sent.append(request)
            return subprocess.CompletedProcess([], 1, "", "refused")

        cluster_command.main(
            [
                "add",
                "-c",
                "gamma",
                "--vip",
                "198.51.100.30",
                "--node-path",
                "gamma",
                "--host",
                "node-c.example.com",
            ],
            stdin=io.StringIO(block("node-c", 10) + "\n"),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            run=run,
        )

        self.assertEqual(json.loads(sent[0])["parameters"]["display_name"], "gamma")

    def test_remove_names_the_archive_and_says_the_nodes_keep_serving(self) -> None:
        def run(request: str) -> subprocess.CompletedProcess[str]:
            self.assertEqual(json.loads(request)["parameters"], {"action": "remove"})
            answer = {
                "operation": "cluster_define",
                "result": {
                    "action": "removed",
                    "archive": "alpha-20260930-101500",
                    "warnings": ["haprion-state-backup@alpha.timer could not be stopped"],
                },
            }
            return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

        out = io.StringIO()
        code = cluster_command.main(["remove", "-c", "alpha"], stdout=out, run=run)

        self.assertEqual(code, 0)
        self.assertIn("archived as alpha-20260930-101500", out.getvalue())
        self.assertIn("keep serving", out.getvalue())
        self.assertIn("WARNING: haprion-state-backup@alpha.timer", out.getvalue())

    def test_a_refusal_is_printed_as_its_sentence(self) -> None:
        def run(_request: str) -> subprocess.CompletedProcess[str]:
            answer = {
                "operation": "cluster_define",
                "error": {"code": "cluster_last", "message": "this is the only cluster"},
            }
            return subprocess.CompletedProcess([], 65, json.dumps(answer), "")

        err = io.StringIO()
        code = cluster_command.main(
            ["remove", "-c", "alpha"], stdout=io.StringIO(), stderr=err, run=run
        )

        self.assertEqual(code, 1)
        self.assertIn("only cluster", err.getvalue())


class TheEditingPolicy(unittest.TestCase):
    def test_removing_the_last_entry_moves_the_line_without_a_backslash(self) -> None:
        text = SUDOERS.format(root="/c")
        edited = cluster_definition.sudoers_with(text, drop=["/c/alpha/manual/reservations.yaml"])
        self.assertIn("    sudoedit /c/alpha/core/haproxy.cfg\n", edited)
        self.assertNotIn("reservations", edited)

    @unittest.skipUnless(shutil.which("visudo"), "visudo is not installed")
    def test_what_it_writes_is_what_visudo_accepts(self) -> None:
        visudo = shutil.which("visudo") or ""
        text = cluster_definition.sudoers_with(
            SUDOERS.format(root="/c"), add=["/c/b/core/haproxy.cfg"]
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sudoers") as handle:
            handle.write(text)
            handle.flush()
            checked = subprocess.run(
                [visudo, "-cqf", handle.name], capture_output=True, check=False
            )
        self.assertEqual(checked.returncode, 0, checked.stderr)


class TheJsonAnswers(unittest.TestCase):
    """`--json` on `haprion-node` and `haprion-cluster` (Fas 23): the helper's envelope as it came."""

    def answering(self, path: str, code: int) -> Any:
        text = (BASE / "fixtures" / path).read_text()

        def run(_request: str) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], code, text, "")

        return run

    def test_both_commands_print_the_envelope_and_keep_its_exit_code(self) -> None:
        from haprion.cli import node as node_command

        for main, argv, path, code, schema in (
            (
                node_command.main,
                ["remove", "-c", "alpha", "node-b", "--json"],
                "haprion-cluster-node/valid/removed.json",
                0,
                "haprion-cluster-node",
            ),
            (
                node_command.main,
                ["remove", "-c", "alpha", "--json", "node-a"],
                "haprion-cluster-node/valid/blocked.json",
                75,
                "haprion-cluster-node",
            ),
            (
                cluster_command.main,
                ["remove", "-c", "gamma", "--json"],
                "haprion-cluster-define/valid/removed.json",
                0,
                "haprion-cluster-define",
            ),
        ):
            with self.subTest(path):
                out = io.StringIO()

                returned = main(
                    argv, stdout=out, stderr=io.StringIO(), run=self.answering(path, code)
                )

                self.assertEqual(returned, code)
                assert_contract(schema, out.getvalue())
