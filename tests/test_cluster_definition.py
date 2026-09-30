"""Creating and removing a cluster, as one change or none (B211)."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from haproxy_mgmt import cluster_definition, node_enrollment
from haproxy_mgmt.cluster_definition import Places, Tools
from haproxy_mgmt.config import RuntimeConfig, load_policy, load_runtime_config
from haproxy_mgmt.git_command import GIT
from haproxy_mgmt.node_enrollment import AskNode, Enrollment, EnrollmentError, Locations
from haproxy_mgmt.status_collect import NodeResponse
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
            "pull_account": "svc-pull",
            "cert_pull_account": "svc-cert-pull",
        }
        self.policy_file = root / "runtime-policy.yaml"
        self.policy_file.write_text(yaml.safe_dump(policy))
        self.policy = load_policy(self.policy_file, require_secure=False)
        for account in ("svc-pull", "svc-cert-pull"):
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
            home=lambda account: root / account,
        )
        self.sudoers = root / "haproxy-config-edit"
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
        )  # noqa: S603

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
        self, spec: cluster_definition.Definition | None = None, ask: AskNode | None = None
    ) -> Any:
        return cluster_definition.add(
            self.policy,
            self.runtime(),
            spec or self.spec(),
            ask=ask or answering_as("gamma"),
            locations=self.locations,
            places=self.places,
            tools=self.tools,
            require_secure=False,
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
            self.assertEqual(log.strip(), "Initial layout for cluster gamma")
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
            self.assertIn(
                "node-d certificate pull",
                (site.root / "svc-cert-pull/.ssh/authorized_keys").read_text(),
            )
            self.assertEqual(len(outcome.fingerprints), 2)

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

    def test_the_seed_carries_every_line_of_step_one_s_core(self) -> None:
        script = (BASE / "install/01-manager-prepare").read_text()
        start = script.index("<<'CORE'\n") + len("<<'CORE'\n")
        theirs = script[start : script.index("\nCORE\n", start)]
        ours = cluster_definition.seed_files("192.0.2.1")["core/haproxy.cfg"].decode()
        self.assertIn("ssl-default-bind-ciphersuites", ours)
        for line in theirs.splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                with self.subTest(line=line):
                    self.assertIn(line, ours.splitlines())
        for directory in cluster_definition.SEED_DIRECTORIES:
            with self.subTest(directory=directory):
                self.assertIn(f'"${{seed}}/{directory}"', script)


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
            self.assertNotIn("node-a", (site.root / "svc-pull/.ssh/authorized_keys").read_text())
            self.assertNotIn("alpha", site.registry.read_text())
            self.assertIn(
                [
                    cluster_definition.SYSTEMCTL,
                    "disable",
                    "--now",
                    "haproxy-state-backup@alpha.timer",
                ],
                site.ran,
            )

    def test_an_archived_name_cannot_be_used_again(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            site.remove("gamma")

            with self.assertRaisesRegex(EnrollmentError, "is archived"):
                site.add()

    def test_the_last_cluster_stays(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Site(Path(raw))
            with self.assertRaisesRegex(EnrollmentError, "only cluster"):
                site.remove("alpha")

    def test_a_failure_puts_back_what_was_moved(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            before = site.snapshot()
            real = node_enrollment._write_like

            def failing(path: Path, content: bytes) -> None:
                if path == site.registry:
                    raise OSError("disk full")
                real(path, content)

            node_enrollment._write_like = failing
            try:
                with self.assertRaises(OSError):
                    site.remove("alpha")
            finally:
                node_enrollment._write_like = real

            self.assertEqual(site.snapshot(), before)
            self.assertFalse(
                (site.config_root / ".removed").exists()
                and any((site.config_root / ".removed").iterdir())
            )


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
            )  # noqa: S603
        self.assertEqual(checked.returncode, 0, checked.stderr)
