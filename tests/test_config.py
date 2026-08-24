from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path

import yaml

from haproxy_mgmt.cli.cluster_config import main as cluster_config_main
from haproxy_mgmt.config import ConfigError, load_policy, load_runtime_config

BASE = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def test_generic_examples_load(self):
        policy = load_policy(BASE / "examples" / "runtime-policy.yaml", require_secure=False)
        policy = replace(policy, cluster_file=BASE / "examples" / "clusters.yaml")
        runtime = load_runtime_config(policy, require_secure=False)
        cluster = runtime.cluster("alpha")
        self.assertEqual(cluster.vip, "192.0.2.20")
        self.assertEqual([node.name for node in cluster.nodes], ["node-a", "node-b"])
        self.assertEqual(cluster.certificate_ids, ("example.com", "example.net"))
        self.assertEqual(cluster.trusted_proxy_cidrs, ("198.51.100.0/24",))

    def write_config(self, directory: Path, mutate=None):
        clusters = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
        if mutate is not None:
            mutate(clusters)
        cluster_file = directory / "clusters.yaml"
        cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False), encoding="utf-8")
        policy = yaml.safe_load((BASE / "examples" / "runtime-policy.yaml").read_text())
        policy["cluster_file"] = str(cluster_file)
        policy_file = directory / "runtime-policy.yaml"
        policy_file.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        return policy_file

    @contextmanager
    def temporary_runtime(self, mutate=None):
        with tempfile.TemporaryDirectory() as raw:
            policy_file = self.write_config(Path(raw), mutate)
            policy = load_policy(policy_file, require_secure=False)
            yield load_runtime_config(policy, require_secure=False)

    def test_unknown_field_is_rejected(self):
        def mutate(data):
            data["clusters"]["alpha"]["unexpected"] = True

        with self.assertRaisesRegex(ConfigError, "unknown field"), self.temporary_runtime(mutate):
            pass

    def test_boolean_schema_version_is_rejected(self):
        def mutate(data):
            data["schema_version"] = True

        with self.assertRaisesRegex(ConfigError, "schema_version"), self.temporary_runtime(mutate):
            pass

    def test_path_escape_is_rejected(self):
        def mutate(data):
            data["clusters"]["alpha"]["config_path"] = "/var/tmp/outside"

        with (
            self.assertRaisesRegex(ConfigError, "escapes its allowed root"),
            self.temporary_runtime(mutate),
        ):
            pass

    def test_duplicate_nodes_are_rejected(self):
        def mutate(data):
            data["clusters"]["alpha"]["nodes"][1] = data["clusters"]["alpha"]["nodes"][0]

        with self.assertRaisesRegex(ConfigError, "unique names"), self.temporary_runtime(mutate):
            pass

    def test_trust_all_network_is_rejected(self):
        def mutate(data):
            data["clusters"]["alpha"]["trusted_proxy_cidrs"] = ["192.0.2.0/0"]

        with (
            self.assertRaisesRegex(ConfigError, "entire address family"),
            self.temporary_runtime(mutate),
        ):
            pass

    def test_symlinked_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            real = root / "real.yaml"
            real.write_text("schema_version: 1\n", encoding="utf-8")
            link = root / "policy.yaml"
            link.symlink_to(real)
            with self.assertRaisesRegex(ConfigError, "non-symlink"):
                load_policy(link, require_secure=False)

    def test_cluster_lookup_and_cli_output(self):
        with tempfile.TemporaryDirectory() as raw:
            policy_path = self.write_config(Path(raw))
            policy = load_policy(policy_path, require_secure=False)
            runtime = load_runtime_config(policy, require_secure=False)
            with self.assertRaisesRegex(ConfigError, "unknown cluster") as caught:
                runtime.cluster("beta")
            self.assertEqual(caught.exception.exit_code, 64)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cluster_config_main(
                    ["-c", "alpha", "--field", "nodes"],
                    policy_path=policy_path,
                    require_secure=False,
                )
        self.assertEqual((code, stderr.getvalue()), (0, ""))
        self.assertEqual(
            stdout.getvalue().splitlines(),
            ["node-a\tnode-a.example.com", "node-b\tnode-b.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
