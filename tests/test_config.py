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


class DeployIdentityTests(unittest.TestCase):
    """The deploy identity, which is configuration and never code.

    The account name and the key path identify a real installation, so they must
    not be compiled in - a repository meant to be public cannot carry either.
    """

    def policy(self, root: Path, identity: object) -> Path:
        body = {
            "schema_version": 1,
            "cluster_file": str(root / "clusters.yaml"),
            "config_root": str(root / "config"),
            "publish_root": str(root / "published"),
            "validation_certs_root": str(root / "certs"),
        }
        if identity is not None:
            body["deploy_identity"] = identity
        path = root / "runtime-policy.yaml"
        path.write_text(yaml.safe_dump(body), encoding="utf-8")
        return path

    def test_a_policy_without_one_is_valid(self) -> None:
        #
        # Every other command works without it. Requiring it everywhere would
        # mean a policy file that all of them reject until it is updated.
        #
        with tempfile.TemporaryDirectory() as raw:
            policy = load_policy(self.policy(Path(raw), None), require_secure=False)

        self.assertIsNone(policy.deploy_identity)

    def test_a_declared_identity_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy = load_policy(
                self.policy(Path(raw), {"user": "svc-app", "key": "/root/.ssh/id_ed25519_example"}),
                require_secure=False,
            )

        assert policy.deploy_identity is not None
        self.assertEqual(policy.deploy_identity.user, "svc-app")
        self.assertEqual(policy.deploy_identity.key, Path("/root/.ssh/id_ed25519_example"))

    def test_an_invalid_account_name_is_refused(self) -> None:
        for user in ("", "Has Spaces", "root/../x", "a" * 40):
            with tempfile.TemporaryDirectory() as raw, self.assertRaises(ConfigError):
                load_policy(
                    self.policy(Path(raw), {"user": user, "key": "/root/.ssh/id"}),
                    require_secure=False,
                )

    def test_a_relative_key_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(ConfigError):
            load_policy(
                self.policy(Path(raw), {"user": "svc-app", "key": ".ssh/id"}),
                require_secure=False,
            )

    def test_an_unknown_field_in_the_identity_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(ConfigError):
            load_policy(
                self.policy(Path(raw), {"user": "svc-app", "key": "/root/id", "port": 22}),
                require_secure=False,
            )


_UNSET = object()


def _cluster(
    vips: object = _UNSET,
    default_vip: object = _UNSET,
    resolvers: object = _UNSET,
    networks: object = _UNSET,
    unknown_host: object = _UNSET,
):
    """One cluster from the shipped example, with its address table replaced.

    Defaults to removing the section entirely, which is the deployment that
    exists today: one virtual address, named for it, no separate source.
    """

    clusters = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
    alpha = clusters["clusters"]["alpha"]
    alpha.pop("vips", None)
    alpha.pop("default_vip", None)
    if vips is not _UNSET:
        alpha["vips"] = vips
    if default_vip is not _UNSET:
        alpha["default_vip"] = default_vip
    if resolvers is not _UNSET:
        alpha["resolvers"] = resolvers
    if networks is not _UNSET:
        alpha["networks"] = networks
    if unknown_host is not _UNSET:
        alpha["unknown_host"] = unknown_host

    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        cluster_file = directory / "clusters.yaml"
        cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False), encoding="utf-8")
        policy = yaml.safe_load((BASE / "examples" / "runtime-policy.yaml").read_text())
        policy["cluster_file"] = str(cluster_file)
        policy_file = directory / "runtime-policy.yaml"
        policy_file.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        loaded = load_policy(policy_file, require_secure=False)
        return load_runtime_config(loaded, require_secure=False).cluster("alpha")


class TheClusterAddressTable(unittest.TestCase):
    """VIPs, and the source address each one connects to backends from.

    Optional, because a cluster with one address and no separate source is the
    normal deployment and should not have to describe one. Everything below is
    about the moment it stops being one address.
    """

    def test_a_cluster_without_the_section_has_one_vip_from_the_line_above(self) -> None:
        cluster = _cluster()

        self.assertEqual(cluster.default_vip, "main")
        self.assertEqual(cluster.vips["main"].address, cluster.vip)
        self.assertIsNone(cluster.vips["main"].source)

    def test_named_vips_carry_their_own_source_address(self) -> None:
        cluster = _cluster(
            vips={
                "internal": {"address": "192.0.2.20", "source": "192.0.2.25"},
                "dmz": {"address": "198.51.100.20"},
            },
            default_vip="internal",
        )

        self.assertEqual(cluster.default_vip, "internal")
        self.assertEqual(cluster.vips["internal"].source, "192.0.2.25")
        self.assertIsNone(cluster.vips["dmz"].source)

    def test_more_than_one_vip_must_say_which_is_the_default(self) -> None:
        """Otherwise the default is whichever one the file happened to list first."""

        with self.assertRaises(ConfigError) as raised:
            _cluster(
                vips={
                    "internal": {"address": "192.0.2.20"},
                    "dmz": {"address": "198.51.100.20"},
                }
            )

        self.assertIn("default_vip", str(raised.exception))

    def test_one_address_may_not_have_two_names(self) -> None:
        """Two names for one address is two frontends binding the same port.

        HAProxy validates that and then refuses to start, on the node, after a
        publish has already reported success.
        """

        with self.assertRaises(ConfigError) as raised:
            _cluster(
                vips={
                    "internal": {"address": "192.0.2.20"},
                    "same": {"address": "192.0.2.20"},
                },
                default_vip="internal",
            )

        self.assertIn("two names", str(raised.exception))

    def test_a_default_naming_no_vip_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(vips={"internal": {"address": "192.0.2.20"}}, default_vip="dmz")

        self.assertIn("dmz", str(raised.exception))

    def test_a_source_that_is_not_an_address_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(vips={"internal": {"address": "192.0.2.20", "source": "not-an-address"}})

        self.assertIn("source", str(raised.exception))


class TheResolversSection(unittest.TestCase):
    def test_a_cluster_may_name_the_resolvers_section_its_servers_use(self) -> None:
        self.assertEqual(_cluster().resolvers, "cluster-dns")

    def test_a_name_that_is_not_a_section_name_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(resolvers="not a section")

        self.assertIn("resolvers", str(raised.exception))


class NamedNetworksAndTheUnknownHostAnswer(unittest.TestCase):
    def test_networks_are_named_groups_of_cidrs(self) -> None:
        self.assertEqual(_cluster().networks["office"], ("198.51.100.0/24",))

    def test_a_group_meaning_everywhere_is_refused(self) -> None:
        """An allowlist that allows everything reads as a restriction and is none."""

        #
        # A documentation address with a zero prefix, the same spelling the
        # trusted-proxy test uses: it normalises to the whole address family
        # without putting a literal default route in the tree.
        #
        with self.assertRaises(ConfigError) as raised:
            _cluster(networks={"anywhere": ["192.0.2.0/0"]})

        self.assertIn("entire address family", str(raised.exception))

    def test_the_unknown_host_answer_is_a_status_or_a_redirect_not_both(self) -> None:
        self.assertEqual(_cluster().unknown_host.status, 404)

        with self.assertRaises(ConfigError) as raised:
            _cluster(unknown_host={"status": 404, "redirect": "https://www.example.com/"})

        self.assertIn("exactly one", str(raised.exception))

    def test_a_redirect_must_be_an_absolute_url(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(unknown_host={"redirect": "/elsewhere"})

        self.assertIn("absolute", str(raised.exception))
