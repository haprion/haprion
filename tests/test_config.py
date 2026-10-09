from __future__ import annotations

import io
import tempfile
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from haproxy_mgmt.cli.cluster_config import main as cluster_config_main
from haproxy_mgmt.config import (
    AbuseProtection,
    Cluster,
    ConfigError,
    PathPolicy,
    Receiver,
    RegisteredCertificate,
    RuntimeConfig,
    load_network,
    load_policy,
    load_runtime_config,
    receiver_id_names_a_host,
)

BASE = Path(__file__).resolve().parents[1]

# Changes a parsed YAML document in place before it is written back out.
Mutate = Callable[[dict[str, Any]], None]


class ConfigTests(unittest.TestCase):
    def test_generic_examples_load(self) -> None:
        policy = load_policy(BASE / "examples" / "runtime-policy.yaml", require_secure=False)
        policy = replace(policy, cluster_file=BASE / "examples" / "clusters.yaml")
        runtime = load_runtime_config(policy, require_secure=False)
        cluster = runtime.cluster("alpha")
        self.assertEqual(cluster.vip, "192.0.2.20")
        self.assertEqual([node.name for node in cluster.nodes], ["node-a", "node-b"])
        self.assertEqual(cluster.certificate_ids, ("example.com", "example.net"))
        self.assertEqual(cluster.trusted_proxy_cidrs, ("198.51.100.0/24",))
        self.assertFalse(cluster.traffic_logging)

    def test_traffic_logging_is_an_explicit_cluster_boolean(self) -> None:
        def enabled(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["traffic_logging"] = True

        with self.temporary_runtime(enabled) as runtime:
            self.assertTrue(runtime.cluster("alpha").traffic_logging)

        def invalid(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["traffic_logging"] = "yes"

        with (
            self.assertRaisesRegex(ConfigError, "must be true or false"),
            self.temporary_runtime(invalid),
        ):
            pass

    def write_config(self, directory: Path, mutate: Mutate | None = None) -> Path:
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
    def temporary_runtime(self, mutate: Mutate | None = None) -> Iterator[RuntimeConfig]:
        with tempfile.TemporaryDirectory() as raw:
            policy_file = self.write_config(Path(raw), mutate)
            policy = load_policy(policy_file, require_secure=False)
            yield load_runtime_config(policy, require_secure=False)

    def test_unknown_field_is_rejected(self) -> None:
        def mutate(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["unexpected"] = True

        with self.assertRaisesRegex(ConfigError, "unknown field"), self.temporary_runtime(mutate):
            pass

    def test_boolean_schema_version_is_rejected(self) -> None:
        def mutate(data: dict[str, Any]) -> None:
            data["schema_version"] = True

        with self.assertRaisesRegex(ConfigError, "schema_version"), self.temporary_runtime(mutate):
            pass

    def test_path_escape_is_rejected(self) -> None:
        def mutate(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["config_path"] = "/var/tmp/outside"

        with (
            self.assertRaisesRegex(ConfigError, "escapes its allowed root"),
            self.temporary_runtime(mutate),
        ):
            pass

    def test_duplicate_nodes_are_rejected(self) -> None:
        def mutate(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["nodes"][1] = data["clusters"]["alpha"]["nodes"][0]

        with self.assertRaisesRegex(ConfigError, "unique names"), self.temporary_runtime(mutate):
            pass

    def test_a_cluster_has_between_two_and_eight_nodes(self) -> None:
        def nodes(count: int) -> Mutate:
            def mutate(data: dict[str, Any]) -> None:
                data["clusters"]["alpha"]["nodes"] = [
                    {"name": f"node-{index}", "mgmt_host": f"node-{index}.example.com"}
                    for index in range(count)
                ]

            return mutate

        for count in (2, 3, 8):
            with self.subTest(count=count), self.temporary_runtime(nodes(count)) as runtime:
                self.assertEqual(len(runtime.cluster("alpha").nodes), count)
        for count in (0, 1, 9):
            with (
                self.subTest(count=count),
                self.assertRaisesRegex(ConfigError, "between 2 and 8 nodes"),
                self.temporary_runtime(nodes(count)),
            ):
                pass

    def test_a_third_node_may_not_share_a_host_with_the_first(self) -> None:
        def mutate(data: dict[str, Any]) -> None:
            first = data["clusters"]["alpha"]["nodes"][0]
            data["clusters"]["alpha"]["nodes"].append(
                {"name": "node-c", "mgmt_host": first["mgmt_host"]}
            )

        with self.assertRaisesRegex(ConfigError, "unique names"), self.temporary_runtime(mutate):
            pass

    def test_trust_all_network_is_rejected(self) -> None:
        def mutate(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["trusted_proxy_cidrs"] = ["192.0.2.0/0"]

        with (
            self.assertRaisesRegex(ConfigError, "entire address family"),
            self.temporary_runtime(mutate),
        ):
            pass

    def test_symlinked_policy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            real = root / "real.yaml"
            real.write_text("schema_version: 1\n", encoding="utf-8")
            link = root / "policy.yaml"
            link.symlink_to(real)
            with self.assertRaisesRegex(ConfigError, "non-symlink"):
                load_policy(link, require_secure=False)

    def test_cluster_lookup_and_cli_output(self) -> None:
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
                self.policy(Path(raw), {"key": "/root/.ssh/id_ed25519_example"}),
                require_secure=False,
            )

        assert policy.deploy_identity is not None
        self.assertEqual(policy.deploy_identity.user, "_haprion-trigger")
        self.assertEqual(policy.deploy_identity.key, Path("/root/.ssh/id_ed25519_example"))

    def test_a_named_account_is_refused(self) -> None:
        # B266: the account is fixed per identity; a policy naming one is from
        # an installation that has not been migrated.
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(ConfigError):
            load_policy(
                self.policy(Path(raw), {"user": "_haprion-trigger", "key": "/root/.ssh/id"}),
                require_secure=False,
            )

    def test_a_relative_key_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(ConfigError):
            load_policy(
                self.policy(Path(raw), {"key": ".ssh/id"}),
                require_secure=False,
            )

    def test_backup_identity_is_separate_and_optional(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            body = yaml.safe_load(self.policy(root, None).read_text(encoding="utf-8"))
            body["backup_identity"] = {
                "key": "/root/.ssh/id_ed25519_node_backup",
            }
            path = root / "runtime-policy.yaml"
            path.write_text(yaml.safe_dump(body), encoding="utf-8")
            policy = load_policy(path, require_secure=False)

        assert policy.backup_identity is not None
        self.assertEqual(policy.backup_identity.user, "_haprion-backup")
        self.assertEqual(policy.backup_identity.key, Path("/root/.ssh/id_ed25519_node_backup"))

    def test_the_accounts_are_fixed_and_no_longer_policy_fields(self) -> None:
        # B266: the worker and the two pull accounts are the installation's own,
        # with fixed names; a policy still naming one is refused, not obeyed.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy = load_policy(self.policy(root, None), require_secure=False)
            self.assertEqual(policy.interface_account, "_haprion-worker")
            self.assertEqual(policy.pull_account, "_haprion-pull")
            self.assertEqual(policy.cert_pull_account, "_haprion-cert-pull")
            for field in ("interface_account", "pull_account", "cert_pull_account"):
                with self.subTest(field=field):
                    body = yaml.safe_load(self.policy(root, None).read_text(encoding="utf-8"))
                    body[field] = "svc-app"
                    path = root / "runtime-policy.yaml"
                    path.write_text(yaml.safe_dump(body), encoding="utf-8")
                    with self.assertRaises(ConfigError):
                        load_policy(path, require_secure=False)

    def test_an_unknown_field_in_the_identity_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(ConfigError):
            load_policy(
                self.policy(Path(raw), {"key": "/root/id", "port": 22}),
                require_secure=False,
            )


_UNSET = object()


def _cluster(
    vips: object = _UNSET,
    default_vip: object = _UNSET,
    resolvers: object = _UNSET,
    networks: object = _UNSET,
    sources: object = _UNSET,
    unknown_host: object = _UNSET,
    abuse_protection: object = _UNSET,
) -> Cluster:
    """One cluster from the shipped example, with its address table replaced.

    Defaults to removing the section entirely, which is the deployment that
    exists today: one virtual address, named for it, no separate source.
    """

    clusters = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
    alpha = clusters["clusters"]["alpha"]
    alpha.pop("vips", None)
    alpha.pop("default_vip", None)
    #
    # Removed like the address table: the section is optional, and a test about
    # what a cluster without one does has to start from a cluster without one.
    #
    alpha.pop("abuse_protection", None)
    if vips is not _UNSET:
        alpha["vips"] = vips
    if default_vip is not _UNSET:
        alpha["default_vip"] = default_vip
    if resolvers is not _UNSET:
        alpha["resolvers"] = resolvers
    if networks is not _UNSET:
        alpha["networks"] = networks
    if sources is not _UNSET:
        alpha["sources"] = sources
    if unknown_host is not _UNSET:
        alpha["unknown_host"] = unknown_host
    if abuse_protection is not _UNSET:
        alpha["abuse_protection"] = abuse_protection

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
        unknown_host = _cluster().unknown_host
        assert unknown_host is not None
        self.assertEqual(unknown_host.status, 404)

        with self.assertRaises(ConfigError) as raised:
            _cluster(unknown_host={"status": 404, "redirect": "https://www.example.com/"})

        self.assertIn("exactly one", str(raised.exception))

    def test_a_redirect_must_be_an_absolute_url(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(unknown_host={"redirect": "/elsewhere"})

        self.assertIn("absolute", str(raised.exception))


class NamedSourceAddresses(unittest.TestCase):
    def test_a_cluster_may_name_sources_beyond_the_ones_its_vips_pair_with(self) -> None:
        self.assertEqual(_cluster().sources["outbound"], "192.0.2.35")

    def test_a_source_that_is_not_an_address_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(sources={"outbound": "not-an-address"})

        self.assertIn("sources.outbound", str(raised.exception))


class TheNetworkDescriptionInTheRepository(unittest.TestCase):
    """`managed/network.yaml`, and what changes once a cluster has one.

    The tables moved so that they could be edited in the interface without the
    web identities gaining any say over the engine's own configuration. What
    the move must not change is how strictly they are read: this file is
    written by the application rather than by root, which makes it less trusted
    than `clusters.yaml`, not more.
    """

    @contextmanager
    def repository(self, description: object) -> Iterator[Path]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "managed").mkdir()
            if description is not None:
                (root / "managed" / "network.yaml").write_text(
                    yaml.safe_dump(description, sort_keys=False), encoding="utf-8"
                )
            yield root

    def test_a_repository_without_the_file_answers_nothing_rather_than_failing(self) -> None:
        with self.repository(None) as root:
            self.assertIsNone(load_network(root, vip="192.0.2.20"))

    def test_a_cluster_falls_back_to_its_own_tables_while_the_file_is_absent(self) -> None:
        cluster = _cluster(vips={"internal": {"address": "192.0.2.20"}})

        network = cluster.network()

        self.assertEqual(network.default_vip, "internal")
        self.assertEqual(network.vips["internal"].address, "192.0.2.20")

    def test_the_file_decides_once_it_exists(self) -> None:
        with self.repository(
            {
                "vips": {"dmz": {"address": "198.51.100.20", "source": "198.51.100.25"}},
                "sources": {"outbound": "192.0.2.35"},
                "networks": {"office": ["198.51.100.0/24"]},
            }
        ) as root:
            network = load_network(root, vip="192.0.2.20")

        assert network is not None
        self.assertEqual(network.default_vip, "dmz")
        self.assertEqual(network.vips["dmz"].source, "198.51.100.25")
        self.assertEqual(network.sources["outbound"], "192.0.2.35")
        self.assertEqual(network.networks["office"], ("198.51.100.0/24",))

    def test_a_description_that_names_no_vip_means_the_one_the_cluster_already_had(self) -> None:
        with self.repository({"networks": {"office": ["198.51.100.0/24"]}}) as root:
            network = load_network(root, vip="192.0.2.20")

        assert network is not None
        self.assertEqual(network.vips["main"].address, "192.0.2.20")

    def test_the_repository_may_not_name_the_address_deploy_checks_ownership_against(self) -> None:
        #
        # The whole reason `vip` stayed behind. A file the interface can write
        # must not be able to move the check that decides which node deploy
        # believes is carrying traffic.
        #
        with self.repository({"vip": "203.0.113.20"}) as root, self.assertRaises(ConfigError):
            load_network(root, vip="192.0.2.20")

    def test_a_default_that_names_no_vip_in_the_file_is_refused(self) -> None:
        with (
            self.repository(
                {"vips": {"dmz": {"address": "198.51.100.20"}}, "default_vip": "internal"}
            ) as root,
            self.assertRaises(ConfigError),
        ):
            load_network(root, vip="192.0.2.20")

    def test_a_group_writable_file_is_read_where_clusters_yaml_would_be_refused(self) -> None:
        #
        # The one deliberate difference. `clusters.yaml` must be root-owned
        # because it decides what the engine may do; this file is owned by the
        # application and group-writable by design.
        #
        with self.repository({"sources": {"outbound": "192.0.2.35"}}) as root:
            (root / "managed" / "network.yaml").chmod(0o664)
            network = load_network(root, vip="192.0.2.20")

        assert network is not None
        self.assertEqual(network.sources["outbound"], "192.0.2.35")

    def test_a_symlink_is_refused_wherever_it_points(self) -> None:
        with self.repository({"sources": {"outbound": "192.0.2.35"}}) as root:
            target = root / "managed" / "network.yaml"
            elsewhere = root / "elsewhere.yaml"
            target.rename(elsewhere)
            target.symlink_to(elsewhere)
            with self.assertRaises(ConfigError):
                load_network(root, vip="192.0.2.20")


class AVipMayNameATlsPolicy(unittest.TestCase):
    """Named rather than written out: a cipher string is raw OpenSSL syntax."""

    def test_a_named_policy_is_carried(self) -> None:
        cluster = _cluster(vips={"internal": {"address": "192.0.2.20", "tls": "modern"}})

        self.assertEqual(cluster.vips["internal"].tls_policy, "modern")

    def test_absent_means_core_keeps_deciding(self) -> None:
        """Which is what every cluster does today, and the reason there is no default."""

        cluster = _cluster(vips={"internal": {"address": "192.0.2.20"}})

        self.assertIsNone(cluster.vips["internal"].tls_policy)

    def test_a_policy_nobody_defined_is_refused_with_the_ones_that_exist(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            _cluster(vips={"internal": {"address": "192.0.2.20", "tls": "paranoid"}})

        self.assertIn("intermediate", str(raised.exception))
        self.assertIn("modern", str(raised.exception))


class TheBrakeOnAbusiveTraffic(unittest.TestCase):
    """A brake and not a ban list, because a reload empties the counters."""

    def protection(self, section: object) -> AbuseProtection | None:
        return _cluster(abuse_protection=section).abuse_protection

    def test_absent_means_nothing_is_generated(self) -> None:
        self.assertIsNone(_cluster().abuse_protection)

    def test_the_window_has_a_default_and_the_thresholds_do_not(self) -> None:
        protection = self.protection({"max_requests": 100})

        assert protection is not None
        self.assertEqual(protection.window, "10s")
        self.assertEqual(protection.max_requests, 100)
        self.assertIsNone(protection.max_errors)

    def test_a_flood_and_a_scanner_are_counted_separately(self) -> None:
        """Many ordinary requests and few requests that are nearly all errors."""

        protection = self.protection({"max_requests": 100, "max_errors": 20})

        assert protection is not None
        self.assertEqual((protection.max_requests, protection.max_errors), (100, 20))

    def test_a_section_with_no_threshold_is_refused(self) -> None:
        """It would count every visitor and refuse nobody."""

        with self.assertRaises(ConfigError) as raised:
            self.protection({"window": "10s"})

        self.assertIn("max_requests", str(raised.exception))

    def test_a_window_that_is_not_a_duration_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.protection({"window": "soon", "max_requests": 10})

        self.assertIn("duration", str(raised.exception))


class RegistryTestCase(unittest.TestCase):
    """A runtime loaded from the example registry, changed by the test first."""

    def setup(
        self,
        root: Path,
        mutate_registry: Mutate | None = None,
        mutate_clusters: Mutate | None = None,
    ) -> Path:
        registry = yaml.safe_load((BASE / "examples" / "certificates.yaml").read_text())
        if mutate_registry is not None:
            mutate_registry(registry)
        registry_file = root / "certificates.yaml"
        registry_file.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")

        clusters = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
        del clusters["clusters"]["alpha"]["certificate_ids"]
        if mutate_clusters is not None:
            mutate_clusters(clusters)
        cluster_file = root / "clusters.yaml"
        cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False), encoding="utf-8")

        policy = yaml.safe_load((BASE / "examples" / "runtime-policy.yaml").read_text())
        policy["cluster_file"] = str(cluster_file)
        policy["certificate_registry"] = str(registry_file)
        policy_file = root / "runtime-policy.yaml"
        policy_file.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
        return policy_file

    def load(
        self, mutate_registry: Mutate | None = None, mutate_clusters: Mutate | None = None
    ) -> RuntimeConfig:
        with tempfile.TemporaryDirectory() as raw:
            policy_file = self.setup(Path(raw), mutate_registry, mutate_clusters)
            policy = load_policy(policy_file, require_secure=False)
            return load_runtime_config(policy, require_secure=False)


class TheCertificateRegistry(RegistryTestCase):
    """B135: one root-owned file says where every certificate comes from and goes.

    Declared in the runtime policy, and once declared it replaces the
    per-cluster allowlist rather than sitting beside it.
    """

    def test_the_example_registry_loads_and_derives_the_cluster_list(self) -> None:
        runtime = self.load()
        assert runtime.registry is not None
        self.assertEqual(runtime.cluster("alpha").certificate_ids, ("example.com", "example.net"))
        self.assertEqual(sorted(runtime.registry.receivers), ["lb-01.example.net"])
        entry = runtime.registry.certificates["lb-01.example.net"]
        self.assertEqual(entry.source.kind, "import")
        self.assertIsNone(entry.source.lineage)
        self.assertEqual(entry.clusters, ())
        self.assertEqual(entry.receivers, ("lb-01.example.net",))

    def test_an_acme_lineage_defaults_to_the_certificate_id(self) -> None:
        registry = self.load().registry
        assert registry is not None
        self.assertEqual(registry.certificates["example.net"].source.lineage, "example.net")
        self.assertEqual(
            registry.certificates["example.com"].source.lineage, "example.com-wildcard"
        )

    def test_an_acme_source_may_name_the_dns_profile_that_renews_it(self) -> None:
        def add_profile(data: dict[str, Any]) -> None:
            data["certificates"]["example.net"]["source"]["dns_profile"] = "cf-main"

        registry = self.load(mutate_registry=add_profile).registry
        assert registry is not None
        self.assertEqual(registry.certificates["example.net"].source.dns_profile, "cf-main")

        def put_profile_on_import(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["source"]["dns_profile"] = "cf-main"

        with self.assertRaisesRegex(ConfigError, "belongs to an acme source only"):
            self.load(mutate_registry=put_profile_on_import)

    def test_the_acme_block_is_read_and_held_to_its_three_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_file = self.setup(Path(raw), None, None)
            document = yaml.safe_load(policy_file.read_text())
            document["acme"] = {"dns_cloudflare_credentials": "/etc/example/cloudflare.ini"}
            policy_file.write_text(yaml.safe_dump(document))
            policy = load_policy(policy_file, require_secure=False)
            assert policy.acme is not None
            self.assertEqual(
                policy.acme.dns_cloudflare_credentials, Path("/etc/example/cloudflare.ini")
            )
            self.assertIsNone(policy.acme.webroot)
            self.assertIsNone(policy.acme.certbot)

            document["acme"]["certbot"] = "/opt/example-certbot/venv/bin/certbot"
            policy_file.write_text(yaml.safe_dump(document))
            policy = load_policy(policy_file, require_secure=False)
            assert policy.acme is not None
            self.assertEqual(policy.acme.certbot, Path("/opt/example-certbot/venv/bin/certbot"))

            document["acme"]["email"] = "admin@example.com"
            policy_file.write_text(yaml.safe_dump(document))
            with self.assertRaises(ConfigError):
                load_policy(policy_file, require_secure=False)

            document["acme"] = {"webroot": "relative/path"}
            policy_file.write_text(yaml.safe_dump(document))
            with self.assertRaises(ConfigError):
                load_policy(policy_file, require_secure=False)

    def test_an_import_source_may_name_the_ndes_profile_that_enrolled_it(self) -> None:
        def add_profile(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["source"]["ndes_profile"] = "certserver1"

        registry = self.load(mutate_registry=add_profile).registry
        assert registry is not None
        self.assertEqual(registry.certificates["lb-01.example.net"].source.ndes_profile, "certserver1")
        self.assertIsNone(registry.certificates["example.net"].source.ndes_profile)

        def put_profile_on_acme(data: dict[str, Any]) -> None:
            data["certificates"]["example.net"]["source"]["ndes_profile"] = "certserver1"

        with self.assertRaisesRegex(ConfigError, "belongs to an import source only"):
            self.load(mutate_registry=put_profile_on_acme)

        def bad_id(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["source"]["ndes_profile"] = "Not Valid"

        with self.assertRaisesRegex(ConfigError, "not a profile ID"):
            self.load(mutate_registry=bad_id)

    def test_the_dns_profiles_block_names_a_directory_and_its_private_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            policy_file = self.setup(Path(raw), None, None)
            document = yaml.safe_load(policy_file.read_text())
            document["acme"] = {
                "dns_profiles": {
                    "directory": "/etc/example/dns-profiles",
                    "private_keys": ["/srv/example/secrets/dns-profile-keys/0123.key"],
                }
            }
            policy_file.write_text(yaml.safe_dump(document))
            policy = load_policy(policy_file, require_secure=False)
            assert policy.acme is not None and policy.acme.dns_profiles is not None
            self.assertEqual(policy.acme.dns_profiles.directory, Path("/etc/example/dns-profiles"))
            self.assertEqual(
                policy.acme.dns_profiles.private_keys,
                (Path("/srv/example/secrets/dns-profile-keys/0123.key"),),
            )
            self.assertIsNone(policy.acme.dns_cloudflare_credentials)

            bad_blocks: list[dict[str, object]] = [
                {"directory": "/etc/example/dns-profiles"},
                {"directory": "/etc/example/dns-profiles", "private_keys": []},
                {"directory": "/etc/example/dns-profiles", "private_keys": ["relative.key"]},
                {"directory": "relative", "private_keys": ["/srv/example/a.key"]},
                {
                    "directory": "/etc/example/dns-profiles",
                    "private_keys": ["/srv/example/a.key", "/srv/example/a.key"],
                },
                {
                    "directory": "/etc/example/dns-profiles",
                    "private_keys": ["/srv/example/a.key"],
                    "public_key": "/srv/example/a.pub",
                },
            ]
            for block in bad_blocks:
                with self.subTest(block=block):
                    document["acme"] = {"dns_profiles": block}
                    policy_file.write_text(yaml.safe_dump(document))
                    with self.assertRaises(ConfigError):
                        load_policy(policy_file, require_secure=False)

    def test_the_allowlist_in_clusters_yaml_is_refused_once_the_registry_exists(self) -> None:
        """One answer, not two that can drift apart."""

        def keep_the_list(data: dict[str, Any]) -> None:
            data["clusters"]["alpha"]["certificate_ids"] = ["example.com"]

        with self.assertRaisesRegex(ConfigError, "has moved to the certificate registry"):
            self.load(mutate_clusters=keep_the_list)

    def test_a_cluster_no_certificate_names_is_refused(self) -> None:
        def nobody_names_alpha(data: dict[str, Any]) -> None:
            for entry in data["certificates"].values():
                entry.pop("clusters", None)

        with self.assertRaisesRegex(ConfigError, "no certificate in the registry names cluster"):
            self.load(mutate_registry=nobody_names_alpha)

    def test_the_default_certificate_must_still_be_one_the_cluster_carries(self) -> None:
        def only_net(data: dict[str, Any]) -> None:
            data["certificates"]["example.com"]["clusters"] = []

        with self.assertRaisesRegex(ConfigError, "default_certificate is not allowlisted"):
            self.load(mutate_registry=only_net)

    def test_a_certificate_naming_an_unknown_cluster_is_refused(self) -> None:
        def typo(data: dict[str, Any]) -> None:
            data["certificates"]["example.net"]["clusters"] = ["alpha", "alhpa"]

        with self.assertRaisesRegex(ConfigError, "names unknown cluster\\(s\\): alhpa"):
            self.load(mutate_registry=typo)

    def test_a_certificate_naming_an_unregistered_receiver_is_refused(self) -> None:
        def typo(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["receivers"] = ["lb-02.example.net"]

        with self.assertRaisesRegex(ConfigError, "unregistered receiver"):
            self.load(mutate_registry=typo)

    def test_a_lineage_on_an_imported_certificate_is_refused(self) -> None:
        def contradiction(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["source"]["lineage"] = "x"

        with self.assertRaisesRegex(ConfigError, "belongs to an acme source only"):
            self.load(mutate_registry=contradiction)

    def test_a_receiver_path_must_be_absolute_and_its_owner_an_account(self) -> None:
        def relative(data: dict[str, Any]) -> None:
            data["receivers"]["lb-01.example.net"]["path"] = "receivers/lb-01"

        with self.assertRaisesRegex(ConfigError, "must be absolute"):
            self.load(mutate_registry=relative)

        def bad_owner(data: dict[str, Any]) -> None:
            data["receivers"]["lb-01.example.net"]["owner"] = "Not An Account"

        with self.assertRaisesRegex(ConfigError, "not a valid account name"):
            self.load(mutate_registry=bad_owner)

    def test_unknown_fields_are_refused_everywhere(self) -> None:
        for where in (
            lambda d: d.__setitem__("extra", 1),
            lambda d: d["receivers"]["lb-01.example.net"].__setitem__("extra", 1),
            lambda d: d["certificates"]["example.net"].__setitem__("extra", 1),
            lambda d: d["certificates"]["example.net"]["source"].__setitem__("extra", 1),
        ):
            with self.assertRaisesRegex(ConfigError, "unknown field"):
                self.load(mutate_registry=where)

    def test_the_interface_certificate_is_read_and_holds_no_target(self) -> None:
        def mark(data: dict[str, Any]) -> None:
            data["certificates"]["ui.example.net"] = {
                "source": {"kind": "import"},
                "interface": True,
            }

        registry = self.load(mutate_registry=mark).registry
        assert registry is not None
        self.assertTrue(registry.certificates["ui.example.net"].interface)
        self.assertFalse(registry.certificates["example.net"].interface)

        def with_cluster(data: dict[str, Any]) -> None:
            data["certificates"]["ui.example.net"] = {
                "source": {"kind": "import"},
                "interface": True,
                "clusters": ["alpha"],
            }

        with self.assertRaisesRegex(ConfigError, "cannot name clusters or receivers"):
            self.load(mutate_registry=with_cluster)

        def with_receiver(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["interface"] = True

        with self.assertRaisesRegex(ConfigError, "cannot name clusters or receivers"):
            self.load(mutate_registry=with_receiver)

    def test_only_one_certificate_is_the_interface_s(self) -> None:
        def two(data: dict[str, Any]) -> None:
            for name in ("ui-a.example.net", "ui-b.example.net"):
                data["certificates"][name] = {"source": {"kind": "import"}, "interface": True}

        with self.assertRaisesRegex(ConfigError, "ui-a.example.net is already the interface"):
            self.load(mutate_registry=two)

    def test_the_interface_flag_is_a_boolean(self) -> None:
        def text(data: dict[str, Any]) -> None:
            data["certificates"]["ui.example.net"] = {
                "source": {"kind": "import"},
                "interface": "yes",
            }

        with self.assertRaisesRegex(ConfigError, "interface must be true or false"):
            self.load(mutate_registry=text)

    def test_without_a_registry_the_allowlist_is_read_as_before(self) -> None:
        policy = load_policy(BASE / "examples" / "runtime-policy.yaml", require_secure=False)
        self.assertIsNone(policy.certificate_registry)
        policy = replace(policy, cluster_file=BASE / "examples" / "clusters.yaml")
        runtime = load_runtime_config(policy, require_secure=False)
        self.assertIsNone(runtime.registry)
        self.assertEqual(runtime.cluster("alpha").certificate_ids, ("example.com", "example.net"))


class AReceiverSaysHowItFetches(RegistryTestCase):
    """C7 step 1: transport, layout and format, with defaults that keep today's file.

    The three receivers registered before C7 state neither transport nor
    layout, and the sentence the defaults have to make true is that their
    entries mean exactly what they meant yesterday - `rsync` and `flat`. The
    test that matters most here is therefore the one that reads the shipped
    example unchanged; the rest hold the new fields to their own rules.
    """

    def receiver(self, **fields: object) -> Receiver:
        def mutate(data: dict[str, Any]) -> None:
            data["receivers"]["lb-01.example.net"].update(fields)

        registry = self.load(mutate_registry=mutate).registry
        assert registry is not None
        return registry.receivers["lb-01.example.net"]

    def test_an_entry_without_the_new_fields_is_rsync_and_flat(self) -> None:
        registry = self.load().registry
        assert registry is not None
        receiver = registry.receivers["lb-01.example.net"]
        self.assertEqual(
            (receiver.transport, receiver.layout, receiver.allow), ("rsync", "flat", ())
        )
        entry = registry.certificates["lb-01.example.net"]
        self.assertEqual(entry.format_for("lb-01.example.net"), "pem")

    def test_transport_and_layout_are_kept_when_stated(self) -> None:
        receiver = self.receiver(transport="sftp", layout="per-certificate")
        self.assertEqual((receiver.transport, receiver.layout), ("sftp", "per-certificate"))

    def test_a_transport_or_layout_outside_the_set_is_refused(self) -> None:
        with self.assertRaisesRegex(ConfigError, "transport must be one of"):
            self.receiver(transport="scp")
        with self.assertRaisesRegex(ConfigError, "layout must be one of"):
            self.receiver(layout="one-big-file")

    def test_an_https_receiver_carries_a_whitelist_and_no_other_one_may(self) -> None:
        receiver = self.receiver(
            transport="https", owner="www-data", allow=["192.0.2.10", "198.51.100.0/24"]
        )
        self.assertEqual(receiver.allow, ("192.0.2.10", "198.51.100.0/24"))

        with self.assertRaisesRegex(ConfigError, "non-empty list for an https receiver"):
            self.receiver(transport="https", allow=[])
        with self.assertRaisesRegex(ConfigError, "non-empty list for an https receiver"):
            self.receiver(transport="https")
        with self.assertRaisesRegex(ConfigError, "belongs to an https receiver only"):
            self.receiver(allow=["192.0.2.10"])

    def test_a_whitelist_entry_must_be_an_address_or_a_network(self) -> None:
        for bad in ("lb-01.example.net", "192.0.2.1/24", "192.0.2.300"):
            with self.assertRaisesRegex(ConfigError, "not an address or network"):
                self.receiver(transport="https", allow=[bad])
        with self.assertRaisesRegex(ConfigError, "allow contains duplicates"):
            self.receiver(transport="https", allow=["192.0.2.10", "192.0.2.10"])


class ACertificateMaySayWhichFormAReceiverGets(RegistryTestCase):
    """B159: `{id, format}` beside the bare ID, which keeps meaning `pem`."""

    def certificate(self, receivers: object) -> RegisteredCertificate:
        def mutate(data: dict[str, Any]) -> None:
            data["certificates"]["lb-01.example.net"]["receivers"] = receivers

        registry = self.load(mutate_registry=mutate).registry
        assert registry is not None
        return registry.certificates["lb-01.example.net"]

    def test_a_mapping_element_names_the_format(self) -> None:
        entry = self.certificate([{"id": "lb-01.example.net", "format": "pkcs12"}])
        self.assertEqual(entry.receivers, ("lb-01.example.net",))
        self.assertEqual(entry.format_for("lb-01.example.net"), "pkcs12")

    def test_a_mapping_without_a_format_is_pem(self) -> None:
        entry = self.certificate([{"id": "lb-01.example.net"}])
        self.assertEqual(entry.format_for("lb-01.example.net"), "pem")

    def test_an_unknown_format_or_field_is_refused(self) -> None:
        with self.assertRaisesRegex(ConfigError, "format must be one of"):
            self.certificate([{"id": "lb-01.example.net", "format": "jks"}])
        with self.assertRaisesRegex(ConfigError, "unknown field"):
            self.certificate([{"id": "lb-01.example.net", "sftp": True}])

    def test_an_element_that_is_neither_an_id_nor_a_mapping_is_refused(self) -> None:
        with self.assertRaisesRegex(ConfigError, "must be a receiver ID or an"):
            self.certificate([["lb-01.example.net"]])

    def test_the_same_receiver_twice_is_refused_in_either_form(self) -> None:
        with self.assertRaisesRegex(ConfigError, "contains duplicates"):
            self.certificate(["lb-01.example.net", {"id": "lb-01.example.net", "format": "pkcs12"}])

    def test_a_mapping_element_is_still_held_to_the_registered_receivers(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unregistered receiver"):
            self.certificate([{"id": "lb-02.example.net", "format": "pkcs12"}])


class AReceiverIdNamesAHost(unittest.TestCase):
    """B141: the ID is what `from=` and `allow` bind to, so it is a host."""

    def test_a_dns_name_or_an_ip_address_is_a_host(self) -> None:
        for value in ("lb-01.example.net", "192.0.2.10", "2001:db8::1"):
            self.assertTrue(receiver_id_names_a_host(value), value)

    def test_anything_else_is_not(self) -> None:
        for value in ("lb-01", "pve-cluster", "192.0.2.0/24", "lb-01.example.net."):
            self.assertFalse(receiver_id_names_a_host(value), value)


class TheReceiverRoot(unittest.TestCase):
    """Where `haprion-cert-receiver` will create directories (C7, §9 choice 2)."""

    def policy(self, value: object = None) -> PathPolicy:
        with tempfile.TemporaryDirectory() as raw:
            data = yaml.safe_load((BASE / "examples" / "runtime-policy.yaml").read_text())
            if value is not None:
                data["receiver_root"] = value
            path = Path(raw) / "runtime-policy.yaml"
            path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
            return load_policy(path, require_secure=False)

    def test_it_is_optional_and_absent_in_the_example(self) -> None:
        self.assertIsNone(self.policy().receiver_root)

    def test_it_is_an_absolute_path_when_stated(self) -> None:
        self.assertEqual(
            self.policy("/srv/certdist/receivers").receiver_root, Path("/srv/certdist/receivers")
        )
        with self.assertRaisesRegex(ConfigError, "must be absolute"):
            self.policy("srv/certdist/receivers")
