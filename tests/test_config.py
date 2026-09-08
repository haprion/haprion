from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path

import yaml

from haproxy_mgmt.cli.cluster_config import main as cluster_config_main
from haproxy_mgmt.config import ConfigError, load_network, load_policy, load_runtime_config

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
        self.assertFalse(cluster.traffic_logging)

    def test_traffic_logging_is_an_explicit_cluster_boolean(self):
        def enabled(data):
            data["clusters"]["alpha"]["traffic_logging"] = True

        with self.temporary_runtime(enabled) as runtime:
            self.assertTrue(runtime.cluster("alpha").traffic_logging)

        def invalid(data):
            data["clusters"]["alpha"]["traffic_logging"] = "yes"

        with (
            self.assertRaisesRegex(ConfigError, "must be true or false"),
            self.temporary_runtime(invalid),
        ):
            pass

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
    sources: object = _UNSET,
    unknown_host: object = _UNSET,
    abuse_protection: object = _UNSET,
):
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
        self.assertEqual(_cluster().unknown_host.status, 404)

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
    def repository(self, description: object):
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

    def protection(self, section: object):
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
