"""A network edit rebuilds the whole managed layer from committed input."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from haproxy_mgmt import crs, geo
from haproxy_mgmt.config import Cluster, ConfigError, Node, UnknownHost
from haproxy_mgmt.managed_publish import managed_files
from haproxy_mgmt.object_manifest import REPOSITORY_PATH as MANIFEST_PATH
from haproxy_mgmt.object_manifest import parse as parse_manifest
from haproxy_mgmt.release_layout import LayoutError, build_node_artifact, build_release_index


def cluster() -> Cluster:
    return Cluster(
        cluster_id="alpha",
        display_name="Alpha",
        vip="192.0.2.20",
        address_prefix=None,
        address_interface=None,
        vips={},
        default_vip="main",
        resolvers=None,
        sources={},
        networks={},
        unknown_host=UnknownHost(status=404),
        abuse_protection=None,
        config_path=Path("/config"),
        publish_path=Path("/published"),
        node_path="node",
        validation_certs=Path("/certs"),
        default_certificate="example.com",
        certificate_ids=(),
        trusted_proxy_cidrs=(),
        nodes=(Node(name="node-a", mgmt_host="node-a.example.com"),),
    )


NETWORK = b"""vips:\n  main:\n    address: 192.0.2.20\n    source: 192.0.2.25\ndefault_vip: main\nnetworks:\n  office:\n  - 198.51.100.0/24\n"""
PROXY = b"""schema: 1\nname: shop\nhostnames: [shop.example.com]\nlisten:\n  protocol: http\nroutes:\n- path: /\n  backend: web\nbackends:\n  web:\n    balance: roundrobin\n    health:\n      type: disabled\n    servers:\n    - host: 198.51.100.10\n      port: 8080\n"""


class ManagedNetworkPublishTests(unittest.TestCase):
    def test_the_network_and_generated_config_are_one_snapshot(self) -> None:
        files = managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/proxies/shop.yaml": PROXY,
                "managed/generated/1001-stale.cfg": b"stale\n",
            },
            network_document=NETWORK,
            cluster=cluster(),
        )

        self.assertEqual(files["managed/network.yaml"], NETWORK)
        self.assertEqual(files["managed/proxies/shop.yaml"], PROXY)
        self.assertNotIn("managed/generated/1001-stale.cfg", files)
        self.assertIn("managed/generated/1000-frontends.cfg", files)
        self.assertIn("source 192.0.2.25", files["managed/generated/1001-shop.cfg"].decode())

    def test_the_addresses_the_nodes_must_carry_are_part_of_the_same_snapshot(self) -> None:
        #
        # One publish, one version, both halves of the change. The generated
        # HAProxy configuration binds an address and this file is what puts it
        # on an interface; published separately they can disagree, and a
        # cluster that binds an address no node carries looks correct from
        # every side except the network's.
        #
        files = managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/keepalived/addresses.conf": b"    198.51.100.99  # gone\n",
            },
            network_document=NETWORK,
            cluster=cluster(),
        )
        fragment = files["managed/keepalived/addresses.conf"].decode()

        self.assertIn("192.0.2.20", fragment)
        self.assertIn("192.0.2.25", fragment)
        # Derived, never carried over: an address removed from the document is
        # removed from the interface the nodes present.
        self.assertNotIn("198.51.100.99", fragment)

    def test_removing_a_vip_used_by_an_object_is_refused_before_commit(self) -> None:
        proxy = PROXY.replace(b"protocol: http", b"protocol: http\n  vip: retired")
        network = NETWORK.replace(b"  main:\n", b"  other:\n").replace(
            b"default_vip: main", b"default_vip: other"
        )
        with self.assertRaisesRegex(ValueError, "VIP retired"):
            managed_files(
                {"managed/proxies/shop.yaml": proxy}, network_document=network, cluster=cluster()
            )


class TheManifestIsPartOfTheVersion(unittest.TestCase):
    """Written into the tree, not derived when a release is built.

    A revert restores an earlier version's bytes. A manifest derived at install
    time would have to be regenerated from objects that version no longer has;
    carried in the commit, an old release's fingerprints are simply what that
    release said.
    """

    def snapshot(self, proxy: bytes = PROXY) -> dict[str, bytes]:
        return managed_files(
            {"managed/network.yaml": NETWORK, "managed/proxies/shop.yaml": proxy},
            network_document=NETWORK,
            cluster=cluster(),
        )

    def test_a_publish_writes_a_fingerprint_for_every_object(self) -> None:
        manifest = parse_manifest(self.snapshot()[MANIFEST_PATH].decode())
        assert manifest is not None
        self.assertEqual(sorted(manifest.objects), ["shop"])

    def test_the_same_objects_publish_to_the_same_manifest(self) -> None:
        """Two derivations of one version must not differ in bytes."""

        self.assertEqual(self.snapshot()[MANIFEST_PATH], self.snapshot()[MANIFEST_PATH])

    def test_a_changed_object_changes_its_fingerprint(self) -> None:
        moved = PROXY.replace(b"198.51.100.10", b"198.51.100.11")
        before = parse_manifest(self.snapshot()[MANIFEST_PATH].decode())
        after = parse_manifest(self.snapshot(moved)[MANIFEST_PATH].decode())
        assert before is not None and after is not None
        self.assertNotEqual(before.objects["shop"].fingerprint, after.objects["shop"].fingerprint)

    def test_the_manifest_never_reaches_the_node(self) -> None:
        """`conf.d` is loaded with `-f`; the manager's index is not for HAProxy."""

        files = {
            **self.snapshot(),
            "core/haproxy.cfg": b"global\n",
            "manual/reservations.yaml": b"{}\n",
        }
        artifact = build_node_artifact(files)
        self.assertNotIn(MANIFEST_PATH, artifact)
        self.assertFalse([name for name in artifact if name.endswith("manifest.json")])
        self.assertEqual(build_release_index(files), {"MANIFEST.json": files[MANIFEST_PATH]})


class OneEditsObjectsReachTheSameSnapshot(unittest.TestCase):
    """A publish carries the objects somebody clicked, applied to the base."""

    def base(self) -> dict[str, bytes]:
        return {"managed/network.yaml": NETWORK, "managed/proxies/shop.yaml": PROXY}

    def test_a_changed_object_is_stored_and_generated_from(self) -> None:
        """Both halves, or the tree says one thing and the nodes serve another."""

        edited = PROXY.replace(b"port: 8080", b"port: 9090")

        files = managed_files(
            self.base(),
            network_document=NETWORK,
            cluster=cluster(),
            objects={"shop": edited},
        )

        self.assertEqual(files["managed/proxies/shop.yaml"], edited)
        self.assertIn(":9090", files["managed/generated/1001-shop.cfg"].decode())
        self.assertNotIn(":8080", files["managed/generated/1001-shop.cfg"].decode())

    def test_a_new_object_is_added_without_disturbing_the_others(self) -> None:
        added = (
            PROXY.replace(b"name: shop", b"name: admin")
            .replace(b"shop.example.com", b"admin.example.com")
            .replace(b"backend: web", b"backend: admin-web")
            .replace(b"  web:\n", b"  admin-web:\n")
        )

        files = managed_files(
            self.base(),
            network_document=NETWORK,
            cluster=cluster(),
            objects={"admin": added},
        )

        self.assertEqual(files["managed/proxies/shop.yaml"], PROXY)
        self.assertIn("managed/generated/1001-admin.cfg", files)

    def test_removing_an_object_takes_its_configuration_with_it(self) -> None:
        files = managed_files(
            self.base(),
            network_document=NETWORK,
            cluster=cluster(),
            objects={"shop": None},
        )

        self.assertNotIn("managed/proxies/shop.yaml", files)
        self.assertNotIn("managed/generated/1001-shop.cfg", files)

    def test_removing_an_object_this_version_does_not_have_is_refused(self) -> None:
        """The tree moved under the draft.

        Succeeding quietly would report that a site was taken down when
        nothing happened.
        """

        with self.assertRaises(ConfigError) as raised:
            managed_files(
                self.base(),
                network_document=NETWORK,
                cluster=cluster(),
                objects={"gone": None},
            )

        self.assertIn("gone", str(raised.exception))

    def test_a_name_that_is_not_a_name_cannot_build_a_path(self) -> None:
        """The names arrive in a job payload.

        A path assembled from an unchecked name is how a publish of a proxy
        object writes somewhere else entirely.
        """

        for name in ("../../core/haproxy", "shop/../../../etc/passwd", "Shop", ""):
            with self.subTest(name), self.assertRaises(ConfigError) as raised:
                managed_files(
                    self.base(),
                    network_document=NETWORK,
                    cluster=cluster(),
                    objects={name: PROXY},
                )

            self.assertIn("usable object name", str(raised.exception))

    def test_an_edit_that_breaks_the_cluster_is_refused_before_commit(self) -> None:
        """The whole layer is regenerated, so a collision with an untouched object shows."""

        clash = PROXY.replace(b"name: shop", b"name: admin")

        with self.assertRaises(ConfigError) as raised:
            managed_files(
                self.base(),
                network_document=NETWORK,
                cluster=cluster(),
                objects={"admin": clash},
            )

        self.assertIn("shop.example.com", str(raised.exception))


class ReservationsReachThePublishPath(unittest.TestCase):
    """The file is read from the committed base, like everything else."""

    def publish(self, reservations: bytes) -> dict[str, bytes]:
        return managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/proxies/shop.yaml": PROXY,
                "manual/reservations.yaml": reservations,
            },
            network_document=NETWORK,
            cluster=cluster(),
        )

    def test_the_empty_mapping_both_clusters_carry_publishes_as_before(self) -> None:
        self.assertIn("managed/generated/1000-frontends.cfg", self.publish(b"{}\n"))

    def test_an_object_claiming_a_reserved_hostname_is_refused_before_commit(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.publish(b"hostnames: [shop.example.com]\n")

        self.assertIn("shop.example.com", str(raised.exception))

    def test_a_missing_file_is_read_as_reserving_nothing(self) -> None:
        """Older repositories predate the format; none of them reserve anything."""

        files = managed_files(
            {"managed/network.yaml": NETWORK, "managed/proxies/shop.yaml": PROXY},
            network_document=NETWORK,
            cluster=cluster(),
        )

        self.assertIn("managed/generated/1000-frontends.cfg", files)


if __name__ == "__main__":
    unittest.main()


class CountriesReachTheNodesAsMaps(unittest.TestCase):
    """B228: a country an object names becomes `maps/geo-xx.lst` in the release."""

    def publish(self, document: bytes, reader: Any, base: dict[str, bytes] | None = None) -> Any:
        return managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/proxies/shop.yaml": document,
                **(base or {}),
            },
            network_document=NETWORK,
            cluster=cluster(),
            country_reader=reader,
        )

    def test_the_reader_is_asked_for_exactly_the_countries_named(self) -> None:
        asked: list[set[str]] = []

        def reader(countries: Any) -> geo.Countries:
            asked.append(set(countries))
            return geo.Countries("2026-10-01", {"SE": ("192.0.2.0/25",), "NO": ("192.0.2.128/25",)})

        document = PROXY.replace(
            b"routes:", b"allow_from: [country:SE, office, country:no]\nroutes:"
        )
        files = self.publish(document, reader, {"managed/maps/geo-cn.lst": b"stale\n"})

        self.assertEqual(asked, [{"SE", "NO"}])
        self.assertEqual(
            files["managed/maps/geo-se.lst"],
            b"# IPFire Location 2026-10-01 (CC BY-SA 4.0) SE\n192.0.2.0/25\n",
        )
        self.assertNotIn("managed/maps/geo-cn.lst", files)
        frontends = files["managed/generated/1000-frontends.cfg"].decode()
        self.assertIn("acl mgd-shop-allow src 198.51.100.0/24", frontends)
        self.assertIn("acl mgd-shop-allow src -f /etc/haproxy/maps/geo-se.lst", frontends)
        artifact = build_node_artifact(
            {**files, "core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"}
        )
        self.assertIn("maps/geo-no.lst", artifact)

    def test_a_cluster_without_countries_never_opens_the_database(self) -> None:
        def reader(_countries: Any) -> geo.Countries:
            raise AssertionError("asked for countries nobody named")

        files = self.publish(PROXY, reader)

        self.assertFalse([name for name in files if name.startswith("managed/maps/")])

    def test_a_country_without_a_reader_is_refused(self) -> None:
        document = PROXY.replace(b"routes:", b"allow_from: [country:SE]\nroutes:")

        with self.assertRaises(ConfigError) as raised:
            self.publish(document, None)

        self.assertIn("SE", str(raised.exception))

    def test_the_managed_map_layer_takes_country_lists_only(self) -> None:
        base = {"core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"}
        for name in ("geo-se.txt", "other.lst", "geo-swe.lst", "sub/geo-se.lst"):
            with self.subTest(name), self.assertRaises(LayoutError):
                build_node_artifact({**base, f"managed/maps/{name}": b"192.0.2.0/24\n"})


class TheWafLayerTravelsWithTheRelease(unittest.TestCase):
    """B229, B233: `managed/waf/` - configuration, SPOE file and the rule set - becomes `waf/`."""

    RULES = crs.RuleSet(
        version="9.9.9",
        files={
            "VERSION": b"9.9.9\n",
            "crs-setup.conf": b"# setup\n",
            "rules/REQUEST-901-INITIALIZATION.conf": b"# rules\n",
        },
    )

    def publish(self, document: bytes, base: dict[str, bytes] | None = None, **options: Any) -> Any:
        options.setdefault("rule_set", lambda: self.RULES)
        return managed_files(
            {
                "managed/network.yaml": NETWORK,
                "managed/proxies/shop.yaml": document,
                **(base or {}),
            },
            network_document=NETWORK,
            cluster=cluster(),
            **options,
        )

    def test_an_object_with_the_engine_brings_its_configuration_and_the_rule_set(self) -> None:
        files = self.publish(PROXY.replace(b"routes:", b"waf: {mode: block}\nroutes:"))

        for name in ("coraza.yaml", "spoe.conf", "crs/VERSION", "crs/crs-setup.conf"):
            self.assertIn(f"managed/waf/{name}", files)
        self.assertIn("managed/waf/crs/rules/REQUEST-901-INITIALIZATION.conf", files)
        self.assertIn(b"- name: shop", files["managed/waf/coraza.yaml"])
        self.assertIn("managed/generated/1000-waf.cfg", files)
        artifact = build_node_artifact(
            {**files, "core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"}
        )
        self.assertIn("waf/coraza.yaml", artifact)
        self.assertIn("waf/crs/rules/REQUEST-901-INITIALIZATION.conf", artifact)

    def test_without_the_engine_the_layer_is_gone_and_the_package_never_read(self) -> None:
        def unread() -> crs.RuleSet:
            raise AssertionError("read the rule set for a cluster that uses no engine")

        files = self.publish(PROXY, {"managed/waf/coraza.yaml": b"stale\n"}, rule_set=unread)

        self.assertFalse([name for name in files if name.startswith("managed/waf/")])
        self.assertNotIn("managed/generated/1000-waf.cfg", files)

    def test_an_engine_without_an_installed_rule_set_is_refused(self) -> None:
        with self.assertRaises(ConfigError) as raised:
            self.publish(PROXY.replace(b"routes:", b"waf: {}\nroutes:"), rule_set=lambda: None)

        self.assertIn("haproxy-manager-crs", str(raised.exception))

    def test_the_waf_layer_takes_its_shapes_only(self) -> None:
        base = {"core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"}
        for name in ("run.sh", "crs/rules/x.sh", "crs/other/x.conf", "coraza.yml"):
            with self.subTest(name), self.assertRaises(LayoutError):
                build_node_artifact({**base, f"managed/waf/{name}": b"x\n"})


RESOLVER = b"""schema: 1
name: resolver
listen: {protocol: dns, port: 53}
backend: dns
allow_from: [192.0.2.0/24]
backends:
  dns:
    balance: roundrobin
    servers: [{host: 198.51.100.53, port: 53}]
"""


class TheDnsLayerTravelsWithTheRelease(unittest.TestCase):
    """B249: `managed/dns/dnsdist.conf` becomes the node's `dns/`, and only while a dns object exists."""

    BASE = {"core/haproxy.cfg": b"global\n", "manual/reservations.yaml": b"{}\n"}

    def publish(self, base: dict[str, bytes]) -> Any:
        return managed_files(
            {"managed/network.yaml": NETWORK, **base}, network_document=NETWORK, cluster=cluster()
        )

    def test_a_dns_object_brings_dnsdists_file_and_no_haproxy_object_file(self) -> None:
        files = self.publish({"managed/proxies/resolver.yaml": RESOLVER})

        self.assertIn(b'PoolAction("dns")', files["managed/dns/dnsdist.conf"])
        self.assertNotIn("managed/generated/1001-resolver.cfg", files)
        artifact = build_node_artifact({**files, **self.BASE})
        self.assertIn("dns/dnsdist.conf", artifact)

    def test_without_a_dns_object_the_layer_is_gone(self) -> None:
        files = self.publish(
            {"managed/proxies/shop.yaml": PROXY, "managed/dns/dnsdist.conf": b"stale\n"}
        )

        self.assertFalse([name for name in files if name.startswith("managed/dns/")])

    def test_the_dns_layer_takes_its_one_file_only(self) -> None:
        for name in ("dnsdist.yml", "other.conf", "sub/dnsdist.conf"):
            with self.subTest(name), self.assertRaises(LayoutError):
                build_node_artifact({**self.BASE, f"managed/dns/{name}": b"x\n"})
