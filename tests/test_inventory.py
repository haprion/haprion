from __future__ import annotations

import unittest
from datetime import UTC, datetime

from haproxy_mgmt import inventory
from haproxy_mgmt.config import Vip
from haproxy_mgmt.deploy_plan import ReleaseTarget
from haproxy_mgmt.generate import generate
from haproxy_mgmt.inventory import InventoryError, inventory_result
from haproxy_mgmt.proxy_model import load_proxy

TARGET = ReleaseTarget(version=12, hash="a" * 40)
TIME = datetime(2026, 8, 29, 12, 30, tzinfo=UTC)


class InventoryTests(unittest.TestCase):
    def test_it_reads_the_three_published_configuration_layers(self) -> None:
        result = inventory_result(
            {
                "core/haproxy.cfg": b"""global\n\ndefaults\n  mode http\n""",
                "core/conf.d/0073-public.cfg": b"""frontend public\n  bind :80\n  acl app hdr(host) -i app.example.test www.example.test\n  use_backend app_pool if app\n""",
                "managed/generated/1001-api.cfg": b"""frontend generated-api\n  bind :443 ssl\n  default_backend api_pool\n""",
                "manual/conf.d/0070-legacy.cfg": b"""listen legacy\n  mode tcp\n  bind 192.0.2.20:8443\n  use_backend legacy_pool\n  use_backend other_pool if TRUE\n""",
                "manual/reservations.yaml": b"{}\n",
                "manual/maps/hosts.map": b"ignored\n",
            },
            TARGET,
            generated_at=TIME,
        )

        self.assertEqual(result["version"], 12)
        self.assertEqual(result["hash"], "a" * 40)
        self.assertEqual(result["generated_at"], "2026-08-29T12:30:00Z")
        self.assertEqual(
            result["proxies"],
            [
                {
                    "id": "proxy:public",
                    "name": "public",
                    "managed": False,
                    "source": "core",
                    "protocol": "http",
                    "enabled": True,
                    "hostnames": ["app.example.test", "www.example.test"],
                    "bind_ports": [80],
                    "backend_count": 1,
                    "backends": ["app_pool"],
                },
                {
                    "id": "proxy:generated-api",
                    "name": "generated-api",
                    "managed": True,
                    "source": "managed",
                    "protocol": "https",
                    "enabled": True,
                    "hostnames": [],
                    "bind_ports": [443],
                    "backend_count": 1,
                    "backends": ["api_pool"],
                },
                {
                    "id": "proxy:legacy",
                    "name": "legacy",
                    "managed": False,
                    "source": "manual",
                    "protocol": "tcp",
                    "enabled": True,
                    "hostnames": [],
                    "bind_ports": [8443],
                    "backend_count": 2,
                    "backends": ["legacy_pool", "other_pool"],
                },
            ],
        )
        self.assertEqual(
            result["reservations"], {"hostnames": [], "tcp_ports": [], "tcp_listeners": []}
        )

    def test_it_reports_what_the_reservations_file_actually_says(self) -> None:
        """The publishing path reads this file to refuse objects; so must this one.

        Two readers of one file with two answers is how an operator ends up
        being told nothing is reserved moments after a publish was refused for
        claiming something reserved.
        """

        result = inventory_result(
            {
                "manual/reservations.yaml": (
                    b"hostnames: [legacy.example.com]\ntcp_ports: [8443]\n"
                ),
            },
            TARGET,
            generated_at=TIME,
        )

        self.assertEqual(
            result["reservations"],
            {"hostnames": ["legacy.example.com"], "tcp_ports": [8443], "tcp_listeners": []},
        )

    def test_a_reservations_file_that_cannot_be_read_fails_the_inventory(self) -> None:
        """Rather than an answer that says nothing is reserved."""

        with self.assertRaises(InventoryError) as raised:
            inventory_result(
                {"manual/reservations.yaml": b"hostnames: 5\n"},
                TARGET,
                generated_at=TIME,
            )

        self.assertIn("manual/reservations.yaml", str(raised.exception))

    def test_an_unpublished_tree_reserves_nothing(self) -> None:
        """No RELEASE stamp means there is no published file to have read."""

        result = inventory_result({}, None, generated_at=TIME)

        self.assertEqual(
            result["reservations"], {"hostnames": [], "tcp_ports": [], "tcp_listeners": []}
        )

    def test_it_never_derives_inventory_from_an_unpublished_tree(self) -> None:
        result = inventory_result(
            {"managed/generated/1003-staged.cfg": b"frontend staged\n  bind :443 ssl\n"},
            None,
            generated_at=TIME,
        )

        self.assertEqual(result["version"], None)
        self.assertEqual(result["hash"], None)
        self.assertEqual(result["proxies"], [])

    def test_duplicate_frontends_are_refused_instead_of_silently_merged(self) -> None:
        with self.assertRaisesRegex(InventoryError, "defines frontend 'public' twice"):
            inventory_result(
                {
                    "core/conf.d/0071-one.cfg": b"frontend public\n  bind :80\n",
                    "manual/conf.d/0072-two.cfg": b"frontend public\n  bind :443 ssl\n",
                },
                TARGET,
                generated_at=TIME,
            )

    def test_non_utf8_configuration_is_refused(self) -> None:
        with self.assertRaisesRegex(InventoryError, "not UTF-8"):
            inventory_result({"core/haproxy.cfg": b"\xff"}, TARGET, generated_at=TIME)


if __name__ == "__main__":
    unittest.main()


class TheHostnamesTheGeneratorActuallyWrites(unittest.TestCase):
    """Read from a generated configuration, not from a line written by hand.

    The parser knew one spelling of a host match and the generator writes
    another, so the inventory found no hostnames at all in anything this
    project produces. Nothing failed. The listing said "No hostname rule", and
    every managed object stayed in the undeployed list for ever - the check
    that would have taken it out compares hostnames, and one side was empty.

    So the case is built by generating a configuration rather than by quoting a
    line: a line quoted here can go stale in exactly the way that caused this.
    """

    def generated(self) -> str:
        proxy = load_proxy(
            "shop",
            b"schema: 1\n"
            b"name: shop\n"
            b"hostnames:\n- admin.example.com\n"
            b"listen:\n  protocol: http\n"
            b"routes:\n- path: /\n  backend: web\n"
            b"backends:\n  web:\n    balance: roundrobin\n"
            b"    health:\n      type: disabled\n"
            b"    servers:\n    - host: 198.51.100.10\n      port: 80\n",
        )
        layer = generate(
            [proxy],
            vips={"main": Vip(name="main", address="192.0.2.25")},
            default_vip="main",
            networks={},
            ports={"http": 80},
        )
        return "\n".join(layer.configuration.values())

    def test_the_generated_host_match_is_read(self) -> None:
        found: set[str] = set()
        for line in self.generated().splitlines():
            found |= inventory._hostnames(line)

        self.assertEqual(found, {"admin.example.com"})

    def test_the_hand_written_spelling_still_works(self) -> None:
        line = "  acl app hdr(host) -i app.example.com www.example.com"

        self.assertEqual(inventory._hostnames(line), {"app.example.com", "www.example.com"})

    def test_a_path_match_is_not_a_hostname(self) -> None:
        self.assertEqual(inventory._hostnames("  acl api path -m str /api"), set())
