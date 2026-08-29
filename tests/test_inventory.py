from __future__ import annotations

import unittest
from datetime import UTC, datetime

from haproxy_mgmt.deploy_plan import ReleaseTarget
from haproxy_mgmt.inventory import InventoryError, inventory_result

TARGET = ReleaseTarget(version=12, hash="a" * 40)
TIME = datetime(2026, 8, 29, 12, 30, tzinfo=UTC)


class InventoryTests(unittest.TestCase):
    def test_it_reads_the_three_published_configuration_layers(self) -> None:
        result = inventory_result(
            {
                "core/haproxy.cfg": b"""global\n\ndefaults\n  mode http\n""",
                "core/conf.d/public.cfg": b"""frontend public\n  bind :80\n  acl app hdr(host) -i app.example.test www.example.test\n  use_backend app_pool if app\n""",
                "managed/generated/api.cfg": b"""frontend generated-api\n  bind :443 ssl\n  default_backend api_pool\n""",
                "manual/conf.d/legacy.cfg": b"""listen legacy\n  mode tcp\n  bind 192.0.2.20:8443\n  use_backend legacy_pool\n  use_backend other_pool if TRUE\n""",
                "manual/reservations.yaml": b"reservations: []\n",
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
                },
            ],
        )
        self.assertEqual(result["reservations"], {"hostnames": [], "tcp_ports": []})

    def test_it_never_derives_inventory_from_an_unpublished_tree(self) -> None:
        result = inventory_result(
            {"managed/generated/staged.cfg": b"frontend staged\n  bind :443 ssl\n"},
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
                    "core/conf.d/one.cfg": b"frontend public\n  bind :80\n",
                    "manual/conf.d/two.cfg": b"frontend public\n  bind :443 ssl\n",
                },
                TARGET,
                generated_at=TIME,
            )

    def test_non_utf8_configuration_is_refused(self) -> None:
        with self.assertRaisesRegex(InventoryError, "not UTF-8"):
            inventory_result({"core/haproxy.cfg": b"\xff"}, TARGET, generated_at=TIME)


if __name__ == "__main__":
    unittest.main()
