"""Publish to… and Remove from…: a batch with a delta, guarded per certificate.

The fixture is the deletion's: a registry with two keepers, one per cluster,
material in the distribution directory, a receiver, and nodes answered by a
fake. What is measured is what the registry says afterwards, which copies
went, which clusters were rolled out, and that a refused certificate leaves
everything of its own in place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from haproxy_mgmt import cert_retarget
from haproxy_mgmt.cert_delete import Guards
from haproxy_mgmt.cert_inventory import FULLCHAIN, PRIVKEY
from haproxy_mgmt.cert_retarget import Change, retarget
from haproxy_mgmt.config import load_policy
from tests.test_cert_delete import DeleteFixture
from tests.test_cert_publish import issue


class RetargetFixture(DeleteFixture):
    def setUp(self) -> None:
        super().setUp()
        self.deployed: list[str] = []

    def deployer(self, cluster_id: str) -> int:
        self.deployed.append(cluster_id)
        return 0

    def retarget(
        self,
        policy_path: Path,
        action: str,
        *certificate_ids: str,
        clusters: tuple[str, ...] = (),
        receivers: tuple[str, ...] = (),
        guards: Guards | None = None,
        deploy: bool = True,
    ) -> cert_retarget.Report:
        return retarget(
            certificate_ids,
            Change(action, clusters=clusters, receivers=receivers),
            load_policy(policy_path, require_secure=False),
            deploy=deploy,
            require_secure=False,
            live=self.live,
            store=self.store,
            lock_path=self.lock,
            deployer=self.deployer,
            node_remover=self.node,
            guards_reader=lambda runtime, ids: guards or Guards(),
        )

    def targets(self, certificate_id: str) -> dict[str, Any]:
        document = yaml.safe_load((self.root / "certificates.yaml").read_text())
        entry = document["certificates"][certificate_id]
        return {"clusters": entry.get("clusters", []), "receivers": entry.get("receivers", [])}


class PublishingToMoreTargets(RetargetFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "shop.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        for name in ("example.com", "shop.example", "keeper-alpha.example", "keeper-beta.example"):
            issue(self.live / name, name)

    def test_two_certificates_gain_a_cluster_and_it_is_rolled_out_once(self) -> None:
        report = self.retarget(
            self.policy_path, "add", "example.com", "shop.example", clusters=("beta",)
        )

        self.assertEqual(report.changed, ("example.com", "shop.example"))
        self.assertEqual(self.targets("example.com")["clusters"], ["alpha", "beta"])
        self.assertEqual(self.targets("shop.example")["clusters"], ["alpha", "beta"])
        self.assertEqual(self.deployed, ["beta"])
        self.assertEqual(
            [d.as_dict() for d in report.deployments], [{"cluster": "beta", "exit_code": 0}]
        )

    def test_a_certificate_already_there_is_unchanged_and_costs_no_rollout(self) -> None:
        report = self.retarget(self.policy_path, "add", "example.com", clusters=("alpha",))

        self.assertEqual(report.unchanged, ("example.com",))
        self.assertEqual(self.deployed, [])

    def test_a_receiver_gets_its_pair_and_no_cluster_is_rolled_out(self) -> None:
        report = self.retarget(self.policy_path, "add", "example.com", receivers=("lb-01",))

        self.assertEqual(report.changed, ("example.com",))
        self.assertEqual(self.targets("example.com")["receivers"], ["lb-01"])
        self.assertTrue((self.receiver_dir / FULLCHAIN).exists())
        self.assertEqual(self.deployed, [])

    def test_an_unknown_target_or_certificate_is_refused_and_the_rest_go_through(self) -> None:
        before = (self.root / "certificates.yaml").read_bytes()
        report = self.retarget(
            self.policy_path, "add", "nobody.example", "example.com", clusters=("beta",)
        )
        self.assertEqual(report.refused, ("nobody.example",))
        self.assertEqual(report.changed, ("example.com",))
        self.assertEqual(report.outcomes[0].code, "unknown_certificate")

        (self.root / "certificates.yaml").write_bytes(before)
        report = self.retarget(self.policy_path, "add", "example.com", receivers=("lb-99",))
        self.assertEqual(report.refused, ("example.com",))
        self.assertEqual(report.outcomes[0].code, "unknown_receiver")
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), before)

    def test_without_deploy_the_registry_and_the_files_change_but_no_node_is_asked(self) -> None:
        report = self.retarget(
            self.policy_path, "add", "example.com", clusters=("beta",), deploy=False
        )

        self.assertEqual(report.changed, ("example.com",))
        self.assertEqual(self.deployed, [])
        self.assertEqual(report.deployments, ())


class RemovingFromATarget(RetargetFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]},
                "shop.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                },
            }
        )

    def test_the_cluster_leaves_the_entry_and_its_nodes_drop_the_copy(self) -> None:
        report = self.retarget(self.policy_path, "remove", "example.com", clusters=("beta",))

        self.assertEqual(report.changed, ("example.com",))
        self.assertEqual(self.targets("example.com")["clusters"], ["alpha"])
        self.assertEqual(report.outcomes[0].abandoned, ("beta",))
        self.assertEqual(
            self.node_calls,
            [("node-a.example.com", "example.com"), ("node-b.example.com", "example.com")],
        )
        self.assertEqual([n.state for n in report.outcomes[0].nodes], ["removed", "removed"])
        # The material for the remaining cluster is not touched.
        self.assertTrue((self.dist / "example.com.pem").exists())
        self.assertEqual(self.deployed, [])

    def test_the_last_cluster_takes_the_distribution_copy_with_it(self) -> None:
        """Off its last cluster the PEM under the certificate root is a key
        pair no entry owns, in a directory the nodes may read; the deletion
        removes it and so does this (review 2026-09-17, finding 5)."""

        self.assertTrue((self.dist / "shop.example.pem").exists())
        report = self.retarget(self.policy_path, "remove", "shop.example", clusters=("alpha",))

        self.assertEqual(report.changed, ("shop.example",))
        self.assertEqual(self.targets("shop.example")["clusters"], [])
        self.assertFalse((self.dist / "shop.example.pem").exists())
        self.assertIn(
            (str(self.dist / "shop.example.pem"), "removed"),
            [(layer.name, layer.state) for layer in report.outcomes[0].layers],
        )
        # The receiver it still publishes to keeps its pair.
        self.assertTrue((self.receiver_dir / FULLCHAIN).exists())

    def test_a_node_that_keeps_its_copy_makes_the_row_incomplete_not_the_registry(self) -> None:
        self.node_answers["node-b.example.com"] = (1, "unknown request: cert-remove")

        report = self.retarget(self.policy_path, "remove", "example.com", clusters=("beta",))

        self.assertEqual(report.incomplete, ("example.com",))
        self.assertEqual(self.targets("example.com")["clusters"], ["alpha"])
        self.assertEqual([n.state for n in report.outcomes[0].nodes], ["removed", "kept"])

    def test_a_receiver_loses_its_pair_and_the_host_is_not_asked(self) -> None:
        report = self.retarget(self.policy_path, "remove", "shop.example", receivers=("lb-01",))

        self.assertEqual(report.changed, ("shop.example",))
        self.assertEqual(self.targets("shop.example")["receivers"], [])
        self.assertFalse((self.receiver_dir / FULLCHAIN).exists())
        self.assertFalse((self.receiver_dir / PRIVKEY).exists())
        self.assertEqual(self.node_calls, [])

    def test_a_shared_receiver_keeps_its_pair_for_the_other_certificate(self) -> None:
        self.policy_path = self.prepared(
            {
                "shop.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                },
                "other.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                },
            }
        )
        report = self.retarget(self.policy_path, "remove", "shop.example", receivers=("lb-01",))

        self.assertEqual(report.changed, ("shop.example",))
        self.assertEqual(self.targets("shop.example")["receivers"], [])
        self.assertTrue((self.receiver_dir / FULLCHAIN).exists())
        self.assertEqual(report.outcomes[0].layers[0].state, "kept")
        self.assertIn("other.example", report.outcomes[0].layers[0].detail)

    def test_a_certificate_not_on_that_target_is_unchanged(self) -> None:
        report = self.retarget(self.policy_path, "remove", "shop.example", clusters=("beta",))

        self.assertEqual(report.unchanged, ("shop.example",))
        self.assertEqual(self.node_calls, [])


class WhatRemovalRefuses(RetargetFixture):
    """The deletion's guards, scoped to the dropped cluster."""

    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]}}
        )
        self.before = (self.root / "certificates.yaml").read_bytes()

    def assert_untouched(self, report: cert_retarget.Report, code: str) -> None:
        self.assertEqual(report.refused, ("example.com",))
        self.assertEqual(report.outcomes[0].code, code)
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), self.before)
        self.assertEqual(self.node_calls, [])

    def test_an_object_in_the_dropped_cluster_naming_it(self) -> None:
        guards = Guards(referenced={"example.com": ("beta/shop",)})
        report = self.retarget(
            self.policy_path, "remove", "example.com", clusters=("beta",), guards=guards
        )
        self.assert_untouched(report, "referenced_by_object")
        self.assertIn("beta/shop", report.outcomes[0].reason)

    def test_an_object_in_another_cluster_does_not_hold_it(self) -> None:
        guards = Guards(referenced={"example.com": ("alpha/shop",)})
        report = self.retarget(
            self.policy_path, "remove", "example.com", clusters=("beta",), guards=guards
        )
        self.assertEqual(report.changed, ("example.com",))

    def test_the_dropped_cluster_s_default(self) -> None:
        guards = Guards(defaults={"example.com": ("beta",)})
        report = self.retarget(
            self.policy_path, "remove", "example.com", clusters=("beta",), guards=guards
        )
        self.assert_untouched(report, "cluster_default")

    def test_the_dropped_cluster_s_last_certificate_seen_after_the_first_went(self) -> None:
        """The registry is re-read per certificate: the second sees the first gone."""

        report = self.retarget(
            self.policy_path, "remove", "example.com", "keeper-beta.example", clusters=("beta",)
        )
        self.assertEqual(report.changed, ("example.com",))
        self.assertEqual(report.refused, ("keeper-beta.example",))
        self.assertEqual(report.outcomes[1].code, "cluster_uncovered")
        self.assertEqual(self.targets("keeper-beta.example")["clusters"], ["beta"])

    def test_a_refused_certificate_stops_nothing_else(self) -> None:
        guards = Guards(defaults={"example.com": ("beta",)})
        self.policy_path = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]},
                "shop.example": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]},
            }
        )
        report = self.retarget(
            self.policy_path,
            "remove",
            "example.com",
            "shop.example",
            clusters=("beta",),
            guards=guards,
        )
        self.assertEqual(report.refused, ("example.com",))
        self.assertEqual(report.changed, ("shop.example",))
        self.assertEqual(self.targets("shop.example")["clusters"], ["alpha"])


class WhatTheRequestMustSay(RetargetFixture):
    def test_an_empty_change_or_an_unknown_action_is_the_request_s_fault(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        with self.assertRaises(cert_retarget.RetargetError) as caught:
            self.retarget(policy_path, "add", "example.com")
        self.assertEqual(caught.exception.code, "bad_input")
        with self.assertRaises(cert_retarget.RetargetError) as caught:
            self.retarget(policy_path, "replace", "example.com", clusters=("alpha",))
        self.assertEqual(caught.exception.code, "bad_input")


class WhatALayoutChangesAboutRemoval(RetargetFixture):
    """Spärr 5 (B138): every reader follows the layout, or it unlinks nothing.

    Under `per-certificate` two certificates on one receiver are two
    directories, so taking one away is not a reason to keep the other's files
    - which is exactly the opposite of the `flat` case one test above.
    """

    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.prepared(
            {
                "shop.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                },
                "other.example": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                },
            }
        )
        registry = self.root / "certificates.yaml"
        raw = yaml.safe_load(registry.read_text())
        raw["receivers"]["lb-01"]["layout"] = "per-certificate"
        raw["certificates"]["other.example"]["receivers"] = [{"id": "lb-01", "format": "pkcs12"}]
        registry.write_text(yaml.safe_dump(raw), encoding="utf-8")
        registry.chmod(0o640)
        #
        # The files as a publish would have left them: a PEM pair for one, a
        # bundle and its password for the other, each under its own directory.
        #
        (self.receiver_dir / "shop.example").mkdir()
        (self.receiver_dir / "shop.example" / FULLCHAIN).write_text("chain\n", encoding="utf-8")
        (self.receiver_dir / "shop.example" / PRIVKEY).write_text("key\n", encoding="utf-8")
        (self.receiver_dir / "other.example").mkdir()
        (self.receiver_dir / "other.example" / "other.example.pfx").write_bytes(b"bundle")
        (self.receiver_dir / "other.example" / "other.example.password").write_text("pw\n")
        for stale in (FULLCHAIN, PRIVKEY):
            (self.receiver_dir / stale).unlink(missing_ok=True)

    def test_one_certificate_leaves_and_the_other_keeps_its_directory(self) -> None:
        report = self.retarget(self.policy_path, "remove", "shop.example", receivers=("lb-01",))

        self.assertEqual(report.changed, ("shop.example",))
        self.assertFalse((self.receiver_dir / "shop.example").exists())
        self.assertTrue((self.receiver_dir / "other.example" / "other.example.pfx").exists())

    def test_a_bundle_is_taken_away_under_the_names_it_was_written_with(self) -> None:
        report = self.retarget(self.policy_path, "remove", "other.example", receivers=("lb-01",))

        self.assertEqual(report.changed, ("other.example",))
        self.assertFalse((self.receiver_dir / "other.example").exists())
        self.assertTrue((self.receiver_dir / "shop.example" / FULLCHAIN).exists())
