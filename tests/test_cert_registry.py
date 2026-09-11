"""Retargeting: what the registry accepts, what it refuses, and what it leaves alone.

The registry is the only thing standing between a job payload and a directory
that receives private key material, so most of what is held here is refusal: a
certificate that does not exist, a cluster `clusters.yaml` does not define, a
receiver nobody registered. The rest is the property the phase gate names -
exactly the chosen targets, and nothing removed.
"""

from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path

import yaml

from haproxy_mgmt import cert_registry
from haproxy_mgmt.cert_registry import RegistryError
from haproxy_mgmt.config import load_policy, load_runtime_config
from tests.test_cert_publish import Fixture, issue

#
# Every cluster has to be named by at least one certificate or the engine
# refuses to load at all, so the fixtures keep one certificate per cluster that
# the tests never move. Without it each test would be measuring that rule
# instead of the one it means to.
#
KEEPERS: dict[str, dict[str, object]] = {
    "keeper-alpha.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
    "keeper-beta.example": {"source": {"kind": "acme"}, "clusters": ["beta"]},
}


class RegistryFixture(Fixture):
    def prepared(self, certificates: dict[str, dict[str, object]]) -> tuple[Path, Path]:
        policy_path = self.write_config(KEEPERS | certificates)
        registry = self.root / "certificates.yaml"
        registry.chmod(0o640)
        return policy_path, registry

    def runtime(self, policy_path: Path):  # type: ignore[no-untyped-def]
        policy = load_policy(policy_path, require_secure=False)
        return load_runtime_config(policy, require_secure=False)

    def retarget(
        self, policy_path: Path, registry: Path, certificate_id: str, **targets: list[str]
    ) -> cert_registry.TargetChange:
        return cert_registry.set_targets(
            registry,
            certificate_id=certificate_id,
            clusters=targets.get("clusters", []),
            receivers=targets.get("receivers", []),
            runtime=self.runtime(policy_path),
            require_secure=False,
        )

    def entries(self, registry: Path) -> dict[str, dict[str, object]]:
        return yaml.safe_load(registry.read_text())["certificates"]


class WhatRetargetingRefuses(RegistryFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy_path, self.registry = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "example.net": {"source": {"kind": "acme"}, "clusters": ["beta"]},
            }
        )
        self.before = self.registry.read_bytes()

    def test_a_certificate_that_is_not_registered(self) -> None:
        with self.assertRaises(RegistryError) as caught:
            self.retarget(self.policy_path, self.registry, "nobody.example", clusters=["alpha"])

        self.assertEqual(caught.exception.code, "unknown_certificate")
        self.assertEqual(self.registry.read_bytes(), self.before)

    def test_a_cluster_the_configuration_does_not_define(self) -> None:
        """The payload cannot bring a cluster into being by naming it."""

        with self.assertRaises(RegistryError) as caught:
            self.retarget(self.policy_path, self.registry, "example.com", clusters=["gamma"])

        self.assertEqual(caught.exception.code, "unknown_cluster")
        self.assertEqual(self.registry.read_bytes(), self.before)

    def test_a_receiver_nobody_registered(self) -> None:
        """The one that matters most: a receiver is a directory key material lands in.

        Registering one is an installation step, deliberately out of reach of
        anything a request can ask for.
        """

        with self.assertRaises(RegistryError) as caught:
            self.retarget(self.policy_path, self.registry, "example.com", receivers=["lb-99"])

        self.assertEqual(caught.exception.code, "unknown_receiver")
        self.assertEqual(self.registry.read_bytes(), self.before)


class WhatRetargetingDoes(RegistryFixture):
    def test_the_whole_target_set_is_replaced_and_the_move_is_named(self) -> None:
        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )

        change = self.retarget(
            policy_path, registry, "example.com", clusters=["beta"], receivers=["lb-01"]
        )

        self.assertTrue(change.changed)
        self.assertEqual(change.clusters, ("beta",))
        self.assertEqual(change.receivers, ("lb-01",))
        self.assertEqual(change.added, ("beta", "lb-01"))
        self.assertEqual(change.abandoned, ("alpha",))
        self.assertEqual(
            self.entries(registry)["example.com"],
            {"source": {"kind": "acme"}, "clusters": ["beta"], "receivers": ["lb-01"]},
        )

    def test_the_dropped_target_keeps_its_copy(self) -> None:
        """Nothing here removes certificate material; the abandonment is reported instead.

        A helper that deleted would be able to erase a certificate a cluster is
        currently serving, one reload away from a site that stops answering.
        """

        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]}}
        )
        for name in ("example.com", *KEEPERS):
            issue(self.live / name, name)
        self.run_publish(policy_path)
        #
        # A receiver has a directory of its own, which is where an abandonment
        # is visible as a file. The clusters share one distribution directory,
        # so dropping one of them leaves nothing behind to look at.
        #
        self.retarget(policy_path, registry, "example.com", receivers=["lb-01"])
        self.run_publish(policy_path)
        delivered = self.receiver_dir / "fullchain.pem"
        self.assertTrue(delivered.is_file())
        material = delivered.read_bytes()

        change = self.retarget(policy_path, registry, "example.com", clusters=["alpha"])
        self.run_publish(policy_path)

        self.assertEqual(change.abandoned, ("lb-01",))
        self.assertEqual(delivered.read_bytes(), material)

    def test_other_entries_and_the_receiver_block_travel_through_untouched(self) -> None:
        policy_path, registry = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "example.net": {
                    "source": {"kind": "acme", "lineage": "example.net-wildcard"},
                    "clusters": ["beta"],
                },
            }
        )
        receivers = yaml.safe_load(registry.read_text())["receivers"]

        self.retarget(policy_path, registry, "example.com", clusters=["alpha", "beta"])

        document = yaml.safe_load(registry.read_text())
        self.assertEqual(document["receivers"], receivers)
        self.assertEqual(
            document["certificates"]["example.net"],
            {"source": {"kind": "acme", "lineage": "example.net-wildcard"}, "clusters": ["beta"]},
        )

    def test_asking_for_what_is_already_there_writes_nothing(self) -> None:
        """A no-op must not give the file a new mtime; that is somebody's only signal."""

        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        before = registry.stat().st_mtime_ns

        change = self.retarget(policy_path, registry, "example.com", clusters=["alpha"])

        self.assertFalse(change.changed)
        self.assertEqual(change.added, ())
        self.assertEqual(change.abandoned, ())
        self.assertEqual(registry.stat().st_mtime_ns, before)

    def test_the_owner_and_mode_survive_the_rewrite(self) -> None:
        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        status = registry.stat()

        self.retarget(policy_path, registry, "example.com", receivers=["lb-01"])

        after = registry.stat()
        self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(status.st_mode))
        self.assertEqual((after.st_uid, after.st_gid), (status.st_uid, status.st_gid))

    def test_a_certificate_may_be_left_with_no_target_at_all(self) -> None:
        """Ending distribution is a decision somebody may make, and it is reported."""

        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )

        change = self.retarget(policy_path, registry, "example.com")

        self.assertEqual(change.abandoned, ("alpha",))
        self.assertEqual(self.entries(registry)["example.com"], {"source": {"kind": "acme"}})

    def test_taking_a_cluster_s_last_certificate_away_is_refused(self) -> None:
        """A cluster no certificate names cannot be loaded - by any command, not just this one.

        Found by a test that meant to measure something else and instead wrote a
        registry the whole engine then refused to read.
        """

        policy_path, registry = self.prepared({})
        before = registry.read_bytes()

        with self.assertRaises(RegistryError) as caught:
            self.retarget(policy_path, registry, "keeper-alpha.example", clusters=["beta"])

        self.assertEqual(caught.exception.code, "cluster_uncovered")
        self.assertIn("alpha", str(caught.exception))
        self.assertEqual(registry.read_bytes(), before)

    def test_a_registry_the_engine_would_refuse_never_reaches_the_path(self) -> None:
        """The load-back happens before the rename, so a bad write is never the file."""

        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        before = registry.read_bytes()
        runtime = self.runtime(policy_path)
        document = cert_registry.read_document(registry)

        with self.assertRaises(RegistryError):
            cert_registry.write(
                registry,
                document=document,
                certificates={"example.com": {"source": {"kind": "acme"}, "clusters": ["gamma"]}},
                runtime=runtime,
                require_secure=False,
            )

        self.assertEqual(registry.read_bytes(), before)
        self.assertEqual(
            sorted(os.listdir(registry.parent)),
            sorted(name for name in os.listdir(registry.parent) if not name.startswith(".cert")),
        )


if __name__ == "__main__":
    unittest.main()
