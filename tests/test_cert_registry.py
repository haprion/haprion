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
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

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


class TheRegistryIsWrittenUnderTheLock(RegistryFixture):
    """Six commands change the registry; a second writer in the gap is a lost update."""

    def setUp(self) -> None:
        super().setUp()
        self.policy_path, self.registry = self.prepared({})
        self.lock = self.root / "cert-publish.lock"

    def test_set_receiver_waits_for_the_lock_and_both_writers_land(self) -> None:
        runtime = self.runtime(self.policy_path)

        def register(receiver_id: str) -> None:
            cert_registry.set_receiver(
                self.registry,
                receiver_id=receiver_id,
                fields={
                    "path": str(self.root / "receivers" / receiver_id),
                    "owner": "crx-" + receiver_id,
                    "transport": "sftp",
                    "layout": "per-certificate",
                },
                runtime=runtime,
                require_secure=False,
                lock_path=self.lock,
            )

        #
        # The first writer holds the lock across its read and write; the
        # second is started in the middle and must wait rather than write
        # over it. Without the lock the second's read predates the first's
        # write and one receiver is gone.
        #
        original_write = cert_registry.write
        started: list[threading.Thread] = []

        def write_then_let_the_other_in(*args: object, **kwargs: object) -> None:
            if not started:
                other = threading.Thread(target=register, args=("lb-02",))
                started.append(other)
                other.start()
                time.sleep(0.3)
            original_write(*args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(cert_registry, "write", side_effect=write_then_let_the_other_in):
            register("lb-01")
        started[0].join(timeout=10)

        receivers = yaml.safe_load(self.registry.read_text())["receivers"]
        self.assertEqual(sorted(receivers), ["lb-01", "lb-02"])

    def test_a_held_lock_is_a_refusal_with_the_contract_s_code(self) -> None:
        with (
            cert_registry.locked(self.lock),
            self.assertRaises(RegistryError) as caught,
            cert_registry.locked(self.lock, wait=0),
        ):
            pass
        self.assertEqual(caught.exception.code, "operation_locked")
        self.assertEqual(caught.exception.exit_code, 75)


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

    def test_a_cluster_s_default_certificate_cannot_be_taken_from_it(self) -> None:
        """clusters.yaml names a default; the loader refuses a registry that moved it away.

        2026-09-19: an enrollment dropped the clusters from the default
        certificate's entry, and every command on the manager refused its
        configuration until the file was edited by hand. Refused here, before
        the rename, with the cluster and the certificate named.
        """

        policy_path, registry = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        before = registry.read_bytes()

        # alpha keeps a certificate (example.com), so this is not `cluster_uncovered`.
        with self.assertRaises(RegistryError) as caught:
            self.retarget(policy_path, registry, "keeper-alpha.example", receivers=["lb-01"])

        self.assertEqual(caught.exception.code, "default_certificate_unassigned")
        self.assertIn("alpha (keeper-alpha.example)", str(caught.exception))
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


class TheRulesThatMakeB138True(RegistryFixture):
    """Spärrarna 1, 2 and 4, checked on the whole registry rather than on a delta.

    They live in the writer every path goes through - issuing, importing,
    retargeting, deleting - so each is refused from either direction: it is
    the same end state either way, and the end state is what is refused.
    """

    def test_a_flat_receiver_takes_one_certificate_at_a_time(self) -> None:
        policy_path, registry = self.prepared(
            {
                "one.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]},
                "two.example": {"source": {"kind": "acme"}},
            }
        )
        before = registry.read_bytes()

        with self.assertRaises(RegistryError) as caught:
            self.retarget(policy_path, registry, "two.example", receivers=["lb-01"])

        self.assertEqual(caught.exception.code, "receiver_full")
        self.assertIn("one certificate at a time", str(caught.exception))
        self.assertEqual(registry.read_bytes(), before)

    def test_a_per_certificate_receiver_takes_as_many_as_it_is_given(self) -> None:
        policy_path, registry = self.prepared(
            {
                "one.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]},
                "two.example": {"source": {"kind": "acme"}},
            },
        )
        raw = yaml.safe_load(registry.read_text())
        raw["receivers"]["lb-01"]["layout"] = "per-certificate"
        registry.write_text(yaml.safe_dump(raw), encoding="utf-8")

        change = self.retarget(policy_path, registry, "two.example", receivers=["lb-01"])

        self.assertEqual(change.receivers, ("lb-01",))
        self.assertEqual(self.entries(registry)["one.example"]["receivers"], ["lb-01"])

    def test_an_https_receiver_and_a_cluster_may_share_a_certificate(self) -> None:
        """B164: the registry no longer fences an https receiver off from the clusters."""

        self.register(
            "web-01.example.net",
            transport="https",
            layout="per-certificate",
            allow=["192.0.2.0/24"],
        )
        policy_path, registry = self.prepared(
            {
                "public.example": {
                    "source": {"kind": "acme"},
                    "receivers": ["web-01.example.net"],
                }
            }
        )

        change = self.retarget(
            policy_path,
            registry,
            "public.example",
            clusters=["alpha"],
            receivers=["web-01.example.net"],
        )

        self.assertEqual(change.clusters, ("alpha",))
        self.assertEqual(self.entries(registry)["public.example"]["clusters"], ["alpha"])
        self.assertEqual(
            self.entries(registry)["public.example"]["receivers"], ["web-01.example.net"]
        )

    def test_a_receiver_that_a_certificate_names_is_in_use(self) -> None:
        policy_path, registry = self.prepared(
            {"one.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]}}
        )
        runtime = self.runtime(policy_path)
        assert runtime.registry is not None

        self.assertEqual(cert_registry.receiver_in_use(runtime.registry, "lb-01"), ("one.example",))

        self.retarget(policy_path, registry, "one.example", receivers=[])
        runtime = self.runtime(policy_path)
        assert runtime.registry is not None
        self.assertEqual(cert_registry.receiver_in_use(runtime.registry, "lb-01"), ())


class AFormatSurvivesARetarget(RegistryFixture):
    """B159: the pair's form is not restated at every target change, so it is kept."""

    def setUp(self) -> None:
        super().setUp()
        self.register("certserver1.example.net", layout="per-certificate")
        self.policy_path, self.registry = self.prepared(
            {
                "one.example": {
                    "source": {"kind": "acme"},
                    "receivers": [{"id": "certserver1.example.net", "format": "pkcs12"}],
                }
            }
        )

    def test_moving_another_target_leaves_the_form_alone(self) -> None:
        self.retarget(
            self.policy_path,
            self.registry,
            "one.example",
            clusters=["alpha"],
            receivers=["certserver1.example.net"],
        )

        self.assertEqual(
            self.entries(self.registry)["one.example"]["receivers"],
            [{"id": "certserver1.example.net", "format": "pkcs12"}],
        )

    def test_a_stated_form_replaces_the_one_before_it(self) -> None:
        cert_registry.set_targets(
            self.registry,
            certificate_id="one.example",
            clusters=[],
            receivers=["certserver1.example.net", "lb-01"],
            formats={"certserver1.example.net": "pem"},
            runtime=self.runtime(self.policy_path),
            require_secure=False,
        )

        self.assertEqual(
            self.entries(self.registry)["one.example"]["receivers"],
            ["certserver1.example.net", "lb-01"],
        )

    def test_a_receiver_taken_away_takes_its_form_with_it(self) -> None:
        self.retarget(self.policy_path, self.registry, "one.example", receivers=["lb-01"])

        self.assertEqual(self.entries(self.registry)["one.example"]["receivers"], ["lb-01"])

    def test_a_changed_form_on_a_kept_receiver_is_a_change_and_is_written(self) -> None:
        change = cert_registry.set_targets(
            self.registry,
            certificate_id="one.example",
            clusters=[],
            receivers=["certserver1.example.net"],
            formats={"certserver1.example.net": "pem"},
            runtime=self.runtime(self.policy_path),
            require_secure=False,
        )

        self.assertTrue(change.changed)
        self.assertEqual(change.reformatted, ("certserver1.example.net",))
        self.assertEqual(change.added, ())
        self.assertEqual(
            self.entries(self.registry)["one.example"]["receivers"], ["certserver1.example.net"]
        )

    def test_restating_the_same_form_changes_nothing(self) -> None:
        change = cert_registry.set_targets(
            self.registry,
            certificate_id="one.example",
            clusters=[],
            receivers=["certserver1.example.net"],
            formats={"certserver1.example.net": "pkcs12"},
            runtime=self.runtime(self.policy_path),
            require_secure=False,
        )

        self.assertFalse(change.changed)
        self.assertEqual(change.reformatted, ())
