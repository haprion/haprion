"""Deleting certificates: what is refused, what goes, and what is left and said.

Most of what is held here is refusal, because the operation is the one thing
in the project that removes key material. The rest is the shape of the answer:
one row per certificate, with every layer that was touched or kept on it, and
that the same selection deleted again finishes what a kept layer left.
"""

from __future__ import annotations

import fcntl
import io
import json
import os
import subprocess
import unittest
import unittest.mock
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from haprion import cert_delete, exit_codes
from haprion.cert_delete import Guards, delete, read_guards
from haprion.cert_inventory import FULLCHAIN, PRIVKEY
from haprion.cert_publish import publish_lock
from haprion.cli import cert_delete_helper
from haprion.config import load_policy, load_runtime_config
from tests.test_cert_publish import Fixture
from tests.test_proxy_model import with_lines

#
# One certificate per cluster the tests never delete, for the reason the
# registry tests give: the engine refuses a cluster nobody names.
#
KEEPERS: dict[str, dict[str, object]] = {
    "keeper-alpha.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
    "keeper-beta.example": {"source": {"kind": "acme"}, "clusters": ["beta"]},
}


def commit(repo: Path, files: dict[str, bytes]) -> None:
    """A cluster repository with one commit holding `files`."""

    def git(*args: str) -> None:
        subprocess.run(["/usr/bin/git", "-C", str(repo), *args], check=True, capture_output=True)

    repo.mkdir(exist_ok=True)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Example Maintainer")
    git("config", "user.email", "maintainer@example.com")
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    git("add", "-A")
    git("commit", "-qm", "objects")


class DeleteFixture(Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.renewal = self.root / "renewal"
        self.renewal.mkdir()
        self.certbot_calls: list[tuple[str, ...]] = []
        self.node_calls: list[tuple[str, str]] = []
        self.node_verbs: list[str] = []
        self.node_answers: dict[str, tuple[int, str]] = {}

    def prepared(self, certificates: dict[str, dict[str, Any]]) -> Path:
        policy_path = self.write_config(KEEPERS | certificates)
        (self.root / "certificates.yaml").chmod(0o640)
        #
        # Material and lineage for every certificate, as publish and certbot
        # would have left them, so a deletion has something to remove.
        #
        for certificate_id, raw in (KEEPERS | certificates).items():
            for cluster_id in raw.get("clusters") or []:
                self.copy(certificate_id, cluster_id).parent.mkdir(exist_ok=True)
                self.copy(certificate_id, cluster_id).write_text("pem\n", encoding="utf-8")
            (self.renewal / f"{certificate_id}.conf").write_text("version = 5.8.0\n")
            if "lb-01" in (raw.get("receivers") or []):
                held = self.receiver_dir / certificate_id
                held.mkdir(exist_ok=True)
                (held / FULLCHAIN).write_text("chain\n", encoding="utf-8")
                (held / PRIVKEY).write_text("key\n", encoding="utf-8")
        #
        # Nodes reachable through an identity the policy names; the key only
        # has to exist for the loader.
        #
        key = self.root / "id_ed25519"
        key.write_text("dummy\n", encoding="utf-8")
        key.chmod(0o600)
        policy = yaml.safe_load(policy_path.read_text())
        policy["cert_deploy_identity"] = {"key": str(key)}
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        return policy_path

    def copy(self, certificate_id: str, cluster_id: str = "alpha") -> Path:
        """A cluster's copy, in its own directory under the certificate root (B358)."""

        return self.dist / cluster_id / f"{certificate_id}.pem"

    def certbot(self, command: Sequence[str]) -> tuple[int, str]:
        self.certbot_calls.append(tuple(command))
        conf = self.renewal / f"{command[3]}.conf"
        conf.unlink(missing_ok=True)
        return 0, ""

    def node(self, identity: Any, host: str, verb: str, certificate_id: str) -> tuple[int, str]:
        """The node script's own lines: one for a copy removed, one for none there."""

        self.node_verbs.append(verb)
        self.node_calls.append((host, certificate_id))
        if host in self.node_answers:
            return self.node_answers[host]
        return 0, f"[ts] Removed {certificate_id}.\n[ts] Done: 1 removed, 0 not present."

    def nodes_have_nothing(self) -> None:
        for host in ("node-a.example.com", "node-b.example.com"):
            self.node_answers[host] = (0, "[ts] x was not present.\n[ts] Done: 0 removed.")

    def run_delete(
        self, policy_path: Path, *certificate_ids: str, guards: Guards | None = None
    ) -> cert_delete.Report:
        return delete(
            certificate_ids,
            load_policy(policy_path, require_secure=False),
            require_secure=False,
            renewal_directory=self.renewal,
            store=self.store,
            certbot="/usr/bin/certbot",
            lock_path=self.lock,
            lineage_remover=self.certbot,
            node_remover=self.node,
            guards_reader=lambda runtime, ids: guards or Guards(),
        )

    def registered(self) -> set[str]:
        return set(yaml.safe_load((self.root / "certificates.yaml").read_text())["certificates"])


class WhatIsRefused(DeleteFixture):
    def setUp(self) -> None:
        super().setUp()
        self.policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.before = (self.root / "certificates.yaml").read_bytes()

    def assert_untouched(self, report: cert_delete.Report, certificate_id: str, code: str) -> None:
        (outcome,) = [o for o in report.outcomes if o.certificate_id == certificate_id]
        self.assertEqual(outcome.state, "refused")
        self.assertEqual(outcome.code, code)
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), self.before)
        self.assertTrue(any(path.exists() for path in self.dist.glob(f"*/{certificate_id}.pem")))
        self.assertTrue((self.renewal / f"{certificate_id}.conf").exists())
        self.assertEqual(self.certbot_calls, [])
        self.assertEqual(self.node_calls, [])

    def test_a_certificate_that_is_not_registered_and_nowhere_else(self) -> None:
        """Every node is asked, because only the nodes know; they had nothing."""

        self.nodes_have_nothing()
        report = self.run_delete(self.policy_path, "nobody.example")
        (outcome,) = report.outcomes
        self.assertEqual((outcome.state, outcome.code), ("refused", "not_registered"))
        self.assertEqual(outcome.layers, ())
        self.assertEqual(
            {host for host, _ in self.node_calls}, {"node-a.example.com", "node-b.example.com"}
        )
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), self.before)

    def test_an_unregistered_certificate_a_committed_object_names_is_refused_first(self) -> None:
        guards = Guards(referenced={"nobody.example": ("alpha/shop",)})
        report = self.run_delete(self.policy_path, "nobody.example", guards=guards)
        self.assertEqual(report.outcomes[0].code, "referenced_by_object")
        self.assertEqual(self.node_calls, [])

    def test_a_lineage_another_entry_also_names(self) -> None:
        policy_path = self.prepared(
            {
                "wild": {
                    "source": {"kind": "acme", "lineage": "example.com"},
                    "clusters": ["alpha"],
                },
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        self.before = (self.root / "certificates.yaml").read_bytes()
        report = self.run_delete(policy_path, "wild", "example.com")
        self.assert_untouched(report, "wild", "shared_source")
        self.assert_untouched(report, "example.com", "shared_source")
        self.assertIn("'example.com'", report.outcomes[0].reason)

    def test_a_per_certificate_receiver_is_not_shared_by_its_certificates(self) -> None:
        #
        # Seen 2026-09-20: a throwaway import to a per-certificate receiver
        # was refused as `shared_receiver` because two other certificates go
        # to the same receiver. They share the receiver, not a directory -
        # each has its own - so nothing the deletion removes is theirs.
        #
        policy_path = self.prepared(
            {
                "one.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]},
                "two.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]},
            }
        )
        report = self.run_delete(policy_path, "one.example")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "removed", outcome)
        self.assertFalse((self.receiver_dir / "one.example").exists())
        self.assertTrue((self.receiver_dir / "two.example" / FULLCHAIN).exists())

    def test_a_certificate_a_committed_object_names(self) -> None:
        guards = Guards(referenced={"example.com": ("alpha/shop",)})
        report = self.run_delete(self.policy_path, "example.com", guards=guards)
        self.assert_untouched(report, "example.com", "referenced_by_object")
        self.assertIn("alpha/shop", report.outcomes[0].reason)

    def test_a_cluster_s_default_certificate(self) -> None:
        guards = Guards(defaults={"example.com": ("alpha",)})
        report = self.run_delete(self.policy_path, "example.com", guards=guards)
        self.assert_untouched(report, "example.com", "cluster_default")

    def test_a_cluster_s_last_certificate(self) -> None:
        """The keeper is beta's only certificate; taking it would make beta unloadable."""

        report = self.run_delete(self.policy_path, "keeper-beta.example")
        self.assert_untouched(report, "keeper-beta.example", "cluster_uncovered")

    def test_the_second_of_two_that_cover_a_cluster_together(self) -> None:
        """Guards see the first deletion: the registry is re-read between certificates."""

        report = self.run_delete(self.policy_path, "example.com", "keeper-alpha.example")
        self.assertEqual(report.removed, ("example.com",))
        self.assertEqual(report.refused, ("keeper-alpha.example",))
        self.assertEqual(report.outcomes[1].code, "cluster_uncovered")
        self.assertEqual(self.registered(), {"keeper-alpha.example", "keeper-beta.example"})


class WhatGoes(DeleteFixture):
    def test_every_layer_is_removed_and_reported(self) -> None:
        policy_path = self.prepared(
            {
                "example.com": {
                    "source": {"kind": "acme"},
                    "clusters": ["alpha"],
                    "receivers": ["lb-01"],
                }
            }
        )
        report = self.run_delete(policy_path, "example.com")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "removed", outcome)
        self.assertNotIn("example.com", self.registered())
        self.assertFalse(self.copy("example.com").exists())
        self.assertFalse((self.receiver_dir / FULLCHAIN).exists())
        self.assertFalse((self.receiver_dir / PRIVKEY).exists())
        self.assertEqual(
            self.certbot_calls,
            [
                (
                    "/usr/bin/certbot",
                    "delete",
                    "--cert-name",
                    "example.com",
                    "--non-interactive",
                    "--quiet",
                )
            ],
        )
        self.assertEqual(
            self.node_calls,
            [("node-a.example.com", "example.com"), ("node-b.example.com", "example.com")],
        )
        states = {layer.name: layer.state for layer in outcome.layers}
        self.assertEqual(states["registry"], "removed")
        self.assertEqual(states["lineage example.com"], "removed")
        self.assertEqual({copy.state for copy in outcome.nodes}, {"removed"})
        #
        # The keepers, and their material, are exactly as they were.
        #
        self.assertTrue(self.copy("keeper-alpha.example").exists())
        self.assertTrue((self.renewal / "keeper-alpha.example.conf").exists())

    def test_every_cluster_s_copy_goes(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha", "beta"]}}
        )
        report = self.run_delete(policy_path, "example.com")

        self.assertEqual(report.removed, ("example.com",))
        self.assertFalse(self.copy("example.com", "alpha").exists())
        self.assertFalse(self.copy("example.com", "beta").exists())
        removed = {layer.name for layer in report.outcomes[0].layers if layer.state == "removed"}
        self.assertLessEqual(
            {str(self.copy("example.com", "alpha")), str(self.copy("example.com", "beta"))},
            removed,
        )
        self.assertTrue(self.copy("keeper-beta.example", "beta").exists())

    def test_an_explicit_lineage_name_is_the_one_certbot_is_asked_for(self) -> None:
        policy_path = self.prepared(
            {
                "wild": {
                    "source": {"kind": "acme", "lineage": "example.com-wildcard"},
                    "clusters": ["alpha"],
                }
            }
        )
        (self.renewal / "example.com-wildcard.conf").write_text("version = 5.8.0\n")
        report = self.run_delete(policy_path, "wild")
        self.assertEqual(report.removed, ("wild",))
        self.assertEqual(self.certbot_calls[0][3], "example.com-wildcard")

    def test_an_imported_certificate_loses_its_store_directory_not_a_lineage(self) -> None:
        policy_path = self.prepared(
            {"imported.example": {"source": {"kind": "import"}, "clusters": ["alpha"]}}
        )
        (self.store / "imported.example").mkdir()
        (self.store / "imported.example" / "fullchain.pem").write_text("x\n")
        report = self.run_delete(policy_path, "imported.example")
        self.assertEqual(report.removed, ("imported.example",))
        self.assertFalse((self.store / "imported.example").exists())
        self.assertEqual(self.certbot_calls, [])

    def test_a_key_left_by_an_interrupted_swap_goes_with_the_certificate(self) -> None:
        policy_path = self.prepared(
            {"imported.example": {"source": {"kind": "import"}, "clusters": ["alpha"]}}
        )
        leftover = self.store / ".imported.example.replaced"
        leftover.mkdir()
        (leftover / "privkey.pem").write_text("KEY\n")
        report = self.run_delete(policy_path, "imported.example")
        self.assertEqual(report.removed, ("imported.example",))
        self.assertFalse(leftover.exists())

    def test_an_ndes_request_goes_with_the_certificate_registered_or_not(self) -> None:
        """The request directory holds a key and the targets; left behind it
        made the ID unusable and the profile unremovable (review 2026-09-17,
        finding 2). With an NDES block in the policy it is a layer of its
        own; a request the CA still holds is deletable by name alone."""

        from haprion import ndes_renew
        from haprion.ndes_state import renewal_record, request_directory

        policy_path = self.prepared(
            {
                "enrolled.example": {
                    "source": {"kind": "import", "ndes_profile": "certserver1"},
                    "clusters": ["alpha"],
                }
            }
        )
        policy = yaml.safe_load(policy_path.read_text())
        state = self.root / "ndes-requests"
        state.mkdir(mode=0o700)
        ca = self.root / "ndes-ca.pem"
        ca.write_text("ca\n")
        policy["ndes"] = {
            "endpoint": "https://ca.example.com/certsrv/mscep/mscep.dll",
            "tls_ca": str(ca),
            "issuing_ca": str(ca),
            "client_root": str(self.root / "scep"),
            "state_root": str(state),
            "profiles": {
                "directory": str(self.root / "ndes-profiles"),
                "private_keys": [str(self.root / "ndes-profile.key")],
            },
        }
        policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        for certificate_id in ("enrolled.example", "waiting.example"):
            directory = request_directory(state, certificate_id)
            directory.mkdir(mode=0o700)
            (directory / "request.json").write_text(f'{{"certificate": "{certificate_id}"}}')
            (directory / "privkey.pem").write_text("key\n")
        #
        # The renewal pass's word about the certificate goes with it: left, a
        # new certificate under the same ID read the old failure (review
        # 2026-10-29, round 2, BBB01).
        #
        ndes_renew.write_record(
            state,
            ndes_renew.Outcome("enrolled.example", "failed", "CA_REJECTED"),
            now=datetime(2026, 9, 15, tzinfo=UTC),
        )

        report = self.run_delete(policy_path, "enrolled.example")
        self.assertEqual(report.removed, ("enrolled.example",))
        self.assertFalse(request_directory(state, "enrolled.example").exists())
        self.assertIsNone(renewal_record(state, "enrolled.example"))
        self.assertIn(
            ("NDES request enrolled.example", "removed"),
            [(layer.name, layer.state) for layer in report.outcomes[0].layers],
        )

        self.nodes_have_nothing()
        report = self.run_delete(policy_path, "waiting.example")
        self.assertEqual(report.removed, ("waiting.example",))
        self.assertFalse(request_directory(state, "waiting.example").exists())

    def test_a_missing_lineage_or_file_is_absent_not_failed(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        (self.renewal / "example.com.conf").unlink()
        self.copy("example.com").unlink()
        report = self.run_delete(policy_path, "example.com")
        self.assertEqual(report.removed, ("example.com",))
        self.assertEqual({layer.state for layer in report.outcomes[0].layers[:-1]}, {"absent"})
        self.assertEqual(self.certbot_calls, [])

    def test_the_run_holds_the_publisher_s_lock_and_gives_up_after_the_wait(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        handle = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, handle)
        fcntl.flock(handle, fcntl.LOCK_EX)
        with (
            unittest.mock.patch.object(cert_delete, "publish_lock", wraps=publish_lock) as held,
            unittest.mock.patch("haprion.cert_publish.LOCK_WAIT_SECONDS", 0),
            self.assertRaises(cert_delete.DeleteError) as refused,
        ):
            self.run_delete(policy_path, "example.com")
        self.assertEqual(refused.exception.code, "operation_locked")
        self.assertEqual(held.call_args.args, (self.lock,))
        self.assertIn("example.com", self.registered())
        self.assertTrue(self.copy("example.com").exists())


class WhatIsLeftAndSaid(DeleteFixture):
    def test_a_node_that_does_not_know_the_verb_keeps_its_copy_by_name(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.node_answers["node-b.example.com"] = (1, "unknown request: cert-remove")
        report = self.run_delete(policy_path, "example.com")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "incomplete")
        self.assertNotIn("example.com", self.registered())
        copies = {copy.node: copy.state for copy in outcome.nodes}
        self.assertEqual(copies, {"node-a": "removed", "node-b": "kept"})
        self.assertIn("unknown request", outcome.nodes[1].detail)

    def test_an_unreachable_node_is_said_and_the_batch_continues(self) -> None:
        policy_path = self.prepared(
            {
                "one.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "two.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        self.node_answers["node-a.example.com"] = (255, "connection refused")
        report = self.run_delete(policy_path, "one.example", "two.example")
        self.assertEqual(report.incomplete, ("one.example", "two.example"))
        self.assertEqual(report.outcomes[0].nodes[0].state, "unreachable")

    def test_a_certbot_failure_keeps_the_lineage_row_and_the_rest_goes(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        working = self.certbot
        self.certbot = lambda command: (1, "certbot: No certificate found")  # type: ignore[method-assign]
        report = self.run_delete(policy_path, "example.com")
        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "incomplete")
        lineage = [layer for layer in outcome.layers if layer.name.startswith("lineage")][0]
        self.assertEqual(lineage.state, "failed")
        self.assertIn("No certificate found", lineage.detail)
        self.assertFalse(self.copy("example.com").exists())
        #
        # The entry stays, so the certificate is still there to delete again;
        # with certbot answering, the second run finishes it.
        #
        self.assertEqual(outcome.layers[-1].state, "kept")
        self.assertIn("example.com", self.registered())
        self.certbot = working  # type: ignore[method-assign]
        again = self.run_delete(policy_path, "example.com")
        self.assertEqual(again.removed, ("example.com",))
        self.assertNotIn("example.com", self.registered())

    def test_a_deleted_certificate_s_leftover_node_copy_is_removed_by_name(self) -> None:
        """A node that missed the first run - unreachable then - is asked again."""

        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.node_answers["node-b.example.com"] = (255, "connection refused")
        first = self.run_delete(policy_path, "example.com")
        self.assertEqual(first.incomplete, ("example.com",))
        self.assertNotIn("example.com", self.registered())

        self.node_answers["node-a.example.com"] = (0, "[ts] example.com was not present.")
        del self.node_answers["node-b.example.com"]
        again = self.run_delete(policy_path, "example.com")
        (outcome,) = again.outcomes
        self.assertEqual(outcome.state, "removed")
        self.assertEqual({layer.state for layer in outcome.layers}, {"absent"})
        self.assertEqual(
            {(copy.cluster, copy.node): copy.state for copy in outcome.nodes},
            {
                ("alpha", "node-a"): "absent",
                ("alpha", "node-b"): "removed",
                ("beta", "node-a"): "absent",
                ("beta", "node-b"): "removed",
            },
        )

    def test_a_copy_left_in_any_cluster_s_directory_is_removed_by_name(self) -> None:
        """Without the entry the search is by ID, in every cluster's directory (B358)."""

        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.node_answers["node-b.example.com"] = (255, "connection refused")
        self.assertEqual(self.run_delete(policy_path, "example.com").incomplete, ("example.com",))
        stray = self.copy("example.com", "beta")
        stray.write_text("pem\n", encoding="utf-8")

        del self.node_answers["node-b.example.com"]
        again = self.run_delete(policy_path, "example.com")

        self.assertFalse(stray.exists())
        self.assertIn(
            (str(stray), "removed"),
            [(layer.name, layer.state) for layer in again.outcomes[0].layers],
        )
        self.assertTrue(self.copy("keeper-beta.example", "beta").exists())


class TheGuardsReadTheCommittedObjects(DeleteFixture):
    def test_an_https_object_naming_the_certificate_is_found_at_head(self) -> None:
        policy_path = self.prepared(
            {
                "example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
                "unused.example": {"source": {"kind": "acme"}, "clusters": ["alpha"]},
            }
        )
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        shop = with_lines(("  protocol: http", "  protocol: https\n  certificate: example.com"))
        commit(runtime.clusters["alpha"].config_path, {"managed/proxies/shop.yaml": shop})
        commit(runtime.clusters["beta"].config_path, {"managed/proxies/.gitkeep": b""})

        guards = read_guards(runtime, ["example.com", "unused.example", "keeper-alpha.example"])

        self.assertEqual(guards.referenced, {"example.com": ("alpha/shop",)})
        #
        # The fixture defaults each cluster to the first certificate naming it.
        #
        self.assertEqual(guards.defaults, {"keeper-alpha.example": ("alpha",)})

    def test_a_pool_verifying_against_a_ca_names_it_too(self) -> None:
        """B276: removing a CA a pool verifies against is refused like a served certificate."""

        policy_path = self.prepared(
            {"corp-root": {"source": {"kind": "authority"}, "clusters": ["alpha"]}}
        )
        policy = load_policy(policy_path, require_secure=False)
        runtime = load_runtime_config(policy, require_secure=False)
        shop = with_lines(
            ("      - host: 192.0.2.10", "      - host: app.example.net"),
            (
                "    balance: roundrobin",
                "    balance: roundrobin\n    tls:\n      verify: ca\n      ca: corp-root",
            ),
        )
        commit(runtime.clusters["alpha"].config_path, {"managed/proxies/shop.yaml": shop})
        commit(runtime.clusters["beta"].config_path, {"managed/proxies/.gitkeep": b""})

        guards = read_guards(runtime, ["corp-root"])

        self.assertEqual(guards.referenced, {"corp-root": ("alpha/shop",)})


class TheHelper(DeleteFixture):
    def invoke(self, policy_path: Path, *certificate_ids: str) -> tuple[int, dict[str, Any], str]:
        request = cert_delete_helper.build_request(str(uuid.uuid4()), certificates=certificate_ids)
        output, errors = io.StringIO(), io.StringIO()
        code = cert_delete_helper.main(
            [],
            policy_path=policy_path,
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            renewal_directory=self.renewal,
            store=self.store,
            lock_path=self.lock,
            lineage_remover=self.certbot,
            node_remover=self.node,
            guards_reader=lambda runtime, ids: Guards(),
        )
        document = json.loads(output.getvalue()) if output.getvalue() else {}
        return code, document, errors.getvalue()

    def test_all_gone_is_done(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        code, document, _ = self.invoke(policy_path, "example.com")
        self.assertEqual(code, 0)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["removed"], ["example.com"])

    def test_one_refused_is_partial_with_a_warning_per_row(self) -> None:
        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        code, document, _ = self.invoke(policy_path, "example.com", "keeper-beta.example")
        self.assertEqual(code, exit_codes.PARTIAL)
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(document["result"]["refused"], ["keeper-beta.example"])
        self.assertEqual(document["warnings"][0]["code"], "cluster_uncovered")

    def test_kept_node_copies_make_a_partial_not_a_failure(self) -> None:
        """The first live run (job 578, 2026-09-13): nodes without the verb."""

        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.node_answers["node-a.example.com"] = (1, "unknown request: cert-remove")
        self.node_answers["node-b.example.com"] = (1, "unknown request: cert-remove")
        code, document, _ = self.invoke(policy_path, "example.com")
        self.assertEqual(code, exit_codes.PARTIAL)
        self.assertEqual(document["outcome"], "partial")
        self.assertEqual(document["result"]["incomplete"], ["example.com"])
        self.assertNotIn("example.com", self.registered())

    @unittest.skipIf(os.geteuid() == 0, "root can unlink from a read-only directory")
    def test_nothing_removed_at_all_is_failed(self) -> None:
        """Every layer refuses to go: the PEM cannot be unlinked, certbot fails, the nodes keep."""

        policy_path = self.prepared(
            {"example.com": {"source": {"kind": "acme"}, "clusters": ["alpha"]}}
        )
        self.alpha.chmod(0o500)
        self.addCleanup(self.alpha.chmod, 0o700)
        self.certbot = lambda command: (1, "certbot: locked")  # type: ignore[method-assign]
        self.node_answers["node-a.example.com"] = (1, "unknown request: cert-remove")
        self.node_answers["node-b.example.com"] = (1, "unknown request: cert-remove")
        code, document, _ = self.invoke(policy_path, "example.com")
        self.assertEqual(code, 1)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "delete_failed")
        self.assertEqual(document["result"]["incomplete"], ["example.com"])
        self.assertIn("example.com", self.registered())

    def test_already_gone_everywhere_is_done(self) -> None:
        """Asked again, a deletion finds nothing: the command said 0, the helper `blocked` (4-1)."""

        policy_path = self.prepared({})
        self.nodes_have_nothing()
        code, document, _ = self.invoke(policy_path, "nobody.example")
        self.assertEqual(code, exit_codes.OK)
        self.assertEqual(document["outcome"], "done")
        self.assertEqual(document["result"]["certificates"][0]["code"], "not_registered")

    def test_every_one_refused_is_blocked_and_nothing_is_touched(self) -> None:
        policy_path = self.prepared({})
        self.nodes_have_nothing()
        before = (self.root / "certificates.yaml").read_bytes()
        code, document, _ = self.invoke(policy_path, "keeper-alpha.example", "nobody.example")
        self.assertEqual(code, exit_codes.BLOCKED)
        self.assertEqual(document["outcome"], "blocked")
        self.assertEqual(document["error"]["code"], "all_refused")
        self.assertEqual((self.root / "certificates.yaml").read_bytes(), before)

    def test_an_empty_list_and_an_argument_are_refused(self) -> None:
        policy_path = self.prepared({})
        code, document, _ = self.invoke(policy_path)
        self.assertEqual(code, 65)
        self.assertEqual(document["error"]["code"], "bad_input")
        self.assertEqual(
            cert_delete_helper.main(
                ["--help"], input_stream=io.BytesIO(b""), error_stream=io.StringIO()
            ),
            64,
        )


if __name__ == "__main__":
    unittest.main()


class DeletingABundleFollowsTheLayout(DeleteFixture):
    """The deletion's receiver layer reads the same layout the publisher wrote with."""

    def test_the_bundle_and_its_password_go_with_the_certificate(self) -> None:
        policy_path = self.prepared(
            {"certserver1.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]}}
        )
        registry = self.root / "certificates.yaml"
        raw = yaml.safe_load(registry.read_text())
        raw["certificates"]["certserver1.example"]["receivers"] = [
            {"id": "lb-01", "format": "pkcs12"}
        ]
        registry.write_text(yaml.safe_dump(raw), encoding="utf-8")
        registry.chmod(0o640)
        directory = self.receiver_dir / "certserver1.example"
        for stale in (FULLCHAIN, PRIVKEY):
            (directory / stale).unlink()
        (directory / "certserver1.example.pfx").write_bytes(b"bundle")
        (directory / "certserver1.example.password").write_text("pw\n", encoding="utf-8")

        report = self.run_delete(policy_path, "certserver1.example")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "removed", outcome)
        self.assertFalse(directory.exists())

    def test_the_pair_of_a_format_the_receiver_left_goes_too(self) -> None:
        """A receiver moved to PKCS#12 still has its old PEM pair (E06)."""

        policy_path = self.prepared(
            {"certserver1.example": {"source": {"kind": "acme"}, "receivers": ["lb-01"]}}
        )
        registry = self.root / "certificates.yaml"
        raw = yaml.safe_load(registry.read_text())
        raw["certificates"]["certserver1.example"]["receivers"] = [
            {"id": "lb-01", "format": "pkcs12"}
        ]
        registry.write_text(yaml.safe_dump(raw), encoding="utf-8")
        registry.chmod(0o640)
        directory = self.receiver_dir / "certserver1.example"
        (directory / "certserver1.example.pfx").write_bytes(b"bundle")
        (directory / "certserver1.example.password").write_text("pw\n", encoding="utf-8")
        self.assertTrue((directory / PRIVKEY).exists())

        report = self.run_delete(policy_path, "certserver1.example")

        (outcome,) = report.outcomes
        self.assertEqual(outcome.state, "removed", outcome)
        self.assertFalse(directory.exists())
