"""The manager's side of joining a new node (B317).

Held here: a v2 block names no cluster and carries the node's one-time key,
which no result or rendering of the stored block gives back; the block the
node's package prints is the one the manager reads; adding a v2 node joins it
first, with the manager's public keys and where the node belongs, and only
then asks it for its status - a join that fails puts every file back; a v1
block joins nothing; a key the web sealed opens only for the cluster and node
it was sealed for, in the root helper, and the helper never takes both a key
and a seal.
"""

from __future__ import annotations

import base64
import io
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from haprion import node_enrollment, node_join
from haprion.cli import node_helper
from haprion.config import Node, load_policy
from haprion.dns_profile_keys import generate, render_private_key
from haprion.node_enrollment import Enrollment, EnrollmentError
from haprion.status_collect import NodeResponse
from tests.contract_schema import published
from tests.test_node_enrollment import (
    CERT_KEY,
    CONFIG_KEY,
    HOST_KEY,
    REQUEST_ID,
    Installation,
    answering,
    key,
)

BASE = Path(__file__).resolve().parents[1]
SSH_KEYGEN = shutil.which("ssh-keygen")
# A made-up key in the key's armour; the armour named apart, as nothing real is.
ARMOUR = "OPENSSH PRIVATE KEY"
PRIVATE = (
    f"-----BEGIN {ARMOUR}-----\n"
    + "\n".join(["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"] * 5)
    + f"\n-----END {ARMOUR}-----\n"
)


def v2(**overrides: Any) -> Enrollment:
    values: dict[str, Any] = {
        "cluster": None,
        "name": "node-c",
        "host": "node-c.example.com",
        "host_key": HOST_KEY,
        "config_pull_key": CONFIG_KEY,
        "cert_pull_key": CERT_KEY,
        "join_key": PRIVATE,
    }
    values.update(overrides)
    return Enrollment(**values)


class TheV2Block(unittest.TestCase):
    def test_it_reads_back_with_its_key_and_without_a_cluster(self) -> None:
        text = node_enrollment.render(v2())
        self.assertTrue(text.startswith("haprion-node-v2:"))
        folded = "\n".join(text[i : i + 60] for i in range(0, len(text), 60))
        self.assertEqual(node_enrollment.parse(folded), v2())

    def test_stored_it_keeps_everything_but_the_key(self) -> None:
        stored = node_enrollment.render(node_enrollment.without_join_key(v2()))
        self.assertTrue(stored.startswith("haprion-node-v2:"))
        self.assertEqual(node_enrollment.parse(stored), v2(join_key=None))
        self.assertNotIn("join_key", v2().as_dict())
        self.assertNotIn("PRIVATE", repr(v2()))

    def test_a_block_a_node_printed_before_0_99_0_reads_the_same(self) -> None:
        """7-17: the old product name stays readable; it is never written."""

        text = node_enrollment.render(v2())
        legacy = node_enrollment.LEGACY_V2_PREFIX + text.removeprefix(
            node_enrollment.BLOCK_V2_PREFIX
        )

        self.assertEqual(node_enrollment.parse(legacy), v2())

    def test_a_cluster_in_a_v2_block_or_a_bad_key_is_refused(self) -> None:
        def encoded(document: dict[str, Any]) -> str:
            raw = json.dumps(document).encode()
            return "haprion-node-v2:" + base64.urlsafe_b64encode(raw).decode()

        good = json.loads(base64.urlsafe_b64decode(node_enrollment.render(v2())[16:]))
        for bad in (
            {**good, "cluster": "alpha"},
            {**good, "join_key": "not base64!"},
            {**good, "join_key": base64.b64encode(b"ssh-ed25519 AAAA").decode()},
        ):
            with self.subTest(bad=sorted(bad)), self.assertRaises(EnrollmentError):
                node_enrollment.parse(encoded(bad))

    def test_a_v2_block_is_made_for_any_cluster_and_a_v1_for_its_own(self) -> None:
        self.assertTrue(node_enrollment.made_for(v2(), "beta"))
        self.assertTrue(node_enrollment.made_for(v2(cluster="alpha", join_key=None), "alpha"))
        self.assertFalse(node_enrollment.made_for(v2(cluster="alpha", join_key=None), "beta"))


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen is not installed where the tests run")
class TheBlockTheNodePrints(unittest.TestCase):
    """haprion-node-key's own rendering, read by the manager's parser."""

    def test_the_package_s_block_is_the_manager_s(self) -> None:
        script = (BASE / "install" / "node" / "haprion-node-key").read_text()
        program = re.search(r"<<'PY'\n(.*?)\nPY\n", script, re.DOTALL)
        assert program
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {}
            for name in ("host", "config", "cert", "join"):
                paths[name] = root / name
                subprocess.run(  # a scratch key
                    [str(SSH_KEYGEN), "-q", "-t", "ed25519", "-N", "", "-f", str(paths[name])],
                    check=True,
                )
            printed = subprocess.run(  # the node's rendering under test
                [
                    "/usr/bin/python3",
                    "-",
                    "node-c",
                    "node-c.example.com",
                    f"{paths['host']}.pub",
                    f"{paths['config']}.pub",
                    f"{paths['cert']}.pub",
                    str(paths["join"]),
                ],
                input=program.group(1),
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            parsed = node_enrollment.parse(printed)
            public = " ".join(Path(f"{paths['host']}.pub").read_text().split()[:2])
            self.assertEqual(parsed.join_key, paths["join"].read_text())
        self.assertIsNone(parsed.cluster)
        self.assertEqual((parsed.name, parsed.host_key), ("node-c", public))


class Site(Installation):
    """An installation whose policy names the identities a join hands over."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        policy_file = root / "runtime-policy.yaml"
        document = yaml.safe_load(policy_file.read_text())
        self.handed: dict[str, str] = {}
        for number, (identity, purpose) in enumerate(
            node_enrollment.JOIN_PURPOSES.items(), start=20
        ):
            if purpose in {"probe", "cert_deploy"}:
                continue
            private = root / "keys" / identity
            private.parent.mkdir(exist_ok=True)
            Path(f"{private}.pub").write_text(f"{key(number)} manager {purpose}\n")
            document[identity] = {"key": str(private)}
            self.handed[purpose] = key(number)
        policy_file.write_text(yaml.safe_dump(document, sort_keys=False))
        self.policy = load_policy(policy_file, require_secure=False)
        self.manager_host_key = root / "ssh_host_ed25519_key.pub"
        self.manager_host_key.write_text(f"{key(40)} root@mgr\n")
        self.collector_key = root / "traffic-collector.pub"
        self.locations = replace(
            self.locations,
            manager_host_key=self.manager_host_key,
            collector_key=self.collector_key,
        )


class JoiningOnAdd(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = tempfile.mkdtemp(prefix="join-manager-")
        self.addCleanup(shutil.rmtree, self.raw, True)
        self.site = Site(Path(self.raw))
        self.calls: list[str] = []

    def joining(self, code: int = 0, stderr: str = "") -> Any:
        def join(node: Node, private: str, document: dict[str, Any]) -> NodeResponse:
            self.calls.append("join")
            self.joined = (node, private, document)
            return NodeResponse(exit_code=code, stdout="", stderr=stderr)

        return join

    def asking(self) -> Any:
        answer = answering()

        def ask(node: Node) -> NodeResponse:
            self.calls.append("ask")
            return answer(node)

        return ask

    def add(self, entry: Enrollment, join: Any) -> Any:
        return node_enrollment.add(
            self.site.policy,
            self.site.runtime(),
            entry,
            cluster="alpha",
            host="node-c.example.com",
            ask=self.asking(),
            join_node=join,
            locations=self.site.locations,
            require_secure=False,
        )

    def test_a_v2_node_is_joined_before_it_is_asked(self) -> None:
        self.add(v2(), self.joining())
        self.assertEqual(self.calls, ["join", "ask"])
        node, private, document = self.joined
        cluster = self.site.runtime().cluster("alpha")
        self.assertEqual((node.name, private), ("node-c", PRIVATE))
        self.assertEqual(
            document,
            {
                "version": 1,
                "cluster": "alpha",
                "node_path": cluster.node_path,
                "vip": cluster.vip,
                "manager_host_key": key(40),
                "keys": self.site.handed,
            },
        )

    def test_the_collector_s_key_goes_with_the_others_when_it_is_installed(self) -> None:
        """Fas 18 (26-10-16): the traffic log is a base function; the node turns it on."""

        self.site.collector_key.write_text(f"{key(41)} haprion traffic collector\n")
        self.add(v2(), self.joining())
        _node, _private, document = self.joined
        self.assertEqual(
            document["keys"],
            {**self.site.handed, node_enrollment.COLLECTOR_PURPOSE: key(41)},
        )

    def test_a_join_that_fails_puts_every_file_back(self) -> None:
        before = self.site.snapshot()
        with self.assertRaises(EnrollmentError) as caught:
            self.add(v2(), self.joining(75, "line one\npreparing this node stopped (exit 1)"))
        self.assertEqual(caught.exception.code, "node_join_failed")
        self.assertIn("preparing this node stopped (exit 1)", str(caught.exception))
        self.assertIn("haprion-node-key --again", str(caught.exception))
        # Review 26-10-24, 12-10: an expired block does not work again, and
        # the hours are the ones the node's key script gives a block.
        script = (Path(__file__).resolve().parents[1] / "install/node/haprion-node-key").read_text()
        [hours] = re.findall(r"^VALID_HOURS=(\d+)$", script, re.MULTILINE)
        self.assertIn(f"valid for {hours} hours and once", str(caught.exception))
        self.assertNotIn("works again", str(caught.exception))
        self.assertEqual(self.calls, ["join"])
        self.assertEqual(self.site.snapshot(), before)

    def test_a_v1_block_joins_nothing(self) -> None:
        self.add(v2(cluster="alpha", join_key=None), self.joining())
        self.assertEqual(self.calls, ["ask"])


class TheSeal(unittest.TestCase):
    def test_it_opens_for_its_cluster_and_node_only(self) -> None:
        private, public = generate()
        box = node_join.seal_join_key(public, cluster="alpha", node="node-c", key=PRIVATE)
        self.assertNotIn(b"PRIVATE", box)
        self.assertEqual(
            node_join.open_join_key(private, box, cluster="alpha", node="node-c"), PRIVATE
        )
        for cluster, node in (("beta", "node-c"), ("alpha", "node-d")):
            with self.subTest(cluster=cluster, node=node), self.assertRaises(EnrollmentError):
                node_join.open_join_key(private, box, cluster=cluster, node=node)
        other, _ = generate()
        with self.assertRaises(EnrollmentError):
            node_join.open_join_key(other, box, cluster="alpha", node="node-c")


class TheHelperOpensTheSeal(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = tempfile.mkdtemp(prefix="join-helper-")
        self.addCleanup(shutil.rmtree, self.raw, True)
        root = Path(self.raw)
        self.site = Site(root)
        self.private, self.public = generate()
        sealing = root / "seal.key"
        sealing.write_text(render_private_key(self.private))
        sealing.chmod(0o600)
        policy_file = root / "runtime-policy.yaml"
        document = yaml.safe_load(policy_file.read_text())
        (root / "profiles").mkdir(mode=0o700)
        document["acme"] = {
            "dns_profiles": {"directory": str(root / "profiles"), "private_keys": [str(sealing)]}
        }
        policy_file.write_text(yaml.safe_dump(document, sort_keys=False))
        self.joined: list[str] = []

    def run_helper(self, request: str) -> tuple[int, str]:
        def join(_node: Node, private: str, _document: dict[str, Any]) -> NodeResponse:
            self.joined.append(private)
            return NodeResponse(exit_code=0, stdout="")

        out, err = io.StringIO(), io.StringIO()
        code = node_helper.main(
            [],
            policy_path=Path(self.raw) / "runtime-policy.yaml",
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=Path(self.raw) / "locks",
            locations=self.site.locations,
            ask=answering(),
            join_node=join,
            publish=published,
        )
        return code, err.getvalue()

    def request(self, entry: Enrollment, sealed: dict[str, str] | None) -> str:
        return node_helper.build_request(
            "alpha",
            REQUEST_ID,
            action="add",
            block=node_enrollment.render(entry),
            host="node-c.example.com",
            join_key=sealed,
        )

    def sealed(self, cluster: str = "alpha") -> dict[str, str]:
        box = node_join.seal_join_key(self.public, cluster=cluster, node="node-c", key=PRIVATE)
        return {"key_id": self.public.key_id, "ciphertext": base64.b64encode(box).decode()}

    def test_a_sealed_key_is_opened_and_joined_with(self) -> None:
        code, err = self.run_helper(self.request(v2(join_key=None), self.sealed()))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.joined, [PRIVATE])

    def test_what_does_not_add_up_is_refused_before_a_join(self) -> None:
        for entry, sealed, code in (
            (v2(join_key=None), None, "enrollment_invalid"),
            (v2(), self.sealed(), "enrollment_invalid"),
            (v2(join_key=None), self.sealed("beta"), "join_key_mismatch"),
            (v2(cluster="alpha", join_key=None), self.sealed(), "enrollment_invalid"),
        ):
            with self.subTest(code=code):
                exit_code, err = self.run_helper(self.request(entry, sealed))
                self.assertNotEqual(exit_code, 0)
                self.assertIn(f"[{code}]", err)
        self.assertEqual(self.joined, [])


if __name__ == "__main__":
    unittest.main()
