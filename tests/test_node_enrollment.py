"""Adding and removing a node changes six files as one, or none of them (B211)."""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from haprion import change_journal
from haprion import node_enrollment as enrollment
from haprion.cli import node as node_command
from haprion.cli import node_helper
from haprion.config import Node, RuntimeConfig, load_policy, load_runtime_config
from haprion.node_enrollment import AskNode, Enrollment, EnrollmentError, Locations, Outcome
from haprion.status_collect import NodeResponse
from tests.contract_schema import assert_contract

BASE = Path(__file__).resolve().parents[1]
REQUEST_ID = "77777777-7777-4777-8777-777777777777"
SSH_KEYGEN = shutil.which("ssh-keygen")


def key(seed: int) -> str:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([seed]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode()}"


HOST_KEY, CONFIG_KEY, CERT_KEY = key(1), key(2), key(3)
EXISTING_LINE = (
    f'restrict,command="/usr/bin/rrsync -ro /srv/haprion/published" {key(9)} node-a config pull\n'
)


def block(**overrides: object) -> Enrollment:
    values: dict[str, object] = {
        "cluster": "alpha",
        "name": "node-c",
        "host": "node-c.example.com",
        "host_key": HOST_KEY,
        "config_pull_key": CONFIG_KEY,
        "cert_pull_key": CERT_KEY,
    }
    values.update(overrides)
    return Enrollment(**values)  # type: ignore[arg-type]


def answering(node: str = "node-c", cluster: str = "alpha", *, owner: bool = False) -> AskNode:
    def ask(_node: Node) -> NodeResponse:
        return NodeResponse(
            exit_code=0,
            stdout=json.dumps({"node": node, "cluster": cluster, "vip": {"owner": owner}}),
        )

    return ask


def silent(_node: Node) -> NodeResponse:
    return NodeResponse(exit_code=255, stdout="")


class Installation:
    """A policy, a cluster file and the five other files, in a directory."""

    def __init__(self, root: Path, *, collector: bool = True, certificates: bool = True):
        self.root = root
        clusters = yaml.safe_load((BASE / "examples" / "clusters.yaml").read_text())
        self.cluster_file = root / "clusters.yaml"
        self.cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False))
        policy = yaml.safe_load((BASE / "examples" / "runtime-policy.yaml").read_text())
        policy["cluster_file"] = str(self.cluster_file)
        if certificates:
            policy["certificate_root"] = "/srv/certdist"
        policy_file = root / "runtime-policy.yaml"
        policy_file.write_text(yaml.safe_dump(policy, sort_keys=False))
        self.policy = load_policy(policy_file, require_secure=False)

        for account in ("_haprion-pull", "_haprion-cert-pull"):
            (root / account / ".ssh").mkdir(parents=True)
            (root / account / ".ssh" / "authorized_keys").write_text(EXISTING_LINE)
        self.known_hosts = root / "known_hosts"
        self.known_hosts.write_text(
            enrollment.hashed_host_line("node-a.example.com", key(8)) + "\n"
        )
        self.collector = root / "collector.json"
        self.collector_known = root / "collector_known_hosts"
        if collector:
            self.collector.write_text(
                json.dumps({"nodes": [{"cluster": "alpha", "node": "node-a", "host": "a"}]})
            )
            self.collector_known.write_text("")
        self.locations = Locations(
            root_known_hosts=self.known_hosts,
            collector_config=self.collector,
            collector_known_hosts=self.collector_known,
            journal=root / ".journal" / "change-journal.json",
            home=lambda account: root / account,
        )
        (root / ".journal").mkdir()

    def runtime(self) -> RuntimeConfig:
        return load_runtime_config(self.policy, require_secure=False)

    def snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if path.is_file()
        }

    def add(
        self,
        entry: Enrollment | None = None,
        *,
        host: str = "node-c.example.com",
        ask: AskNode | None = None,
    ) -> Outcome:
        return enrollment.add(
            self.policy,
            self.runtime(),
            entry or block(),
            cluster="alpha",
            host=host,
            ask=ask or answering(),
            locations=self.locations,
            require_secure=False,
        )


class TheBlock(unittest.TestCase):
    def test_a_rendered_block_reads_back_even_when_a_terminal_folds_it(self) -> None:
        text = enrollment.render(block())
        folded = "\n".join(text[i : i + 60] for i in range(0, len(text), 60))

        self.assertEqual(enrollment.parse(folded), block())

    def test_the_fingerprint_is_the_one_ssh_keygen_prints(self) -> None:
        if SSH_KEYGEN is None:
            self.skipTest("ssh-keygen is not installed")
        with tempfile.NamedTemporaryFile("w", suffix=".pub") as handle:
            handle.write(HOST_KEY + "\n")
            handle.flush()
            printed = subprocess.run(
                [SSH_KEYGEN, "-lf", handle.name], capture_output=True, text=True, check=True
            ).stdout.split()[1]

        self.assertEqual(enrollment.fingerprint(HOST_KEY), printed)

    def test_anything_but_a_block_is_refused_by_name(self) -> None:
        for text in ("", "ssh-ed25519 AAAA", enrollment.BLOCK_PREFIX + "!!!"):
            with self.subTest(text=text), self.assertRaises(EnrollmentError):
                enrollment.parse(text)

    def test_a_key_that_is_not_ed25519_is_refused(self) -> None:
        with self.assertRaisesRegex(EnrollmentError, "not an ssh-ed25519 key"):
            enrollment.public_key("ssh-rsa AAAAB3NzaC1yc2E=", "the host key")


class KnownHosts(unittest.TestCase):
    def test_a_hashed_line_is_found_by_ssh_keygen(self) -> None:
        if SSH_KEYGEN is None:
            self.skipTest("ssh-keygen is not installed")
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "known_hosts"
            path.write_text(enrollment.hashed_host_line("node-c.example.com", HOST_KEY) + "\n")
            found = subprocess.run(
                [SSH_KEYGEN, "-F", "node-c.example.com", "-f", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(found.returncode, 0)

    def test_removal_takes_hashed_and_plain_lines_and_leaves_comments(self) -> None:
        text = (
            "# kept\n"
            + enrollment.hashed_host_line("node-c.example.com", HOST_KEY)
            + "\n"
            + f"node-c.example.com,192.0.2.3 {HOST_KEY}\n"
            + enrollment.hashed_host_line("node-a.example.com", key(8))
            + "\n"
        ).encode()

        left = enrollment.known_hosts_without(text, "node-c.example.com").decode()

        self.assertEqual(left.count("\n"), 2)
        self.assertIn("# kept", left)
        self.assertIn(key(8), left)


class AddingANode(unittest.TestCase):
    def test_all_six_files_gain_the_node(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))

            outcome = site.add()

            self.assertEqual(len(outcome.files), 6)
            nodes = site.runtime().cluster("alpha").nodes
            self.assertEqual(nodes[-1], Node(name="node-c", mgmt_host="node-c.example.com"))
            pull = (site.root / "_haprion-pull/.ssh/authorized_keys").read_text()
            self.assertIn(EXISTING_LINE, pull)
            self.assertIn(
                'restrict,command="/usr/bin/rrsync -ro /srv/haprion/published" '
                f"{CONFIG_KEY} node-c config pull\n",
                pull,
            )
            self.assertIn(
                f'-ro /srv/certdist" {CERT_KEY} node-c certificate pull',
                (site.root / "_haprion-cert-pull/.ssh/authorized_keys").read_text(),
            )
            self.assertEqual(
                enrollment.known_hosts_without(site.known_hosts.read_bytes(), "node-c.example.com")
                .decode()
                .count("\n"),
                1,
            )
            self.assertIn(
                {"cluster": "alpha", "node": "node-c", "host": "node-c.example.com"},
                json.loads(site.collector.read_text())["nodes"],
            )
            self.assertEqual(outcome.fingerprint, enrollment.fingerprint(HOST_KEY))

    def test_a_node_that_does_not_answer_leaves_every_file_as_it_was(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            before = site.snapshot()

            with self.assertRaises(EnrollmentError) as caught:
                site.add(ask=silent)

            self.assertEqual(caught.exception.code, "node_unverified")
            self.assertEqual(site.snapshot(), before)

    def test_a_node_answering_as_another_node_is_undone(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            before = site.snapshot()

            with self.assertRaisesRegex(EnrollmentError, "answered as 'node-x'"):
                site.add(ask=answering(node="node-x"))

            self.assertEqual(site.snapshot(), before)

    def test_a_write_failing_part_way_puts_back_what_was_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            before = site.snapshot()
            real = change_journal.write_like
            calls = {"n": 0}

            def failing(path: Path, content: bytes) -> None:
                calls["n"] += 1
                if calls["n"] == 3:
                    raise OSError("disk full")
                real(path, content)

            change_journal.write_like = failing
            try:
                with self.assertRaises(OSError):
                    site.add()
            finally:
                change_journal.write_like = real

            self.assertEqual(site.snapshot(), before)

    def test_a_block_for_another_cluster_is_refused_before_anything_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            before = site.snapshot()

            with self.assertRaisesRegex(EnrollmentError, "made for cluster 'beta'"):
                site.add(block(cluster="beta"))

            self.assertEqual(site.snapshot(), before)

    def test_a_name_or_host_already_in_use_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            existing = site.runtime().cluster("alpha").nodes[0]
            with self.assertRaisesRegex(EnrollmentError, "already a node"):
                site.add(block(name=existing.name))
            with self.assertRaisesRegex(EnrollmentError, "already"):
                site.add(host=existing.mgmt_host)

    def test_a_ninth_node_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            clusters = yaml.safe_load(site.cluster_file.read_text())
            clusters["clusters"]["alpha"]["nodes"] = [
                {"name": f"node-{index}", "mgmt_host": f"node-{index}.example.com"}
                for index in range(8)
            ]
            site.cluster_file.write_text(yaml.safe_dump(clusters, sort_keys=False))

            with self.assertRaisesRegex(EnrollmentError, "at most 8"):
                site.add()

    def test_an_installation_without_a_collector_changes_four_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw), collector=False)

            self.assertEqual(len(site.add().files), 4)

    def test_each_file_keeps_its_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            keys = site.root / "_haprion-pull/.ssh/authorized_keys"
            os.chmod(keys, 0o600)
            #
            # Not the 0600 a new temporary file is created with, so keeping the
            # mode is something the rename had to do rather than a coincidence.
            #
            os.chmod(site.cluster_file, 0o400)

            site.add()

            self.assertEqual(keys.stat().st_mode & 0o777, 0o600)
            self.assertEqual(site.cluster_file.stat().st_mode & 0o777, 0o400)


class RemovingANode(unittest.TestCase):
    def added(self, raw: str) -> Installation:
        site = Installation(Path(raw))
        site.add()
        return site

    def remove(self, site: Installation, name: str = "node-c", ask: AskNode = silent) -> Outcome:
        return enrollment.remove(
            site.policy,
            site.runtime(),
            cluster="alpha",
            name=name,
            ask=ask,
            locations=site.locations,
            require_secure=False,
        )

    def test_removal_takes_the_node_out_of_every_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)

            self.remove(site)

            self.assertNotIn(
                "node-c", [node.name for node in site.runtime().cluster("alpha").nodes]
            )
            for account in ("_haprion-pull", "_haprion-cert-pull"):
                keys = (site.root / account / ".ssh/authorized_keys").read_text()
                self.assertNotIn("node-c", keys)
                self.assertIn("node-a config pull", keys)
            self.assertEqual(site.known_hosts.read_text().count("\n"), 1)
            self.assertNotIn("node-c", site.collector.read_text())

    def test_the_node_holding_the_vip_is_not_removed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            before = site.snapshot()

            with self.assertRaises(EnrollmentError) as caught:
                self.remove(site, ask=answering(owner=True))

            self.assertEqual(caught.exception.code, "node_owns_vip")
            self.assertEqual(site.snapshot(), before)

    def test_a_cluster_keeps_two_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            name = site.runtime().cluster("alpha").nodes[0].name

            with self.assertRaisesRegex(EnrollmentError, "at least 2 nodes"):
                self.remove(site, name=name)


class ChangingAHost(unittest.TestCase):
    """The same node at another name (B295): the pinned key moves, or nothing does."""

    def added(self, raw: str) -> Installation:
        site = Installation(Path(raw))
        site.add()
        return site

    def move(
        self, site: Installation, host: str = "lb-03.example.com", ask: AskNode | None = None
    ) -> Outcome:
        return enrollment.change_host(
            site.policy,
            site.runtime(),
            cluster="alpha",
            name="node-c",
            host=host,
            ask=ask or answering(),
            locations=site.locations,
            require_secure=False,
        )

    def test_the_host_and_its_pinned_key_move_together(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            asked: list[Node] = []

            def ask(node: Node) -> NodeResponse:
                asked.append(node)
                return answering()(node)

            outcome = self.move(site, ask=ask)

            self.assertEqual(asked, [Node(name="node-c", mgmt_host="lb-03.example.com")])
            self.assertIn(
                Node(name="node-c", mgmt_host="lb-03.example.com"),
                site.runtime().cluster("alpha").nodes,
            )
            known = site.known_hosts.read_bytes()
            self.assertEqual(enrollment.host_keys(known, "lb-03.example.com"), [HOST_KEY])
            self.assertEqual(enrollment.host_keys(known, "node-c.example.com"), [])
            self.assertEqual(enrollment.host_keys(known, "node-a.example.com"), [key(8)])
            self.assertEqual(
                enrollment.host_keys(site.collector_known.read_bytes(), "lb-03.example.com"),
                [HOST_KEY],
            )
            self.assertIn(
                {"cluster": "alpha", "node": "node-c", "host": "lb-03.example.com"},
                json.loads(site.collector.read_text())["nodes"],
            )
            self.assertEqual(
                (outcome.previous_host, outcome.fingerprint),
                ("node-c.example.com", enrollment.fingerprint(HOST_KEY)),
            )
            self.assertEqual(len(outcome.files), 4)

    def test_a_node_that_does_not_answer_there_keeps_its_old_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            before = site.snapshot()

            with self.assertRaises(EnrollmentError) as caught:
                self.move(site, ask=silent)

            self.assertEqual(caught.exception.code, "node_unverified")
            self.assertIn("still reached at node-c.example.com", str(caught.exception))
            self.assertEqual(site.snapshot(), before)

    def test_another_node_answering_there_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            before = site.snapshot()

            with self.assertRaises(EnrollmentError):
                self.move(site, ask=answering(node="node-a"))

            self.assertEqual(site.snapshot(), before)

    def test_what_is_refused_before_anything_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = self.added(raw)
            before = site.snapshot()
            for host, code in (
                ("node-c.example.com", "host_unchanged"),
                ("node-a.example.com", "node_exists"),
            ):
                with self.subTest(host), self.assertRaises(EnrollmentError) as caught:
                    self.move(site, host=host)
                self.assertEqual(caught.exception.code, code)
            site.known_hosts.write_text("")
            with self.assertRaises(EnrollmentError) as caught:
                self.move(site)
            self.assertEqual(caught.exception.code, "host_key_unknown")
            site.known_hosts.write_bytes(before["known_hosts"])
            self.assertEqual(site.snapshot(), before)


class TheHelper(unittest.TestCase):
    """The request the worker and the terminal send, answered in an envelope."""

    def run_helper(
        self, site: Installation, request: str, *, ask: AskNode | None = None
    ) -> tuple[int, dict[str, object] | None, str]:
        out, err = io.StringIO(), io.StringIO()
        policy = site.root / "runtime-policy.yaml"
        code = node_helper.main(
            [],
            policy_path=policy,
            input_stream=io.BytesIO(request.encode()),
            output_stream=out,
            error_stream=err,
            require_secure=False,
            require_root=False,
            lock_root=site.root / "locks",
            locations=site.locations,
            ask=ask or answering(),
        )
        printed = out.getvalue()
        return code, json.loads(printed) if printed else None, err.getvalue()

    def test_an_addition_answers_with_what_changed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            request = node_helper.build_request(
                "alpha",
                REQUEST_ID,
                action="add",
                block=enrollment.render(block()),
                host="node-c.example.com",
            )

            code, document, err = self.run_helper(site, request)

            self.assertEqual((code, err), (0, ""))
            assert document is not None
            self.assertEqual(document["outcome"], "done")
            result = document["result"]
            assert isinstance(result, dict)
            self.assertEqual(result["action"], "added")
            self.assertEqual(result["node"], "node-c")
            self.assertEqual(result["host_key_fingerprint"], enrollment.fingerprint(HOST_KEY))

    def interrupted_addition(self, site: Installation) -> None:
        """An addition killed after its files were written, before the node answered."""
        changes = enrollment.plan_add(
            site.policy,
            site.runtime(),
            block(),
            cluster="alpha",
            host="node-c.example.com",
            locations=site.locations,
            require_secure=False,
        )
        change_journal._write_record(
            site.locations.journal, change_journal.Record("node add", "alpha", tuple(changes))
        )
        change_journal.apply(changes)

    def test_the_next_request_puts_back_an_interrupted_change_first(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            before = site.snapshot()
            self.interrupted_addition(site)
            self.assertNotEqual(site.snapshot(), before)
            request = node_helper.build_request(
                "alpha",
                REQUEST_ID,
                action="add",
                block=enrollment.render(block()),
                host="node-c.example.com",
            )

            # Without the recovery the node would already be there.
            code, document, err = self.run_helper(site, request)

            self.assertEqual(code, 0, document)
            self.assertIn("NOTICE: a node add of cluster 'alpha' did not finish", err)
            self.assertFalse(site.locations.journal.exists())
            nodes = [node.name for node in site.runtime().cluster("alpha").nodes]
            self.assertEqual(nodes.count("node-c"), 1)

    def test_an_interrupted_change_edited_since_refuses_the_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            self.interrupted_addition(site)
            site.known_hosts.write_text("edited by hand\n")
            during = site.snapshot()
            request = node_helper.build_request("alpha", REQUEST_ID, action="remove", node="node-a")

            code, document, _err = self.run_helper(site, request)

            self.assertEqual(code, 75)
            assert document is not None
            error = document["error"]
            assert isinstance(error, dict)
            self.assertEqual(error["code"], "change_interrupted")
            after = {name: data for name, data in site.snapshot().items() if "locks/" not in name}
            self.assertEqual(after, during)

    def test_a_damaged_block_is_refused_before_anything_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            before = site.snapshot()
            request = node_helper.build_request(
                "alpha", REQUEST_ID, action="add", block="not a block", host="node-c.example.com"
            )

            code, document, _err = self.run_helper(site, request)

            self.assertEqual(code, 65)
            assert document is not None
            error = document["error"]
            assert isinstance(error, dict)
            self.assertEqual(error["code"], "enrollment_invalid")
            self.assertEqual(site.snapshot(), before)

    def test_a_removal_names_its_node_and_nothing_else(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            request = node_helper.build_request(
                "alpha", REQUEST_ID, action="remove", node="node-a", host="x.example.com"
            )

            code, document, _err = self.run_helper(site, request)

            self.assertEqual(code, 65)
            assert document is not None
            self.assertIn("takes no host", str(document["error"]))

    def test_a_host_change_answers_with_the_old_and_the_new_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Installation(Path(raw))
            site.add()
            request = node_helper.build_request(
                "alpha", REQUEST_ID, action="host", node="node-c", host="lb-03.example.com"
            )

            code, document, err = self.run_helper(site, request)

            self.assertEqual((code, err), (0, ""))
            answer = assert_contract("haprion-cluster-node", json.dumps(document))
            self.assertEqual(
                (
                    answer["result"]["action"],
                    answer["result"]["host"],
                    answer["result"]["previous_host"],
                ),
                ("host_changed", "lb-03.example.com", "node-c.example.com"),
            )


class TheCommand(unittest.TestCase):
    def test_add_sends_the_block_and_the_host_and_says_what_is_next(self) -> None:
        sent: list[str] = []

        def run(request: str) -> subprocess.CompletedProcess[str]:
            sent.append(request)
            answer = {
                "operation": "cluster_node",
                "result": {
                    "action": "added",
                    "node": "node-c",
                    "host": "node-c.example.com",
                    "files": ["clusters.yaml"],
                    "host_key_fingerprint": "SHA256:x",
                },
            }
            return subprocess.CompletedProcess([], 0, json.dumps(answer), "")

        out = io.StringIO()
        code = node_command.main(
            ["add", "-c", "alpha", "--host", "node-c.example.com"],
            stdin=io.StringIO(enrollment.render(block())),
            stdout=out,
            run=run,
        )

        self.assertEqual(code, 0)
        parameters = json.loads(sent[0])["parameters"]
        self.assertEqual(parameters["host"], "node-c.example.com")
        self.assertEqual(enrollment.parse(parameters["block"]), block())
        self.assertIn("haprion-cert-deploy -c alpha, then haprion-deploy -c alpha", out.getvalue())

    def test_a_refusal_is_printed_as_its_sentence(self) -> None:
        def run(_request: str) -> subprocess.CompletedProcess[str]:
            answer = {
                "operation": "cluster_node",
                "error": {"code": "node_owns_vip", "message": "node-a holds the VIP right now."},
            }
            return subprocess.CompletedProcess([], 75, json.dumps(answer), "")

        err = io.StringIO()
        code = node_command.main(
            ["remove", "-c", "alpha", "node-a"], stdout=io.StringIO(), stderr=err, run=run
        )

        self.assertEqual(code, 1)
        self.assertIn("holds the VIP", err.getvalue())


class TheNodeSideBlock(unittest.TestCase):
    """`04-node-prepare` renders the block the manager parses; one format, held here."""

    def renderer(self) -> str:
        script = (BASE / "install" / "04-node-prepare").read_text()
        start = script.index("<<'PY'\n", script.index('step "Enrollment block"')) + len("<<'PY'\n")
        return script[start : script.index("\nPY\n", start)]

    def test_the_node_s_block_is_the_manager_s_block(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            files = []
            for index, value in enumerate((HOST_KEY, CONFIG_KEY, CERT_KEY)):
                path = Path(raw) / f"{index}.pub"
                path.write_text(f"{value} root@node-c\n")
                files.append(str(path))
            printed = subprocess.run(
                [sys.executable, "-", "alpha", "node-c", "node-c.example.com", *files],
                input=self.renderer(),
                capture_output=True,
                text=True,
                check=True,
            ).stdout

        self.assertEqual(enrollment.parse(printed), block())
        self.assertEqual(printed.strip(), enrollment.render(block()))

    def test_without_a_certificate_key_the_block_has_none(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host, config = Path(raw) / "h.pub", Path(raw) / "c.pub"
            host.write_text(HOST_KEY + "\n")
            config.write_text(CONFIG_KEY + "\n")
            printed = subprocess.run(
                [
                    sys.executable,
                    "-",
                    "alpha",
                    "node-c",
                    "node-c.example.com",
                    str(host),
                    str(config),
                    "",
                ],
                input=self.renderer(),
                capture_output=True,
                text=True,
                check=True,
            ).stdout

        self.assertIsNone(enrollment.parse(printed).cert_pull_key)


class TheInstallersKeepTheRecord(unittest.TestCase):
    """Once written, `clusters.yaml` is the record; a second install run keeps it (B211)."""

    def test_step_two_keeps_an_existing_cluster_file(self) -> None:
        step = (BASE / "install" / "02-manager-config").read_text()

        self.assertIn(
            'if [[ -f "$CLUSTER_FILE" && "${REWRITE_CLUSTER_FILE:-}" != yes ]]; then', step
        )

    def test_step_two_keeps_an_existing_runtime_policy(self) -> None:
        """The policy holds blocks no answer renders - the certificate registry,
        acme, ndes - so rendering it again from the answers would drop them."""

        step = (BASE / "install" / "02-manager-config").read_text()

        self.assertIn('if [[ -f "$POLICY_FILE" && "${REWRITE_POLICY:-}" != yes ]]; then', step)
