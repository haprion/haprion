from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import time
import unittest
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock
from uuid import uuid4

from haproxy_mgmt import node_bundle, node_restore
from haproxy_mgmt.cli import node_restore_ask, node_restore_helper
from haproxy_mgmt.cli.node_restore_helper import (
    DISCARD,
    PREPARE,
    PREVIEW,
    RUN,
    ParameterProblem,
)
from haproxy_mgmt.node_restore import Clock
from tests.contract_schema import assert_contract
from tests.restore_fixture import build
from tests.test_node_restore import (
    CLUSTER,
    FINGERPRINT,
    INSPECTED,
    PUBLISH_ROOT,
    TARGET_KEY,
    VERSION,
    FakeSession,
)

RUN_ID = "r260101-0000abcd"
TEST = {"hostname": "node-test", "address": "192.0.2.29/24", "vip": "198.51.100.254/32"}
COMMANDS = {
    PREPARE: "haproxy-node-restore-prepare",
    PREVIEW: "haproxy-node-restore-preview",
    RUN: "haproxy-node-restore",
    DISCARD: "haproxy-node-restore-discard",
}


class HelperTest(unittest.TestCase):
    def setUp(self) -> None:
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        self.backups = work / "backups"
        (self.backups / "node-a").mkdir(parents=True)
        shutil.move(build(work), self.backups / "node-a" / f"{VERSION}.tar.gz")
        self.root = work / "runs"
        FakeSession.calls = []
        FakeSession.answers = {"inspect": dict(INSPECTED)}
        self.silent = {"192.0.2.29", "192.0.2.21"}
        carried = work / "node-bundle.tar.gz"
        carried.write_bytes(b"the release's node bundle")
        self.bundle = node_bundle.ReleaseBundle(
            path=carried,
            root="haproxy-manager-node-0123456789ab",
            commit="0123456789ab" + "0" * 28,
            sha256=hashlib.sha256(carried.read_bytes()).hexdigest(),
        )

    def answering(self, address: str) -> bool:
        if address in self.silent and any(c[1]["op"] == "network" for c in FakeSession.calls):
            return True
        return address not in self.silent

    def engine(self) -> SimpleNamespace:
        """The real engine, with SSH, the host key scan and the clock replaced."""

        ticks = iter(range(10_000))
        return SimpleNamespace(
            node_of=node_restore.node_of,
            archive_path=node_restore.archive_path,
            read_json=node_restore.read_json,
            run_directory=node_restore.run_directory,
            discard=node_restore.discard,
            sweep=node_restore.sweep,
            prepare=partial(node_restore.prepare, source_of=lambda _: "192.0.2.7"),
            preview=partial(
                node_restore.preview,
                scan=lambda _: TARGET_KEY,
                fingerprint_of=lambda key: FINGERPRINT if key == TARGET_KEY else "SHA256:x",
                answering=self.answering,
                session_for=FakeSession,
                bundle_of=lambda: self.bundle,
            ),
            run=partial(
                node_restore.run,
                answering=self.answering,
                clock=Clock(now=lambda: float(next(ticks)), sleep=lambda _: None),
                session_for=FakeSession,
                bundle_of=lambda: self.bundle,
            ),
        )

    def ask(
        self,
        operation: str,
        parameters: dict[str, Any],
        *,
        cluster: str = "alpha",
        now: float | None = None,
    ) -> tuple[dict[str, Any], int]:
        request = node_restore_helper.build_request(operation, cluster, str(uuid4()), parameters)
        policy = SimpleNamespace(backup_root=self.backups, publish_root=PUBLISH_ROOT)
        runtime = SimpleNamespace(cluster=lambda _cluster: CLUSTER)
        output = io.StringIO()
        with (
            mock.patch.object(node_restore_helper, "load_policy", return_value=policy),
            mock.patch.object(node_restore_helper, "load_runtime_config", return_value=runtime),
        ):
            code = node_restore_helper.main(
                [],
                run_root=self.root,
                input_stream=io.BytesIO(request.encode()),
                output_stream=output,
                error_stream=io.StringIO(),
                require_root=False,
                engine=self.engine(),
                now=time.time if now is None else (lambda: now),
            )
        return assert_contract(COMMANDS[operation], output.getvalue()), code

    def prepared(self, test: dict[str, str] | None = TEST) -> None:
        document, code = self.ask(
            PREPARE,
            {
                "run": RUN_ID,
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "test": test,
            },
        )
        self.assertEqual((document["outcome"], code), ("done", 0), document)


class ThreeJobs(HelperTest):
    def test_prepare_answers_with_the_paste_line(self) -> None:
        document, code = self.ask(
            PREPARE,
            {
                "run": RUN_ID,
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "test": TEST,
            },
        )
        self.assertEqual(code, 0)
        self.assertIn(f"haproxy-restore-{RUN_ID}", document["result"]["paste"])
        self.assertEqual(document["result"]["mode"], "test")
        self.assertTrue((self.root / RUN_ID / "key").is_file())

    def test_a_run_that_exists_is_not_prepared_twice(self) -> None:
        self.prepared()
        document, code = self.ask(
            PREPARE,
            {
                "run": RUN_ID,
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "test": TEST,
            },
        )
        self.assertEqual((document["outcome"], code), ("blocked", 75))
        self.assertIn("already exists", document["error"]["message"])

    def test_preview_done_and_blocked_are_both_in_contract(self) -> None:
        self.prepared()
        document, code = self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": FINGERPRINT})
        self.assertEqual((document["outcome"], code), ("done", 0))
        self.assertEqual(document["result"]["plan"]["hostname"], "node-test")
        self.silent.discard("192.0.2.29")
        document, code = self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": FINGERPRINT})
        self.assertEqual((document["outcome"], code), ("blocked", 75))
        self.assertTrue(document["result"]["problems"])

    def test_a_wrong_fingerprint_is_blocked_without_a_plan(self) -> None:
        self.prepared()
        document, code = self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": "SHA256:" + "B" * 43})
        self.assertEqual((document["outcome"], code), ("blocked", 75))
        self.assertIsNone(document["result"])
        self.assertEqual(FakeSession.calls, [])

    def test_the_run_is_in_contract_and_carries_no_hashes(self) -> None:
        self.prepared()
        self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": FINGERPRINT})
        FakeSession.answers["network"] = {
            "ok": True,
            "rollback_unit": "u",
            "steps": [],
            "warnings": [],
        }
        document, code = self.ask(RUN, {"run": RUN_ID, "confirm": "node-test"})
        self.assertEqual((document["outcome"], code), ("done", 0), document)
        self.assertEqual(document["result"]["address"], "192.0.2.29")
        self.assertNotIn("$y$", json.dumps(document))

    def test_a_rolled_back_run_is_failed_with_the_field(self) -> None:
        self.prepared()
        self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": FINGERPRINT})
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        self.answering = lambda address: address == "192.0.2.120"  # type: ignore[method-assign]
        document, code = self.ask(RUN, {"run": RUN_ID, "confirm": "node-test"})
        self.assertEqual((document["outcome"], code), ("failed", 1))
        self.assertTrue(document["result"]["rolled_back"])
        self.assertEqual(document["error"]["code"], "restore_failed")

    def test_the_overwrite_ticks_reach_the_engine_through_the_helper(self) -> None:
        """What the web sends passes the protocol layer too, not only `validate` (job 1092)."""

        self.prepared()
        self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": FINGERPRINT})
        FakeSession.answers["network"] = {"ok": True, "rollback_unit": "u"}
        document, code = self.ask(
            RUN,
            {
                "run": RUN_ID,
                "confirm": "node-test",
                "backup_failed_ok": True,
                "break_traffic": False,
            },
        )
        self.assertEqual((document["outcome"], code), ("done", 0), document)

    def test_a_run_of_another_cluster_is_refused(self) -> None:
        self.prepared()
        request = node_restore_helper.build_request(
            PREVIEW, "beta", str(uuid4()), {"run": RUN_ID, "fingerprint": FINGERPRINT}
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                node_restore_helper,
                "load_policy",
                return_value=SimpleNamespace(backup_root=self.backups, publish_root=PUBLISH_ROOT),
            ),
            mock.patch.object(
                node_restore_helper,
                "load_runtime_config",
                return_value=SimpleNamespace(cluster=lambda _c: CLUSTER),
            ),
        ):
            code = node_restore_helper.main(
                [],
                run_root=self.root,
                input_stream=io.BytesIO(request.encode()),
                output_stream=output,
                error_stream=io.StringIO(),
                require_root=False,
                engine=self.engine(),
            )
        self.assertEqual(code, 75)
        self.assertIn("belongs to cluster alpha", output.getvalue())


class Discard(HelperTest):
    def test_discard_removes_the_run_and_says_so(self) -> None:
        self.prepared()
        document, code = self.ask(DISCARD, {"run": RUN_ID})
        self.assertEqual((document["outcome"], code), ("done", 0))
        self.assertEqual(document["result"], {"run": RUN_ID, "removed": True})
        self.assertFalse((self.root / RUN_ID).exists())
        # Already gone - swept, or discarded twice: nothing to remove, still done.
        document, code = self.ask(DISCARD, {"run": RUN_ID})
        self.assertEqual(document["result"]["removed"], False)

    def test_a_run_of_another_cluster_is_not_discarded(self) -> None:
        self.prepared()
        document, code = self.ask(DISCARD, {"run": RUN_ID}, cluster="beta")
        self.assertEqual((document["outcome"], code), ("blocked", 75))
        self.assertTrue((self.root / RUN_ID).is_dir())

    def test_a_step_past_the_hour_is_refused_in_words_then_swept(self) -> None:
        self.prepared()
        after = time.time() + node_restore.START_WINDOW + 60
        document, code = self.ask(PREVIEW, {"run": RUN_ID, "fingerprint": FINGERPRINT}, now=after)
        self.assertEqual((document["outcome"], code), ("blocked", 75))
        self.assertIn("has expired", document["error"]["message"])
        self.assertFalse((self.root / RUN_ID).exists())

    def test_every_call_sweeps_the_runs_past_their_hour(self) -> None:
        self.prepared()
        other = "r260101-0000beef"
        document, _code = self.ask(
            PREPARE,
            {
                "run": other,
                "node": "node-a",
                "archive": VERSION,
                "target": "192.0.2.120",
                "test": TEST,
            },
            now=time.time() + node_restore.START_WINDOW + 60,
        )
        self.assertEqual(document["outcome"], "done")
        # The first run's hour is past by the second call's clock; the second is new.
        self.assertFalse((self.root / RUN_ID).exists())
        self.assertTrue((self.root / other).is_dir())


class Parameters(unittest.TestCase):
    def test_each_operation_takes_exactly_its_keys(self) -> None:
        with self.assertRaises(ParameterProblem):
            node_restore_helper.validate(PREVIEW, {"run": RUN_ID})
        with self.assertRaises(ParameterProblem):
            node_restore_helper.validate(RUN, {"run": RUN_ID, "confirm": "x", "force": True})

    def test_values_are_held_to_their_patterns(self) -> None:
        good = {
            "run": RUN_ID,
            "node": "node-a",
            "archive": VERSION,
            "target": "192.0.2.1",
            "test": None,
        }
        node_restore_helper.validate(PREPARE, good)
        for key, value in (
            ("run", "../x"),
            ("archive", "../node-b/x"),
            ("target", "node-a.example.com"),
            ("test", {"hostname": "x", "address": "192.0.2.29", "vip": "198.51.100.1/32"}),
            (
                "test",
                {"hostname": "Bad_Name", "address": "192.0.2.29/24", "vip": "198.51.100.1/32"},
            ),
        ):
            with self.assertRaises(ParameterProblem, msg=f"{key}={value!r}"):
                node_restore_helper.validate(PREPARE, {**good, key: value})
        with self.assertRaises(ParameterProblem):
            node_restore_helper.validate(PREVIEW, {"run": RUN_ID, "fingerprint": "SHA256:short"})

    def test_the_fingerprint_is_read_out_of_the_line_the_console_printed(self) -> None:
        bare = "SHA256:" + "Ab+/" * 10 + "Ab+"
        line = f"256 {bare} root@node-test (ED25519)"
        self.assertEqual(node_restore_helper.fingerprint_in(line), bare)
        self.assertEqual(node_restore_helper.fingerprint_in(f"  {bare}\n"), bare)
        # Nothing that looks like one: given back as typed, for validate to refuse.
        self.assertEqual(node_restore_helper.fingerprint_in(" SHA256:short "), "SHA256:short")
        # One character too many is not a fingerprint with a tail.
        self.assertEqual(node_restore_helper.fingerprint_in(bare + "A"), bare + "A")

    def test_the_overwrite_ticks_are_optional_booleans(self) -> None:
        """B183: a request from before Overwrite node is exactly what it was."""

        prepare = {
            "run": RUN_ID,
            "node": "node-a",
            "archive": "2026-01-01_04-00-00",
            "target": "192.0.2.21",
            "test": None,
        }
        node_restore_helper.validate(PREPARE, prepare)
        self.assertEqual(node_restore_helper.mode_of(prepare), "new_vm")
        self.assertEqual(node_restore_helper.mode_of({**prepare, "test": TEST}), "test")
        # B184: as the node is one request; the preview says which case it is.
        with self.assertRaises(ParameterProblem):
            node_restore_helper.validate(PREPARE, {**prepare, "overwrite": True})
        run = {"run": RUN_ID, "confirm": "node-a"}
        node_restore_helper.validate(RUN, run)
        node_restore_helper.validate(RUN, {**run, "backup_failed_ok": True, "break_traffic": False})
        with self.assertRaises(ParameterProblem):
            node_restore_helper.validate(RUN, {**run, "break_traffic": 1})
        with self.assertRaises(ParameterProblem):
            node_restore_helper.validate(
                PREVIEW, {"run": RUN_ID, "fingerprint": "x", "overwrite": True}
            )

    def test_the_helper_takes_no_arguments_and_runs_as_root(self) -> None:
        self.assertEqual(node_restore_helper.main(["x"], error_stream=io.StringIO()), 64)


class Ask(unittest.TestCase):
    def test_an_absent_socket_is_a_dependency_failure_in_contract(self) -> None:
        request = node_restore_helper.build_request(
            PREVIEW, "alpha", str(uuid4()), {"run": RUN_ID, "fingerprint": FINGERPRINT}
        )
        output = io.StringIO()
        code = node_restore_ask.main(
            [],
            input_stream=io.BytesIO(request.encode()),
            output_stream=output,
            error_stream=io.StringIO(),
            socket_path="/nonexistent/node-restore.sock",
        )
        self.assertEqual(code, 78)
        document = assert_contract("haproxy-node-restore-preview", output.getvalue())
        self.assertEqual(document["error"]["code"], "dependency_unavailable")

    def test_the_client_gives_up_no_later_than_systemd_stops_the_helper(self) -> None:
        unit = (
            Path(__file__).resolve().parents[1]
            / "install/platform/examples/haproxy-node-restore-helper@.service.example"
        ).read_text()
        minutes = int(unit.split("TimeoutStartSec=", 1)[1].split("min", 1)[0])
        self.assertLessEqual(node_restore_ask.TIMEOUT_SECONDS, minutes * 60)
        # And the worker's 900 s job timeout is longer still (ui/.../operations.py).
        self.assertLess(node_restore_ask.TIMEOUT_SECONDS, 900)


if __name__ == "__main__":
    unittest.main()
