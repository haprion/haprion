"""The install test's opt-in scenarios (B481): what can be held to without containers."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import generate, proxy_model, status_collect
from haprion.cli import objects_apply

BASE = Path(__file__).resolve().parents[1]


class TheScenariosAreOptIn(unittest.TestCase):
    def install_test(self) -> Any:
        loader = importlib.machinery.SourceFileLoader(
            "install_test_scenarios", str(BASE / "tools/install-test")
        )
        spec = importlib.util.spec_from_loader("install_test_scenarios", loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["install_test_scenarios"] = module
        self.addCleanup(sys.modules.pop, "install_test_scenarios", None)
        loader.exec_module(module)
        return module

    def test_there_are_three_and_a_release_run_starts_no_machine_limited(self) -> None:
        tool = self.install_test()

        self.assertEqual(sorted(tool.SCENARIOS), ["faults", "readdress", "scale"])
        with tempfile.TemporaryDirectory() as raw:
            run = tool.Run(tool.DISTRIBUTIONS["debian13"], Path(raw))
        self.assertEqual(run.limits, {})

    def test_a_scenario_installs_packages_and_nothing_else(self) -> None:
        text = (BASE / "tools/install-test").read_text()
        start = text.index("    if args.scenario and not args.packages:")

        self.assertIn('parser.error("--scenario installs --packages")', text[start : start + 200])

    def test_the_scale_scenario_holds_the_machines_to_the_documented_sizes(self) -> None:
        tool = self.install_test()
        install = (BASE / "docs/install.md").read_text()

        self.assertIn(
            "| Manager | one | Ubuntu 26.04 or Debian 13, amd64 | 2 vCPU, 4 GB memory |", install
        )
        self.assertEqual(tool.MANAGER_SIZE, ("--cpus", "2", "--memory", "4g"))
        self.assertEqual(tool.Scale().manager(), tool.MANAGER_SIZE)
        self.assertEqual(tool.Scale().node(), tool.NODE_SIZE)
        self.assertEqual(tool.Scale().objects, 10_000)
        self.assertIn("| HAProxy node |", install)
        self.assertEqual(tool.NODE_SIZE, ("--cpus", "1", "--memory", "1g"))

    def test_the_objects_it_generates_are_ones_the_product_accepts(self) -> None:
        """The generator's output, light and heavy, through the checks `haprion-objects apply` makes."""

        tool = self.install_test()
        for kind, servers in (("light", 3), ("heavy", 10)):
            with self.subTest(kind), tempfile.TemporaryDirectory() as raw:
                subprocess.run(  # the interpreter running this test, a script of the tool's own
                    [sys.executable, "-I", "-", "198.51.100.10", "25", raw, kind],
                    input=tool.SCALE_GENERATE,
                    text=True,
                    check=True,
                )
                documents = objects_apply.read_files([raw])
                plan = objects_apply.plan_apply(documents, {}, prune=False)
                #
                # And what the generator refuses of one object (26-11-06: the
                # heavy one sent two rewrites to one pool, and `apply --check`
                # refused it in the lab).
                #
                for name, document in sorted(documents.items())[:3]:
                    proxy = proxy_model.load_proxy(name, document.encode())
                    generate._rewrites_per_backend(proxy)

                self.assertEqual(len(documents), 25)
                self.assertEqual(len(plan.added), 25)
                self.assertEqual(sorted(documents)[:2], ["s0", "s1"])
                self.assertEqual(documents["s7"].count("port: "), servers)
                self.assertIn(kind, tool.COUNTERS_PER_OBJECT)

    def test_the_sizes_are_for_the_scale_scenario_only(self) -> None:
        tool = self.install_test()
        asked = ["install-test", "--packages", "/nowhere", "--no-upgrade"]
        for extra in (
            ["--objects", "2500"],
            ["--manager-cpus", "4"],
            ["--scenario", "faults", "--object-kind", "heavy"],
            ["--scenario", "scale", "--objects", "10"],
            ["--scenario", "scale", "--manager-memory", "8G"],
            ["--node-memory", "2g"],
            ["--scenario", "scale", "--node-cpus", "0"],
        ):
            with (
                self.subTest(extra),
                mock.patch.object(sys, "argv", [*asked, *extra]),
                mock.patch("sys.stderr"),
                self.assertRaises(SystemExit) as refused,
            ):
                tool.main()
            self.assertEqual(refused.exception.code, 2)

    def test_the_fake_provider_and_the_sampler_are_python(self) -> None:
        tool = self.install_test()

        for source in (tool.FAKE_IDP, tool.SAMPLER, tool.SCALE_GENERATE):
            compile(source, "<scenario>", "exec")
        self.assertIn(f":{tool.IDP_PORT}", tool.IDP_ISSUER)
        self.assertNotIn("@PORT@", tool.FAKE_IDP)

    def test_the_readings_agree_only_when_all_three_say_the_same(self) -> None:
        tool = self.install_test()

        def seen(cli: int, ui: int, own: int, state: str = "converged") -> dict[str, Any]:
            nodes = {"node-a": 4, "node-b": 4}
            return {
                "cli": {"target": 4, "nodes": {**nodes, "node-b": cli}, "state": state},
                "ui": {"target": 4, "nodes": {**nodes, "node-b": ui}, "state": state},
                "nodes": {**nodes, "node-b": own},
            }

        self.assertTrue(tool.agreed(seen(4, 4, 4)))
        self.assertFalse(tool.agreed(seen(3, 4, 4)))
        self.assertFalse(tool.agreed(seen(4, 3, 4)))
        self.assertFalse(tool.agreed(seen(4, 4, 3)))
        self.assertTrue(tool.agreed(seen(3, 3, 3, state="behind")))

    def test_the_release_states_it_waits_for_are_ones_the_product_says(self) -> None:
        # The faults run of 26-11-06 waited for "current", a word the status
        # never says, and failed on a converged cluster.
        text = (BASE / "tools/install-test").read_text()
        target = object()
        said = {
            status_collect._release_state([], None),
            status_collect._release_state([{"current": True}], target),  # type: ignore[arg-type]
            status_collect._release_state([{"current": False}], target),  # type: ignore[arg-type]
            status_collect._release_state(
                [{"current": None}, {"current": True}],
                target,  # type: ignore[arg-type]
            ),
        }
        waited = set(re.findall(r'\["(?:cli|ui)"\]\["state"\] [!=]= "(\w+)"', text))

        self.assertEqual(said, {"unknown", "converged", "behind", "incomplete"})
        self.assertTrue(waited)
        self.assertLessEqual(waited, said)

    def test_the_combined_fault_steps_follow_the_existing_ones_in_order(self) -> None:
        tool = self.install_test()
        titles: list[str] = []
        with tempfile.TemporaryDirectory() as raw:
            scenario = tool.Scenario(
                tool.Run(tool.DISTRIBUTIONS["debian13"], Path(raw)),
                lambda title, _action: titles.append(title),
            )
            tool.faults_steps(scenario)

        wanted = [
            "a deploy cut",
            "the break-glass admin turns it off",
            "an administrator for the Jobs page",
            "(backup, run) the older backup put back",
            "(backup, run) run on the Jobs page",
            "(deploy, discard) the older backup put back",
            "(deploy, discard) discard on the Jobs page",
            "drain pauses the queue",
            "under the pause recovery puts the job back",
            "the pause lifted",
            "HAProxy reload made to fail",
            "the activation fails on that node",
            "still has its previous release",
            "a plain deploy converges both nodes",
        ]
        places = [
            next(index for index, title in enumerate(titles) if needle in title)
            for needle in wanted
        ]
        self.assertEqual(places, sorted(places))
        self.assertEqual(len(set(places)), len(places))

    def test_the_fault_that_stops_a_reload_clears_haproxys_own_and_sorts_before_the_slow_one(
        self,
    ) -> None:
        tool = self.install_test()
        lines = tool.FAULT_RELOAD_UNIT.splitlines()

        self.assertEqual(lines, ["[Service]", "ExecReload=", "ExecReload=/bin/false"])
        self.assertEqual(tool.FAULT_RELOAD.parent, tool.SLOW_RELOAD.parent)
        self.assertLess(tool.FAULT_RELOAD.name, tool.SLOW_RELOAD.name)

    def test_the_waits_are_the_workers_own_numbers(self) -> None:
        tool = self.install_test()
        source = (BASE / "ui/src/haprion_ui/worker.py").read_text()

        for name, constant in (
            ("IDLE_SECONDS", tool.WORKER_IDLE_SECONDS),
            ("LEASE_SECONDS", tool.WORKER_LEASE_SECONDS),
        ):
            match = re.search(rf"^{name} = (\d+)$", source, re.M)
            self.assertIsNotNone(match, name)
            assert match is not None
            self.assertEqual(int(match.group(1)), constant, name)

    def test_the_commands_and_words_the_combined_faults_rest_on_are_the_products(self) -> None:
        backup = (BASE / "install/platform/bin/haprion-backup").read_text()
        drain = (BASE / "install/platform/bin/haprion-drain").read_text()
        pull = (BASE / "install/node/haprion-pull-deploy").read_text()
        status = (BASE / "src/haprion/cli/status.py").read_text()
        ahead = (BASE / "src/haprion/cluster_status.py").read_text()
        dashboard = (BASE / "ui/src/haprion_ui/pages/dashboard.py").read_text()
        worker = (BASE / "ui/src/haprion_ui/worker.py").read_text()
        tool = (BASE / "tools/install-test").read_text()

        # The restore holds the waiting jobs and says which, in the words the step reads.
        self.assertIn('log "held for an admin on Jobs: ${jobs}"', backup)
        self.assertIn("backup restore", tool)
        # Drain says it is quiet in the words the step waits for.
        self.assertIn('log "  no job is running"', drain)
        self.assertIn("lease_until > statement_timestamp()", drain)
        # Run and Discard are a web form post with a `decision` field.
        self.assertIn('@router.post("/jobs/{job_id}/held")', dashboard)
        self.assertIn('{"run", "discard"}', dashboard)
        self.assertIn('"held_discarded"', worker)
        self.assertIn('"answer_kept"', worker)
        # A node that cannot go back keeps its marker; the CLI says so.
        self.assertIn("could not be returned", pull)
        self.assertIn("(( ! restored )) || settle_incomplete", pull)
        self.assertIn("INCOMPLETE - a step after the reload failed", status)
        self.assertIn("which this manager has no record of", ahead)
        self.assertIn(
            "the deploy trigger failed on", (BASE / "src/haprion/deploy_run.py").read_text()
        )
        self.assertIn("/var/lib/haprion/pull-deploy.incomplete", pull)

    def test_the_table_has_a_row_per_measurement_and_a_column_per_machine(self) -> None:
        tool = self.install_test()
        with tempfile.TemporaryDirectory() as raw:
            scenario = tool.Scenario(tool.Run(tool.DISTRIBUTIONS["debian13"], Path(raw)), None)
        scenario.measurements.append(tool.Measured("apply", 12.34, {"mgr": (2 * 1048576, 1048576)}))
        scenario.measurements.append(
            tool.Measured("deploy", 5.0, {"mgr": (1048576, 1048576), "node-a": (3145728, 2097152)})
        )

        lines = scenario.table().splitlines()

        self.assertIn("mgr MiB", lines[0])
        self.assertIn("node-a MiB", lines[0])
        self.assertIn("apply", lines[2])
        self.assertIn("12.3", lines[2])
        self.assertIn("1 (2)", lines[2])
        self.assertIn("2 (3)", lines[3])


if __name__ == "__main__":
    unittest.main()
