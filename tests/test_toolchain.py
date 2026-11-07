"""The gate's versions are toolchain.json's, here and on GitHub (B494)."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

BASE = Path(__file__).resolve().parents[1]
TOOL = BASE / "tools" / "check_toolchain.py"
CI = BASE / ".github" / "workflows" / "ci.yml"


def tool() -> Any:
    spec = importlib.util.spec_from_file_location("check_toolchain", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ThePins(unittest.TestCase):
    def test_the_file_reads(self) -> None:
        pythons, git = tool().load()
        self.assertEqual(len(pythons), 2)
        self.assertRegex(git, r"^\d+\.\d+\.\d+$")

    def test_a_file_that_pins_two_patches_of_one_minor_is_refused(self) -> None:
        for document in (
            {"schema_version": 1, "python": ["3.13.5", "3.13.6"], "git": "2.53.0"},
            {"schema_version": 1, "python": ["3.13"], "git": "2.53.0"},
            {"schema_version": 1, "python": [], "git": "2.53.0"},
            {"schema_version": 1, "python": ["3.13.5"], "git": "2.53"},
            {"python": ["3.13.5"], "git": "2.53.0"},
        ):
            with self.subTest(document=document), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "toolchain.json"
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    tool().load(path)

    def test_a_version_that_moved_is_named(self) -> None:
        module = tool()
        pins = (("3.13.15", "3.14.4"), "2.53.0")
        self.assertEqual(
            module.problems(*pins, running="3.13.15", ui="3.13.15", found_git="2.53.0"), []
        )
        said = module.problems(*pins, running="3.13.18", ui="3.13.15", found_git="2.56.0")
        self.assertEqual(len(said), 3)
        self.assertIn("Python 3.13.18", said[0])
        self.assertIn("3.13.15", said[1])
        self.assertIn("git 2.56.0", said[2])
        self.assertEqual(module.git_version("git version 2.53.0\n"), "2.53.0")
        self.assertIsNone(module.git_version("not git"))

    def test_a_build_without_what_the_product_calls_is_refused(self) -> None:
        """26-11-07: uv's 3.13.5 had no os.memfd_create and no os.getrandom."""

        module = tool()
        (said,) = module.problems(
            ("3.13.5",),
            "2.53.0",
            running="3.13.5",
            ui=None,
            found_git="2.53.0",
            missing=["memfd_create", "getrandom"],
        )
        self.assertIn("os.memfd_create, os.getrandom", said)

    def test_the_python_running_this_has_what_the_product_calls(self) -> None:
        for name in tool().REQUIRED_CALLS:
            with self.subTest(name=name):
                self.assertTrue(hasattr(os, name))

    def test_local_work_starts_on_the_floor(self) -> None:
        pythons, _ = tool().load()
        self.assertEqual((BASE / ".python-version").read_text().strip(), pythons[0])


class GitHubRunsThePins(unittest.TestCase):
    def job(self) -> dict[str, Any]:
        job: dict[str, Any] = yaml.safe_load(CI.read_text())["jobs"]["checks"]
        return job

    def test_the_gate_matrix_is_the_pinned_pythons(self) -> None:
        pythons, _ = tool().load()
        self.assertEqual(self.job()["strategy"]["matrix"]["python"], list(pythons))

    def test_the_gate_installs_the_pinned_git_before_it_runs(self) -> None:
        steps = [step.get("name", "") for step in self.job()["steps"]]
        self.assertIn("Install the git the installations run", steps)
        self.assertLess(
            steps.index("Install the git the installations run"),
            steps.index("Run all source, quality, test, and dependency gates"),
        )


if __name__ == "__main__":
    unittest.main()
