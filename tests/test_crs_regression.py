"""The rule set's regression rig, as tools/crs-regression adapts upstream's (B337)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

BASE = Path(__file__).resolve().parents[1]


def load(name: str, relative: str) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(BASE / relative))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


RIG = load("crs_regression", "tools/crs-regression")

# The parts of upstream's rig the tool rewrites, as upstream writes them.
ENGINE = """\
bind: 0.0.0.0:9000
applications:
  - name: ftw
    directives: |
      Include @coraza.conf-recommended
      SecDefaultAction "phase:3,log,auditlog,pass"
      SecDefaultAction "phase:4,log,auditlog,pass"
      SecDefaultAction "phase:5,log,auditlog,pass"
      Include @crs-setup.conf.example
      Include @owasp_crs/*.conf
    log_file: /build/ftw.log
"""
HAPROXY = """\
frontend default
    bind *:8080
    filter spoe engine coraza config /usr/local/etc/haproxy/coraza.cfg
backend test
    server test backend:8081
backend coraza-spoa
    server coraza_spoa coraza-spoa:9000
"""
FTW = """\
logfile: '/build/ftw.log'
testoverride:
  input:
    dest_addr: 'haproxy'
    port: 8080
  ignore:
    920100-4: 'upstream reason'
"""


class TheRig(unittest.TestCase):
    def setUp(self) -> None:
        self.crs = Path(tempfile.mkdtemp(prefix="crs-"))
        self.addCleanup(shutil.rmtree, self.crs)
        self.work = Path("/work")

    def setup_file(self, *phases: int) -> None:
        lines = [f'SecDefaultAction "phase:{p},log,auditlog,pass"' for p in phases]
        (self.crs / "crs-setup.conf.example").write_text("\n".join(lines) + "\n")

    def test_the_engine_runs_our_rules_with_xml_attributes_inspected(self) -> None:
        self.setup_file(1, 2, 3, 4, 5)
        text = RIG.engine_configuration(ENGINE, self.crs, self.work)
        self.assertIn(f"Include {self.crs}/crs-setup.conf.example", text)
        self.assertIn(f"Include {self.crs}/rules/*.conf", text)
        self.assertNotIn("@owasp_crs", text)
        # The rule set's own tests of GHSA-6jp8-c2w2-x7wr expect it on; its
        # LTS line ships it off (223 tests failed without it, 26-10-19).
        self.assertIn("setvar:tx.crs_xml_attr_inspect=1", text)
        self.assertIn("bind: 127.0.0.1:", text)
        self.assertIn("log_file: /work/ftw.log", text)

    def test_default_actions_are_dropped_only_where_our_setup_has_them(self) -> None:
        # The engine refuses a phase's default action defined twice.
        self.setup_file(1, 2, 3, 4, 5)
        self.assertNotIn("SecDefaultAction", RIG.engine_configuration(ENGINE, self.crs, self.work))
        self.setup_file(1, 2)
        text = RIG.engine_configuration(ENGINE, self.crs, self.work)
        self.assertEqual(text.count("SecDefaultAction"), 3)

    def test_a_changed_rig_stops_the_run(self) -> None:
        self.setup_file(1, 2)
        for changed in (
            ENGINE.replace("Include @owasp_crs/*.conf", "Include @owasp_crs/rules/*.conf"),
            ENGINE.replace("bind: 0.0.0.0:9000", "bind: 0.0.0.0:9001"),
        ):
            with self.subTest(changed=changed), self.assertRaises(RIG.RegressionError):
                RIG.engine_configuration(changed, self.crs, self.work)
        with self.assertRaises(RIG.RegressionError):
            RIG.haproxy_configuration(HAPROXY.replace("coraza-spoa:9000", "spoa:9000"), self.work)

    def test_haproxy_speaks_to_the_loopback(self) -> None:
        text = RIG.haproxy_configuration(HAPROXY, self.work)
        self.assertIn(f"bind 127.0.0.1:{RIG.HAPROXY_PORT}", text)
        self.assertIn(f"server test 127.0.0.1:{RIG.BACKEND_PORT}", text)
        self.assertIn(f"server coraza_spoa 127.0.0.1:{RIG.ENGINE_PORT}", text)
        self.assertIn("config /work/coraza.cfg", text)

    def test_our_expected_failures_join_upstreams_and_never_repeat_them(self) -> None:
        settings = yaml.safe_load(
            RIG.ftw_configuration(FTW, {"941100-99": "our reason"}, self.work)
        )
        self.assertEqual(settings["testoverride"]["input"]["dest_addr"], "127.0.0.1")
        self.assertEqual(settings["testoverride"]["input"]["port"], RIG.HAPROXY_PORT)
        self.assertEqual(
            settings["testoverride"]["ignore"],
            {"920100-4": "upstream reason", "941100-99": "our reason"},
        )
        self.assertEqual(settings["logfile"], "/work/ftw.log")
        with self.assertRaisesRegex(RIG.RegressionError, "upstream's already"):
            RIG.ftw_configuration(FTW, {"920100-4": "again"}, self.work)

    def test_the_tools_are_the_versions_the_rig_names(self) -> None:
        dockerfile = "FROM ghcr.io/coreruleset/go-ftw:2.1.0@sha256:" + "a" * 64
        self.assertEqual(RIG.rig_version(dockerfile, "go-ftw", where="x"), "2.1.0")
        with self.assertRaises(RIG.RegressionError):
            RIG.rig_version("FROM ghcr.io/coreruleset/go-ftw:latest", "go-ftw", where="x")

    def test_our_list_is_a_mapping_of_test_to_reason(self) -> None:
        ours = yaml.safe_load((BASE / RIG.OUR_IGNORES).read_text()) or {}
        self.assertIsInstance(ours, dict)
        for test, reason in ours.items():
            self.assertRegex(test, r"^\d{6}-\d+$")
            self.assertTrue(str(reason).strip())


if __name__ == "__main__":
    unittest.main()
