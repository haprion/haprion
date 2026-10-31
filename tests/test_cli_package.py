"""The CLI package: its tree, its commands and the operators' sudo rules (B266)."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
SUDOERS = BASE / "install/sudoers/haprion"
RULE = re.compile(
    r'^%sudo ALL=\(root\) (NOPASSWD: )?/opt/haprion/current/bin/(haprion-[a-z-]+-helper) ""$'
)


def tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "build_cli_package", BASE / "tools/build-cli-package.py"
    )
    assert spec is not None and spec.loader is not None  # local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = tool()


def wheel_with(directory: Path, scripts: list[str]) -> Path:
    wheel = directory / "haprion-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "haprion-0.1.0.dist-info/entry_points.txt",
            "[console_scripts]\n" + "".join(f"{name} = haprion.cli.x:main\n" for name in scripts),
        )
    return wheel


def rules() -> dict[str, bool]:
    """Helper -> whether its rule is NOPASSWD."""

    found = {}
    for line in SUDOERS.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        matched = RULE.fullmatch(line)
        assert matched, f"not an exact operator rule: {line}"
        found[matched.group(2)] = matched.group(1) is not None
    return found


class TheEngineLevel(unittest.TestCase):
    def test_the_package_provides_the_engine_at_its_api_level(self) -> None:
        """What the interface's package depends on (review 2026-10-22, 6-4)."""

        commit = TOOL._git(BASE, "rev-parse", "HEAD").decode().strip()
        committed = json.loads(TOOL._git(BASE, "show", f"{commit}:src/haprion/compatibility.json"))
        self.assertEqual(
            TOOL.provides(BASE, commit), f"haprion-engine (= {committed['engine_api']})"
        )


class TheTree(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_operators_get_commands_and_helpers_asks_and_services_do_not(self) -> None:
        wheel = wheel_with(
            self.root,
            [
                "haprion-status",
                "haprion-status-helper",
                "haprion-node-ask",
                "haprion-cert-renew",
                "haprion-traffic-collector",
                "haprion-deploy",
            ],
        )

        self.assertEqual(TOOL.operator_commands(wheel), ["haprion-deploy", "haprion-status"])

    def test_the_package_tree_carries_the_payload_the_commands_and_the_rules(self) -> None:
        wheel = wheel_with(self.root, ["haprion-status", "haprion-status-helper"])
        node = self.root / "haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb"
        node.write_bytes(b"node package")
        engine = self.root / "haprion-coraza-spoa_0.9.0-7_amd64.deb"
        engine.write_bytes(b"engine package")
        keyring = self.root / "haprion-archive-keyring_2026.10.17_all.deb"
        keyring.write_bytes(b"key package")
        tree = self.root / "tree"

        TOOL.assemble(
            tree,
            wheel=wheel,
            node_deb=node,
            waf_engine_deb=engine,
            keyring_deb=keyring,
            installer=b"#!/usr/bin/python3\n",
            sudoers=SUDOERS.read_bytes(),
            licence=b"licence text\n",
            commit="0" * 40,
        )

        lib = tree / "usr/lib/haprion/cli"
        payload = (lib / "PAYLOAD").read_text()
        self.assertIn(f"WHEEL={wheel.name}\n", payload)
        self.assertIn(f"NODE_PACKAGE={node.name}\n", payload)
        self.assertIn(f"WAF_ENGINE_PACKAGE={engine.name}\n", payload)
        self.assertEqual((lib / engine.name).read_bytes(), b"engine package")
        self.assertIn("--waf-engine-package", (tree / "DEBIAN/postinst").read_text())
        # The node package depends on it; a node restored from files gets it here (B339).
        self.assertIn(f"KEYRING_PACKAGE={keyring.name}\n", payload)
        self.assertEqual((lib / keyring.name).read_bytes(), b"key package")
        self.assertIn("--keyring-package", (tree / "DEBIAN/postinst").read_text())
        self.assertEqual(
            (tree / "usr/bin/haprion-status").read_text(),
            '#!/bin/sh\nexec /opt/haprion/current/bin/haprion-status "$@"\n',
        )
        self.assertFalse((tree / "usr/bin/haprion-status-helper").exists())
        self.assertEqual((tree / "etc/sudoers.d/haprion").stat().st_mode & 0o777, 0o440)
        self.assertTrue(
            (tree / "usr/share/doc/haprion-cli/copyright").read_bytes().endswith(b"licence text\n")
        )
        self.assertEqual((tree / "DEBIAN/conffiles").read_text(), "/etc/sudoers.d/haprion\n")
        postinst = (tree / "DEBIAN/postinst").read_text()
        self.assertIn("install-release.py", postinst)
        #
        # The fetch keys bound after the release is in place (B358), and a step
        # that cannot finish never fails the package: the nodes fetch as before.
        #
        self.assertLess(postinst.index("install-release.py"), postinst.index("pull-keys"))
        self.assertIn("/usr/bin/haprion-node pull-keys || echo", postinst)
        self.assertIn("rm -rf /opt/haprion", (tree / "DEBIAN/postrm").read_text())

    def test_a_rule_visudo_refuses_stops_the_build(self) -> None:
        wheel = wheel_with(self.root, ["haprion-status"])
        node = self.root / "node.deb"
        node.write_bytes(b"x")

        with self.assertRaisesRegex(TOOL.BuildError, "visudo refuses"):
            TOOL.assemble(
                self.root / "tree",
                wheel=wheel,
                node_deb=node,
                waf_engine_deb=node,
                keyring_deb=node,
                installer=b"",
                sudoers=b"%sudo ALL=(root) NOPASSWD /broken\n",
                licence=b"",
                commit="0" * 40,
            )


class TheOperatorsRules(unittest.TestCase):
    def test_visudo_accepts_the_file(self) -> None:
        checked = subprocess.run(  # fixed checker, repository file
            ["/usr/sbin/visudo", "-cf", str(SUDOERS)], capture_output=True, text=True, check=False
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_every_rule_names_a_helper_the_release_has(self) -> None:
        helpers = set(
            re.findall(r"^(haprion-[a-z-]+-helper) =", (BASE / "pyproject.toml").read_text(), re.M)
        )

        self.assertLessEqual(set(rules()), helpers)

    def test_a_read_without_a_prompt_and_a_write_with_one_as_the_command_asks(self) -> None:
        """`sudo -n` needs NOPASSWD; plain sudo asks for the password the rule keeps."""

        granted = rules()
        asked: dict[str, bool] = {}
        for path in (BASE / "src/haprion/cli").glob("*.py"):
            if path.stem.endswith(("_helper", "_ask")):
                continue
            helper = re.search(
                r'^HELPER = "/opt/haprion/current/bin/(haprion-[a-z-]+-helper)"$',
                path.read_text(),
                re.M,
            )
            if helper is None:
                continue
            asked[helper.group(1)] = '"-n"' in path.read_text()
            stem = path.stem
            with self.subTest(command=stem):
                if helper.group(1) in granted:
                    self.assertEqual(granted[helper.group(1)], asked[helper.group(1)])
                else:
                    self.assertFalse(asked[helper.group(1)], "sudo -n with no rule fails at once")

    def test_every_rule_is_the_humans_and_names_one_helper(self) -> None:
        # rules() refuses any line that is not `%sudo ... <helper> ""`, so no
        # rule can reach %haprion, which holds the worker, or an account.
        self.assertEqual(len(rules()), 16)


class TheWheel(unittest.TestCase):
    def test_its_modes_are_the_builds_not_the_operators_umask(self) -> None:
        # v0.9.1: the wheel built under umask 002 differed from CI's by its
        # group-write bits alone. RECORD is written 0664 whatever the umask.
        uv = shutil.which("uv")
        self.assertIsNotNone(uv, "uv must be on PATH")
        assert uv is not None  # narrowed for the type checker
        previous = os.umask(0o002)
        self.addCleanup(os.umask, previous)
        with tempfile.TemporaryDirectory() as directory:
            wheel = TOOL.build_wheel(BASE, "HEAD", 0, Path(uv), Path(directory))
            with zipfile.ZipFile(wheel) as archive:
                writable = [
                    entry.filename
                    for entry in archive.infolist()
                    if entry.external_attr >> 16 & 0o022
                    and not entry.filename.endswith(".dist-info/RECORD")
                ]
        self.assertEqual(writable, [])


if __name__ == "__main__":
    unittest.main()
