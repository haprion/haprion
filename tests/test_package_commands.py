"""Every command and module the scripts use is a package the package depends on.

A new node stopped on its first deploy on `rsync: command not found`, and a new
manager's CLI package would not configure for want of PyJWT (Fas 18, findings
37 and 38): the machines the tests ran on had both for other reasons. Debian
policy asks a package to name what it uses directly. These tests read the
scripts the packages carry (`tools/package_commands.py`) and the modules the
engine imports, and hold each to the `Depends` of the package that carries it.

The table below says which package carries each command. It was measured with
`dpkg -S` on Debian 13 and Ubuntu 26.04 (26-10-15), and the two agree; a
command missing from it fails here until it is measured and added.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import sys
import tomllib
import unittest
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
INSTALL = BASE / "install"


def load(name: str, relative: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, BASE / relative)
    assert spec is not None and spec.loader is not None  # noqa: S101 - local tool must exist
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COMMANDS = load("package_commands", "tools/package_commands.py")
CLI = load("build_cli_package_commands", "tools/build-cli-package.py")
UI = load("build_ui_package_commands", "tools/build-ui-package.py")
from haprion import node_package  # noqa: E402 - after the tools, which set sys.path

#
# Commands from Essential packages, which policy lets a package use without
# naming them (on Ubuntu 26.04 coreutils' are rust-coreutils', under the
# Essential coreutils).
#
ESSENTIAL = frozenset(
    [
        "basename",
        "cat",
        "chmod",
        "chown",
        "cmp",
        "cp",
        "cut",
        "date",
        "df",
        "diff",
        "dirname",
        "dpkg",
        "dpkg-deb",
        "dpkg-query",
        "du",
        "find",
        "flock",
        "getent",
        "grep",
        "head",
        "hostname",
        "id",
        "install",
        "ln",
        "mkdir",
        "mktemp",
        "mv",
        "readlink",
        "rm",
        "rmdir",
        "sed",
        "seq",
        "sh",
        "sha256sum",
        "sleep",
        "sort",
        "stat",
        "tac",
        "tail",
        "tar",
        "touch",
        "tr",
        "wc",
    ]
)
PACKAGE_OF = {
    "apt-cache": "apt",
    "apt-get": "apt",
    "apt-mark": "apt",
    "awk": "mawk",
    "curl": "curl",
    "git": "git",
    "groupadd": "passwd",
    "haproxy": "haproxy",
    "ip": "iproute2",
    "ipvsadm": "ipvsadm",
    "journalctl": "systemd",
    "keepalived": "keepalived",
    "nginx": "nginx",
    "openssl": "openssl",
    "passwd": "passwd",
    "pg_lsclusters": "postgresql-common",
    "python3": "python3",
    "rrsync": "rsync",
    "rsync": "rsync",
    "rsyslogd": "rsyslog",
    "ss": "iproute2",
    "ssh": "openssh-client",
    "ssh-keygen": "openssh-client",
    "ssh-keyscan": "openssh-client",
    "sshd": "openssh-server",
    "sudo": "sudo",
    "sysctl": "procps",
    "systemctl": "systemd",
    "systemd-run": "systemd",
    "systemd-sysusers": "systemd",
    "systemd-tmpfiles": "systemd",
    "timedatectl": "systemd",
    "useradd": "passwd",
    "userdel": "passwd",
    "usermod": "passwd",
    "visudo": "sudo",
}
#
# Run, and not through a package's Depends, with why.
#
INSTALLED_BY_THE_PRODUCT = {
    "dnsdist": "lib.sh's ensure_dnsdist installs it from PowerDNS's repository",
    "certbot": "the haprion-certbot package carries its environment; step 14 makes it current",
    "pg_dump": "ensure-postgresql installs the server, and its client with it",
    "pg_restore": "ensure-postgresql installs the server, and its client with it",
    "psql": "ensure-postgresql installs the server, and its client with it",
    "coraza-spoa": "the WAF engine package the CLI release carries",
    "nologin": "a login shell written for an account, never run",
    "policy-rc.d": "a file the restore agent writes on a node, never run here",
}
#
# Run by another command rather than by the scripts themselves.
#
INDIRECT = {
    "node": {"ssh"},  # rsync -e "ssh -i ..." in haprion-pull-deploy and haprion-cert-pull
}
#
# Imported by the engine, by the Debian package that carries the module.
#
MODULE_PACKAGES = {
    "yaml": "python3-yaml",
    "nacl": "python3-nacl",
    "psycopg": "python3-psycopg",
    "jwt": "python3-jwt",
    "location": "python3-location",
}
#
# pyproject's names for the same, with the extras that need their own package.
#
DISTRIBUTION_PACKAGES = {
    "pynacl": ["python3-nacl"],
    "pyyaml": ["python3-yaml"],
    "psycopg": ["python3-psycopg"],
    "pyjwt[crypto]": ["python3-jwt", "python3-cryptography"],
}


def names(field: str) -> set[str]:
    """Every package a control field names, alternatives included."""

    found: set[str] = set()
    for item in field.split(","):
        for alternative in item.split("|"):
            name = re.sub(r"\(.*?\)", "", alternative).strip()
            if name:
                found.add(name)
    return found


def library_functions() -> set[str]:
    found: set[str] = set()
    for name in ("lib.sh", "accounts.sh", "defaults.sh", "setup.sh"):
        found |= COMMANDS.shell_functions((INSTALL / name).read_text())
    return found


def commands_of(paths: list[Path]) -> set[str]:
    functions = library_functions()
    found: set[str] = set()
    for path in paths:
        found |= COMMANDS.script_commands(path, functions)
    return {command for command in found if not command.startswith("haprion-")}


def node_scripts() -> list[Path]:
    return [
        BASE / source
        for source, _mode in node_package.CONTENTS.values()
        if source.startswith("install/")
        and "/apt-keys/" not in source
        and "/sysusers/" not in source
    ]


def manager_scripts() -> list[Path]:
    platform = INSTALL / "platform"
    steps = [
        path
        for path in sorted(platform.iterdir())
        if path.is_file() and not path.suffix and path.name != "README.md"
    ]
    steps += sorted((platform / "bin").iterdir())
    steps += [
        INSTALL / name
        for name in (
            "01-manager-prepare",
            "02-manager-config",
            "03-manager-keys",
            "05-verify",
            "haprion-setup",
            "setup.sh",
            "lib.sh",
            "accounts.sh",
            "defaults.sh",
        )
    ]
    return steps


def engine_commands() -> set[str]:
    found: set[str] = set()
    for path in (BASE / "src/haprion").rglob("*.py"):
        found |= COMMANDS.python_commands(path.read_text())
    return {command for command in found if not command.startswith("haprion-")}


class EveryCommandIsDeclared(unittest.TestCase):
    def assert_declared(self, used: set[str], declared: set[str], package: str) -> None:
        unknown = sorted(used - ESSENTIAL - set(PACKAGE_OF) - set(INSTALLED_BY_THE_PRODUCT))
        self.assertEqual(
            unknown,
            [],
            f"{package}: measure which package carries these (dpkg -S) and add them here",
        )
        missing = sorted(
            f"{command} ({PACKAGE_OF[command]})"
            for command in used
            if command in PACKAGE_OF and PACKAGE_OF[command] not in declared
        )
        self.assertEqual(missing, [], f"{package} runs these without depending on their package")

    def test_the_node_package(self) -> None:
        used = commands_of(node_scripts()) | INDIRECT["node"]
        self.assertIn("rsync", used)
        self.assert_declared(used, names(node_package.DEPENDS), "haprion-node")

    def test_the_manager_s_packages(self) -> None:
        # The steps run on a manager with both packages, and the engine is the
        # CLI package's; optional features may be satisfied by Recommends.
        used = commands_of(manager_scripts()) | engine_commands()
        declared = names(CLI.DEPENDS) | names(UI.UI_DEPENDS) | names(CLI.RECOMMENDS)
        self.assertIn("psql", used)
        self.assert_declared(used, declared, "haprion-cli and haprion-ui")

    def test_the_engine_s_commands_are_the_cli_package_s_own(self) -> None:
        used = engine_commands() - ESSENTIAL - set(INSTALLED_BY_THE_PRODUCT)
        declared = names(CLI.DEPENDS) | names(CLI.RECOMMENDS)
        missing = sorted(c for c in used if PACKAGE_OF.get(c) not in declared)
        # An https certificate receiver is served by the web platform's nginx,
        # which the UI package brings.
        self.assertEqual(missing, ["nginx"])
        self.assertIn("nginx", names(UI.UI_DEPENDS))


class TheSystemBusIsDeclaredWhereSystemdRunRuns(unittest.TestCase):
    """systemd-run needs the system bus, which systemd only recommends (finding
    46): the engine's candidate sandbox on the manager, and the restore agent's
    rollback timer on a node."""

    def test_both_packages_name_it(self) -> None:
        self.assertIn("systemd-run", (BASE / "src/haprion/restore_agent.py").read_text())
        self.assertIn("systemd-run", engine_commands())
        for depends in (CLI.DEPENDS, node_package.DEPENDS):
            self.assertIn("default-dbus-system-bus", names(depends))

    def test_steps_1_and_4_start_it(self) -> None:
        for step in ("01-manager-prepare", "04-node-prepare"):
            with self.subTest(step=step):
                self.assertIn("\nensure_system_bus\n", (INSTALL / step).read_text())


class TheRepositoryResolvesTheRest(unittest.TestCase):
    """`apt install haprion-ui` is the whole manager and `apt install haprion-node`
    a node with its engine, from the project's repository (B325)."""

    def test_the_manager_brings_engine_rules_and_key(self) -> None:
        for package in ("haprion-coraza-spoa", "haprion-crs", "haprion-archive-keyring"):
            with self.subTest(package=package):
                self.assertIn(package, names(CLI.DEPENDS))
        self.assertTrue({"haprion-cli", "haprion-certbot"} <= names(UI.depends("3.14")))

    def test_a_node_brings_its_engine_and_key(self) -> None:
        for package in ("haprion-coraza-spoa", "haprion-archive-keyring"):
            with self.subTest(package=package):
                self.assertIn(package, names(node_package.DEPENDS))
        self.assertNotIn("haprion-crs", names(node_package.DEPENDS))


class EveryModuleIsDeclared(unittest.TestCase):
    def imports(self) -> set[str]:
        found: set[str] = set()
        for path in (BASE / "src/haprion").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Import):
                    found |= {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    found.add(node.module.split(".")[0])
        return found - set(sys.stdlib_module_names) - {"haprion", "__future__"}

    def test_each_import_is_a_package_the_cli_names(self) -> None:
        imported = self.imports()
        self.assertEqual(sorted(imported - set(MODULE_PACKAGES)), [], "add their Debian package")
        declared = names(CLI.DEPENDS) | names(CLI.RECOMMENDS)
        for module in sorted(imported):
            with self.subTest(module=module):
                self.assertIn(MODULE_PACKAGES[module], declared)

    def test_the_lazy_import_is_recommended_not_required(self) -> None:
        # geo.py imports location inside the function that needs it (B322).
        self.assertIn("python3-location", names(CLI.RECOMMENDS))
        self.assertIn("location", names(CLI.RECOMMENDS))
        self.assertNotIn("python3-location", names(CLI.DEPENDS))

    def test_each_runtime_requirement_has_its_package(self) -> None:
        project = tomllib.loads((BASE / "pyproject.toml").read_text())
        for requirement in project["project"]["dependencies"]:
            name = re.split(r"[<>=!~ ]", requirement, maxsplit=1)[0].lower()
            with self.subTest(requirement=name):
                self.assertIn(name, DISTRIBUTION_PACKAGES)
                for package in DISTRIBUTION_PACKAGES[name]:
                    self.assertIn(package, names(CLI.DEPENDS))


class TheReaderFindsCommandsAndNothingElse(unittest.TestCase):
    def found(self, script: str, defined: tuple[str, ...] = ()) -> set[str]:
        return set(COMMANDS.shell_commands(script, defined))

    def test_commands_in_their_places(self) -> None:
        script = (
            "set -e\n"
            'x="$(readlink -f "$1")"\n'
            "if ! grep -q a b; then rsync -a x y; fi\n"
            "sudo -n /usr/sbin/ipvsadm -Ln | awk '{ print $1 }'\n"
            "VAR=1 exec timeout 5 ssh host true\n"
            "cat <<EOF\nnotacommand here\nEOF\n"
        )
        self.assertEqual(
            self.found(script), {"readlink", "grep", "rsync", "ipvsadm", "awk", "ssh", "cat"}
        )

    def test_quoted_text_comments_and_labels_are_not_commands(self) -> None:
        script = (
            "# rsync is not run here\n"
            'log "  ok; done | fine"\n'
            '"$HELPER" reload\n'
            'case "$x" in\n    cert-pull) run_it ;;\nesac\n'
            "for name in alpha beta; do :; done\n"
            "list=(one two)\n"
            "(( count > 0 )) && [[ -n $x ]]\n"
            "run_it() { echo hi; }\n"
        )
        self.assertEqual(self.found(script, ("log",)), set())

    def test_a_python_script_names_its_commands_by_path(self) -> None:
        text = 'import subprocess\nsubprocess.run(["/usr/bin/journalctl", "-u", "x"])\n'
        self.assertEqual(COMMANDS.python_commands(text), {"journalctl"})


if __name__ == "__main__":
    unittest.main()
