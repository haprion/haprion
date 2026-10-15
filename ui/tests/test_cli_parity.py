"""Every write the interface makes has its terminal counterpart (Fas 23, B269, B293).

The interface is the first way in and the terminal is how the same installation
is automated, so what one can set the other must. Each POST route - and each
operation the shared `/operations` route queues - is listed here once, as the
command that does the same, as a gap with the Fas 23 step that closes it, or
as something that is not a setting. A route added without an entry fails, and
so does a command named here that does not exist.

The gaps are the list Fas 23 empties.
"""

from __future__ import annotations

import ast
import tomllib
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from haprion_ui.app import create_app
from tests.test_login import configuration

ROOT = Path(__file__).resolve().parents[2]
VIEWS = ROOT / "ui" / "src" / "haprion_ui" / "views.py"
SCHEMAS = ROOT / "schemas" / "v1"
#
# The contracts that only read. A command whose answer is one of these shows a
# setting; it does not say whether it changed one.
#
READS = frozenset(
    {
        "haprion-cluster-settings",
        "haprion-network",
        "haprion-objects",
        "haprion-list",
        "haprion-status",
        "haprion-cert-list",
        "haprion-inventory",
        "haprion-list-backups",
        "haprion-readings",
        "haprion-cluster-list",
    }
)


@dataclass(frozen=True)
class Command:
    """The terminal's way to the same thing; the first word is the program.

    `schema` is the contract its `--json` answer is held to: a command a
    configuration tool cannot read `changed` or the outcome from is not the
    terminal's way to a setting, however well it works at a prompt.
    """

    line: str
    schema: str


@dataclass(frozen=True)
class Gap:
    """Not there yet: the Fas 23 step that adds it, and what it will be."""

    step: str
    planned: str


@dataclass(frozen=True)
class NotASetting:
    why: str


PARITY: dict[str, Command | Gap | NotASetting] = {
    "/proxies/{cluster}/new": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/edit": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/advanced": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/remove": Command("haprion-objects remove", "haprion-objects-apply"),
    "/waf/allow": Command("haprion-objects apply", "haprion-objects-apply"),
    "/waf/exceptions/remove": Command("haprion-objects apply", "haprion-objects-apply"),
    "/proxies/{cluster}/{name}/lookup": NotASetting("looks a name up for the form"),
    "/proxies/{cluster}/{name}/servers": Command("haprion-server-state", "haprion-server-state"),
    "/proxies/{cluster}/{name}/unblock": Command(
        "haprion-server-state unblock", "haprion-server-state"
    ),
    "/certificates/new": Command("haprion-cert-issue", "haprion-cert-issue"),
    "/certificates/import": Command("haprion-cert-import", "haprion-cert-import"),
    "/certificates/{certificate_id}/upload": Command("haprion-cert-import", "haprion-cert-import"),
    "/certificates/{certificate_id}/resume": Command(
        "haprion-cert-scep --resume", "haprion-cert-scep"
    ),
    "/certificates/{certificate_id}/publish": Command(
        "haprion-cert-publish --certificate", "haprion-cert-publish"
    ),
    "/certificates/renew": Command("haprion-cert-issue --renew", "haprion-cert-issue"),
    "/certificates/renew/confirm": Command("haprion-cert-issue --renew", "haprion-cert-issue"),
    "/certificates/{certificate_id}/download": NotASetting("hands the certificate to the browser"),
    "/certificates/export": NotASetting("hands key material to the browser"),
    "/certificates/{certificate_id}/export": NotASetting("hands key material to the browser"),
    "/certificates/targets/{action}": Command("haprion-cert-target", "haprion-cert-target"),
    "/certificates/targets/{action}/confirm": Command("haprion-cert-target", "haprion-cert-target"),
    "/certificates/delete": Command("haprion-cert-delete", "haprion-cert-delete"),
    "/certificates/delete/confirm": Command("haprion-cert-delete", "haprion-cert-delete"),
    "/certificates/receivers/new": Command("haprion-cert-receiver add", "haprion-cert-receiver"),
    "/certificates/receivers/remove": Command(
        "haprion-cert-receiver remove", "haprion-cert-receiver"
    ),
    "/certificates/receivers/secret": Command(
        "haprion-cert-receiver secret", "haprion-cert-receiver"
    ),
    "/dns-profiles/new": Command("haprion-profiles apply", "haprion-profiles-apply"),
    "/dns-profiles/{profile_id}/replace": Command(
        "haprion-profiles apply", "haprion-profiles-apply"
    ),
    "/dns-profiles/{profile_id}/remove": Command(
        "haprion-profiles remove", "haprion-profiles-apply"
    ),
    "/ndes-profiles/new": Command("haprion-profiles apply", "haprion-profiles-apply"),
    "/ndes-profiles/{profile_id}/replace": Command(
        "haprion-profiles apply", "haprion-profiles-apply"
    ),
    "/ndes-profiles/{profile_id}/remove": Command(
        "haprion-profiles remove", "haprion-profiles-apply"
    ),
    "/settings/clusters/{cluster}": Command(
        "haprion-cluster-settings apply", "haprion-cluster-settings-apply"
    ),
    "/settings/nodes/{cluster}/add": Command("haprion-node add", "haprion-cluster-node"),
    "/settings/nodes/{cluster}/remove": Command("haprion-node remove", "haprion-cluster-node"),
    "/settings/nodes/{cluster}/host": Command("haprion-node host", "haprion-cluster-node"),
    "/settings/nodes/{cluster}/remove-cluster": Command(
        "haprion-cluster remove", "haprion-cluster-define"
    ),
    "/settings/new-cluster": Command("haprion-cluster add", "haprion-cluster-define"),
    "/settings/new-user": Command("haprion-user apply", "haprion-user-apply"),
    "/settings/users/{name}": Command("haprion-user apply", "haprion-user-apply"),
    "/settings/oidc": Command("haprion-settings apply", "haprion-settings-apply"),
    "/settings/features/{name}": Command("haprion-settings apply", "haprion-settings-apply"),
    "/attention/acknowledge": NotASetting(
        "a judgement on a row of Needs attention, not something the installation is"
    ),
    "/getting-started/hide": NotASetting(
        "what the dashboard shows an admin, not something the installation is"
    ),
    "/settings/status-access": Command("haprion-settings apply", "haprion-settings-apply"),
    "/backups/restore/new": Command("haprion-node-restore prepare", "haprion-node-restore-prepare"),
    "/backups/restore/{run}/preview": Command(
        "haprion-node-restore preview", "haprion-node-restore-preview"
    ),
    "/backups/restore/{run}/run": Command("haprion-node-restore run", "haprion-node-restore"),
    "/backups/restore/{run}/discard": Command(
        "haprion-node-restore discard", "haprion-node-restore-discard"
    ),
    "/backups/restore/{run}/status": Command(
        "haprion-node-restore status", "haprion-node-restore-status"
    ),
    "/history/{cluster}/publish": NotASetting(
        "publishes what was saved in the interface; the terminal's apply publishes at once (B293)"
    ),
    "/login": NotASetting("signs in"),
    "/logout": NotASetting("signs out"),
    "/account/password": NotASetting("the signed-in person's own password; haprion-user reset"),
}

#
# What `/operations` queues, by its `operation` field.
#
OPERATIONS: dict[str, Command | Gap | NotASetting] = {
    "deploy": Command("haprion-deploy", "haprion-deploy"),
    "revert": Command("haprion-revert", "haprion-revert"),
    "network_publish": Command("haprion-network apply", "haprion-network-apply"),
    "backup_run": Command("haprion-state-backup", "haprion-backup-run"),
    "backup_schedule": Command("haprion-backup-schedule", "haprion-backup-schedule"),
}


def _posted_routes() -> set[str]:
    app = create_app(replace(configuration(), management_writes=True))
    found: set[str] = set()
    for route in app.routes:
        inner = getattr(route, "original_router", None)
        for candidate in (route, *(inner.routes if inner is not None else ())):
            methods = getattr(candidate, "methods", None) or set()
            if methods & {"POST", "PUT", "PATCH", "DELETE"}:
                found.add(str(getattr(candidate, "path", "")))
    return found


def _queued_operations() -> set[str]:
    """The `operation == "..."` branches of the `/operations` route, read from the source."""

    tree = ast.parse(VIEWS.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "queue_operation":
            return {
                compare.comparators[0].value
                for compare in ast.walk(node)
                if isinstance(compare, ast.Compare)
                and isinstance(compare.left, ast.Name)
                and compare.left.id == "operation"
                and isinstance(compare.ops[0], ast.Eq)
                and isinstance(compare.comparators[0], ast.Constant)
                and isinstance(compare.comparators[0].value, str)
            }
    raise AssertionError("queue_operation is no longer where this test reads it")


def _entry_points() -> dict[str, str]:
    points: dict[str, str] = {}
    for pyproject in (ROOT / "pyproject.toml", ROOT / "ui" / "pyproject.toml"):
        points.update(tomllib.loads(pyproject.read_text())["project"].get("scripts", {}))
    return points


def _sources(line: str) -> list[Path]:
    """The module a command line runs, and the one its verb dispatches to, when there is one."""

    words = line.split()
    module = _entry_points()[words[0]].split(":")[0]
    package, _, name = module.rpartition(".")
    base = (
        ROOT / ("src" if package.startswith("haprion.") else "ui/src") / package.replace(".", "/")
    )
    found = [base / f"{name}.py"]
    if len(words) > 1 and not words[1].startswith("-"):
        verb = base / f"{name}_{words[1]}.py"
        if verb.exists():
            found.append(verb)
    return found


def _programs() -> set[str]:
    programs: set[str] = set()
    for pyproject in (ROOT / "pyproject.toml", ROOT / "ui" / "pyproject.toml"):
        scripts = tomllib.loads(pyproject.read_text())["project"].get("scripts", {})
        programs.update(scripts)
    programs.update(path.name for path in (ROOT / "install" / "platform" / "bin").iterdir())
    return programs


class EveryWriteHasItsCommand(unittest.TestCase):
    def test_every_route_that_writes_is_listed_once(self) -> None:
        routes = _posted_routes()
        listed = set(PARITY) | {"/operations"}

        self.assertEqual(sorted(routes - listed), [], "a write with no terminal counterpart named")
        self.assertEqual(sorted(listed - routes), [], "listed here, but no such route")

    def test_every_queued_operation_is_listed_once(self) -> None:
        self.assertEqual(sorted(_queued_operations()), sorted(OPERATIONS))

    def test_every_command_named_exists(self) -> None:
        programs = _programs()
        named = {
            entry.line.split()[0]
            for entry in (*PARITY.values(), *OPERATIONS.values())
            if isinstance(entry, Command)
        }

        self.assertEqual(sorted(named - programs), [])

    def test_every_command_answers_in_a_contract(self) -> None:
        """A schema for each, and `--json` where the command is written (Fas 23 review).

        `haprion-cluster-settings --set` was listed here for a day while it had
        neither `--json` nor `--check`; the program existed, so the list was
        satisfied, and a playbook could not tell a change from none.
        """

        entries = [
            entry
            for entry in (*PARITY.values(), *OPERATIONS.values())
            if isinstance(entry, Command)
        ]
        missing = sorted(
            {entry.schema for entry in entries}
            - {path.name.removesuffix(".schema.json") for path in SCHEMAS.iterdir()}
        )
        self.assertEqual(missing, [])
        self.assertEqual(sorted({entry.line for entry in entries if entry.schema in READS}), [])
        silent = sorted(
            {
                entry.line
                for entry in entries
                if not any("--json" in source.read_text() for source in _sources(entry.line))
            }
        )
        self.assertEqual(silent, [])

    def test_the_check_would_notice_a_new_route(self) -> None:
        """A check that cannot fail is not a check."""

        routes = _posted_routes() | {"/settings/something-new"}

        self.assertIn("/settings/something-new", routes - set(PARITY))

    def test_fas_23_left_no_gap(self) -> None:
        """Every write the interface makes now has its command; a new one must name its own."""

        gaps = sorted(
            (entry.step, path)
            for path, entry in (*PARITY.items(), *OPERATIONS.items())
            if isinstance(entry, Gap)
        )

        self.assertEqual(gaps, [])


if __name__ == "__main__":
    unittest.main()
