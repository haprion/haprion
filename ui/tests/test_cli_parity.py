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


@dataclass(frozen=True)
class Command:
    """The terminal's way to the same thing; the first word is the program."""

    line: str


@dataclass(frozen=True)
class Gap:
    """Not there yet: the Fas 23 step that adds it, and what it will be."""

    step: str
    planned: str


@dataclass(frozen=True)
class NotASetting:
    why: str


PARITY: dict[str, Command | Gap | NotASetting] = {
    "/proxies/{cluster}/new": Gap("P2", "haprion-objects apply"),
    "/proxies/{cluster}/{name}/edit": Gap("P2", "haprion-objects apply"),
    "/proxies/{cluster}/{name}/advanced": Gap("P2", "haprion-objects apply"),
    "/proxies/{cluster}/{name}/remove": Gap("P2", "haprion-objects remove"),
    "/waf/allow": Gap("P2", "haprion-objects apply"),
    "/waf/exceptions/remove": Gap("P2", "haprion-objects apply"),
    "/proxies/{cluster}/{name}/lookup": NotASetting("looks a name up for the form"),
    "/proxies/{cluster}/{name}/servers": Command("haprion-server-state"),
    "/proxies/{cluster}/{name}/unblock": Command("haprion-server-state unblock"),
    "/certificates/new": Command("haprion-cert-issue"),
    "/certificates/import": Command("haprion-cert-import"),
    "/certificates/{certificate_id}/upload": Command("haprion-cert-import"),
    "/certificates/{certificate_id}/resume": Command("haprion-cert-scep --resume"),
    "/certificates/{certificate_id}/publish": Command("haprion-cert-publish --certificate"),
    "/certificates/renew": Command("haprion-cert-renew"),
    "/certificates/renew/confirm": Command("haprion-cert-renew"),
    "/certificates/{certificate_id}/download": NotASetting("hands the certificate to the browser"),
    "/certificates/export": NotASetting("hands key material to the browser"),
    "/certificates/{certificate_id}/export": NotASetting("hands key material to the browser"),
    "/certificates/targets/{action}": Gap("P6", "haprion-cert-target"),
    "/certificates/targets/{action}/confirm": Gap("P6", "haprion-cert-target"),
    "/certificates/delete": Gap("P6", "haprion-cert-delete"),
    "/certificates/delete/confirm": Gap("P6", "haprion-cert-delete"),
    "/certificates/receivers/new": Command("haprion-cert-receiver add"),
    "/certificates/receivers/remove": Command("haprion-cert-receiver remove"),
    "/dns-profiles/new": Gap("P6", "haprion-dns-profile apply"),
    "/dns-profiles/{profile_id}/replace": Gap("P6", "haprion-dns-profile apply"),
    "/dns-profiles/{profile_id}/remove": Gap("P6", "haprion-dns-profile remove"),
    "/ndes-profiles/new": Gap("P6", "haprion-ndes-profile apply"),
    "/ndes-profiles/{profile_id}/replace": Gap("P6", "haprion-ndes-profile apply"),
    "/ndes-profiles/{profile_id}/remove": Gap("P6", "haprion-ndes-profile remove"),
    "/settings/clusters/{cluster}": Command("haprion-cluster-settings --set"),
    "/settings/nodes/{cluster}/add": Command("haprion-node add"),
    "/settings/nodes/{cluster}/remove": Command("haprion-node remove"),
    "/settings/nodes/{cluster}/remove-cluster": Command("haprion-cluster remove"),
    "/settings/new-cluster": Command("haprion-cluster add"),
    "/settings/new-user": Gap("P4", "haprion-user apply"),
    "/settings/users/{name}": Gap("P4", "haprion-user apply"),
    "/settings/oidc": Gap("P5", "haprion-settings oidc"),
    "/settings/features/{name}": Gap("P5", "haprion-settings features"),
    "/settings/status-access": Gap("P5", "haprion-settings status-access"),
    "/backups/restore/new": Command("haprion-node-restore prepare"),
    "/backups/restore/{run}/preview": Command("haprion-node-restore preview"),
    "/backups/restore/{run}/run": Command("haprion-node-restore run"),
    "/backups/restore/{run}/discard": Command("haprion-node-restore discard"),
    "/backups/restore/{run}/status": Command("haprion-node-restore status"),
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
    "deploy": Command("haprion-deploy"),
    "revert": Command("haprion-revert"),
    "network_publish": Gap("P3", "haprion-network apply"),
    "backup_run": Command("haprion-state-backup"),
    "backup_schedule": Gap("P7", "haprion-state-backup --schedule"),
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

    def test_the_check_would_notice_a_new_route(self) -> None:
        """A check that cannot fail is not a check."""

        routes = _posted_routes() | {"/settings/something-new"}

        self.assertIn("/settings/something-new", routes - set(PARITY))

    def test_what_fas_23_has_left(self) -> None:
        gaps = sorted(
            (entry.step, path)
            for path, entry in (*PARITY.items(), *OPERATIONS.items())
            if isinstance(entry, Gap)
        )
        steps = {step for step, _ in gaps}

        self.assertTrue(steps <= {f"P{number}" for number in range(1, 11)}, steps)


if __name__ == "__main__":
    unittest.main()
