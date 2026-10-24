"""``haprion-export`` without a database: the layout, the refusals and the answer (Fas 23, B293).

That the interface's three files apply unchanged to the installation they
came from is held against the real schema in `test_database_integration`
(`TheExportAppliesUnchanged`); this holds the clusters' files the same way
against the readers their apply commands compare with, and the answer's
shape against the fixture the contract suite validates against
`schemas/v1/haprion-export`.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from unittest import mock

from haprion import backup_schedule, cluster_settings, exit_codes

from haprion_ui import (
    account_apply,
    admin,
    config,
    db,
    export_tool,
    profile_apply,
    settings_apply,
    tool_answer,
)

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/haprion-export/valid/done.json"

SHOP = "name: shop\nlisten:\n  hostnames: [shop.example.com]\n"
NETWORK = "vips:\n  - name: public\n    address: 192.0.2.10\n"
SETTINGS: dict[str, Any] = {
    "log_targets": [
        {"name": "siem", "address": "192.0.2.20", "port": 6514, "disk_mib": 512, "tls": True}
    ],
    "not_logged_from": ["198.51.100.0/24"],
    "metrics": {"port": 8405, "sources": ["192.0.2.0/24"]},
    "peers": None,
}


def answered(write: Callable[[], int]) -> tuple[int, dict[str, Any]]:
    """What a tool printed with `--json`, through the engine's envelope (4-9)."""

    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = write()
    return code, json.loads(out.getvalue())


class Engine:
    """The engine's readings, as `read_engine` would return their results."""

    def __init__(self) -> None:
        self.asked: list[tuple[str, ...]] = []
        self.refuse: str | None = None
        self.objects: list[dict[str, Any]] | None = None

    def __call__(self, argv: Sequence[str]) -> Mapping[str, Any]:
        self.asked.append(tuple(argv))
        if self.refuse == argv[0]:
            raise export_tool.ExportError(f"{argv[0]}: refused", exit_codes.UNAVAILABLE)
        command, cluster = argv[0], argv[2]
        if command == "haprion-objects" and self.objects is not None:
            return {"objects": self.objects}
        if command == "haprion-objects":
            return {
                "objects": [
                    {"name": "shop", "document": SHOP, "readable": True, "problem": None},
                    {"name": "broken", "document": "x", "readable": False, "problem": "bad port"},
                ]
            }
        if command == "haprion-network":
            if cluster == "alpha":
                return {"origin": "repository", "document": NETWORK}
            return {"origin": "cluster_file", "document": None}
        if command == "haprion-cluster-settings":
            return dict(SETTINGS)
        if command == "haprion-list-backups":
            return {
                "schedule": {
                    "known": True,
                    "scheduled": cluster == "alpha",
                    "enabled": True,
                    "calendar": "Mon,Thu *-*-* 04:30:00",
                    "retention": 9,
                }
            }
        raise AssertionError(f"not a reading: {argv}")


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = Engine()
        parent = tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        self.target = Path(parent.name) / "export"
        settings = mock.Mock(spec=config.Config)
        settings.clusters = ("alpha", "beta")
        for patch in (
            mock.patch.object(config, "load", return_value=settings),
            mock.patch.object(export_tool, "load_environment"),
            mock.patch.object(export_tool, "connect", return_value=contextlib.nullcontext()),
            mock.patch.object(db, "cluster_list", return_value=None),
            mock.patch.object(
                account_apply, "document", return_value={"accounts": [{"username": "admin"}]}
            ),
            mock.patch.object(settings_apply, "document", return_value={"status_access": []}),
            mock.patch.object(
                profile_apply, "document", return_value={"dns_profiles": [], "ndes_profiles": []}
            ),
            mock.patch.dict(
                os.environ, {"SUDO_UID": str(os.getuid()), "SUDO_GID": str(os.getgid())}
            ),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def export(self, *argv: str) -> tuple[int, dict[str, Any]]:
        parsed = export_tool.build_parser().parse_args([str(self.target), "--json", *argv])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = export_tool.command_export(parsed, read=self.engine)
        return code, json.loads(out.getvalue())


class TheLayout(Harness):
    def test_every_file_in_its_place_and_what_could_not_be_said_skipped(self) -> None:
        code, answer = self.export()

        self.assertEqual(code, 0, answer)
        result = answer["result"]
        self.assertEqual(result["clusters"], ["alpha", "beta"])
        self.assertEqual(
            result["files"],
            [
                "accounts.yaml",
                "clusters/alpha/backup-schedule.yaml",
                "clusters/alpha/cluster-settings.yaml",
                "clusters/alpha/network.yaml",
                "clusters/alpha/objects/shop.yaml",
                "clusters/beta/cluster-settings.yaml",
                "clusters/beta/objects/shop.yaml",
                "profiles.yaml",
                "settings.yaml",
            ],
        )
        self.assertEqual(
            [(entry["path"], entry["reason"]) for entry in result["skipped"]],
            [
                ("clusters/alpha/objects/broken.yaml", "bad port"),
                ("clusters/beta/objects/broken.yaml", "bad port"),
                ("clusters/beta/network.yaml", "derived from the cluster file; nothing to apply"),
                ("clusters/beta/backup-schedule.yaml", "no schedule has been set"),
            ],
        )
        self.assertEqual((self.target / "clusters/alpha/objects/shop.yaml").read_text(), SHOP)
        self.assertEqual((self.target / "clusters/alpha/network.yaml").read_text(), NETWORK)

    def test_only_the_owner_reads_it_and_the_owner_is_who_ran_sudo(self) -> None:
        self.export()

        for path in [self.target, *self.target.rglob("*")]:
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o700 if path.is_dir() else 0o600, path)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (os.getuid(), os.getgid()))

    def test_one_cluster_when_asked_for(self) -> None:
        code, answer = self.export("-c", "beta")

        self.assertEqual(code, 0)
        self.assertEqual(answer["result"]["clusters"], ["beta"])
        self.assertFalse((self.target / "clusters/alpha").exists())
        self.assertEqual({argv[2] for argv in self.engine.asked}, {"beta"})

    def test_an_empty_directory_is_used(self) -> None:
        self.target.mkdir(mode=0o755)

        code, _answer = self.export()

        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)

    def test_a_cluster_without_objects_still_has_its_objects_directory(self) -> None:
        self.engine.objects = []

        self.export("-c", "beta")

        kept = [path.name for path in (self.target / "clusters/beta/objects").iterdir()]
        self.assertEqual(kept, [".gitkeep"])


class TheRefusals(Harness):
    def test_a_directory_with_something_in_it_is_left_alone(self) -> None:
        self.target.mkdir()
        (self.target / "keep").write_text("mine")

        code, answer = self.export()

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(answer["outcome"], "failed")
        self.assertIn("not empty", answer["error"]["message"])
        self.assertEqual(sorted(path.name for path in self.target.iterdir()), ["keep"])

    def test_a_link_is_not_followed(self) -> None:
        elsewhere = self.target.parent / "elsewhere"
        elsewhere.mkdir()
        self.target.symlink_to(elsewhere)

        code, answer = self.export()

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("not a directory", answer["error"]["message"])
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_cluster_nobody_has_is_refused_before_anything_is_written(self) -> None:
        code, answer = self.export("-c", "gamma")

        self.assertEqual(code, exit_codes.REFUSED)
        self.assertIn("no such cluster: gamma", answer["error"]["message"])
        self.assertFalse(self.target.exists())

    def test_a_reading_that_fails_writes_nothing(self) -> None:
        self.engine.refuse = "haprion-network"

        code, answer = self.export()

        self.assertEqual(code, exit_codes.UNAVAILABLE)
        self.assertIn("haprion-network: refused", answer["error"]["message"])
        self.assertFalse(self.target.exists())

    def test_without_root_it_says_so_in_the_contract(self) -> None:
        out = io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=1000),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = export_tool.main([str(self.target), "--json"])

        self.assertEqual(code, 77)
        self.assertEqual(json.loads(out.getvalue())["outcome"], "failed")

    def test_without_the_database_it_says_so_in_the_contract(self) -> None:
        out = io.StringIO()
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(
                export_tool, "command_export", side_effect=admin.AdminError("no ui-admin.conf")
            ),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = export_tool.main([str(self.target), "--json"])

        self.assertEqual(code, 64)
        self.assertEqual(json.loads(out.getvalue())["error"]["message"], "no ui-admin.conf")


class TheClusterFilesApplyUnchanged(unittest.TestCase):
    """Each is what its apply command compares with, so applying it changes nothing."""

    def test_the_settings_read_back_as_the_reading(self) -> None:
        text = export_tool.cluster_settings_text(SETTINGS)

        self.assertEqual(
            cluster_settings.document_result(cluster_settings.load_document(text.encode())),
            SETTINGS,
        )

    def test_no_settings_is_an_empty_document(self) -> None:
        nothing = cluster_settings.document_result(cluster_settings.NOTHING)

        text = export_tool.cluster_settings_text(nothing)

        self.assertEqual(
            cluster_settings.document_result(cluster_settings.load_document(text.encode())),
            nothing,
        )

    def test_each_schedule_shape_gives_back_its_calendar(self) -> None:
        for calendar in ("*-*-* 02:15:00", "Mon,Thu *-*-* 04:30:00", "*-*-07 23:00:00"):
            with self.subTest(calendar=calendar):
                document = export_tool.schedule_document(
                    {
                        "known": True,
                        "scheduled": True,
                        "enabled": False,
                        "calendar": calendar,
                        "retention": 9,
                    }
                )
                if not isinstance(document, dict):
                    self.fail(document)
                weekly, monthly = document.get("weekly"), document.get("monthly")
                schedule = backup_schedule.Schedule(
                    document["time"],
                    "weekly" if weekly else "monthly" if monthly else "daily",
                    tuple(weekly.split(",")) if weekly else (),
                    monthly,
                    document["retention"],
                )
                self.assertEqual(schedule.calendar(), calendar)
                self.assertEqual((document["retention"], document["enabled"]), (9, False))

    def test_a_schedule_the_form_cannot_say_is_skipped_with_why(self) -> None:
        self.assertEqual(export_tool.schedule_document(None), "the cluster has no backup timer")
        reason = export_tool.schedule_document(
            {"known": True, "scheduled": True, "calendar": "hourly", "retention": 9}
        )
        self.assertEqual(reason, "the timer's calendar 'hourly' is not one the form can set")


class TheAnswer(unittest.TestCase):
    def test_it_has_the_shape_the_contract_holds(self) -> None:
        fixture = json.loads(FIXTURE.read_text())

        code, answer = answered(lambda: tool_answer.done(export_tool.OPERATION, fixture["result"]))
        self.assertEqual(code, 0)

        self.assertEqual(set(answer), set(fixture))
        self.assertEqual(answer["operation"], fixture["operation"])
        self.assertEqual(set(answer["result"]), set(fixture["result"]))


if __name__ == "__main__":
    unittest.main()
