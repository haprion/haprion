"""*Settings → Path lists* (B527, B532): the form, the card, removal, *Add to proxies* and the command.

Pinned here: the form holds a list to the engine's own rule; a save stores
the row and queues its apply job together; a list an object, a saved change
or a draft names is not removed; *Add to proxies* starts a list in `log only`
and adds it once; and `haprion-path-lists` plans the changes the form would
make.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock
from uuid import UUID, uuid4

import yaml

from haprion_ui import auth, db, path_list_apply, path_list_form
from tests.test_login import LoginTestCase, configuration
from tests.test_queue_route import queued

KEY = str(uuid4())
NOW = datetime(2026, 11, 24, 8, 0, tzinfo=UTC)


def list_row(**overrides: Any) -> db.PathList:
    fields: dict[str, Any] = {
        "name": "scanners",
        "description": "",
        "paths": ["/.env", "/wp-login.php"],
        "revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
        "updated_by": "admin",
    }
    return db.PathList(**{**fields, **overrides})


def site(name: str, extra: str = "", protocol: str = "https") -> str:
    return (
        f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
        f"listen:\n  protocol: {protocol}\n  certificate: example.com\n{extra}"
        f"routes:\n- path: /\n  backend: web\nbackends:\n  web:\n    balance: roundrobin\n"
        "    health:\n      type: disabled\n    servers:\n    - host: 192.0.2.10\n      port: 8080\n"
    )


def objects_reading(cluster: str, documents: dict[str, str]) -> db.ClusterObjects:
    return db.ClusterObjects(
        cluster=cluster,
        observed_at=NOW,
        outcome="done",
        result={
            "objects": [
                {"name": name, "document": text, "readable": True, "protocol": "https"}
                for name, text in documents.items()
            ]
        },
        warnings=[],
        error=None,
        poll_error=None,
    )


NAMED = "deny_paths:\n  mode: deny\n  lists: [scanners]\n"


class TheForm(unittest.TestCase):
    def test_a_list_is_held_to_the_engine_s_rule(self) -> None:
        item = path_list_form.checked(
            path_list_form.Form(name="scanners", paths="/.env\n\n /.git \n/.env\n")
        )
        self.assertEqual(item.paths, ("/.env", "/.git"))
        for form, said in (
            (path_list_form.Form(name="Bad", paths="/x"), "Name —"),
            (path_list_form.Form(name="a", paths=""), "write at least one path"),
            (path_list_form.Form(name="a", paths="/x\n/"), "line 2 is /"),
            (path_list_form.Form(name="a", paths="/x\nrelative"), "line 2 must be an absolute"),
            (path_list_form.Form(name="a", paths="/a%2e"), "as it reads decoded"),
        ):
            with self.subTest(form=form), self.assertRaisesRegex(path_list_form.FormProblem, said):
                path_list_form.checked(form)

    def test_an_existing_list_keeps_its_name(self) -> None:
        form = path_list_form.from_posted({"name": "other", "paths": "/x"}, list_row())
        self.assertEqual(form.name, "scanners")


class TheCardRows(unittest.TestCase):
    def test_a_list_says_its_paths_and_who_uses_it(self) -> None:
        rows = path_list_form.rows(
            [list_row(), list_row(name="wordpress", paths=["/wp-admin"])],
            {"scanners": {"alpha": ("shop", "web"), "beta": ("api",)}},
            {},
            writes=True,
        )
        self.assertEqual(
            [(row.name, row.paths, row.used_by) for row in rows],
            [("scanners", "2", "3 proxies"), ("wordpress", "1", "")],
        )
        self.assertEqual(rows[0].href, "/settings/path-lists/scanners/edit")

    def test_a_failed_apply_of_the_revision_links_to_its_job(self) -> None:
        job = replace(
            queued(
                operation="path_list_apply",
                cluster=None,
                payload={"name": "scanners", "revision": 1},
            ),
            state="failed",
        )
        (row,) = path_list_form.rows([list_row()], {}, {"scanners": job}, writes=True)
        self.assertEqual((row.status, row.status_tone), ("Apply failed", "critical"))


class AddingToAnObject(unittest.TestCase):
    def test_a_proxy_without_denied_paths_starts_by_looking(self) -> None:
        changed = yaml.safe_load(path_list_form.with_list("scanners", "shop", site("shop")))
        self.assertEqual(changed["deny_paths"], {"mode": "log", "lists": ["scanners"]})

    def test_a_list_joins_the_proxy_s_own_once_and_keeps_its_mode(self) -> None:
        own = site("shop", "deny_paths:\n  mode: block\n  paths: [/server-info]\n  block_for: 1h\n")
        changed = path_list_form.with_list("scanners", "shop", own)
        data = yaml.safe_load(changed)
        self.assertEqual(
            data["deny_paths"],
            {"mode": "block", "paths": ["/server-info"], "block_for": "1h", "lists": ["scanners"]},
        )
        self.assertEqual(path_list_form.with_list("scanners", "shop", changed), changed)

    def test_a_raw_port_is_left_alone(self) -> None:
        document = (
            "schema: 1\nname: db\nlisten:\n  protocol: tcp\n  port: 5432\nbackend: pool\n"
            "backends:\n  pool:\n    balance: leastconn\n    health:\n      type: tcp\n"
            "    servers:\n    - host: 192.0.2.10\n      port: 5432\n"
        )
        self.assertEqual(path_list_form.with_list("scanners", "db", document), document)


class PathListRouteTestCase(LoginTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.lists: list[db.PathList] = []
        self.saved: list[dict[str, Any]] = []
        self.queued: list[dict[str, Any]] = []
        self.object_rows: list[db.ClusterObjects] = []
        self.drafts: list[db.ProxyDraft] = []

        def save(_c: object, **fields: Any) -> db.PathList:
            self.saved.append(fields)
            return list_row(name=fields["name"], revision=(fields["previous"] or 0) + 1)

        def queue(_c: object, **fields: Any) -> db.Job:
            self.queued.append(fields)
            return queued(operation="path_list_apply", cluster=None, payload=fields["payload"])

        for patch in (
            mock.patch("haprion_ui.db.save_path_list", side_effect=save),
            mock.patch("haprion_ui.db.queue_job", side_effect=queue),
            mock.patch("haprion_ui.db.job_for_key", return_value=None),
            mock.patch("haprion_ui.db.job_state", return_value="done"),
            mock.patch("haprion_ui.db.path_lists", side_effect=lambda _c: list(self.lists)),
            mock.patch(
                "haprion_ui.db.path_list",
                side_effect=lambda _c, name: next((r for r in self.lists if r.name == name), None),
            ),
            mock.patch(
                "haprion_ui.db.cluster_objects", side_effect=lambda _c: list(self.object_rows)
            ),
            mock.patch("haprion_ui.db.live_drafts", side_effect=lambda _c, _l: list(self.drafts)),
            mock.patch("haprion_ui.pages.path_lists.APPLY_WAIT", 0.3),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def admin(self) -> Any:
        client = self.client(replace(configuration(), management_writes=True))
        self.sign_in(client)
        return client

    def token(self, client: Any) -> str:
        return auth.csrf_token(client.cookies[auth.SESSION_COOKIE])

    def post(self, client: Any, path: str = "/settings/path-lists/new", **fields: Any) -> Any:
        data: dict[str, Any] = {
            "name": "scanners",
            "description": "What scanners ask for",
            "paths": "/.env\n/wp-login.php\n",
            "action": "save",
            "idempotency_key": KEY,
            auth.CSRF_FIELD: self.token(client),
        }
        data.update(fields)
        return client.post(path, data=data, follow_redirects=False)


class TheSettingsCard(PathListRouteTestCase):
    def test_the_card_lists_each_list_and_who_uses_it(self) -> None:
        self.lists = [list_row()]
        self.object_rows = [objects_reading("alpha", {"shop": site("shop", NAMED)})]
        page = self.admin().get("/settings").text
        self.assertIn('id="path-lists"', page)
        self.assertIn('href="/settings/path-lists/new"', page)
        self.assertIn('href="/settings/path-lists/scanners/add-to-proxies"', page)
        self.assertIn("1 proxy", page)

    def test_an_unused_list_says_no_proxy(self) -> None:
        self.lists = [list_row()]
        self.assertIn("No proxy", self.admin().get("/settings").text)


class SavingAPathList(PathListRouteTestCase):
    def test_a_save_stores_the_list_and_queues_its_apply_job(self) -> None:
        response = self.post(self.admin())
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/settings#path-lists")
        (saved,) = self.saved
        self.assertEqual(
            (saved["name"], saved["previous"], saved["paths"]),
            ("scanners", None, ("/.env", "/wp-login.php")),
        )
        (job,) = self.queued
        self.assertEqual(job["operation"], "path_list_apply")
        self.assertEqual(job["payload"], {"name": "scanners", "revision": 1})
        self.assertEqual(job["idempotency_key"], UUID(KEY))

    def test_an_edit_is_the_next_revision(self) -> None:
        self.lists = [list_row(revision=4)]
        response = self.post(self.admin(), "/settings/path-lists/scanners/edit", paths="/.git")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.saved[0]["previous"], 4)
        self.assertEqual(self.saved[0]["paths"], ("/.git",))

    def test_a_refusal_redraws_the_form_with_the_line_and_keeps_nothing(self) -> None:
        response = self.post(self.admin(), paths="/.env\n/\n")
        self.assertEqual(response.status_code, 400)
        self.assertIn("line 2 is /", response.text)
        self.assertIn("/.env", response.text)
        self.assertEqual((self.saved, self.queued), ([], []))


class RemovingAPathList(PathListRouteTestCase):
    def remove(self, client: Any) -> Any:
        return client.post(
            "/settings/path-lists/scanners/remove",
            data={auth.CSRF_FIELD: self.token(client), "idempotency_key": KEY},
            follow_redirects=False,
        )

    def test_a_list_an_object_names_is_not_removed(self) -> None:
        self.lists = [list_row()]
        self.object_rows = [objects_reading("alpha", {"shop": site("shop", NAMED)})]
        client = self.admin()
        page = client.get("/settings/path-lists/scanners/remove").text
        self.assertIn("scanners is under Denied paths in shop on alpha", page)
        self.assertEqual(self.remove(client).status_code, 409)
        self.assertEqual(self.queued, [])

    def test_a_draft_that_names_it_blocks_the_removal(self) -> None:
        self.lists = [list_row()]
        self.object_rows = [objects_reading("alpha", {})]
        self.drafts = [
            db.ProxyDraft(
                cluster="alpha",
                object_id="api",
                yaml=site("api", NAMED),
                base_version=None,
                base_hash="a" * 40,
                revision=1,
                updated_by="admin",
                updated_at=NOW,
                deleted=False,
                stage="saved",
                replaces=None,
                base_document=None,
            )
        ]
        response = self.remove(self.admin())
        self.assertEqual(response.status_code, 409)
        self.assertIn("api on alpha", response.text)

    def test_an_unused_list_is_removed_by_its_job(self) -> None:
        self.lists = [list_row(revision=3)]
        self.object_rows = [objects_reading("alpha", {"shop": site("shop")})]
        self.assertEqual(self.remove(self.admin()).status_code, 303)
        (job,) = self.queued
        self.assertEqual(job["payload"], {"name": "scanners", "revision": 3, "remove": True})


class TheCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def file(self, body: str) -> Path:
        path = self.directory / "path-lists.yaml"
        path.write_text(body)
        return path

    def test_a_file_is_read_by_the_engine_s_rule(self) -> None:
        (item,) = path_list_apply.read_file(
            self.file("path_lists:\n  - name: scanners\n    paths: [/.env, /.env, /.git]\n")
        )
        self.assertEqual((item.name, item.paths), ("scanners", ("/.env", "/.git")))
        for body, said in (
            ("lists: []\n", "one section, path_lists"),
            ("path_lists:\n  - name: a\n    paths: [/]\n", "every path"),
            ("path_lists:\n  - name: a\n    paths: [/x]\n    url: x\n", "unknown field: url"),
            ("path_lists:\n  - {name: a, paths: [/x]}\n  - {name: a, paths: [/y]}\n", "twice"),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(path_list_apply.ApplyError, said):
                path_list_apply.read_file(self.file(body))

    def test_the_plan_creates_replaces_applies_again_and_prunes(self) -> None:
        found = path_list_apply.read_file(
            self.file(
                "path_lists:\n"
                "  - {name: fresh, paths: [/a]}\n"
                "  - {name: scanners, paths: [/.env, /.git]}\n"
                "  - {name: same, paths: [/b]}\n"
                "  - {name: stuck, paths: [/c]}\n"
            )
        )
        done = queued(
            operation="path_list_apply", cluster=None, payload={"name": "same", "revision": 1}
        )
        stored = {
            "scanners": list_row(),
            "same": list_row(name="same", paths=["/b"]),
            "stuck": list_row(name="stuck", paths=["/c"]),
            "old": list_row(name="old"),
        }
        latest = {"same": replace(done, state="done")}
        plan = path_list_apply.plan(found, stored, latest, prune=True)
        self.assertEqual(
            [(change.name, change.action) for change in plan.changes],
            [("fresh", "create"), ("scanners", "replace"), ("stuck", "apply"), ("old", "remove")],
        )
        self.assertEqual(plan.unchanged, ("same",))


if __name__ == "__main__":
    unittest.main()
