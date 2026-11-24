"""haprion-path-list-apply-helper: one path list written root-only, checked as the engine reads it (B532)."""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from haprion import exit_codes, path_lists
from haprion.cli import path_list_apply_helper
from tests.contract_schema import assert_contract


class Applying(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "path-lists"
        self.directory.mkdir(mode=0o700)

    users: list[str] = []

    def invoke(self, **parameters: object) -> tuple[int, dict[str, Any], str]:
        request = json.dumps(
            {
                "schema_version": 1,
                "operation": "path_list_apply",
                "cluster": None,
                "request_id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "parameters": {
                    "name": "scanners",
                    "revision": 2,
                    "description": "What scanners ask for",
                    "paths": ["/.env", "/wp-login.php"],
                    **parameters,
                },
            }
        )
        output, errors = io.StringIO(), io.StringIO()
        code = path_list_apply_helper.main(
            [],
            input_stream=io.BytesIO(request.encode("utf-8")),
            output_stream=output,
            error_stream=errors,
            require_secure=False,
            require_root=False,
            directory=self.directory,
            users_reader=lambda _name: list(self.users),
        )
        said = output.getvalue()
        document = assert_contract("haprion-path-list-apply", said) if said else {}
        return code, document, errors.getvalue()

    def test_the_list_is_written_at_its_revision(self) -> None:
        code, document, errors = self.invoke()
        self.assertEqual(code, 0, errors)
        self.assertEqual(document["result"], {"name": "scanners", "revision": 2, "paths": 2})
        stored = path_lists.read_all(directory=self.directory)["scanners"]
        self.assertEqual(stored.paths, ("/.env", "/wp-login.php"))
        self.assertEqual((stored.revision, stored.description), (2, "What scanners ask for"))

    def test_remove_says_whether_there_was_a_list(self) -> None:
        self.invoke()
        code, document, _ = self.invoke(remove=True, revision=3)
        self.assertEqual(code, 0)
        self.assertEqual(document["result"], {"name": "scanners", "revision": 3, "removed": True})
        self.assertEqual(path_lists.read_all(directory=self.directory), {})
        _, again, _ = self.invoke(remove=True, revision=4)
        self.assertFalse(again["result"]["removed"])

    def test_a_list_a_cluster_s_committed_object_names_is_not_removed(self) -> None:
        """Review 26-11-24, PW11: the web's check is a poll old; root's is the repository's."""

        self.invoke()
        self.users = ["alpha/shop"]
        try:
            code, document, _ = self.invoke(remove=True, revision=3)
        finally:
            self.users = []
        self.assertEqual(code, exit_codes.REFUSED)
        self.assertEqual(document["outcome"], "failed")
        self.assertEqual(document["error"]["code"], "in_use")
        self.assertIn("alpha/shop", document["error"]["message"])
        self.assertIn("scanners", path_lists.read_all(directory=self.directory))

    def test_what_the_engine_would_not_read_is_refused_and_nothing_written(self) -> None:
        for parameters, said in (
            ({"paths": ["/"]}, "every path"),
            ({"paths": []}, "at least one path"),
            ({"name": "Bad"}, "name"),
            ({"revision": 0}, "revision"),
            ({"remove": "yes"}, "remove"),
        ):
            with self.subTest(parameters=parameters):
                code, document, _ = self.invoke(**parameters)
                self.assertEqual(code, exit_codes.REFUSED)
                self.assertEqual(document["error"]["code"], "bad_input")
                self.assertIn(said, document["error"]["message"])
                self.assertEqual(path_lists.read_all(directory=self.directory), {})

    def test_a_list_over_a_file_at_a_higher_revision_is_done_with_a_warning(self) -> None:
        """Review 26-11-24, PW02: the row is what was saved; the file is made to match."""

        self.invoke(revision=5)
        code, document, errors = self.invoke(revision=4, paths=["/.git"])
        self.assertEqual(code, 0, errors)
        self.assertEqual(document["outcome"], "done")
        self.assertIn("WARNING: revision_behind", errors)
        stored = path_lists.read_all(directory=self.directory)["scanners"]
        self.assertEqual((stored.revision, stored.paths), (4, ("/.git",)))

    def test_an_unknown_parameter_is_refused(self) -> None:
        code, document, errors = self.invoke(extra=1)
        self.assertNotEqual(code, 0)
        self.assertEqual(document, {})
        self.assertIn("extra", errors)


class ReadingTheCommittedObjects(unittest.TestCase):
    """`committed_users` against real repositories: each cluster's HEAD, not its work tree."""

    def repository(self, name: str, files: dict[str, str]) -> Path:
        repo = Path(self.enterContext(tempfile.TemporaryDirectory())) / name
        repo.mkdir()

        def git(*args: str) -> None:
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), *args], check=True, capture_output=True
            )

        git("init", "-q", "-b", "main")
        git("config", "user.name", "Example Maintainer")
        git("config", "user.email", "maintainer@example.com")
        for relative, content in files.items():
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        git("add", "-A")
        git("commit", "-qm", "objects")
        return repo

    def runtime(self, **repos: Path) -> Any:
        return SimpleNamespace(
            clusters={name: SimpleNamespace(config_path=path) for name, path in repos.items()}
        )

    def document(self, name: str, extra: str = "") -> str:
        return (
            f"schema: 1\nname: {name}\nhostnames: [{name}.example.com]\n"
            f"listen: {{protocol: http}}\n{extra}"
            "routes:\n  - {path: /, backend: web}\n"
            "backends:\n  web: {balance: roundrobin, servers: [{host: 192.0.2.10, port: 80}]}\n"
        )

    def test_the_objects_that_name_the_list_in_any_cluster_are_found(self) -> None:
        naming = self.document("shop", "deny_paths: {mode: deny, lists: [scanners]}\n")
        alpha = self.repository(
            "alpha",
            {
                "managed/proxies/shop.yaml": naming,
                "managed/proxies/api.yaml": self.document("api"),
            },
        )
        beta = self.repository("beta", {"managed/proxies/api.yaml": self.document("api")})
        gamma = self.repository(
            "gamma",
            {"managed/proxies/blog.yaml": naming.replace("shop", "blog")},
        )
        found = path_list_apply_helper.committed_users(
            "scanners", self.runtime(alpha=alpha, beta=beta, gamma=gamma)
        )
        self.assertEqual(found, ["alpha/shop", "gamma/blog"])
        self.assertEqual(
            path_list_apply_helper.committed_users("other", self.runtime(alpha=alpha)), []
        )

    def test_a_cluster_that_cannot_be_read_refuses_the_removal(self) -> None:
        missing = Path(self.enterContext(tempfile.TemporaryDirectory())) / "nowhere"
        with self.assertRaisesRegex(path_lists.PathListError, "cannot read the committed objects"):
            path_list_apply_helper.committed_users("scanners", self.runtime(alpha=missing))


if __name__ == "__main__":
    unittest.main()
