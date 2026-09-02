"""The privileged half: what it accepts across the boundary, and what it refuses.

It takes no arguments and believes nothing it is told about the repository. These
cases are mostly about the refusals - an unconfirmed request, arguments where
there should be none, and a caller that is not root.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml

from haproxy_mgmt.cli import history_reset_helper
from haproxy_mgmt.cli.history_reset_helper import ACKNOWLEDGEMENT, OPERATION, main

BASE = Path(__file__).resolve().parents[1]
HAPROXY_CFG = b"global\n  daemon\ndefaults\n  mode http\n"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class HelperTests(unittest.TestCase):
    def runtime(self, root: Path, versions: int = 3) -> tuple[Path, Path]:
        config_root = root / "config"
        publish_root = root / "published"
        cert_root = root / "validation-certs"
        for directory in (config_root, publish_root / "alpha", cert_root):
            directory.mkdir(parents=True)
        (cert_root / "validation.pem").write_text("dummy PEM\n", encoding="utf-8")

        seed = root / "seed"
        seed.mkdir()
        git(seed, "init", "-q", "-b", "main")
        git(seed, "config", "user.name", "Example Maintainer")
        git(seed, "config", "user.email", "maintainer@example.com")
        (seed / "core").mkdir()
        (seed / "manual").mkdir()
        (seed / "manual" / "reservations.yaml").write_bytes(b"{}\n")
        for number in range(versions):
            (seed / "core" / "haproxy.cfg").write_bytes(HAPROXY_CFG + f"# {number}\n".encode())
            git(seed, "add", "-A")
            git(seed, "commit", "-qm", f"Version {number + 1}")

        history = config_root / "alpha.git"
        subprocess.run(
            [
                "/usr/bin/git",
                "clone",
                "-q",
                "--bare",
                str(history.parent / ".." / "seed"),
                str(history),
            ],
            check=True,
            capture_output=True,
        )
        git(history, "config", "user.name", "Example Maintainer")
        git(history, "config", "user.email", "maintainer@example.com")
        draft = config_root / "alpha"
        git(history, "worktree", "add", "-q", str(draft), "main")

        clusters = yaml.safe_load((BASE / "examples/clusters.yaml").read_text())
        cluster = clusters["clusters"]["alpha"]
        cluster["config_path"] = str(draft)
        cluster["publish_path"] = str(publish_root / "alpha")
        cluster["validation_certs"] = str(cert_root)
        clusters_file = root / "clusters.yaml"
        clusters_file.write_text(yaml.safe_dump(clusters), encoding="utf-8")

        policy = root / "runtime-policy.yaml"
        policy.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "cluster_file": str(clusters_file),
                    "config_root": str(config_root),
                    "publish_root": str(publish_root),
                    "validation_certs_root": str(cert_root),
                }
            ),
            encoding="utf-8",
        )
        return policy, draft

    def request(self, **overrides: object) -> bytes:
        document: dict[str, object] = {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": "alpha",
            "request_id": str(uuid.uuid4()),
            "parameters": {"acknowledgement": ACKNOWLEDGEMENT},
        }
        document.update(overrides)
        return json.dumps(document).encode()

    def run_helper(self, policy: Path, request: bytes, **overrides: object):
        out, err = io.StringIO(), io.StringIO()
        arguments: dict[str, object] = {
            "policy_path": policy,
            "input_stream": io.BytesIO(request),
            "output_stream": out,
            "error_stream": err,
            "require_secure": False,
            "require_root": False,
            "change_owner": lambda path, uid, gid: None,
            "resolve_group": lambda _name: os.getgid(),
        }
        arguments.update(overrides)
        code = main([], **arguments)  # type: ignore[arg-type]
        return code, out.getvalue(), err.getvalue()

    # ------------------------------------------------------------------ refusing

    def test_a_request_without_the_acknowledgement_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, _, err = self.run_helper(policy, self.request(parameters={}))
            self.assertEqual(code, 77)
            self.assertIn("acknowledgement", err)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)

    def test_a_wrong_acknowledgement_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            code, _, _ = self.run_helper(
                policy, self.request(parameters={"acknowledgement": "yes please"})
            )
            self.assertEqual(code, 77)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)

    def test_arguments_are_refused(self) -> None:
        """One no-argument sudoers rule covers every cluster; argv must stay empty."""
        with TemporaryDirectory() as raw:
            policy, _ = self.runtime(Path(raw))
            out, err = io.StringIO(), io.StringIO()
            code = main(
                ["-c", "alpha"],
                policy_path=policy,
                input_stream=io.BytesIO(self.request()),
                output_stream=out,
                error_stream=err,
                require_secure=False,
                require_root=False,
            )
            self.assertEqual(code, 64)
            self.assertIn("no command-line arguments", err.getvalue())

    def test_another_operation_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            policy, _ = self.runtime(Path(raw))
            code, _, err = self.run_helper(policy, self.request(operation="publish_release"))
            self.assertNotEqual(code, 0)
            self.assertIn("operation", err)

    def test_running_without_root_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            policy, _ = self.runtime(Path(raw))
            code, _, err = self.run_helper(policy, self.request(), require_root=True)
            expected = 0 if os.geteuid() == 0 else 77
            self.assertEqual(code, expected)
            if expected == 77:
                self.assertIn("must run as root", err)

    def test_unpublished_work_is_refused(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            (draft / "core" / "haproxy.cfg").write_bytes(HAPROXY_CFG + b"# unsaved\n")
            code, _, err = self.run_helper(policy, self.request())
            self.assertEqual(code, 65)
            self.assertIn("not published", err)

    def test_a_missing_management_group_fails_before_writing(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            before = git(draft, "rev-parse", "HEAD")
            with mock.patch.object(history_reset_helper.grp, "getgrnam", side_effect=KeyError):
                code, out, err = self.run_helper(
                    policy,
                    self.request(),
                    resolve_group=history_reset_helper._group_id,
                )

            self.assertEqual(code, 78)
            self.assertEqual(out, "")
            self.assertIn("group 'haproxy-mgmt' does not exist", err)
            self.assertEqual(git(draft, "rev-parse", "HEAD"), before)

    # ------------------------------------------------------------------ doing it

    def test_a_confirmed_request_resets_the_history(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw), versions=4)
            code, out, err = self.run_helper(policy, self.request())
            self.assertEqual(code, 0, err)
            answer = json.loads(out)
            self.assertEqual(answer["versions_discarded"], 4)
            self.assertEqual(answer["cluster"], "alpha")
            self.assertEqual(git(draft, "rev-list", "--first-parent", "--count", "HEAD"), "1")
            self.assertEqual(answer["commit"], git(draft, "rev-parse", "HEAD"))

    def test_the_answer_names_the_undo_path(self) -> None:
        with TemporaryDirectory() as raw:
            policy, draft = self.runtime(Path(raw))
            _, out, _ = self.run_helper(policy, self.request())
            answer = json.loads(out)
            self.assertTrue(Path(answer["archived_history"]).is_dir())
            self.assertTrue(Path(answer["archived_draft"]).is_dir())

    def test_the_request_id_is_echoed_back(self) -> None:
        with TemporaryDirectory() as raw:
            policy, _ = self.runtime(Path(raw))
            request = self.request()
            _, out, _ = self.run_helper(policy, request)
            self.assertEqual(json.loads(out)["request_id"], json.loads(request)["request_id"])


if __name__ == "__main__":
    unittest.main()
