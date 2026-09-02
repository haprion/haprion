"""The two confirmations, and what happens when they are not given.

A reset must never be the outcome of a mistake, a held-down key, or a closed
pipe. Most of these cases are about refusing, because refusing is the part that
has to be right every single time.

This half is unprivileged, so the privileged helper is stubbed. What is asserted
is what the operator sees and what crosses the boundary - not what happens on the
other side, which has its own tests.
"""

from __future__ import annotations

import io
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from haproxy_mgmt.cli.history_reset import CONFIRMATION, OPERATION, main

HAPROXY_CFG = b"global\n  daemon\ndefaults\n  mode http\n"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


class CommandTests(unittest.TestCase):
    def layout(self, root: Path, versions: int = 3) -> Path:
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

        history = root / "alpha.git"
        subprocess.run(
            ["/usr/bin/git", "clone", "-q", "--bare", str(seed), str(history)],
            check=True,
            capture_output=True,
        )
        draft = root / "alpha"
        git(history, "worktree", "add", "-q", str(draft), "main")
        return draft

    def run_command(
        self, draft: Path, answers: str, *, helper_code: int = 0, publish_code: int = 0
    ):
        crossed: list[dict[str, object]] = []
        published: list[str] = []

        def run_helper(cluster_id: str, request: bytes) -> tuple[int, str, str]:
            crossed.append(json.loads(request))
            if helper_code != 0:
                return helper_code, "", "ERROR: refused on the other side\n"
            answer = {
                "schema_version": 1,
                "operation": OPERATION,
                "cluster": cluster_id,
                "request_id": "x",
                "commit": "c" * 40,
                "versions_discarded": 3,
                "archived_history": f"{draft}.git.pre-reset-20260901-120000",
                "archived_draft": f"{draft}.pre-reset-20260901-120000",
            }
            return 0, json.dumps(answer), ""

        def publish(cluster_id: str) -> int:
            published.append(cluster_id)
            return publish_code

        output = io.StringIO()
        code = main(
            ["-c", "alpha"],
            stream_in=io.StringIO(answers),
            stream_out=output,
            run_helper=run_helper,
            publish=publish,
            config_path=lambda _cluster: draft,
        )
        return code, output.getvalue(), crossed, published

    # ------------------------------------------------------------------ refusing

    def test_answering_no_crosses_nothing(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, output, crossed, published = self.run_command(draft, "n\n")
            self.assertEqual(code, 0)
            self.assertIn("Nothing was changed", output)
            self.assertEqual(crossed, [])
            self.assertEqual(published, [])

    def test_the_default_answer_is_no(self) -> None:
        """A held-down return key must not reset a cluster."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, output, crossed, _ = self.run_command(draft, "\n\n\n")
            self.assertEqual(code, 0)
            self.assertIn("Nothing was changed", output)
            self.assertEqual(crossed, [])

    def test_a_closed_pipe_is_not_a_yes(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, _, crossed, _ = self.run_command(draft, "")
            self.assertEqual(code, 0)
            self.assertEqual(crossed, [])

    def test_the_wrong_phrase_stops_it(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, output, crossed, _ = self.run_command(draft, "y\nreset\n")
            self.assertEqual(code, 0)
            self.assertIn("did not match", output)
            self.assertEqual(crossed, [])

    def test_yes_alone_is_not_enough(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, _, crossed, _ = self.run_command(draft, "y\n\n")
            self.assertEqual(code, 0)
            self.assertEqual(crossed, [])

    def test_unpublished_work_is_refused_before_anything_is_asked(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            (draft / "core" / "haproxy.cfg").write_bytes(HAPROXY_CFG + b"# unsaved\n")
            code, output, crossed, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertEqual(code, 65)
            self.assertIn("not published", output)
            self.assertEqual(crossed, [])

    # ------------------------------------------------------- what crosses over

    def test_the_request_carries_the_acknowledgement(self) -> None:
        """The privileged half refuses anything that was never confirmed."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            _, _, crossed, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertEqual(len(crossed), 1)
            request = crossed[0]
            self.assertEqual(request["operation"], OPERATION)
            self.assertEqual(request["cluster"], "alpha")
            self.assertEqual(request["parameters"], {"acknowledgement": CONFIRMATION})
            self.assertEqual(request["schema_version"], 1)

    def test_no_repository_state_is_sent_across(self) -> None:
        """The other side reads everything again; sending it would invite trust."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            _, _, crossed, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertEqual(set(crossed[0]["parameters"]), {"acknowledgement"})  # type: ignore[arg-type]

    def test_each_run_has_its_own_request_id(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            _, _, first, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            _, _, second, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertNotEqual(first[0]["request_id"], second[0]["request_id"])

    # ------------------------------------------------------------------ reporting

    def test_it_reports_and_publishes(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, output, _, published = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertEqual(code, 0, output)
            self.assertIn("now starts at version 1", output)
            self.assertIn("3 versions", output)
            self.assertEqual(published, ["alpha"])

    def test_the_undo_path_is_on_screen(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            _, output, _, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertIn(".git.pre-reset-20260901-120000", output)
            self.assertIn(f"{draft.name}.pre-reset-20260901-120000", output)

    def test_it_does_not_deploy(self) -> None:
        """Reloading production nodes is not this command's job."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            _, output, _, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n")
            self.assertNotIn("Deploying", output)
            self.assertIn("already running this configuration", output)
            self.assertIn("haproxy-deploy -c alpha", output)

    def test_a_refusal_on_the_other_side_is_shown_verbatim(self) -> None:
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, output, _, published = self.run_command(
                draft, f"y\n{CONFIRMATION}\n", helper_code=77
            )
            self.assertEqual(code, 77)
            self.assertIn("refused on the other side", output)
            self.assertEqual(published, [], "publishing must not follow a failed reset")

    def test_a_failed_publish_is_reported_as_unfinished(self) -> None:
        """The reset stands, so the operator must be told what is now inconsistent."""
        with TemporaryDirectory() as raw:
            draft = self.layout(Path(raw))
            code, output, _, _ = self.run_command(draft, f"y\n{CONFIRMATION}\n", publish_code=65)
            self.assertEqual(code, 65)
            self.assertIn("refers to a version that", output)
            self.assertIn("haproxy-publish -c alpha", output)


if __name__ == "__main__":
    unittest.main()
