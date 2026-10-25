"""A socket helper's answer is kept for recovery (B367)."""

from __future__ import annotations

import fcntl
import io
import json
import os
import tempfile
import time
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO
from unittest import mock
from uuid import uuid4

from haprion import answer_receipt
from haprion.cli import backup_job_helper, cert_receiver_helper, node_helper, node_restore_helper

REQUEST_ID = "6f1e2d3c-4b5a-4968-8776-655443322110"


@contextmanager
def receipts() -> Iterator[Path]:
    with (
        tempfile.TemporaryDirectory() as raw,
        mock.patch.object(answer_receipt, "root", return_value=Path(raw)),
    ):
        yield Path(raw)


@answer_receipt.keeps_answer
def helper(
    argv: list[str] | None = None,
    *,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    request_id: str = REQUEST_ID,
    during: object = None,
    code: int = 0,
) -> int:
    assert output_stream is not None
    output_stream.write("before\n")
    answer_receipt.begin(output_stream, request_id)
    if callable(during):
        during()
    output_stream.write('{"outcome": "done"}\n')
    return code


class AReceipt(unittest.TestCase):
    def test_keeps_what_the_helper_wrote_and_how_it_exited(self) -> None:
        with receipts() as directory:
            output = io.StringIO()

            self.assertEqual(helper(output_stream=output, code=75), 75)

            receipt = answer_receipt.read(REQUEST_ID, directory)
            self.assertEqual(receipt.state, "answered")
            self.assertEqual(receipt.stdout, output.getvalue())
            self.assertEqual(receipt.stdout, 'before\n{"outcome": "done"}\n')
            self.assertEqual(receipt.exit_code, 75)

    def test_reads_as_running_while_its_helper_works(self) -> None:
        seen: list[str] = []
        with receipts() as directory:
            helper(
                output_stream=io.StringIO(),
                during=lambda: seen.append(answer_receipt.read(REQUEST_ID, directory).state),
            )

        self.assertEqual(seen, ["running"])

    def test_a_helper_that_raised_is_kept_without_an_exit_code(self) -> None:
        def fail() -> None:
            raise RuntimeError("stopped")

        with receipts() as directory:
            with self.assertRaises(RuntimeError):
                helper(output_stream=io.StringIO(), during=fail)

            receipt = answer_receipt.read(REQUEST_ID, directory)

        self.assertEqual((receipt.state, receipt.exit_code), ("answered", None))

    def test_a_helper_that_died_reads_as_silent_and_not_as_running(self) -> None:
        """The kernel lets go of a dead process's lock; nothing was written."""

        with receipts() as directory:
            output = answer_receipt.Kept(io.StringIO(), directory)
            output.begin(REQUEST_ID)
            os.close(output._fd)  # type: ignore[arg-type]

            self.assertEqual(answer_receipt.read(REQUEST_ID, directory).state, "silent")

    def test_is_absent_when_its_helper_never_began(self) -> None:
        with receipts() as directory:
            self.assertEqual(answer_receipt.read(REQUEST_ID, directory).state, "absent")

    def test_is_unavailable_where_none_are_kept(self) -> None:
        self.assertEqual(
            answer_receipt.read(REQUEST_ID, Path("/nonexistent/answers")).state, "unavailable"
        )
        with receipts() as directory:
            self.assertEqual(
                answer_receipt.read("../../etc/passwd", directory).state, "unavailable"
            )
            self.assertEqual(
                answer_receipt.read(REQUEST_ID.upper(), directory).state, "unavailable"
            )

    def test_nothing_is_kept_when_not_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with (
                mock.patch.object(answer_receipt, "ROOT", Path(raw)),
                mock.patch("os.geteuid", return_value=1000),
            ):
                helper(output_stream=io.StringIO())

            self.assertEqual(os.listdir(raw), [])

    def test_is_the_directory_s_group_and_not_world_readable(self) -> None:
        with receipts() as directory:
            helper(output_stream=io.StringIO())

            metadata = (directory / f"{REQUEST_ID}.json").stat()
            group = directory.stat().st_gid

        self.assertEqual(metadata.st_mode & 0o777, 0o640)
        self.assertEqual(metadata.st_gid, group)

    def test_old_receipts_are_removed_and_held_ones_kept(self) -> None:
        with receipts() as directory:
            old, held, new = (str(uuid4()) for _ in range(3))
            for request_id in (old, held, new):
                (directory / f"{request_id}.json").write_text("{}")
            (directory / f".{old}.json.123").write_text("")
            month_ago = time.time() - 30 * 24 * 3600
            for name in (f"{old}.json", f"{held}.json", f".{old}.json.123"):
                os.utime(directory / name, (month_ago, month_ago))
            with open(directory / f"{held}.json") as holding:
                fcntl.flock(holding, fcntl.LOCK_SH)
                helper(output_stream=io.StringIO())

            left = sorted(os.listdir(directory))

        self.assertEqual(left, sorted([f"{held}.json", f"{new}.json", f"{REQUEST_ID}.json"]))


class EverySocketHelperKeepsItsAnswer(unittest.TestCase):
    """The four helpers behind sockets (`Accept=yes`), each through its own refusal."""

    def ask(
        self,
        main: object,
        operation: str,
        parameters: dict[str, object],
        cluster: str | None = "alpha",
    ) -> None:
        request_id = str(uuid4())
        request = {
            "schema_version": 1,
            "operation": operation,
            "cluster": cluster,
            "request_id": request_id,
            "parameters": parameters,
        }
        with receipts() as directory:
            output = io.StringIO()
            main(  # type: ignore[operator]
                [],
                policy_path=Path("/nonexistent/runtime-policy.yaml"),
                input_stream=io.BytesIO(json.dumps(request).encode()),
                output_stream=output,
                error_stream=io.StringIO(),
                require_root=False,
            )
            receipt = answer_receipt.read(request_id, directory)

        self.assertEqual(receipt.state, "answered", operation)
        self.assertEqual(receipt.stdout, output.getvalue())
        self.assertIn(request_id, receipt.stdout)

    def test_the_node_helper(self) -> None:
        self.ask(node_helper.main, node_helper.OPERATION, {"action": "remove", "node": "node-a"})

    def test_the_backup_job_helper(self) -> None:
        self.ask(backup_job_helper.main, backup_job_helper.RUN, {})

    def test_the_node_restore_helper(self) -> None:
        self.ask(node_restore_helper.main, node_restore_helper.STATUS, {"run": str(uuid4())})

    def test_the_certificate_receiver_helper(self) -> None:
        self.ask(
            cert_receiver_helper.main,
            cert_receiver_helper.OPERATION,
            {"action": "remove", "receiver": "fs-a"},
            cluster=None,
        )


if __name__ == "__main__":
    unittest.main()
