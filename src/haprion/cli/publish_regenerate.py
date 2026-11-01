"""`haprion-publish --regenerate` - publish the generated layer made again, nothing else changed.

The terminal's way to what *Publish & deploy* does on a cluster's *Versions*
page when a newer release of the product would write other configuration from
the same objects (`haprion-config-status` says so). The request is the one the
interface queues: `changes_publish` with `regenerate: true`, fenced on the
version just read, through the helper that already publishes saved changes. A
publish is not a deploy: `haprion-deploy -c <cluster>` takes it to the nodes.

    haprion-publish -c <cluster> --regenerate [-m <comment>] [--check]
                    [--expect <fingerprint>] [--allow-certificate-mismatch] [--json]

`--check` says what a publish would change and publishes nothing; it prints the
reading's fingerprint. `--expect` refuses unless the reading now is that one,
which is what the page's button does with the reading it was drawn from. The
helper makes the publish's own checks whatever is asked here, and says when
there is nothing to publish.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes
from haprion.cli import arguments, changes_publish
from haprion.cli import config_status as status
from haprion.cli.apply_common import Refused, RunPublish, answer_of, envelope
from haprion.cli.caller import config_path as _config_path
from haprion.cli.caller import looked_up, without_answer
from haprion.cli.cluster_settings import run_publish_helper
from haprion.envelope import envelope as make_envelope
from haprion.envelope import new_request_id
from haprion.git_command import GitError
from haprion.helper_protocol import write_document
from haprion.regeneration import diff_from_dict
from haprion.repo_health import describe_problem, is_repo_root
from haprion.repo_snapshot import PublishError, resolve_head
from haprion.version_diff import render

ANSWER = changes_publish.OPERATION
COMMENT = "Regenerated with the installed version."

type ConfigPath = Callable[[str], Path]
type ReadRegeneration = Callable[[str], Mapping[str, Any] | None]


def _parser() -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(prog="haprion-publish", add_help=True)
    parser.add_argument("-c", "--cluster", required=True)
    parser.add_argument("--regenerate", action="store_true", required=True)
    parser.add_argument("-m", "--comment", default=COMMENT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--expect", metavar="FINGERPRINT")
    parser.add_argument("--allow-certificate-mismatch", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def _check(
    cluster: str,
    reading: Mapping[str, Any] | None,
    *,
    json_mode: bool,
    writer: TextIO,
) -> int:
    """What a publish would change, in the words `haprion-config-status` uses."""

    if reading is None or reading.get("outcome") == status.UNREADABLE_OUTCOME:
        message = (reading or {}).get("message") or status.UNREADABLE
        return _refuse(
            cluster,
            Refused("dependency_unavailable", str(message), exit_codes.UNAVAILABLE),
            json_mode=json_mode,
            writer=writer,
            errors=writer,
        )
    if json_mode:
        write_document(
            writer,
            make_envelope(
                operation="regeneration", outcome="done", cluster=cluster, result=dict(reading)
            ),
            0,
        )
        return 0
    line = status.regeneration_line(reading, cluster)
    if line is None:
        writer.write(f"Publishing again would not change what {cluster} runs.\n")
    else:
        writer.write(line)
        if reading.get("diff"):
            writer.write("\n" + render(diff_from_dict(reading["diff"])))
    if reading.get("fingerprint"):
        writer.write(f"Fingerprint: {reading['fingerprint']}\n")
    return 0


def _refuse(
    cluster: str, refused: Refused, *, json_mode: bool, writer: TextIO, errors: TextIO
) -> int:
    if json_mode:
        write_document(writer, envelope(ANSWER, cluster, None, refused), refused.exit_code)
    else:
        errors.write(refused.report())
    return refused.exit_code


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    config_path: ConfigPath = _config_path,
    read_regeneration: ReadRegeneration = status.ask_regeneration,
    run_publish: RunPublish = run_publish_helper,
) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster = str(args.cluster)
    json_mode = bool(args.json)
    if args.check and args.expect:
        _parser().error("--check publishes nothing, so there is nothing to expect")

    repo = looked_up(config_path, cluster, operation=ANSWER, json_mode=json_mode, writer=writer)
    try:
        if not is_repo_root(repo):
            raise Refused(
                "dependency_unavailable", describe_problem(cluster, repo), exit_codes.UNAVAILABLE
            )
        if args.check or args.expect:
            reading = read_regeneration(cluster)
            if args.check:
                return _check(cluster, reading, json_mode=json_mode, writer=writer)
            if reading is None or reading.get("outcome") == status.UNREADABLE_OUTCOME:
                raise Refused(
                    "dependency_unavailable",
                    str((reading or {}).get("message") or status.UNREADABLE),
                    exit_codes.UNAVAILABLE,
                )
            if reading.get("fingerprint") != args.expect:
                raise Refused(
                    "expected_target_changed",
                    "what a publish would change is not what was read: the reading now is "
                    f"{reading.get('fingerprint')}. Read it again before publishing.",
                    exit_codes.BLOCKED,
                )
        _, head = resolve_head(repo)
    except Refused as refused:
        return _refuse(cluster, refused, json_mode=json_mode, writer=writer, errors=errors)
    except (GitError, PublishError) as exc:
        return _refuse(
            cluster,
            Refused("dependency_unavailable", str(exc), exc.exit_code),
            json_mode=json_mode,
            writer=writer,
            errors=errors,
        )

    request = changes_publish.build_request(
        cluster,
        new_request_id(),
        expected_head=head,
        comment=args.comment,
        allow_certificate_mismatch=bool(args.allow_certificate_mismatch),
        regenerate=True,
    )
    completed = run_publish(request)
    if json_mode:
        #
        # The helper's own document, as `haprion-publish --json` has it: the
        # contract is its.
        #
        if not completed.stdout.strip():
            return without_answer(
                completed,
                operation=ANSWER,
                cluster=cluster,
                json_mode=True,
                writer=writer,
                errors=errors,
                fallback=f"publishing failed with exit code {completed.returncode}.",
            )
        writer.write(
            completed.stdout if completed.stdout.endswith("\n") else completed.stdout + "\n"
        )
        return exit_codes.of_process(completed.returncode, exit_codes.INTERNAL) or exit_codes.OK
    try:
        result = answer_of(completed, ANSWER, changes=True)
    except Refused as refused:
        return _refuse(cluster, refused, json_mode=False, writer=writer, errors=errors)
    if not result.get("changed"):
        writer.write(
            f"Publishing again would not change what {cluster} runs; nothing was published.\n"
        )
        return 0
    writer.write(f"Published version {result['version']} of {cluster}.\n")
    if result.get("deployment_required"):
        writer.write(f"Deploy it with: haprion-deploy -c {cluster}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
