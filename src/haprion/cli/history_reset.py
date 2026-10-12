"""`haprion-history-reset` - start a cluster's version history over.

The name is the contract. This resets the HISTORY; the configuration is kept
exactly as it is and becomes version 1. A command called "factory reset" would
imply the opposite, and an operator reading it under pressure would be right to
assume their configuration was about to be thrown away.

This half is unprivileged. It reads the repository - which the management group
can already read - to show what would be discarded, asks, and then hands a
structured request to the root helper. The privileged half takes no arguments and
believes nothing it is told about the repository; it reads everything again on
its own side.

Two confirmations, for two different mistakes
---------------------------------------------
The yes/no question guards against running the command at all. The typed phrase
guards against running it while distracted - it cannot be answered by reflex, and
it cannot be answered by a key held down. The phrase is then carried in the
request, so the privileged half can refuse anything that was never confirmed.

What it does and does not do
----------------------------
It publishes version 1 on the way out, because without that the manager describes
itself incorrectly: the published release is named after a commit that no longer
exists. Publishing is local, validated, and touches no node.

For automation, `--confirm '<phrase>'` gives the typed phrase on the command
line and asks nothing, and `--json` prints one envelope
(`schemas/v1/haprion-history-reset`). `--json` requires `--confirm`: a
command that would stop to ask cannot answer in one document.

It does NOT deploy. Sending a reload to production nodes is not something a
command named "history-reset" should do quietly, and it is not urgent: the nodes
are already running this exact configuration, since the configuration is what was
kept. Only the release metadata differs. The deploy is printed as the next step,
and `haprion-config-status` keeps showing the difference until it is run.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from haprion.cli.caller import config_path as _config_path
from haprion.cli.caller import usage
from haprion.envelope import Message, envelope, failure
from haprion.history_reset import ResetError, preview

CONFIRMATION = "please reset me"
BASELINE_MESSAGE = "Baseline after the build phase"
OPERATION = "reset_history"

HELPER = "/opt/haprion/current/bin/haprion-history-reset-helper"
PUBLISH = "/opt/haprion/current/bin/haprion-publish"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haprion-history-reset -c <cluster>\n"
    f"  haprion-history-reset -c <cluster> --confirm '{CONFIRMATION}' [--json]"
)

type RunHelper = Callable[[str, bytes], tuple[int, str, str]]
type PublishCall = Callable[[str], int]


def _run_helper(cluster_id: str, request: bytes) -> tuple[int, str, str]:
    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=request,
        capture_output=True,
        check=False,
    )
    return (
        completed.returncode,
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )


def _publish(cluster_id: str) -> int:
    return subprocess.run(  # noqa: S603 - fixed path, fixed arguments
        [PUBLISH, "-c", cluster_id, BASELINE_MESSAGE],
        check=False,
    ).returncode


def _parse(argv: list[str]) -> tuple[str, str | None, bool]:
    """(cluster, the phrase given with --confirm, --json)."""

    json_mode = "--json" in argv
    rest = [item for item in argv if item != "--json"]
    confirm: str | None = None
    if len(rest) == 4 and rest[2] == "--confirm":
        confirm = rest[3]
        rest = rest[:2]
    if len(rest) != 2 or rest[0] not in ("-c", "--cluster") or (json_mode and confirm is None):
        usage(USAGE)
    return rest[1], confirm, json_mode


def _ask(reader: TextIO, writer: TextIO, question: str) -> str:
    writer.write(question)
    writer.flush()
    answer = reader.readline()
    if not answer:
        #
        # End of input rather than an answer. Treated as "no": a reset must never
        # be the default outcome of a closed pipe.
        #
        return ""
    return str(answer).strip()


def main(
    argv: list[str] | None = None,
    *,
    stream_in: TextIO | None = None,
    stream_out: TextIO | None = None,
    run_helper: RunHelper = _run_helper,
    publish: PublishCall = _publish,
    config_path: Callable[[str], Path] = _config_path,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    reader: TextIO = stream_in or sys.stdin
    writer: TextIO = stream_out or sys.stdout
    cluster_id, confirm, json_mode = _parse(argv)
    request_id = str(uuid.uuid4())
    say: TextIO = io.StringIO() if json_mode else writer

    def refuse(code: str, message: str, exit_code: int) -> int:
        if json_mode:
            emit(
                failure(
                    operation=OPERATION,
                    cluster=cluster_id,
                    request_id=request_id,
                    code=code,
                    message=message[:2048],
                    exit_code=exit_code,
                )
            )
        else:
            writer.write(f"{message}\n" if message.startswith("ERROR") else f"ERROR: {message}\n")
        return exit_code

    def emit(document: dict[str, object]) -> None:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")

    try:
        plan = preview(cluster_id, config_path(cluster_id))
    except ResetError as exc:
        return refuse("refused", str(exc), exc.exit_code)

    say.write(
        f"\nThis discards the version history for cluster '{cluster_id}'.\n\n"
        "  Configuration:      kept exactly as it is, and becomes version 1\n"
        f"  Version history:    {plan.versions} versions discarded\n"
        f"  Draft area:         {plan.draft}\n"
        f"  History:            {plan.history}\n\n"
        "The previous history is kept beside the new one and can be moved back.\n"
        "Nothing is deleted by this command.\n\n"
    )

    if confirm is None:
        if _ask(reader, writer, "Continue? [y/N] ").lower() not in ("y", "yes"):
            writer.write("Nothing was changed.\n")
            return 0
        confirm = _ask(reader, writer, f"Type '{CONFIRMATION}' to confirm: ")
    if confirm != CONFIRMATION:
        if json_mode:
            return refuse("not_confirmed", "The phrase did not match. Nothing was changed.", 64)
        writer.write("The phrase did not match. Nothing was changed.\n")
        return 0

    request = json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "parameters": {"acknowledgement": CONFIRMATION},
        }
    ).encode()

    code, out, err = run_helper(cluster_id, request)
    if code != 0:
        return refuse(
            "reset_failed", err.strip() or f"the reset failed with exit code {code}.", code
        )

    try:
        result = json.loads(out)
    except json.JSONDecodeError:
        return refuse(
            "unknown",
            "the reset reported success but its answer could not be read. "
            "Check the cluster's state before doing anything else.",
            70,
        )

    say.write(
        f"\nCluster '{cluster_id}' now starts at version 1.\n\n"
        f"  Discarded:  {result['versions_discarded']} versions\n"
        f"  Kept:       {result['archived_history']}\n"
        f"              {result['archived_draft']}\n\n"
    )

    #
    # Publish immediately. Until this runs the published release is named after a
    # commit that no longer exists, and every status view is misleading.
    #
    say.write("Publishing version 1...\n")
    published = publish(cluster_id)
    outcome = {
        "versions_discarded": result["versions_discarded"],
        "archived_history": result["archived_history"],
        "archived_draft": result["archived_draft"],
        "published": published == 0,
        "next_command": f"haprion-deploy -c {cluster_id}"
        if published == 0
        else f'haprion-publish -c {cluster_id} "{BASELINE_MESSAGE}"',
    }
    if published != 0:
        if json_mode:
            emit(
                envelope(
                    operation=OPERATION,
                    outcome="partial",
                    cluster=cluster_id,
                    request_id=request_id,
                    result=outcome,
                    warnings=(
                        Message(
                            code="publish_failed",
                            message="the reset succeeded but publishing version 1 did not",
                        ),
                    ),
                )
            )
            return published
        writer.write(
            "\nERROR: the reset succeeded but publishing version 1 did not.\n"
            "Until it does, this cluster's published release refers to a version that\n"
            "no longer exists. Fix the cause and run:\n\n"
            f'  haprion-publish -c {cluster_id} "{BASELINE_MESSAGE}"\n'
        )
        return published

    if json_mode:
        emit(
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=cluster_id,
                request_id=request_id,
                result=outcome,
            )
        )
        return 0
    writer.write(
        "\nThe nodes are already running this configuration - only the release metadata\n"
        "differs. Bring them into step with:\n\n"
        f"  haprion-deploy -c {cluster_id}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
