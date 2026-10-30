"""``haprion-cluster-settings`` - where a cluster's traffic log goes, and metrics.

Shows the settings the interface's *Logs & metrics* card edits, and sets them
from a file through the helper the interface publishes saved changes with,
so the terminal and the browser make the same version (Fas 15, B209, B257):

    haprion-cluster-settings -c <cluster> [--json]
    haprion-cluster-settings -c <cluster> --set <file> -m <comment>
    haprion-cluster-settings apply -c <cluster> <file> [--check] [-m <comment>] [--json]

`apply` is the form automation uses (`cluster_settings_apply`): it compares
first, says `changed`, and publishes nothing when the file is what is stored.
A change is published, not deployed: `haprion-deploy -c <cluster>` takes it
to the nodes, as after any other publish.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes
from haprion.cli import changes_publish
from haprion.cli.caller import usage, without_answer
from haprion.cluster_settings import MAX_BYTES
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document

OPERATION = "cluster_settings"
HELPER = "/opt/haprion/current/bin/haprion-cluster-settings-helper"
SUDO = "/usr/bin/sudo"
USAGE = (
    "Usage:\n"
    "  haprion-cluster-settings -c <cluster> [--json]\n"
    "  haprion-cluster-settings -c <cluster> --set <file> -m <comment>\n"
    "  haprion-cluster-settings apply -c <cluster> <file> [--check] [-m <comment>] [--json]\n"
)

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]


def _through(helper: str, *sudo: str) -> list[str]:
    """The helper's argv: through sudo, or directly when this already runs as root.

    An operator runs this command with `sudo`, since the installation grants
    no rule for it. A second sudo inside the first would then name `root` as
    the account that ran the helper, and the version would record `root`
    rather than the person (review 2026-09-29 F2). Run directly, the helper
    inherits the outer sudo's `SUDO_USER` and records who asked.
    """

    return [helper] if os.geteuid() == 0 else [SUDO, *sudo, helper]


type RunPublish = Callable[[str], subprocess.CompletedProcess[str]]


def run_settings_helper(cluster_id: str, request_id: str) -> subprocess.CompletedProcess[str]:
    """Ask the root helper for one cluster's settings."""

    request = {
        "schema_version": 1,
        "operation": OPERATION,
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {},
    }
    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        _through(HELPER, "-n"),
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


def run_publish_helper(request: str) -> subprocess.CompletedProcess[str]:
    """Publish through the root helper; sudo may ask for the operator's password."""

    return subprocess.run(  # noqa: S603 - fixed helper path, no caller argv
        _through(changes_publish.HELPER, "--"),
        input=request,
        capture_output=True,
        text=True,
        check=False,
    )


def _parse(argv: list[str]) -> tuple[str, bool, Path | None, str | None]:
    if len(argv) < 2 or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    cluster, rest = argv[1], argv[2:]
    if rest == []:
        return cluster, False, None, None
    if rest == ["--json"]:
        return cluster, True, None, None
    if len(rest) == 4 and rest[0] == "--set" and rest[2] in ("-m", "--comment") and rest[3]:
        return cluster, False, Path(rest[1]), rest[3]
    usage(USAGE)


def _result(document: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
    if document.get("operation") != operation:
        raise ValueError("the helper returned an invalid result")
    error = document.get("error")
    if isinstance(error, Mapping):
        raise ValueError(f"{error.get('code')}: {error.get('message')}")
    result = document.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("the helper returned an invalid result")
    return result


def _render(result: Mapping[str, Any], cluster: str, writer: TextIO) -> None:
    writer.write(f"Cluster: {cluster}\n\n")
    targets = result.get("log_targets")
    writer.write(f"{'LOG TARGET':<20}{'ADDRESS':<44}{'DISK QUEUE':<12}TLS\n")
    writer.write(f"{'-' * 18:<20}{'-' * 42:<44}{'-' * 10:<12}---\n")
    if not isinstance(targets, list) or not targets:
        writer.write("none; the traffic log is not sent anywhere\n")
    else:
        for target in targets:
            address = str(target.get("address", ""))
            shown = f"[{address}]" if ":" in address else address
            writer.write(
                f"{str(target.get('name', '')):<20}{shown + ':' + str(target.get('port', '')):<44}"
                f"{str(target.get('disk_mib', '')) + ' MiB':<12}"
                f"{'yes' if target.get('tls') else 'no'}\n"
            )
    quiet = result.get("not_logged_from")
    if isinstance(quiet, list) and quiet:
        listed = ", ".join(str(source) for source in quiet)
        writer.write(f"answered requests from {listed} are not logged\n")
    metrics = result.get("metrics")
    writer.write("\nMETRICS\n-------\n")
    if not isinstance(metrics, Mapping):
        writer.write("off\n")
    else:
        sources = metrics.get("sources")
        listed = ", ".join(str(source) for source in sources) if isinstance(sources, list) else "-"
        # The exporter binds each node's own address, never a VIP (generate.py,
        # `_metrics_frontend`); "every address" said otherwise (review 2026-10-24).
        writer.write(f"on port {metrics.get('port')}, on each node's own address, for {listed}\n")
    peers = result.get("peers")
    writer.write("\nSHARED COUNTERS\n---------------\n")
    if not isinstance(peers, Mapping):
        writer.write("off\n")
    else:
        writer.write(f"on port {peers.get('port')}, between the nodes\n")


def _read(
    cluster: str,
    run_helper: RunHelper,
    errors: TextIO,
    *,
    json_mode: bool = False,
    writer: TextIO | None = None,
) -> tuple[int, Any]:
    completed = run_helper(cluster, new_request_id())
    try:
        return completed.returncode, json.loads(completed.stdout)
    except json.JSONDecodeError:
        return without_answer(
            completed,
            operation=OPERATION,
            cluster=cluster,
            json_mode=json_mode,
            writer=writer or sys.stdout,
            errors=errors,
            fallback="the settings helper returned no result",
        ), None


def _set(
    cluster: str,
    path: Path,
    comment: str,
    *,
    run_helper: RunHelper,
    run_publish: RunPublish,
    writer: TextIO,
    errors: TextIO,
) -> int:
    try:
        text = path.read_bytes()
    except OSError as exc:
        errors.write(f"ERROR: cannot read {path}: {exc.strerror}\n")
        return exit_codes.NOT_FOUND
    if len(text) > MAX_BYTES:
        errors.write(f"ERROR: {path} is larger than {MAX_BYTES} bytes\n")
        return exit_codes.REFUSED
    try:
        settings_text = text.decode("utf-8")
    except UnicodeDecodeError:
        errors.write(f"ERROR: {path} is not UTF-8\n")
        return exit_codes.REFUSED
    #
    # Built against the head the settings were just read at, so a change that
    # somebody else published in between is refused instead of overwritten.
    #
    code, document = _read(cluster, run_helper, errors)
    if document is None:
        return code
    try:
        head = str(_result(document, OPERATION)["head"])
    except (ValueError, KeyError) as exc:
        errors.write(f"ERROR: {exc}\n")
        return code or exit_codes.UNAVAILABLE
    request = changes_publish.build_request(
        cluster,
        new_request_id(),
        settings=settings_text,
        expected_head=head,
        comment=comment,
    )
    completed = run_publish(request)
    try:
        answer = json.loads(completed.stdout)
        result = _result(answer, changes_publish.OPERATION)
    except (json.JSONDecodeError, ValueError) as exc:
        detail = completed.stderr.strip() or str(exc)
        errors.write(f"{detail}\n")
        return completed.returncode or exit_codes.UNAVAILABLE
    if result.get("changed"):
        writer.write(f"Published version {result.get('version')} of {cluster}.\n")
    else:
        writer.write(f"{cluster} already has these settings (version {result.get('version')}).\n")
    writer.write(f"Deploy it with: haprion-deploy -c {cluster}\n")
    return completed.returncode


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_settings_helper,
    run_publish: RunPublish = run_publish_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    if argv and argv[0] == "apply":
        from haprion.cli import cluster_settings_apply

        return cluster_settings_apply.main(
            argv[1:],
            run_helper=run_helper,
            run_publish=run_publish,
            stream_out=writer,
            stream_err=errors,
        )
    cluster, json_mode, path, comment = _parse(argv)
    if path is not None and comment is not None:
        return _set(
            cluster,
            path,
            comment,
            run_helper=run_helper,
            run_publish=run_publish,
            writer=writer,
            errors=errors,
        )

    code, document = _read(cluster, run_helper, errors, json_mode=json_mode, writer=writer)
    if document is None:
        return code
    if json_mode:
        return write_document(writer, document, code)
    try:
        _render(_result(document, OPERATION), cluster, writer)
    except ValueError as exc:
        errors.write(f"ERROR: {exc}\n")
        return code or exit_codes.UNAVAILABLE
    return code


if __name__ == "__main__":
    raise SystemExit(main())
