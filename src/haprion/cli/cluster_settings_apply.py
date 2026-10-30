"""``haprion-cluster-settings apply`` - a cluster's *Logs & metrics* from a file (Fas 23).

The same document `--set` publishes - `managed/cluster.yaml`, the format
`haprion-cluster-settings -c <cluster> --json` reports field by field - read
by the engine's own loader and compared with what is stored, field by field,
so the same file twice publishes nothing and `--check` can say whether it
would. A change is one version against the head just read; deploying it is
`haprion-deploy`, as after any other publish.

    haprion-cluster-settings apply -c <cluster> <file> [--check] [-m <comment>] [--json]
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes
from haprion.cli import arguments, changes_publish
from haprion.cli.apply_common import (
    Refused,
    RunHelper,
    RunPublish,
    answer_of,
    envelope,
    unreadable,
)
from haprion.cluster_settings import (
    LOCATION,
    MAX_BYTES,
    document_result,
    dump_document,
    load_document,
)
from haprion.config import ConfigError
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document
from haprion.release_install import DEPLOYMENT_REQUIRED_AFTER_INSTALL

OPERATION = "cluster_settings_apply"
READ_OPERATION = "cluster_settings"
COMMENT = "From the terminal: cluster settings"


def _parser() -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(prog="haprion-cluster-settings apply")
    parser.add_argument("-c", "--cluster", required=True)
    parser.add_argument("file")
    parser.add_argument(
        "--check", action="store_true", help="say what would change; change nothing"
    )
    parser.add_argument("-m", "--comment", default="")
    parser.add_argument("--json", action="store_true")
    return parser


def stored_fields(reading: Mapping[str, Any], keys: Mapping[str, Any]) -> dict[str, Any]:
    """The settings part of a reading, as the keys `document_result` reports."""

    return {key: reading.get(key) for key in keys}


def main(
    argv: list[str],
    *,
    run_helper: RunHelper,
    run_publish: RunPublish,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    args = _parser().parse_args(argv)
    cluster = str(args.cluster)
    path = Path(args.file)
    try:
        try:
            text = path.read_bytes()
        except OSError as exc:
            raise unreadable(path, exc) from exc
        if len(text) > MAX_BYTES:
            raise Refused("too_long", f"{path}: larger than {MAX_BYTES} bytes")
        try:
            wanted = load_document(text)
        except ConfigError as exc:
            raise Refused("settings_invalid", f"{path}: {exc}") from exc
        reading = answer_of(run_helper(cluster, new_request_id()), READ_OPERATION)
        head = reading.get("head")
        if not isinstance(head, str):
            raise Refused(
                "dependency_unavailable",
                "the settings helper returned no head",
                exit_codes.UNAVAILABLE,
            )
        fields = document_result(wanted)
        changed = fields != stored_fields(reading, fields)
        versions: list[Mapping[str, Any]] = []
        if changed and not args.check:
            request = changes_publish.build_request(
                cluster,
                new_request_id(),
                expected_head=head,
                comment=args.comment or COMMENT,
                settings=dump_document(wanted).decode("utf-8"),
            )
            versions = [answer_of(run_publish(request), changes_publish.OPERATION, changes=True)]
    except Refused as refused:
        if args.json:
            write_document(writer, envelope(OPERATION, cluster, None, refused), refused.exit_code)
        else:
            errors.write(refused.report())
        return refused.exit_code
    published = [v for v in versions if v.get("changed")]
    summary = {
        "changed": changed and (args.check or bool(published)),
        "check": args.check,
        "versions": [
            {"version": v.get("version"), "hash": v.get("hash"), "changed": v.get("changed")}
            for v in versions
        ],
        "deployment_required": DEPLOYMENT_REQUIRED_AFTER_INSTALL and bool(published),
    }
    if args.json:
        return write_document(writer, envelope(OPERATION, cluster, summary, None), 0)
    if not changed:
        writer.write(f"{cluster}: {LOCATION} is as the file says; nothing to change.\n")
        return 0
    writer.write(f"{'Would change' if args.check else 'Changed'} {LOCATION} of {cluster}\n")
    for version in summary["versions"]:
        writer.write(f"Published version {version['version']} of {cluster}.\n")
    if summary["deployment_required"]:
        writer.write(f"Deploy it with: haprion-deploy -c {cluster}\n")
    return 0
