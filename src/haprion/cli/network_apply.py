"""``haprion-network apply`` - the network description from a file (Fas 23, B293).

The terminal's way to what *Network* saves: the VIPs, the source addresses and
the groups as one document, `managed/network.yaml`, in the form the interface
stores (`haprion-network -c <cluster> --json` carries it as `document`). The
stored description is read first and the file is published only where it
differs, as one version against the head just read; the same file again
changes nothing. A cluster whose tables come from its own definition rather
than the repository has no description to change, here as in the interface.

    haprion-network apply -c <cluster> <file> [--check] [-m <comment>]
                          [--allow-certificate-mismatch] [--json]
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from haprion.cli import changes_publish
from haprion.cli.apply_common import (
    EXIT_NOT_FOUND,
    EXIT_UNAVAILABLE,
    Refused,
    RunHelper,
    RunPublish,
    answer_of,
    diff,
    envelope,
)
from haprion.cli.cluster_settings import run_publish_helper
from haprion.config import ConfigError
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document
from haprion.managed_network import MAX_NETWORK_BYTES, load_document, location

OPERATION = "network_apply"
COMMENT = "From the terminal: the network"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="haprion-network apply")
    parser.add_argument("-c", "--cluster", required=True)
    parser.add_argument("file")
    parser.add_argument(
        "--check", action="store_true", help="say what would change; change nothing"
    )
    parser.add_argument("-m", "--comment", default="")
    parser.add_argument("--allow-certificate-mismatch", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def read_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise Refused("unreadable", f"{path}: {exc.strerror}", EXIT_NOT_FOUND) from exc
    if len(data) > MAX_NETWORK_BYTES:
        raise Refused("too_long", f"{path}: larger than {MAX_NETWORK_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("network_invalid", f"{path}: not UTF-8") from exc


def main(
    argv: list[str],
    *,
    run_helper: RunHelper,
    run_publish: RunPublish = run_publish_helper,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    args = _parser().parse_args(argv)
    cluster = str(args.cluster)
    path = Path(args.file)
    try:
        wanted = read_file(path)
        reading = answer_of(run_helper(cluster, new_request_id()), "network")
        if reading.get("origin") != "repository":
            raise Refused(
                "network_not_managed",
                f"{cluster}'s network comes from its cluster definition, not the repository; "
                "there is no description to change",
            )
        ownership = reading.get("ownership_vip")
        head = reading.get("head")
        if not isinstance(ownership, str) or not isinstance(head, str):
            raise Refused("unavailable", "the network helper returned no head", EXIT_UNAVAILABLE)
        current = reading.get("document")
        if not isinstance(current, str):
            raise Refused(
                "unavailable",
                "the network helper does not report the document; is the CLI release current?",
                EXIT_UNAVAILABLE,
            )
        #
        # Read as the publish will read it, so a mistake is named by the file
        # before anything is asked of the manager.
        #
        try:
            load_document(wanted.encode("utf-8"), ownership_vip=ownership, location=str(path))
        except ConfigError as exc:
            raise Refused("network_invalid", str(exc)) from exc
        changed = wanted != current
        versions: list[Mapping[str, Any]] = []
        if changed and not args.check:
            request = changes_publish.build_request(
                cluster,
                new_request_id(),
                expected_head=head,
                comment=args.comment or COMMENT,
                network=wanted,
                allow_certificate_mismatch=args.allow_certificate_mismatch,
            )
            versions = [answer_of(run_publish(request), changes_publish.OPERATION)]
    except Refused as refused:
        if args.json:
            write_document(writer, envelope(OPERATION, cluster, "failed", None, refused))
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
        "deployment_required": bool(published),
    }
    if args.json:
        write_document(writer, envelope(OPERATION, cluster, "done", summary, None))
        return 0
    if not changed:
        writer.write(f"{cluster}: the network is as the file says; nothing to change.\n")
        return 0
    writer.write(f"{'Would change' if args.check else 'Changed'} {location()}\n")
    writer.write(diff(location(), current, wanted))
    for version in summary["versions"]:
        writer.write(f"Published version {version['version']} of {cluster}.\n")
    if summary["deployment_required"]:
        writer.write(f"Deploy it with: haprion-deploy -c {cluster}\n")
    return 0
