"""``haprion-cert-target`` - publish certificates to more targets, or withdraw them (Fas 23).

The terminal's way to *Publish to…* and *Remove from…* on the certificates
page: one delta - targets to add, or targets to remove - for a list of
certificates, sent to the same root helper the interface's job runs. What it
means per certificate is the helper's to decide from the registry, the
cluster files and the committed objects; a certificate that already is as
asked is `unchanged`, so the same command twice changes nothing.

    haprion-cert-target add|remove <certificate>... [--cluster <id>]...
                        [--receiver <id>]... [--format <receiver>=<format>]...
                        [--no-deploy] [--json]

`--json` prints the helper's envelope (`schemas/v1/haprion-cert-target`).
The interface also refuses a removal from a cluster while an unpublished draft
there names the certificate; drafts live in the interface's database, which
this command does not read, so publish or discard them first.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable
from typing import Any, TextIO

from haprion.cert_retarget import HELPER
from haprion.cli import cert_target_helper
from haprion.cli.cluster_settings import _through
from haprion.envelope import new_request_id

type RunHelper = Callable[[list[str], str], subprocess.CompletedProcess[str]]

EXIT_USAGE = 64
EXIT_UNAVAILABLE = 69


def run_helper(argv: list[str], request: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - a fixed helper path; the request is on stdin
        argv, input=request, capture_output=True, text=True, check=False
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-cert-target",
        description="Publish certificates to more clusters or receivers, or withdraw them.",
    )
    parser.add_argument("action", choices=("add", "remove"))
    parser.add_argument("certificates", nargs="+", metavar="certificate")
    parser.add_argument("--cluster", action="append", default=[])
    parser.add_argument("--receiver", action="append", default=[])
    parser.add_argument(
        "--format",
        action="append",
        default=[],
        metavar="RECEIVER=FORMAT",
        help="how a receiver added here is written",
    )
    parser.add_argument(
        "--no-deploy", action="store_true", help="publish without rolling the clusters out"
    )
    parser.add_argument("--json", action="store_true")
    return parser


def summary(document: dict[str, Any], writer: TextIO) -> None:
    result = document.get("result") or {}
    for entry in result.get("certificates", []):
        line = f"{entry.get('certificate')}: {entry.get('state')}"
        if entry.get("reason"):
            line += f" - {entry['reason']}"
        writer.write(line + "\n")
    for deployment in result.get("deployments", []):
        state = "ok" if deployment.get("exit_code") == 0 else f"exit {deployment.get('exit_code')}"
        writer.write(f"deploy {deployment.get('cluster')}: {state}\n")
    error = document.get("error")
    if isinstance(error, dict):
        writer.write(f"ERROR: [{error.get('code')}] {error.get('message')}\n")


def main(
    argv: list[str] | None = None,
    *,
    run: RunHelper = run_helper,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    formats: dict[str, str] = {}
    for given in args.format:
        receiver, separator, form = given.partition("=")
        if not separator or not receiver or not form:
            errors.write(f"ERROR: --format takes <receiver>=<format>, not {given!r}\n")
            return EXIT_USAGE
        formats[receiver] = form
    if not args.cluster and not args.receiver:
        errors.write("ERROR: name at least one --cluster or --receiver\n")
        return EXIT_USAGE
    request = cert_target_helper.build_request(
        new_request_id(),
        certificates=tuple(args.certificates),
        action=args.action,
        clusters=tuple(args.cluster),
        receivers=tuple(args.receiver),
        deploy=not args.no_deploy,
        formats=formats or None,
    )
    completed = run(_through(HELPER, "--"), request)
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr or "ERROR: the certificate target helper gave no answer\n")
        return completed.returncode or EXIT_UNAVAILABLE
    if args.json:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    else:
        summary(document, writer)
    return completed.returncode
