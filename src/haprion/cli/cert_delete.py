"""``haprion-cert-delete`` - delete certificates everywhere they are (Fas 23).

The terminal's way to *Delete* on the certificates page: a list of
certificate IDs sent to the same root helper the interface's job runs, which
decides per certificate whether it may go and removes it from the registry,
the targets, certbot and the nodes.

A certificate that is already gone - not in the registry, and nothing of it
left on the manager or any node - is answered `not_registered`. That is what
the command was asked to bring about, so it exits 0 when every certificate is
either removed or already gone, and the same command twice changes nothing
the second time. Any other refusal is the helper's exit code.

    haprion-cert-delete <certificate>... [--json]

`--json` prints the helper's envelope (`schemas/v1/haprion-cert-delete`).
The interface also refuses a certificate an unpublished draft names; drafts
live in the interface's database, which this command does not read.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, TextIO

from haprion.cert_delete import HELPER
from haprion.cli import cert_delete_helper
from haprion.cli.cert_target import EXIT_UNAVAILABLE, RunHelper, run_helper, summary
from haprion.cli.cluster_settings import _through
from haprion.envelope import new_request_id

ALREADY_GONE = "not_registered"


def gone_or_removed(document: dict[str, Any]) -> bool:
    """Whether every certificate is removed now or was already gone."""

    result = document.get("result")
    if not isinstance(result, dict) or not result.get("certificates"):
        return False
    return all(
        entry.get("state") == "removed"
        or (entry.get("state") == "refused" and entry.get("code") == ALREADY_GONE)
        for entry in result["certificates"]
    )


def main(
    argv: list[str] | None = None,
    *,
    run: RunHelper = run_helper,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    parser = argparse.ArgumentParser(
        prog="haprion-cert-delete",
        description="Delete certificates from the registry, the targets, certbot and the nodes.",
    )
    parser.add_argument("certificates", nargs="+", metavar="certificate")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    request = cert_delete_helper.build_request(
        new_request_id(), certificates=tuple(args.certificates)
    )
    completed = run(_through(HELPER, "--"), request)
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.write(completed.stderr or "ERROR: the certificate delete helper gave no answer\n")
        return completed.returncode or EXIT_UNAVAILABLE
    if args.json:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    else:
        summary(document, writer)
    return 0 if gone_or_removed(document) else completed.returncode
