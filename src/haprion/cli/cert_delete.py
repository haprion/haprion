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

import json
import sys
from typing import TextIO

from haprion.cert_delete import HELPER, OPERATION
from haprion.cli import arguments, cert_delete_helper
from haprion.cli.caller import without_answer
from haprion.cli.cert_target import RunHelper, run_helper, summary
from haprion.cli.cluster_settings import _through
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document


def main(
    argv: list[str] | None = None,
    *,
    run: RunHelper = run_helper,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    parser = arguments.ArgumentParser(
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
        return without_answer(
            completed,
            operation=OPERATION,
            cluster=None,
            json_mode=args.json,
            writer=writer,
            errors=errors,
            fallback="the certificate delete helper gave no answer",
        )
    if args.json:
        return write_document(writer, document, completed.returncode)
    summary(document, writer)
    return completed.returncode
