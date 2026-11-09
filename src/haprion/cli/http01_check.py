"""`haprion-http01-check` - whether Let's Encrypt's HTTP-01 would reach this manager for a name.

    sudo haprion-http01-check <name> [--json]

What *Check HTTP-01* on the interface's new-certificate page does, through
the same code as its helper: a test file with a random name is written in
the runtime policy's HTTP-01 webroot, fetched over
`http://<name>/.well-known/acme-challenge/`, and removed again. The answer
says whether the file came back, what answered instead, or that nothing did.
It is checked from this manager, not from the internet. Root, because the
webroot is root's. `--json` answers with the helper's document.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes, http01_check
from haprion.cli.arguments import ArgumentParser
from haprion.cli.http01_check_helper import OPERATION, perform
from haprion.config import DEFAULT_POLICY_PATH, ConfigError
from haprion.envelope import envelope, failure
from haprion.helper_protocol import HelperProtocolError, write_document


def _parser() -> argparse.ArgumentParser:
    parser = ArgumentParser(
        prog="haprion-http01-check",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("name", help="the name the certificate is for")
    parser.add_argument("--json", action="store_true", help="answer with the JSON document")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    fetch: http01_check.Fetch = http01_check.fetch,
    resolve: http01_check.Resolve = http01_check.resolve,
    policy_path: os.PathLike[str] | None = None,
) -> int:
    out: TextIO = stream_out or sys.stdout
    err: TextIO = stream_err or sys.stderr
    arguments = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    path = DEFAULT_POLICY_PATH if policy_path is None else Path(policy_path)
    request_id = str(uuid.uuid4())
    code, message, exit_code = "", "", exit_codes.OK
    result: dict[str, Any] = {}
    if os.geteuid() != 0:
        code, message = "not_root", "this writes a test file in the webroot: run it with sudo"
        exit_code = exit_codes.NOT_ROOT
    else:
        try:
            result = perform(
                {"name": arguments.name}, policy_path=path, fetch=fetch, resolve=resolve
            )
        except http01_check.CheckError as exc:
            code, message, exit_code = exc.code, str(exc), exc.exit_code
        except HelperProtocolError as exc:
            code, message, exit_code = "bad_input", str(exc), exc.exit_code
        except ConfigError as exc:
            code, message, exit_code = "bad_policy", str(exc), exit_codes.CONFIG
    if code:
        if arguments.json:
            return write_document(
                out,
                failure(
                    operation=OPERATION,
                    cluster=None,
                    request_id=request_id,
                    code=code,
                    message=message,
                    exit_code=exit_code,
                ),
                exit_code,
            )
        err.write(f"ERROR: {message}\n")
        return exit_code
    if arguments.json:
        return write_document(
            out,
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=None,
                request_id=request_id,
                result=result,
            ),
            exit_codes.OK,
        )
    out.write(http01_check.Check(**result).sentence() + "\n")
    return exit_codes.OK


if __name__ == "__main__":
    raise SystemExit(main())
