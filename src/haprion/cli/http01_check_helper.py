"""`haprion-http01-check-helper` - whether HTTP-01 would reach this manager, for the web (B496, B499).

The web asks over `/run/haprion/http01-check.sock`, one request per
connection, with one parameter: the name a certificate is for. The answer is
`haprion.http01_check`'s: `reached`, `other`, `silent` or `unresolved`.

Root, because the test file is written in the HTTP-01 webroot, which certbot
writes as root in the worker's namespace and the web cannot (B499); and the
network, because fetching the file over the name is the point. What it
writes is bounded by `haprion.http01_check`: one file with a random name under
`<webroot>/.well-known/acme-challenge/`, removed again in the same process.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import exit_codes, http01_check
from haprion.cli import cert_job
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy
from haprion.envelope import envelope
from haprion.helper_protocol import HelperProtocolError, write_document

OPERATION = "http01_check"
PARAMETERS = frozenset({"name"})


def webroot(policy_path: Path = DEFAULT_POLICY_PATH) -> Path:
    """The runtime policy's HTTP-01 webroot, or CheckError when it names none."""

    acme = load_policy(policy_path).acme
    if acme is None or acme.webroot is None:
        raise http01_check.CheckError(
            "dependency_unavailable",
            "the runtime policy names no HTTP-01 webroot (acme.webroot)",
            exit_code=exit_codes.CONFIG,
        )
    return acme.webroot


def perform(
    parameters: dict[str, Any],
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    fetch: http01_check.Fetch = http01_check.fetch,
    resolve: http01_check.Resolve = http01_check.resolve,
) -> dict[str, Any]:
    name = parameters.get("name")
    if not isinstance(name, str) or not name or len(name) > 253:
        raise HelperProtocolError("parameters.name must be a string", exit_code=exit_codes.REFUSED)
    return http01_check.check(name, webroot(policy_path), fetch=fetch, resolve=resolve).as_dict()


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
    fetch: http01_check.Fetch = http01_check.fetch,
    resolve: http01_check.Resolve = http01_check.resolve,
    require_root: bool = True,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-http01-check-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        result = perform(
            dict(request.parameters), policy_path=policy_path, fetch=fetch, resolve=resolve
        )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except http01_check.CheckError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except ConfigError as exc:
        return refuse("bad_policy", str(exc), exit_codes.CONFIG)
    #
    # The journal's line (stderr is the journal): root wrote in the webroot
    # and removed it again, whatever the answer.
    #
    errors.write(f"http01_check: {result['name']} {result['answer']}\n")
    errors.flush()
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
