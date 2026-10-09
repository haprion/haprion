"""Install the interface certificate at the worker's request (B188, D3).

The helpers the worker starts through sudo - issue, enroll, import - run in
the worker's sandbox, and `ProtectSystem=strict` keeps `/etc/haprion`
read-only for them: `haprion-tls` could neither write the pair nor make its
rollback directory. So the last step of publishing the interface certificate
is asked of this helper, on `/run/haprion/ui-tls.sock`, from a unit of
its own outside the sandbox (B163's pattern).

It takes one thing: a certificate ID. It reads the registry and the material
itself, refuses an entry that is not marked `interface: true`, and runs
`ui_interface.install` - the same function the renewal timer runs directly.
A caller that could hand over bytes could have nginx serve any certificate;
a caller that can only name one can have it serve the one the registry
already says is the interface's.

No lock of its own. Its callers hold the publisher's lock while they wait for
the answer - the request is a step inside their publish - so taking it here
would wait for itself. The socket takes one connection at a time.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import ui_interface
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import PublishError, read_material
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = ui_interface.OPERATION
PARAMETERS = frozenset({"id"})

__all__ = ["OPERATION", "main"]

EXIT_REFUSED = 64
EXIT_UNAVAILABLE = 78


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    installer: ui_interface.Installer | None = None,
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
            helper_name="haprion-tls-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    certificate_id = request.parameters.get("id")
    if not isinstance(certificate_id, str) or not CERTIFICATE_ID.fullmatch(certificate_id):
        return refuse("bad_input", "parameters.id is not a certificate ID", 65)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    entry = runtime.registry.certificates.get(certificate_id) if runtime.registry else None
    if entry is None:
        return refuse(
            "unknown_certificate", f"{certificate_id} is not in the registry", EXIT_REFUSED
        )
    if not entry.interface:
        return refuse(
            "bad_input",
            f"{certificate_id} is not the interface certificate; only the entry marked "
            "interface: true is installed here",
            EXIT_REFUSED,
        )

    try:
        material = read_material(entry, live=live, store=store)
        changed = (installer or ui_interface.install)(material)
    except PublishError as exc:
        code = EXIT_UNAVAILABLE if exc.code == "dependency_unavailable" else EXIT_REFUSED
        return refuse(exc.code, str(exc), code)

    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result={
                "id": certificate_id,
                "changed": changed,
                "fingerprint_sha256": material.fingerprint,
                "not_after": material.facts.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
