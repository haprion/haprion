"""`haprion-cert-export-helper` - an exportable certificate's key, for the web (B255, 2026-10-06).

The web cannot read the certificate store, and it is meant not to: the store is
root's, and no application identity reads a key back. The one exception is an
entry the registry marks `exportable` - one host, no targets, made to be
installed by hand somewhere this manager never reaches. The web asks for it
here, over `/run/haprion/cert-export.sock`; this runs as root, refuses
every entry without the mark, and answers with the file.

The answer is the one document a request gets, and nothing is kept: no copy of
the key or the bundle, no password. What happened goes to the journal - which
certificate, which form, for whom - and the web writes the same into the audit
trail.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.cert_export import ExportError, export
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import HelperProtocolError, write_document
from haproxy_mgmt.version_history import trailer_name

OPERATION = "cert_export"
PARAMETERS = frozenset({"id", "format", "password", "requested_by"})


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
            helper_name="haprion-cert-export-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        certificate_id = cert_job.certificate(request.parameters, "id")
        form = request.parameters.get("format")
        if not isinstance(form, str):
            raise HelperProtocolError("parameters.format must be a string", exit_code=65)
        #
        # Who asked, for the journal line. Held to the trailer rule the
        # version history uses, so a name cannot break the line it is in.
        #
        requested_by = trailer_name(request.parameters.get("requested_by"))
    except (HelperProtocolError, ValueError) as exc:
        return refuse("bad_input", str(exc), 65)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
        exported = export(
            runtime.registry,
            certificate_id,
            form,
            request.parameters.get("password"),
            live=live,
            store=store,
        )
    except ConfigError as exc:
        return refuse(
            "bad_input" if exc.exit_code == 64 else "dependency_unavailable",
            str(exc),
            exc.exit_code,
        )
    except ExportError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    errors.write(f"exported {certificate_id} as {form} for {requested_by}\n")
    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result={
                "id": exported.certificate_id,
                "format": exported.form,
                "filename": exported.filename,
                "media_type": exported.media_type,
                "fingerprint_sha256": exported.fingerprint,
                "content_base64": base64.b64encode(exported.content).decode("ascii"),
            },
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
