"""How the web asks for an exportable certificate's key (B255).

Over `/run/haprion/cert-export.sock` to `haprion-cert-export-helper`, which
runs as root and gives out the key of an entry the registry marks exportable,
and of no other. A service that cannot be asked is said as such, not as a
refusal of the certificate.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid

from haproxy_mgmt import helper_socket
from haproxy_mgmt.cert_export import Export, ExportError

SOCKET_PATH = "/run/haprion/cert-export.sock"
#
# Reading two files and one openssl run: well under a second when measured
# (2026-10-06). Bounded so a helper that hangs becomes a sentence.
#
TIMEOUT_SECONDS = 30.0


def ask(
    certificate_id: str,
    form: str,
    password: str | None,
    *,
    requested_by: str,
    path: str = SOCKET_PATH,
) -> Export:
    """The helper's file for one certificate, or ExportError with its sentence."""

    parameters: dict[str, str] = {
        "id": certificate_id,
        "format": form,
        "requested_by": requested_by,
    }
    if password:
        parameters["password"] = password
    request = {
        "schema_version": 1,
        "operation": "cert_export",
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "parameters": parameters,
    }
    try:
        raw = helper_socket.ask(
            request, path=path, timeout=TIMEOUT_SECONDS, what="the certificate export service"
        )
    except helper_socket.HelperUnavailable as error:
        raise ExportError("dependency_unavailable", str(error), 78) from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise ExportError(
            "dependency_unavailable",
            "the export service answered with something that is not JSON",
            78,
        ) from error
    if not isinstance(document, dict):
        raise ExportError("dependency_unavailable", "the export service did not say", 78)
    result = document.get("result")
    if document.get("outcome") != "done" or not isinstance(result, dict):
        refusal = document.get("error")
        message = refusal.get("message") if isinstance(refusal, dict) else None
        code = refusal.get("code") if isinstance(refusal, dict) else None
        raise ExportError(
            str(code or "export_failed"), str(message or "the export service did not say")
        )
    try:
        content = base64.b64decode(str(result["content_base64"]), validate=True)
        return Export(
            certificate_id=str(result["id"]),
            form=str(result["format"]),
            filename=str(result["filename"]),
            media_type=str(result["media_type"]),
            content=content,
            fingerprint=str(result["fingerprint_sha256"]),
        )
    except (KeyError, binascii.Error) as error:
        raise ExportError(
            "dependency_unavailable", "the export service's answer was incomplete", 78
        ) from error
