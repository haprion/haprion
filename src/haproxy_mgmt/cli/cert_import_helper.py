"""`haprion-cert-import-helper` - one uploaded file across the root boundary (C9, B165).

The worker's way to `cert_import` for a file the interface received. The
request carries the file sealed against the installation's public key; this
helper holds the private half, opens the box, takes the material apart and
imports it exactly as `haprion-cert-import` does from files on disk. The
plaintext exists in this process and in the store it writes, nowhere else:
the result names the certificate, never the key.

Two shapes of upload, told apart by what the box holds:

- a certificate with its key (PEM, or a PKCS#12 with its password): a new
  import, or a replacement of an earlier import of the same ID;
- a certificate without a key: matched against the key an earlier import of
  the same ID left in the store - a renewal on the manager's own key, or
  the certificate a CA returned for a CSR made here. No stored key, no
  import; the refusal says which way to take instead.
"""

from __future__ import annotations

import base64
import binascii
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt import cert_upload, ui_interface
from haproxy_mgmt.cert_import import (
    ImportError_,
    assemble,
    assemble_for,
    import_certificate,
    read_bytes,
    stored_key,
)
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_import import result_envelope
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.dns_profile_keys import KeyFileError, read_private_key
from haproxy_mgmt.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = cert_upload.OPERATION
HELPER = cert_upload.HELPER
PARAMETERS = frozenset(
    {"certificate", "key_id", "ciphertext", "clusters", "receivers", "formats", "interface"}
)


def _key_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 16
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise HelperProtocolError("parameters.key_id must be a 16-character key ID", exit_code=65)
    return value


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
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
            helper_name="haprion-cert-import-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        certificate_id = cert_job.certificate(request.parameters)
        key_id = _key_id(request.parameters.get("key_id"))
        encoded = request.parameters.get("ciphertext")
        if not isinstance(encoded, str) or len(encoded) > cert_upload.MAX_CIPHERTEXT * 2:
            raise HelperProtocolError("parameters.ciphertext must be base64", exit_code=65)
        ciphertext = base64.b64decode(encoded, validate=True)
        clusters = cert_job.clusters(request.parameters)
        receivers = cert_job.receivers(request.parameters)
        formats = cert_job.formats(request.parameters, receivers)
        interface = cert_job.interface(request.parameters)
    except (HelperProtocolError, binascii.Error, ValueError) as exc:
        return refuse("bad_input", str(exc), 65)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    #
    # The same pair that seals DNS profiles (B146): the installation's, named
    # under `acme.dns_profiles` because that is where it was first needed.
    #
    profile_policy = policy.acme.dns_profiles if policy.acme is not None else None
    if profile_policy is None:
        return refuse(
            "dependency_unavailable", "runtime policy.acme.dns_profiles is not configured", 78
        )
    selected = None
    try:
        for path in profile_policy.private_keys:
            candidate = read_private_key(path, require_secure=require_secure)
            if candidate.key_id == key_id:
                selected = candidate
                break
    except KeyFileError as exc:
        return refuse("dependency_unavailable", str(exc), 78)
    if selected is None:
        return refuse("profile_key_unavailable", "the upload's private key is not configured", 78)

    try:
        opened = cert_upload.open_upload(selected, ciphertext, certificate_id=certificate_id)
    except cert_upload.UploadError as exc:
        return refuse(
            "upload_binding_mismatch",
            str(exc),
            65,
            {"certificate": certificate_id, "binding": "sealed_upload"},
        )

    try:
        certificates, keys = read_bytes(opened.data, password=opened.password)
        if not keys:
            existing = stored_key(store, certificate_id)
            if existing is None:
                raise ImportError_(
                    "no_key",
                    f"the file holds no private key and {certificate_id!r} has none on the "
                    "manager. Upload the file with its key, or import the pair with "
                    "haprion-cert-import.",
                )
            keys = [existing]
            material = assemble_for(certificates, keys, pending=True)
        else:
            material = assemble(certificates, keys)
        result = import_certificate(
            certificate_id=certificate_id,
            material=material,
            clusters=clusters,
            receivers=receivers,
            formats=formats,
            interface=interface,
            policy=policy,
            runtime=runtime,
            deployer=deployer if deployer is not None else default_deployer(errors),
            # Inside the worker's sandbox: the root service installs it (B188).
            installer=installer if installer is not None else ui_interface.socket_installer(),
            live=live,
            store=store,
            lock_path=lock_path,
            require_secure=require_secure,
        )
    except ImportError_ as exc:
        return refuse(exc.code, str(exc), exc.exit_code, exc.details or None)

    document, exit_code = result_envelope(result, request_id=request.request_id)
    write_document(writer, document)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
