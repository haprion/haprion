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

And a CA certificate (B276), asked for by name with `authority`: `upload`
opens the box as above and refuses a key in it; `ndes` carries no box at all
and imports the file the runtime policy names as the NDES issuing CA, which
only root reads by its path.
"""

from __future__ import annotations

import base64
import binascii
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import cert_upload, exit_codes, ui_interface
from haprion.cert_import import (
    ImportError_,
    assemble,
    assemble_for,
    authority_blocks,
    import_authority,
    import_certificate,
    ndes_authority_blocks,
    read_bytes,
    stored_key,
)
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haprion.cli import cert_job
from haprion.cli.cert_import import result_envelope
from haprion.cli.cert_publish import default_deployer
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.dns_profile_keys import KeyFileError, read_private_key
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = cert_upload.OPERATION
HELPER = cert_upload.HELPER
PARAMETERS = frozenset(
    {
        "certificate",
        "key_id",
        "ciphertext",
        "clusters",
        "receivers",
        "formats",
        "interface",
        "authority",
        "key",
    }
)
AUTHORITY_SOURCES = ("upload", "ndes")


def _key_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 16
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise HelperProtocolError(
            "parameters.key_id must be a 16-character key ID", exit_code=exit_codes.REFUSED
        )
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
        authority = request.parameters.get("authority")
        if authority is not None and authority not in AUTHORITY_SOURCES:
            raise HelperProtocolError(
                "parameters.authority must be one of: " + ", ".join(AUTHORITY_SOURCES),
                exit_code=exit_codes.REFUSED,
            )
        key_id = ""
        ciphertext = b""
        if authority == "ndes":
            if "key_id" in request.parameters or "ciphertext" in request.parameters:
                raise HelperProtocolError("the NDES CA is read on the manager; send no file")
        else:
            key_id = _key_id(request.parameters.get("key_id"))
            encoded = request.parameters.get("ciphertext")
            if not isinstance(encoded, str) or len(encoded) > cert_upload.MAX_CIPHERTEXT * 2:
                raise HelperProtocolError(
                    "parameters.ciphertext must be base64", exit_code=exit_codes.REFUSED
                )
            ciphertext = base64.b64decode(encoded, validate=True)
        clusters = cert_job.clusters(request.parameters)
        receivers = cert_job.receivers(request.parameters)
        formats = cert_job.formats(request.parameters, receivers)
        interface = cert_job.interface(request.parameters)
        if authority is not None and (receivers or formats or interface):
            raise HelperProtocolError(
                "a CA certificate goes to clusters only: no receivers, not the interface"
            )
        keep_key = request.parameters.get("key")
        if keep_key not in (None, "keep") or (keep_key is not None and authority is not None):
            raise HelperProtocolError("parameters.key may only be keep, for a certificate")
    except (HelperProtocolError, binascii.Error, ValueError) as exc:
        return refuse("bad_input", str(exc), exit_codes.REFUSED)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    if authority == "ndes":
        if policy.ndes is None:
            return refuse(
                "dependency_unavailable", "runtime policy.ndes is not configured", exit_codes.CONFIG
            )
        try:
            result = import_authority(
                certificate_id=certificate_id,
                blocks=ndes_authority_blocks(policy.ndes.servers),
                clusters=clusters,
                policy=policy,
                runtime=runtime,
                deployer=deployer if deployer is not None else default_deployer(errors),
                live=live,
                store=store,
                lock_path=lock_path,
                require_secure=require_secure,
            )
        except ImportError_ as exc:
            return refuse(exc.code, str(exc), exc.exit_code, exc.details or None)
        document, exit_code = result_envelope(result, request_id=request.request_id)
        return write_document(writer, document, exit_code)
    #
    # The same pair that seals DNS profiles (B146): the installation's, named
    # under `acme.dns_profiles` because that is where it was first needed.
    #
    profile_policy = policy.acme.dns_profiles if policy.acme is not None else None
    if profile_policy is None:
        return refuse(
            "dependency_unavailable",
            "runtime policy.acme.dns_profiles is not configured",
            exit_codes.CONFIG,
        )
    selected = None
    try:
        for path in profile_policy.private_keys:
            candidate = read_private_key(path, require_secure=require_secure)
            if candidate.key_id == key_id:
                selected = candidate
                break
    except KeyFileError as exc:
        return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
    if selected is None:
        return refuse(
            "profile_key_unavailable",
            "the upload's private key is not configured",
            exit_codes.CONFIG,
        )

    try:
        opened = cert_upload.open_upload(selected, ciphertext, certificate_id=certificate_id)
    except cert_upload.UploadError as exc:
        return refuse(
            "upload_binding_mismatch",
            str(exc),
            exit_codes.REFUSED,
            {"certificate": certificate_id, "binding": "sealed_upload"},
        )

    try:
        certificates, keys = read_bytes(opened.data, password=opened.password)
        if authority == "upload":
            result = import_authority(
                certificate_id=certificate_id,
                blocks=authority_blocks(certificates, keys),
                clusters=clusters,
                policy=policy,
                runtime=runtime,
                deployer=deployer if deployer is not None else default_deployer(errors),
                live=live,
                store=store,
                lock_path=lock_path,
                require_secure=require_secure,
            )
            document, exit_code = result_envelope(result, request_id=request.request_id)
            return write_document(writer, document, exit_code)
        if keys and keep_key == "keep":
            #
            # The row's upload promises the key stays. A key in the file -
            # a PKCS#12 the page cannot read for one - is a new pair, and that
            # is Import certificate's (review 26-10-24, 09-07).
            #
            return refuse(
                "bad_input",
                "the file holds a private key, and this upload keeps the key the manager "
                "holds. Upload only the certificate, or use Import certificate to replace "
                "the key as well.",
                exit_codes.REFUSED,
            )
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
    return write_document(writer, document, exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
