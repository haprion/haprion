"""The BMC helpers: the web's and the worker's way to a certificate's BMC (B526, B536).

Two entrances, one per socket, so what each caller may ask is decided by which
socket it can connect to and not by a field in its request:

`haprion-bmc-helper`, for the web over `/run/haprion/bmc.sock` (operation `bmc`):

    check    sign in with the account the web sealed and say what the BMC serves,
             for the administrator to confirm
    save     write the target into the registry and keep the account, when the
             BMC still serves the certificate that was confirmed
    remove   take the target and its account away; the certificate stays exportable

`haprion-bmc-install-helper`, for the worker over `/run/haprion/bmc-install.sock`
(operation `bmc_install`): install the certificate on its BMC now - *Install
now*, and the install a save starts.

Root, because the account is opened with the installation's private key and
the key is root's, and the registry is written in `/etc/haprion`; with the
network, because asking the BMC is the point. The web never holds the account
in the clear beyond the request that sealed it.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import bmc_redfish, bmc_targets, cert_registry, exit_codes
from haprion.bmc_redfish import BmcError
from haprion.bmc_targets import Root, TargetError
from haprion.cert_inventory import describe
from haprion.certificates import CertificateError
from haprion.cli import cert_job
from haprion.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    BmcTarget,
    ConfigError,
    bmc_target,
    load_policy,
    load_runtime_config,
)
from haprion.dns_profile_keys import KeyFileError, read_private_key
from haprion.envelope import envelope
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = "bmc"
INSTALL_OPERATION = "bmc_install"
PARAMETERS = frozenset(
    {"action", "id", "address", "port", "fingerprint_sha256", "key_id", "ciphertext_base64"}
)
INSTALL_PARAMETERS = frozenset({"id", "by"})
ACTIONS = ("check", "save", "remove")
INSTALLED_BY = ("install_now", "save")


def build_install_request(request_id: str, *, certificate_id: str, by: str) -> str:
    """The exact bounded request the worker sends for an install. Null cluster, by contract."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": INSTALL_OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {"id": certificate_id, "by": by},
        },
        separators=(",", ":"),
    )


def root_side(policy_path: Path, *, require_secure: bool = True) -> Root:
    """What the helpers and the timer work with, read from the runtime policy."""

    policy = load_policy(policy_path, require_secure=require_secure)
    runtime = load_runtime_config(policy, require_secure=require_secure)
    if policy.certificate_registry is None:
        raise TargetError(
            "dependency_unavailable",
            "the runtime policy names no certificate registry",
            exit_codes.CONFIG,
        )
    profiles = policy.acme.dns_profiles if policy.acme is not None else None
    if profiles is None:
        raise TargetError(
            "dependency_unavailable",
            "runtime policy.acme.dns_profiles is not configured: no key opens a sealed account",
            exit_codes.CONFIG,
        )
    try:
        keys = [
            read_private_key(path, require_secure=require_secure) for path in profiles.private_keys
        ]
    except KeyFileError as exc:
        raise TargetError("dependency_unavailable", str(exc), exit_codes.CONFIG) from exc
    return Root(
        runtime=runtime,
        registry_path=policy.certificate_registry,
        private_keys=keys,
        require_secure=require_secure,
    )


def _string(parameters: dict[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(
            f"parameters.{name} must be a string", exit_code=exit_codes.REFUSED
        )
    return value


def _certificate(parameters: dict[str, Any]) -> str:
    certificate_id = _string(parameters, "id")
    if not CERTIFICATE_ID.fullmatch(certificate_id):
        raise HelperProtocolError(
            "parameters.id is not a certificate ID", exit_code=exit_codes.REFUSED
        )
    return certificate_id


def _target(parameters: dict[str, Any], fingerprint: str, username: str) -> BmcTarget:
    """The address and port as the registry holds them, checked by the registry's own reader.

    The user is the one root opened from the sealed account, never a field the
    web sends beside it: what the page says is the account that signs in.
    """

    try:
        target = bmc_target(
            {
                "address": parameters.get("address"),
                "port": parameters.get("port", 443),
                "fingerprint_sha256": fingerprint,
                "username": username,
            },
            "parameters",
        )
    except ConfigError as exc:
        raise HelperProtocolError(str(exc), exit_code=exit_codes.REFUSED) from None
    assert target is not None  # noqa: S101 - a mapping was given
    return target


def _account(parameters: dict[str, Any]) -> tuple[str, bytes]:
    key_id = _string(parameters, "key_id")
    try:
        ciphertext = base64.b64decode(_string(parameters, "ciphertext_base64"), validate=True)
    except binascii.Error:
        raise HelperProtocolError(
            "parameters.ciphertext_base64 is not base64", exit_code=exit_codes.REFUSED
        ) from None
    return key_id, ciphertext


def _served_facts(served: bmc_redfish.Served) -> dict[str, Any]:
    try:
        facts = describe(served.pem)
    except CertificateError:
        return {"subject": None, "issuer": None, "not_after": None}
    return {
        "subject": facts.common_name or facts.subject or None,
        "issuer": facts.issuer or None,
        "not_after": facts.not_after.isoformat().replace("+00:00", "Z"),
    }


def perform(parameters: dict[str, Any], root: Root) -> dict[str, Any]:
    action = parameters.get("action")
    if action not in ACTIONS:
        raise HelperProtocolError(
            "parameters.action must be one of: " + ", ".join(ACTIONS), exit_code=exit_codes.REFUSED
        )
    certificate_id = _certificate(parameters)
    registry = root.runtime.registry
    entry = registry.certificates.get(certificate_id) if registry is not None else None
    if entry is None:
        raise TargetError("not_registered", f"{certificate_id} is not in the registry")
    if not entry.exportable:
        raise TargetError(
            "not_exportable",
            f"{certificate_id} is not exportable; only an exportable certificate has a BMC",
        )
    if action == "remove":
        #
        # Not under an install: its last step writes the target it installed
        # on back into the registry, and would bring a removed one back.
        #
        with bmc_targets.install_lock(root.state, wait=False):
            cert_registry.set_bmc(
                root.registry_path,
                certificate_id=certificate_id,
                target=None,
                runtime=root.runtime,
                require_secure=root.require_secure,
                lock_path=root.lock_path,
            )
            bmc_targets.remove_account(certificate_id, directory=root.accounts)
            bmc_targets.forget(certificate_id, directory=root.state)
        return {"id": certificate_id, "removed": True}

    key_id, ciphertext = _account(parameters)
    probe = _target(parameters, "0" * 64, "-")
    username, password = bmc_targets.open_account(
        root.private_keys, key_id, ciphertext, certificate_id=certificate_id, address=probe.address
    )
    if action == "check":
        checked = bmc_redfish.check(probe.address, probe.port, username=username, password=password)
        return {
            "id": certificate_id,
            "address": probe.address,
            "port": probe.port,
            "served_sha256": checked.served.fingerprint_sha256,
            **_served_facts(checked.served),
            "model": checked.firmware.model,
            "firmware": checked.firmware.version,
            "may_upload": checked.may_upload,
        }
    #
    # `save`: what the administrator confirmed is what is written, so the BMC is
    # asked again and has to serve exactly that certificate (as an NDES server's
    # CA is, review 2026-10-28, U02), and the account has to be let in.
    #
    confirmed = _string(parameters, "fingerprint_sha256")
    target = _target(parameters, confirmed, username)
    #
    # Not under an install either, for the same reason as `remove`: an install
    # ending after the save would write its own target over the new one.
    #
    with bmc_targets.install_lock(root.state, wait=False):
        checked = bmc_redfish.check(
            target.address, target.port, username=username, password=password
        )
        if checked.served.fingerprint_sha256 != confirmed:
            raise TargetError(
                "expected_target_changed",
                f"{target.address} now serves {checked.served.fingerprint_sha256}, not the "
                "certificate that was confirmed; check it again",
            )
        bmc_targets.write_account(certificate_id, key_id, ciphertext, directory=root.accounts)
        cert_registry.set_bmc(
            root.registry_path,
            certificate_id=certificate_id,
            target=target,
            runtime=root.runtime,
            require_secure=root.require_secure,
            lock_path=root.lock_path,
        )
        bmc_targets.forget(certificate_id, directory=root.state)
    return {
        "id": certificate_id,
        "address": target.address,
        "port": target.port,
        "fingerprint_sha256": target.fingerprint_sha256,
        "username": target.username,
    }


def perform_install(parameters: dict[str, Any], root: Root) -> dict[str, Any]:
    certificate_id = _certificate(parameters)
    by = _string(parameters, "by")
    if by not in INSTALLED_BY:
        raise HelperProtocolError(
            "parameters.by must be one of: " + ", ".join(INSTALLED_BY), exit_code=exit_codes.REFUSED
        )
    attempt = bmc_targets.install(root, certificate_id, by=by)
    if attempt.outcome != "done":
        #
        # Failed for the job, in the BMC's own words; the attempt is in the
        # state file either way. `unreached` is a sentence and no fault (B536).
        #
        raise TargetError(
            f"bmc_{attempt.code or 'failed'}", attempt.message or "the install failed"
        )
    return {"id": certificate_id, **asdict(attempt)}


def _run(
    operation: str,
    parameters: frozenset[str],
    helper_name: str,
    work: Any,
    *,
    argv: list[str] | None,
    policy_path: Path,
    input_stream: BinaryIO | None,
    output_stream: TextIO | None,
    error_stream: TextIO | None,
    require_root: bool,
    require_secure: bool,
    root: Root | None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            operation,
            parameters=parameters,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name=helper_name,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(operation, request, writer, errors)
    try:
        side = root or root_side(policy_path, require_secure=require_secure)
        result = work(dict(request.parameters), side)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except TargetError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except cert_registry.RegistryError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except BmcError as exc:
        return refuse(f"bmc_{exc.code}", str(exc), exit_codes.REFUSED)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    #
    # The journal's line of what root did (stderr is the journal); never the account.
    #
    action = request.parameters.get("action", "install")
    if action != "check":
        errors.write(f"{operation}: {action} {result['id']}: {_journal(result)}\n")
        errors.flush()
    return write_document(
        writer,
        envelope(
            operation=operation,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


def _journal(result: dict[str, Any]) -> str:
    if result.get("removed"):
        return "target and account removed"
    if "outcome" in result:
        return (
            f"{result['outcome']} {result.get('code') or ''} {result['fingerprint_sha256']}".strip()
        )
    return f"{result['address']}:{result['port']} pinned {result['fingerprint_sha256']}"


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_root: bool = True,
    require_secure: bool = True,
    root: Root | None = None,
) -> int:
    return _run(
        OPERATION,
        PARAMETERS,
        "haprion-bmc-helper",
        perform,
        argv=argv,
        policy_path=policy_path,
        input_stream=input_stream,
        output_stream=output_stream,
        error_stream=error_stream,
        require_root=require_root,
        require_secure=require_secure,
        root=root,
    )


def install_main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_root: bool = True,
    require_secure: bool = True,
    root: Root | None = None,
) -> int:
    return _run(
        INSTALL_OPERATION,
        INSTALL_PARAMETERS,
        "haprion-bmc-install-helper",
        perform_install,
        argv=argv,
        policy_path=policy_path,
        input_stream=input_stream,
        output_stream=output_stream,
        error_stream=error_stream,
        require_root=require_root,
        require_secure=require_secure,
        root=root,
    )


if __name__ == "__main__":
    raise SystemExit(main())
