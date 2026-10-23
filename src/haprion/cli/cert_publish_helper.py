"""The privileged half of `haprion-cert-publish` - registered certificates to their targets.

The same `publish` the certbot deploy hook runs, reached from a job instead of
from a hook. The caller may narrow the run to certificates the registry already
lists and may ask for the rollout afterwards; it cannot name a path, an account
or a target, because every one of those is read from the registry and the
runtime policy.

`partial` is a real outcome here and not a rounding of failure: a registry can
hold an entry whose source is an import whose material has not arrived yet, and
a run that published everything else is not a failed run. The skipped entries
arrive as warnings naming each one.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import ui_interface
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import (
    DEFAULT_LOCK_PATH,
    Deployer,
    Installer,
    PublishError,
    publish,
)
from haprion.cli import cert_job
from haprion.cli.cert_publish import default_deployer, publish_exit_code, result_envelope
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    write_document,
)

OPERATION = "cert_publish"
PARAMETERS = frozenset({"certificates", "deploy"})
HELPER = "/opt/haprion/current/bin/haprion-cert-publish-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    request_id: str,
    *,
    certificates: tuple[str, ...] = (),
    deploy: bool = False,
) -> str:
    """The exact bounded request the worker sends. An empty list means all of them."""

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": {"certificates": list(certificates), "deploy": deploy},
        },
        separators=(",", ":"),
    )


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
    now: datetime | None = None,
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
            helper_name="haprion-cert-publish-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        only = cert_job.certificates(request.parameters)
        deploy = cert_job.flag(request.parameters, "deploy")
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    try:
        report = publish(
            runtime,
            policy,
            #
            # An empty list is every certificate, which is what the hook does.
            # `publish` says that with None, and the difference is kept at this
            # boundary rather than given to the caller as two ways to say it.
            #
            only=list(only) or None,
            live=live,
            store=store,
            lock_path=lock_path,
            deployer=(deployer if deployer is not None else default_deployer(errors))
            if deploy
            else None,
            # Inside the worker's sandbox: the root service installs it (B188).
            installer=installer if installer is not None else ui_interface.socket_installer(),
            now=now,
        )
    except PublishError as exc:
        return refuse(exc.code, str(exc), publish_exit_code(exc))

    document, exit_code = result_envelope(report, request_id=request.request_id)
    return write_document(writer, document, exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
