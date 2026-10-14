"""Register a receiver, or take one away, at the interface's request (B142).

The operation the interface's receivers page becomes. One request names one
receiver and one of two actions: `add`, with the transport and either the
public key text or the https allowlist, or `remove`. What each means - the
account, the directory, the lock in `authorized_keys` or the nginx block -
is `cert_receiver`'s, exactly as when the operator types
`haprion-cert-receiver` (user-manual.md, 'Registering a receiver'); this helper only carries
the request across the privilege boundary and hands back the same layers
and the same instructions.

The public key arrives as text, not as a path: the interface has the
operator paste the `.pub` line, and a helper that took a path would be a
helper that reads any file root can. Migration is not offered here. It has a
step on the receiving host in the middle, which is a terminal's operation.

Not run through sudo (B163). It writes `/etc`, and the worker's sandbox keeps
`/etc` read-only for anything the worker starts; so it answers on
`/run/haprion/cert-receiver.sock` from a unit of its own, and the worker
sends the request there with `haprion-cert-receiver-ask`.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import cert_receiver
from haprion.cert_lock import DEFAULT_LOCK_PATH
from haprion.cert_receiver import Locations, ReceiverError, Result, Tools
from haprion.cli import cert_job
from haprion.config import (
    DEFAULT_POLICY_PATH,
    RECEIVER_ID,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import envelope
from haprion.helper_protocol import (
    HelperProtocolError,
    JsonValue,
    config_error_code,
    write_document,
)

OPERATION = "cert_receiver"
HELPER = "/opt/haprion/current/bin/haprion-cert-receiver-helper"

PARAMETERS = frozenset({"receiver", "action", "transport", "public_key", "allow", "secret_hash"})
#
# `secret` gives an https receiver a new secret (B306). What arrives is its hash:
# the password was shown to whoever made it and travels nowhere, not in this
# request and not in the job that carries it.
#
ACTIONS = frozenset({"add", "remove", "secret"})
MAX_SECRET_HASH = 160

# A pasted key is one line; anything longer is not one.
MAX_PUBLIC_KEY = 4096
MAX_ALLOW = 32

__all__ = ["HELPER", "OPERATION", "build_request", "main"]

# EX_CONFIG: the installation has no registry, which is not the request's fault.
EXIT_NO_REGISTRY = 78


def build_request(
    request_id: str,
    *,
    receiver: str,
    action: str,
    transport: str | None = None,
    public_key: str | None = None,
    allow: tuple[str, ...] = (),
    secret_hash: str | None = None,
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract."""

    parameters: dict[str, JsonValue] = {"receiver": receiver, "action": action}
    if transport is not None:
        parameters["transport"] = transport
    if public_key is not None:
        parameters["public_key"] = public_key
    if allow:
        parameters["allow"] = list(allow)
    if secret_hash is not None:
        parameters["secret_hash"] = secret_hash
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def _text(parameters: Mapping[str, JsonValue], key: str, limit: int) -> str:
    value = parameters.get(key)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(f"parameters.{key} must be a non-empty string", exit_code=65)
    if len(value) > limit:
        raise HelperProtocolError(f"parameters.{key} is longer than {limit}", exit_code=65)
    return value


def _allow(parameters: Mapping[str, JsonValue]) -> tuple[str, ...]:
    raw = parameters.get("allow", [])
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_ALLOW:
        raise HelperProtocolError(
            f"parameters.allow must be a list of at most {MAX_ALLOW}", exit_code=65
        )
    #
    # Shape only: a string short enough to be an address or a network. Whether
    # it is one is `cert_receiver`'s refusal, in the words the command uses.
    #
    for item in raw:
        if not isinstance(item, str) or not item or len(item) > 64:
            raise HelperProtocolError("parameters.allow contains a non-address", exit_code=65)
    return tuple(str(item) for item in raw)


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    tools: Tools | None = None,
    locations: Locations | None = None,
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
            helper_name="haprion-cert-receiver-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    parameters = request.parameters
    try:
        receiver_id = _text(parameters, "receiver", 63)
        if not RECEIVER_ID.fullmatch(receiver_id):
            raise HelperProtocolError("parameters.receiver is not a receiver ID", exit_code=65)
        action = _text(parameters, "action", 8)
        if action not in ACTIONS:
            raise HelperProtocolError(
                "parameters.action must be add, remove or secret", exit_code=65
            )
        transport = public_key = hashed = None
        allow: tuple[str, ...] = ()
        if "secret_hash" in parameters:
            hashed = _text(parameters, "secret_hash", MAX_SECRET_HASH)
        if action == "add":
            transport = _text(parameters, "transport", 8)
            if "public_key" in parameters:
                public_key = _text(parameters, "public_key", MAX_PUBLIC_KEY)
            allow = _allow(parameters)
        elif action == "secret":
            extra = sorted(set(parameters) - {"receiver", "action", "secret_hash"})
            if extra or hashed is None:
                raise HelperProtocolError(
                    "a new secret takes the receiver and its secret_hash only", exit_code=65
                )
        else:
            extra = sorted(set(parameters) - {"receiver", "action"})
            if extra:
                raise HelperProtocolError(f"a removal takes no {', '.join(extra)}", exit_code=65)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)
    if runtime.registry is None:
        return refuse(
            "dependency_unavailable",
            "no certificate registry is configured. Add certificate_registry to the "
            "runtime policy.",
            EXIT_NO_REGISTRY,
        )

    try:
        result: Result
        if action == "add":
            result = cert_receiver.add(
                policy,
                runtime,
                receiver_id=receiver_id,
                transport=transport or "",
                public_key=public_key,
                allow=allow,
                hashed_secret=hashed,
                tools=tools,
                locations=locations,
                require_secure=require_secure,
                lock_path=lock_path,
            )
        elif action == "secret":
            assert hashed is not None  # noqa: S101 - required above
            result = cert_receiver.set_secret(
                runtime,
                receiver_id=receiver_id,
                hashed_secret=hashed,
                tools=tools,
                locations=locations,
            )
        else:
            result = cert_receiver.remove(
                policy,
                runtime,
                receiver_id=receiver_id,
                tools=tools,
                locations=locations,
                require_secure=require_secure,
                lock_path=lock_path,
            )
    except ReceiverError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    failed = [layer for layer in result.layers if layer.state == "failed"]
    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="partial" if failed else "done",
            cluster=None,
            request_id=request.request_id,
            result=result.as_dict(),
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
