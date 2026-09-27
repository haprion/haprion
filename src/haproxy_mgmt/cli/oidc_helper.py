"""The OIDC helper: the one part of the interface that talks to the provider (O3, B196).

Answers on `/run/haproxy-mgmt/oidc.sock`, one instance per connection, as an
account of its own - the identity policy's `oidc` role, not root. Nothing it does needs root, and
what it reads comes from a provider an administrator chose, so it runs with as
little as the job allows: the private key that opens the client secret, and a
way out to the network, which the web does not have.

One operation, `oidc`, and an `action`:

* `discover` - the provider's endpoints, checked against its issuer.
* `verify` - what the settings page's Verify shows: discovery, the key set,
  the client's method, and whether the provider accepts the client and its
  secret, without anyone signing in.
* `exchange` - a sign-in's code for who signed in: the id_token verified, the
  userinfo added when it is about the same subject, and the name and groups
  read from the claims the provider row names.

It never takes a URL. See `haproxy_mgmt.oidc` for the rest.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import oidc
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.dns_profile_keys import KeyFileError, read_private_key
from haproxy_mgmt.envelope import envelope
from haproxy_mgmt.helper_protocol import HelperProtocolError, JsonValue, write_document

OPERATION = "oidc"
ACTIONS = ("discover", "verify", "exchange")
PARAMETERS = frozenset(
    {
        "action",
        "issuer",
        "ca_pem",
        "client_id",
        "client_secret_sealed",
        "key_id",
        "auth_method",
        "redirect_uri",
        "code",
        "verifier",
        "nonce",
        "username_claim",
        "groups_claim",
        "claims",
    }
)
#
# The key the web seals the client secret against; its public half is what
# the web reads. The directory is this helper's account's alone.
#
KEY_DIRECTORY = Path("/etc/haproxy-manager/oidc")
KEY_ID = re.compile(r"^[0-9a-f]{16}$")
CLAIM_PATH = re.compile(r"^[A-Za-z0-9_:./-]{1,128}$")
TOKEN = re.compile(r"^[A-Za-z0-9._~-]{16,512}$")

EXIT_REFUSED = 64
EXIT_BAD_INPUT = 65
EXIT_UNAVAILABLE = 69

__all__ = ["OPERATION", "main"]


def _text(parameters: Any, key: str, *, limit: int = 2048, required: bool = True) -> str:
    value = parameters.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value or len(value) > limit:
        raise HelperProtocolError(f"parameters.{key} is missing or too long", exit_code=65)
    return value


def _secret(
    parameters: Any, *, issuer: str, client_id: str, key_directory: Path, owner: int
) -> str:
    key_id = _text(parameters, "key_id", limit=16)
    if not KEY_ID.fullmatch(key_id):
        raise HelperProtocolError("parameters.key_id is not a key ID", exit_code=65)
    try:
        sealed = base64.b64decode(
            _text(parameters, "client_secret_sealed", limit=8192), validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise HelperProtocolError(
            "parameters.client_secret_sealed is not base64", exit_code=65
        ) from exc
    try:
        key = read_private_key(key_directory / f"{key_id}.key", owner=owner)
    except KeyFileError as exc:
        raise oidc.OidcError("no_key", str(exc)) from exc
    return oidc.open_client_secret(key, sealed, issuer=issuer, client_id=client_id)


def _discovery_result(discovery: oidc.Discovery) -> dict[str, JsonValue]:
    return {
        "issuer": discovery.issuer,
        "authorization_endpoint": discovery.authorization_endpoint,
        "token_endpoint": discovery.token_endpoint,
        "jwks_uri": discovery.jwks_uri,
        "userinfo_endpoint": discovery.userinfo_endpoint,
        "end_session_endpoint": discovery.end_session_endpoint,
        "auth_methods": list(discovery.auth_methods),
        "algorithms": list(discovery.algorithms),
    }


def _verify(
    client: oidc.Client, parameters: Any, issuer: str, *, key_directory: Path, owner: int
) -> dict[str, JsonValue]:
    """Each check in order, stopping at the first that leaves nothing to check."""

    checks: list[dict[str, JsonValue]] = []

    def record(name: str, ok: bool, message: str) -> bool:
        checks.append({"name": name, "ok": ok, "message": message})
        return ok

    def done() -> dict[str, JsonValue]:
        return {"ok": all(check["ok"] for check in checks), "checks": list(checks)}

    try:
        discovery = oidc.discover(client, issuer)
    except oidc.OidcError as exc:
        record("discovery", False, str(exc))
        return done()
    record("discovery", True, f"{discovery.issuer} describes itself as this issuer")

    try:
        keys = oidc.signing_keys(client, discovery)
        record("keys", True, f"{len(keys.keys)} signing key(s)")
    except oidc.OidcError as exc:
        record("keys", False, str(exc))

    method = _text(parameters, "auth_method", limit=32)
    record(
        "method",
        method in discovery.auth_methods,
        f"{method} is offered"
        if method in discovery.auth_methods
        else f"{method} is not offered; the provider offers {', '.join(discovery.auth_methods)}",
    )
    usable = [name for name in discovery.algorithms if name in oidc.ASYMMETRIC | oidc.SYMMETRIC]
    record(
        "algorithm",
        bool(usable),
        f"signs with {', '.join(usable)}" if usable else "signs with nothing this accepts",
    )

    client_id = _text(parameters, "client_id", limit=256)
    try:
        secret = _secret(
            parameters, issuer=issuer, client_id=client_id, key_directory=key_directory, owner=owner
        )
    except oidc.OidcError as exc:
        record("client", False, str(exc))
        return done()
    accepted, message = oidc.check_client(
        client,
        discovery,
        client_id=client_id,
        secret=secret,
        method=method,
        redirect_uri=_text(parameters, "redirect_uri"),
    )
    record("client", accepted, message)
    return done()


def _exchange(
    client: oidc.Client, parameters: Any, issuer: str, *, key_directory: Path, owner: int
) -> dict[str, JsonValue]:
    client_id = _text(parameters, "client_id", limit=256)
    code = _text(parameters, "code", limit=4096)
    verifier = _text(parameters, "verifier", limit=128)
    nonce = _text(parameters, "nonce", limit=128)
    if not TOKEN.fullmatch(verifier) or not TOKEN.fullmatch(nonce):
        raise HelperProtocolError("the verifier or nonce is not a token", exit_code=65)
    username_claim = _text(parameters, "username_claim", limit=128)
    groups_claim = _text(parameters, "groups_claim", limit=128)
    if not CLAIM_PATH.fullmatch(username_claim) or not CLAIM_PATH.fullmatch(groups_claim):
        raise HelperProtocolError("a claim is not a claim path", exit_code=65)

    secret = _secret(
        parameters, issuer=issuer, client_id=client_id, key_directory=key_directory, owner=owner
    )
    discovery = oidc.discover(client, issuer)
    keys = oidc.signing_keys(client, discovery)
    signed_in = oidc.exchange(
        client,
        discovery,
        keys,
        client_id=client_id,
        secret=secret,
        method=_text(parameters, "auth_method", limit=32),
        code=code,
        verifier=verifier,
        redirect_uri=_text(parameters, "redirect_uri"),
        nonce=nonce,
        username_claim=username_claim,
        groups_claim=groups_claim,
    )
    result: dict[str, JsonValue] = {
        "issuer": signed_in.issuer,
        "subject": signed_in.subject,
        "username": signed_in.username,
        "groups": list(signed_in.groups),
        "id_token": signed_in.id_token,
        "userinfo": signed_in.userinfo,
    }
    #
    # The claims themselves only when asked - Test sign-in shows them to the
    # admin setting the provider up; a real sign-in has no use for them.
    #
    if parameters.get("claims") is True:
        result["claims"] = signed_in.claims
    return result


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    key_directory: Path = KEY_DIRECTORY,
    owner: int | None = None,
    client_factory: Any = None,
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
            require_root=False,
            helper_name="haproxy-oidc-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    parameters = request.parameters
    action = parameters.get("action")
    if action not in ACTIONS:
        return refuse("bad_input", f"parameters.action must be one of {', '.join(ACTIONS)}", 65)

    try:
        issuer = oidc.issuer_url(_text(parameters, "issuer", limit=512))
        ca_pem = _text(parameters, "ca_pem", limit=65536, required=False) or None
        client = (client_factory or oidc.Client)(ca_pem=ca_pem)
        key_owner = os.geteuid() if owner is None else owner
        if action == "discover":
            result = _discovery_result(oidc.discover(client, issuer))
        elif action == "verify":
            result = _verify(
                client, parameters, issuer, key_directory=key_directory, owner=key_owner
            )
        else:
            result = _exchange(
                client, parameters, issuer, key_directory=key_directory, owner=key_owner
            )
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except oidc.OidcError as exc:
        unavailable = exc.code in ("unreachable", "tls", "no_key")
        return refuse(exc.code, str(exc), EXIT_UNAVAILABLE if unavailable else EXIT_REFUSED)

    write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
