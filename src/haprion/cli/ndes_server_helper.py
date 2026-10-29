"""`haprion-ndes-server-helper` - confirm an NDES server for the web (B383, B385).

The web asks over `/run/haprion/ndes-server.sock`, one request per connection:

    list     the servers the runtime policy names
    fetch    the CA certificates the server gives (`GetCACert`), to show, and
             whether they are the ones saved for it (`new`, `confirmed`, `changed`)
    add      write the server into the runtime policy, if it still gives exactly
             the CA certificates with the given SHA-256s
    remove   take it out, unless a profile on this manager uses it

Root, because `add` and `remove` write `/etc/haprion` - which the worker's
helpers cannot (B163) - and the network, because asking the server is the
point. What it writes is bounded by `haprion.ndes_servers`: one CA file under
`/etc/haprion/ndes-ca` and the policy's `ndes:` block, read back by the
engine's parser before it replaces the file.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import exit_codes, ndes_servers
from haprion.cli import cert_job
from haprion.config import DEFAULT_POLICY_PATH, SYSTEM_TRUST, ConfigError, load_policy
from haprion.envelope import envelope
from haprion.helper_protocol import HelperProtocolError, write_document

OPERATION = "ndes_server"
PARAMETERS = frozenset({"action", "endpoint", "sha256"})
ACTIONS = ("list", "fetch", "add", "remove")


def _string(parameters: dict[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise HelperProtocolError(
            f"parameters.{name} must be a string", exit_code=exit_codes.REFUSED
        )
    return value


def _fingerprints(parameters: dict[str, Any]) -> list[str]:
    value = parameters.get("sha256")
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 16
        or not all(isinstance(each, str) and len(each) <= 64 for each in value)
    ):
        raise HelperProtocolError(
            "parameters.sha256 must list the SHA-256 of every CA certificate shown",
            exit_code=exit_codes.REFUSED,
        )
    return value


def perform(
    parameters: dict[str, Any],
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    fetch: ndes_servers.Fetch = ndes_servers.get_ca_cert,
) -> dict[str, Any]:
    action = parameters.get("action")
    if action not in ACTIONS:
        raise HelperProtocolError(
            "parameters.action must be one of: " + ", ".join(ACTIONS), exit_code=exit_codes.REFUSED
        )
    if action == "list":
        ndes = load_policy(policy_path).ndes
        return {
            "servers": [
                {
                    "endpoint": server.endpoint,
                    "issuing_ca": str(server.issuing_ca),
                    "expires": ndes_servers.ca_expires(server.issuing_ca),
                }
                for server in (ndes.servers if ndes is not None else ())
            ]
        }
    endpoint = _string(parameters, "endpoint")
    policy = load_policy(policy_path).ndes if action in ("fetch", "add") else None
    server = policy.server(endpoint) if policy is not None else None
    #
    # A chain short of its root is completed from the store the server's
    # HTTPS is checked against: its own tls_ca, or the system's (B388).
    #
    trust = server.tls_ca if server is not None else SYSTEM_TRUST
    if action == "fetch":
        found = ndes_servers.authorities(endpoint, fetch=fetch, trust=trust)
        return {
            "endpoint": endpoint,
            "authorities": [authority.summary() for authority in found],
            "state": ndes_servers.confirmation(
                found, server.issuing_ca if server is not None else None
            ),
        }
    if action == "add":
        return ndes_servers.add(
            endpoint, _fingerprints(parameters), policy_path=policy_path, fetch=fetch, trust=trust
        )

    def used_by() -> tuple[str, ...]:
        policy = load_policy(policy_path).ndes
        if policy is None:
            return ()
        return ndes_servers.profiles_using(policy.profiles.directory, endpoint)

    return ndes_servers.remove(endpoint, used_by=used_by, policy_path=policy_path)


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
    fetch: ndes_servers.Fetch = ndes_servers.get_ca_cert,
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
            helper_name="haprion-ndes-server-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        result = perform(dict(request.parameters), policy_path=policy_path, fetch=fetch)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exc.exit_code)
    except ndes_servers.NdesServerError as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    except ConfigError as exc:
        return refuse("bad_policy", str(exc), exit_codes.CONFIG)
    #
    # The journal's line of a change root made (stderr is the journal): the
    # web records its own only when the answer reaches it (review 2026-10-29,
    # B12). The command's is sudo's.
    #
    action = request.parameters.get("action")
    if action == "add":
        errors.write(
            f"ndes_server: added {result['endpoint']} with the CA certificates "
            f"{', '.join(result['sha256'])} in {result['issuing_ca']}\n"
        )
    elif action == "remove":
        errors.write(f"ndes_server: removed {result['endpoint']}\n")
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
