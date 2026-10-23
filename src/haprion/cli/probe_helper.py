"""The privileged half of `haprion-probe` - ask the nodes to try a check.

Takes no arguments; the request arrives on stdin, the same form and for the same
reason as every other helper: PRIVILEGE.md forbids wildcards in sudoers argument
matching, so one no-argument rule covers every cluster.

Why this needs root for something that changes nothing
------------------------------------------------------
One thing only: the probe identity's private key is root-owned, because no
application identity may hold a key that reaches a node. Nothing here writes,
and nothing here takes the cluster lock - a probe must stay answerable while a
deploy is running, and one that queued behind a rollout would answer about a
pool that has since moved.

What it does not trust
----------------------
The targets. They arrive from a caller that may be a web request somebody typed
into, so each one is validated here before it is sent, and the node validates
them again before it opens anything. Neither check is redundant with the other:
this one protects the node from a manager, and the node's protects it from
whoever holds the key.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from haprion import dnsdist_config, exit_codes
from haprion.certificates import CERTIFICATE_OPENING, authority_path
from haprion.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    DeployIdentity,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import Message, envelope
from haprion.health_probe import MAX_TARGETS, Target, probe
from haprion.helper_protocol import (
    HelperProtocolError,
    HelperRequest,
    config_error_code,
    read_helper_request,
    require_no_arguments,
    write_document,
    write_failure,
)
from haprion.proxy_model import (
    DEFAULT_QUERY_NAME,
    DEFAULT_QUERY_TYPE,
    DNS_NAME,
    DNS_QUERY_TYPES,
    HOSTNAME,
)
from haprion.tls_policy import BACKEND_MIN_VERSION, DEFAULT_MIN_VERSION

OPERATION = "probe"
PARAMETERS = frozenset({"targets", "source", "timeout_ms"})


#
# `udp` is keepalived's check on a syslog pool (Fas 19b B5): its receivers are
# addresses, IPv6 among them, which the host-name rule does not take.
#
TYPES = ("tcp", "http", "dns", "udp")


def _dns_question(
    entry: dict[str, object], host: str, lookup: dnsdist_config.Lookup
) -> dict[str, str]:
    """A dns check's question, and the address it is asked of (B253).

    The name and type held to what the object model allows, so nothing else
    reaches the node. A server written as a name is looked up here, with the
    manager's resolver, as the publish looks it up for dnsdist - asking the
    node's resolver could reach a different address than dnsdist does.
    """

    name = entry.get("query_name") or DEFAULT_QUERY_NAME
    kind = entry.get("query_type") or DEFAULT_QUERY_TYPE
    if not isinstance(name, str) or not DNS_NAME.match(name):
        raise HelperProtocolError(
            "a target's query_name is not a DNS name", exit_code=exit_codes.REFUSED
        )
    if kind not in DNS_QUERY_TYPES:
        raise HelperProtocolError(
            "a target's query_type is not one a dns check may ask", exit_code=exit_codes.REFUSED
        )
    #
    # A name that gives no single address raises `Unresolved`, which `main`
    # answers with an envelope: the sentence is the generator's, and the form
    # shows it where the check is.
    #
    address = host.strip("[]") if dnsdist_config.is_address(host) else lookup(host)
    return {
        "query_name": name if name.endswith(".") else f"{name}.",
        "query_type": str(kind),
        "address": address,
    }


def _is_address(host: str) -> bool:
    """An address as the node's probe reads one: no brackets, no name."""

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _targets(
    parameters: object, lookup: dnsdist_config.Lookup | None = None
) -> tuple[list[Target], str, int]:
    """The request's targets, or a refusal naming the field that was wrong."""

    if not isinstance(parameters, dict):
        raise HelperProtocolError("parameters must be an object", exit_code=exit_codes.REFUSED)

    entries = parameters.get("targets")
    if not isinstance(entries, list) or not entries:
        raise HelperProtocolError("targets must be a non-empty list", exit_code=exit_codes.REFUSED)
    if len(entries) > MAX_TARGETS:
        raise HelperProtocolError(
            f"at most {MAX_TARGETS} targets may be probed at once", exit_code=exit_codes.REFUSED
        )

    targets = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise HelperProtocolError("a target is not an object", exit_code=exit_codes.REFUSED)
        host = entry.get("host")
        port = entry.get("port")
        kind = entry.get("type", "tcp")
        if kind == "udp":
            if not isinstance(host, str) or not _is_address(host):
                raise HelperProtocolError(
                    "a udp target's host must be an IP address", exit_code=exit_codes.REFUSED
                )
        #
        # A name, or an address of either family (review 26-10-08, F5): a
        # syslog pool on an IPv6 VIP has IPv6 receivers, which the name rule
        # does not take.
        #
        elif not isinstance(host, str) or not (HOSTNAME.match(host) or _is_address(host)):
            raise HelperProtocolError("a target's host is not usable", exit_code=exit_codes.REFUSED)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise HelperProtocolError("a target's port is not a port", exit_code=exit_codes.REFUSED)
        if kind not in TYPES:
            raise HelperProtocolError(
                "a target's type must be tcp, http, dns or udp", exit_code=exit_codes.REFUSED
            )
        path = entry.get("path", "/") or "/"
        header = entry.get("host_header", "") or ""
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
            raise HelperProtocolError("a target's path is not a path", exit_code=exit_codes.REFUSED)
        if not isinstance(header, str) or (header and not HOSTNAME.match(header)):
            raise HelperProtocolError(
                "a target's host header is not a name", exit_code=exit_codes.REFUSED
            )
        #
        # Refused here as well as on the node. The node's own refusal would
        # arrive as a probe that answered nothing, from four nodes at once, and
        # the field it is about would not be in the message.
        #
        min_version = entry.get("min_version", DEFAULT_MIN_VERSION) or DEFAULT_MIN_VERSION
        if min_version not in BACKEND_MIN_VERSION.values():
            raise HelperProtocolError(
                "a target's min_version is not a TLS version this may ask for",
                exit_code=exit_codes.REFUSED,
            )
        authority = entry.get("ca", "") or ""
        if not isinstance(authority, str) or (authority and not CERTIFICATE_ID.match(authority)):
            raise HelperProtocolError(
                "a target's ca does not name a certificate", exit_code=exit_codes.REFUSED
            )
        targets.append(
            Target(
                host=host,
                port=port,
                type=kind,
                tls=entry.get("tls") is True,
                verify=entry.get("verify") is True,
                path=path,
                host_header=header,
                min_version=min_version,
                ca=authority,
                **(
                    _dns_question(entry, host, lookup or dnsdist_config.lookup)
                    if kind == "dns"
                    else {}
                ),
            )
        )

    source = parameters.get("source", "") or ""
    if not isinstance(source, str) or len(source) > 45:
        raise HelperProtocolError("source must be an address", exit_code=exit_codes.REFUSED)

    timeout = parameters.get("timeout_ms", 2000)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise HelperProtocolError("timeout_ms must be a number", exit_code=exit_codes.REFUSED)
    return targets, source, timeout


#
# A CA bundle is a root and an intermediate or two; this is far beyond that and
# keeps the request under the node's limit with every target naming one.
#
MAX_AUTHORITY_BYTES = 16 * 1024


def _authorities(certificate_root: Path | None, targets: list[Target]) -> dict[str, str]:
    """The CAs the targets name, read where the nodes fetch them from (B276).

    The node's probe runs unprivileged and cannot read the node's copy beside
    its private keys, so the manager's copy - the same bytes - is sent along
    (26-10-12). A CA that is not published here is refused: a pool that names
    it could not be published either.
    """

    named = sorted({target.ca for target in targets if target.ca})
    if not named:
        return {}
    if certificate_root is None:
        raise HelperProtocolError(
            "a target names a CA but no certificate_root is configured",
            exit_code=exit_codes.REFUSED,
        )
    found: dict[str, str] = {}
    for identifier in named:
        path = authority_path(certificate_root, identifier)
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_AUTHORITY_BYTES + 1)
        except OSError:
            raise HelperProtocolError(
                f"the CA {identifier} is not published on this manager",
                exit_code=exit_codes.REFUSED,
            ) from None
        text = raw.decode("ascii", errors="replace")
        if (
            len(raw) > MAX_AUTHORITY_BYTES
            or "PRIVATE KEY" in text
            or CERTIFICATE_OPENING not in text
        ):
            raise HelperProtocolError(
                f"the CA {identifier} is not a certificate bundle", exit_code=exit_codes.REFUSED
            )
        found[identifier] = text
    return found


def _refused(
    writer: TextIO, errors: TextIO, request: HelperRequest, exc: HelperProtocolError
) -> int:
    errors.write(f"ERROR: [bad_input] {exc}\n")
    return write_failure(
        writer,
        operation=OPERATION,
        cluster=request.cluster,
        request_id=request.request_id,
        code="bad_input",
        message=str(exc),
        exit_code=exc.exit_code,
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
    ask: object = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        require_no_arguments(argv)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError(
                "haprion-probe-helper must run as root", exit_code=exit_codes.NOT_ROOT
            )
        request = read_helper_request(
            input_stream or sys.stdin.buffer,
            expected_operation=OPERATION,
            allowed_parameter_keys=PARAMETERS,
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    #
    # From here the request is known, so every refusal is an envelope (B32): a
    # bare stderr line left the web saying the probe "answered with nothing at
    # all" when it had said why (review 2026-10-22, 4-3).
    #
    try:
        targets, source, timeout_ms = _targets(request.parameters)
    except HelperProtocolError as exc:
        return _refused(writer, errors, request, exc)
    except dnsdist_config.Unresolved as exc:
        errors.write(f"ERROR: [dns_unresolved] {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code="dns_unresolved",
            message=str(exc),
            exit_code=exit_codes.REFUSED,
        )

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
    except ConfigError as exc:
        errors.write(f"ERROR: {exc}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code=config_error_code(exc.exit_code),
            message=str(exc),
            exit_code=exc.exit_code,
        )

    try:
        authorities = _authorities(policy.certificate_root, targets)
    except HelperProtocolError as exc:
        return _refused(writer, errors, request, exc)

    identity = policy.probe_identity
    if identity is None and ask is None:
        message = (
            "no probe identity is configured. Add probe_identity with "
            "'user' and 'key' to the runtime policy."
        )
        errors.write(f"ERROR: [probe_unavailable] {message}\n")
        return write_failure(
            writer,
            operation=OPERATION,
            cluster=request.cluster,
            request_id=request.request_id,
            code="probe_unavailable",
            message=message,
            exit_code=exit_codes.CONFIG,
        )

    #
    # Only reachable with an identity, or with a caller that replaces the SSH
    # entirely - which is what the tests do. Stated rather than ignored, so the
    # reader is not left checking whether the guard above really covers it.
    #
    assert identity is not None or ask is not None  # noqa: S101
    answers = probe(
        cluster.nodes,
        identity if identity is not None else DeployIdentity(user="", key=Path("/dev/null")),
        targets,
        source=source,
        timeout_ms=timeout_ms,
        ask=ask,
        authorities=authorities,
    )
    #
    # `done` whenever the nodes answered, whatever they said about the pool. A
    # server that is down is a finding, not a failure of the command: reporting
    # it as a failed operation would put a red job in the queue every time
    # somebody checked a pool they already knew was broken.
    #
    reachable = [answer for answer in answers if answer.reachable]
    #
    # An object with a source address can only be answered for from the node
    # that holds it, and in an active/passive pair that is one node. Asking the
    # other would bind a foreign address and fail the route lookup, which
    # describes the binding and not the pool - so those nodes probe nothing and
    # say so.
    #
    # All of them saying so is a different matter: the address is nowhere, and
    # nothing was tried anywhere. That is the probe being unable to run rather
    # than a pool that failed, and it is reported as such.
    #
    answered = [answer for answer in reachable if answer.source_held is not False]
    nowhere = bool(source) and bool(reachable) and not answered
    ran = bool(answered)
    result = {
        "source": source,
        "nodes": [
            {
                "node": answer.node,
                "reachable": answer.reachable,
                "error": answer.error,
                "source_held": answer.source_held,
                "results": [
                    {
                        "host": entry.host,
                        "port": entry.port,
                        "ok": entry.ok,
                        "status": entry.status,
                        "error": entry.error,
                        "ms": entry.ms,
                    }
                    for entry in answer.results
                ],
            }
            for answer in answers
        ],
    }
    warnings = tuple(
        Message(code="probe_node_error", message=answer.error[:1024], node=answer.node)
        for answer in answers
        if answer.error and answer.reachable
    )
    document = envelope(
        operation=OPERATION,
        outcome="done" if ran else "failed",
        cluster=request.cluster,
        request_id=request.request_id,
        result=result,
        warnings=warnings,
        error=None
        if ran
        else Message(
            code="probe_unavailable",
            message=(
                f"no node carries the source address {source}, so nothing was tried"
                if nowhere
                else "no node answered the probe"
            ),
        ),
    )
    return write_document(writer, document, exit_codes.OK if ran else exit_codes.UNAVAILABLE)


if __name__ == "__main__":
    raise SystemExit(main())
