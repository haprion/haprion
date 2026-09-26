"""The boundary the three certificate helpers share: read a request, refuse in one shape.

Why these three have no cluster
-------------------------------
Every other privileged helper acts on one cluster, and its request says which.
A certificate does not work that way, and the registry is what says so: the
wildcard names two clusters, the PVE certificates name none, and the publisher
serialises certificate work with a single lock across all of it rather than per
cluster. So these requests carry a null cluster and name the certificate in
their parameters instead, and the queue that feeds them agrees (migration 0024).

What lives here is only the boundary. The work itself is the same `issue`,
`publish` and `set_targets` the terminal commands call - §4.1 is explicit that
there is one implementation and not two, and a helper that reimplemented any of
it would be the second one.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt.config import CERTIFICATE_ID, CLUSTER_ID, RECEIVER_FORMATS, RECEIVER_ID
from haproxy_mgmt.envelope import failure
from haproxy_mgmt.helper_protocol import (
    ClusterlessRequest,
    HelperProtocolError,
    JsonValue,
    read_clusterless_request,
    require_no_arguments,
    write_document,
)

EXIT_NOT_ROOT = 77
#
# A certificate goes to the targets one person picked on one page, not to an
# imported list. The ceiling is here so an oversized request is a sentence about
# the request rather than a root helper working through it.
#
MAX_TARGETS = 32


class Refuse:
    """Write the one valid failure envelope, once the request is known.

    The same class the objects helper has, with the cluster left null. It is
    here rather than imported from there because the two are separate contracts
    that happen to look alike, and binding them would make one of them change
    when the other did.
    """

    def __init__(self, operation: str, request: ClusterlessRequest, output: TextIO, errors: TextIO):
        self.operation = operation
        self.request = request
        self.output = output
        self.errors = errors

    def __call__(
        self, code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        self.errors.write(f"ERROR: [{code}] {message}\n")
        write_document(
            self.output,
            failure(
                operation=self.operation,
                cluster=self.request.cluster,
                request_id=self.request.request_id,
                code=code,
                message=message,
                exit_code=exit_code,
                details=details,
            ),
        )
        return exit_code


def read_request(
    operation: str,
    *,
    parameters: frozenset[str],
    input_stream: BinaryIO | None,
    argv: Sequence[str],
    require_root: bool,
    helper_name: str,
) -> ClusterlessRequest:
    """Everything every certificate helper does before it knows what it was asked.

    Raises `HelperProtocolError`; the caller reports it on stderr alone, for the
    reason the deploy helper gives - an envelope invented before the request
    parses cannot be bound to the caller's job.
    """

    require_no_arguments(argv)
    if require_root and os.geteuid() != 0:
        raise HelperProtocolError(f"{helper_name} must run as root", exit_code=EXIT_NOT_ROOT)
    return read_clusterless_request(
        input_stream or sys.stdin.buffer,
        expected_operation=operation,
        allowed_parameter_keys=parameters,
    )


def _identifiers(
    parameters: Mapping[str, JsonValue], key: str, pattern: Any, what: str
) -> tuple[str, ...]:
    """A list of identifiers of one kind, checked for shape before anything reads it.

    Shape only. Whether a cluster or a receiver exists is the registry's answer
    and is asked later, where the registry is open; what is refused here is a
    value that is not an identifier at all, which is the form a payload takes
    when it is trying to be a path.
    """

    raw = parameters.get(key, [])
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise HelperProtocolError(f"parameters.{key} must be a list", exit_code=65)
    if len(raw) > MAX_TARGETS:
        raise HelperProtocolError(
            f"parameters.{key} names more than {MAX_TARGETS} {what}s", exit_code=65
        )
    checked: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise HelperProtocolError(f"parameters.{key} contains an invalid {what}", exit_code=65)
        checked.append(item)
    #
    # Order preserved and duplicates dropped, so a request that names a target
    # twice is the same request as one that names it once.
    #
    return tuple(dict.fromkeys(checked))


def clusters(parameters: Mapping[str, JsonValue], key: str = "clusters") -> tuple[str, ...]:
    return _identifiers(parameters, key, CLUSTER_ID, "cluster ID")


def receivers(parameters: Mapping[str, JsonValue], key: str = "receivers") -> tuple[str, ...]:
    return _identifiers(parameters, key, RECEIVER_ID, "receiver ID")


def formats(
    parameters: Mapping[str, JsonValue],
    receivers: Sequence[str],
    key: str = "formats",
) -> dict[str, str]:
    """How each named receiver is written, `{receiver_id: format}`, beside `receivers`.

    An object beside the list rather than a richer list element, so every
    payload that carries receivers is unchanged until it states a format
    (B159). A receiver named here and not in the list is refused: a format
    for a target the request does not have is a request that disagrees with
    itself.
    """

    raw = parameters.get(key)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise HelperProtocolError(f"parameters.{key} must be an object", exit_code=65)
    checked: dict[str, str] = {}
    for receiver_id, form in raw.items():
        if receiver_id not in receivers:
            raise HelperProtocolError(
                f"parameters.{key} names {receiver_id!r}, which is not in receivers",
                exit_code=65,
            )
        if not isinstance(form, str) or form not in RECEIVER_FORMATS:
            raise HelperProtocolError(
                f"parameters.{key}[{receiver_id!r}] must be one of {', '.join(RECEIVER_FORMATS)}",
                exit_code=65,
            )
        checked[receiver_id] = form
    return checked


def format_flags(values: Sequence[str], receivers: Sequence[str]) -> dict[str, str]:
    """`--format <receiver>=<format>` as the commands take it, checked like `formats`."""

    parsed: dict[str, JsonValue] = {}
    for value in values:
        receiver_id, separator, form = value.partition("=")
        if not separator or not receiver_id or not form:
            raise HelperProtocolError(
                f"--format takes <receiver>=<{'|'.join(RECEIVER_FORMATS)}>, not {value!r}",
                exit_code=64,
            )
        parsed[receiver_id] = form
    return formats({"formats": parsed}, receivers)


def certificates(parameters: Mapping[str, JsonValue], key: str = "certificates") -> tuple[str, ...]:
    return _identifiers(parameters, key, CERTIFICATE_ID, "certificate ID")


def certificate(parameters: Mapping[str, JsonValue], key: str = "certificate") -> str:
    value = parameters.get(key)
    if not isinstance(value, str) or not CERTIFICATE_ID.fullmatch(value):
        raise HelperProtocolError(f"parameters.{key} must be a certificate ID", exit_code=65)
    return value


def flag(parameters: Mapping[str, JsonValue], key: str) -> bool:
    value = parameters.get(key, False)
    if not isinstance(value, bool):
        raise HelperProtocolError(f"parameters.{key} must be true or false", exit_code=65)
    return value


def interface(parameters: Mapping[str, JsonValue]) -> bool:
    """Whether the request is for the manager's own interface certificate (B188).

    Absent is false, so every request written before the field existed means
    what it meant. The certificate it names has no targets; the operation
    refuses a request that names both.
    """

    value = parameters.get("interface", False)
    if not isinstance(value, bool):
        raise HelperProtocolError("parameters.interface must be true or false", exit_code=65)
    return value
