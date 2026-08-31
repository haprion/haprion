from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, BinaryIO, TextIO, cast

from haproxy_mgmt.config import CLUSTER_ID
from haproxy_mgmt.envelope import failure

MAX_REQUEST_BYTES = 64 * 1024
OPERATION = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
REQUEST_FIELDS = frozenset({"schema_version", "operation", "cluster", "request_id", "parameters"})

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type ParameterValidator = Callable[[Mapping[str, JsonValue]], None]


class HelperProtocolError(ValueError):
    """A request crossed the privilege boundary in an invalid form."""

    def __init__(self, message: str, *, exit_code: int = 64):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class HelperRequest:
    operation: str
    cluster: str
    request_id: str
    parameters: Mapping[str, JsonValue]


def require_no_arguments(argv: Sequence[str]) -> None:
    """Fail closed when a no-argument sudo helper receives caller-controlled argv."""

    if argv:
        raise HelperProtocolError("this helper accepts no command-line arguments")


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise HelperProtocolError(f"duplicate JSON field: {key}", exit_code=65)
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise HelperProtocolError(f"non-finite JSON number is not allowed: {value}", exit_code=65)


def _read_document(stream: BinaryIO, *, max_bytes: int) -> dict[str, JsonValue]:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")

    #
    # One line, not one stream. Reading to EOF would force the caller to close
    # stdin to say "that is the whole request", and closing it throws away the
    # only channel that survives sudo - which closes every descriptor from 3 up.
    # That channel is the helper's lifeline: EOF on stdin is how a caller says
    # it has let go, and it arrives by itself when the caller dies, without any
    # code having to run and without anyone needing privilege to signal a
    # process running as root.
    #
    # A line ending is what ends the request, but EOF still ends it too. That is
    # what makes this readable by a caller that has not been changed yet, and it
    # decides the rollout order: a new helper understands an old caller, while a
    # new caller against an old helper would hang rather than fail.
    #
    raw = stream.readline(max_bytes + 2)
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if len(raw) > max_bytes:
        raise HelperProtocolError("helper request exceeds the size limit", exit_code=65)
    if not raw:
        raise HelperProtocolError("helper request is empty", exit_code=65)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HelperProtocolError("helper request is not valid UTF-8", exit_code=65) from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
        )
    except HelperProtocolError:
        raise
    except json.JSONDecodeError as exc:
        raise HelperProtocolError(
            "helper request is not one valid JSON document", exit_code=65
        ) from exc

    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise HelperProtocolError("helper request must be a JSON object", exit_code=65)
    return cast(dict[str, JsonValue], value)


def _required_string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(f"{field} must be a non-empty string", exit_code=65)
    return value


def read_helper_request(
    stream: BinaryIO,
    *,
    expected_operation: str,
    allowed_parameter_keys: frozenset[str] = frozenset(),
    validate_parameters: ParameterValidator | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
    lifeline: bool = False,
) -> HelperRequest:
    """Read and validate exactly one request for an exact privileged helper.

    `lifeline` says what stdin is for once the request has been read. Left
    False, the stream must be at its end and anything after the request is
    refused - the guarantee a helper has always had, and the one every
    read-only helper still wants.

    Set True by a helper whose caller holds stdin open on purpose: the stream is
    then the caller's lifeline, and the helper reads it to learn that the caller
    has let go. The refusal above cannot apply there - the whole point is that
    nothing arrives - so a helper that asks for a lifeline takes on the duty of
    refusing anything that does.
    """

    if not OPERATION.fullmatch(expected_operation):
        raise ValueError("expected_operation is invalid")

    document = _read_document(stream, max_bytes=max_bytes)
    missing = sorted(REQUEST_FIELDS - document.keys())
    unknown = sorted(document.keys() - REQUEST_FIELDS)
    if missing:
        raise HelperProtocolError(
            f"helper request is missing field(s): {', '.join(missing)}", exit_code=65
        )
    if unknown:
        raise HelperProtocolError(
            f"helper request contains unknown field(s): {', '.join(unknown)}", exit_code=65
        )

    schema_version = document["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise HelperProtocolError("schema_version must be 1", exit_code=65)

    operation = _required_string(document, "operation")
    if operation != expected_operation:
        raise HelperProtocolError("operation is not allowed by this helper")

    cluster = _required_string(document, "cluster")
    if not CLUSTER_ID.fullmatch(cluster):
        raise HelperProtocolError("cluster is not a valid cluster ID")

    request_id = _required_string(document, "request_id")
    try:
        parsed_request_id = uuid.UUID(request_id)
    except ValueError as exc:
        raise HelperProtocolError("request_id must be a UUID", exit_code=65) from exc
    if str(parsed_request_id) != request_id.lower():
        raise HelperProtocolError("request_id must use canonical UUID form", exit_code=65)

    if not lifeline and stream.read(1):
        #
        # Nothing may follow the request when stdin is not a lifeline. The line
        # framing ends the document, so trailing bytes are no longer a JSON
        # error the parser happens to catch - they are a second request, or a
        # caller that does not agree with this one about what it is sending.
        #
        raise HelperProtocolError("helper request is followed by more input", exit_code=65)

    raw_parameters = document["parameters"]
    if not isinstance(raw_parameters, dict) or not all(
        isinstance(key, str) for key in raw_parameters
    ):
        raise HelperProtocolError("parameters must be a JSON object", exit_code=65)
    parameters = raw_parameters
    unknown_parameters = sorted(parameters.keys() - allowed_parameter_keys)
    if unknown_parameters:
        raise HelperProtocolError(
            f"parameters contains unknown field(s): {', '.join(unknown_parameters)}",
            exit_code=65,
        )
    if validate_parameters is not None:
        validate_parameters(parameters)

    return HelperRequest(
        operation=operation,
        cluster=cluster,
        request_id=request_id,
        parameters=parameters,
    )


def write_document(stream: TextIO, document: Mapping[str, Any]) -> None:
    """Write one helper result to stdout, in the one form every helper uses.

    Sorted keys and no incidental whitespace, so two helpers answering the same
    question produce byte-identical documents and a diff between a fixture and a
    real run is a difference in content rather than in formatting.
    """

    json.dump(document, stream, separators=(",", ":"), sort_keys=True)
    stream.write("\n")


def config_error_code(exit_code: int) -> str:
    """The stable code a configuration failure is reported under.

    64 is the caller's mistake - a cluster this installation does not have.
    Anything else means the configuration a helper depends on could not be read
    or used, which is the installation's problem and not the request's.
    """

    return "bad_input" if exit_code == 64 else "dependency_unavailable"


def write_failure(
    stream: TextIO,
    *,
    operation: str,
    cluster: str | None,
    request_id: str,
    code: str,
    message: str,
    exit_code: int,
    details: dict[str, Any] | None = None,
) -> int:
    """Write one refusal envelope and hand back the exit code to return.

    A helper that has read its request knows which operation, cluster and
    request ID an answer belongs to, so every exit from there on can carry the
    document the contract promises. Returning the exit code keeps the call site
    to one line, which is the difference between a rule that is followed and one
    that is remembered.
    """

    write_document(
        stream,
        failure(
            operation=operation,
            cluster=cluster,
            request_id=request_id,
            code=code,
            message=message,
            exit_code=exit_code,
            details=details,
        ),
    )
    return exit_code
