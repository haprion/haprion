from __future__ import annotations

import json
import re
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, BinaryIO, TextIO, cast

from haproxy_mgmt.config import CLUSTER_ID
from haproxy_mgmt.envelope import failure

MAX_REQUEST_BYTES = 64 * 1024
OPERATION = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
REQUIRED_REQUEST_FIELDS = frozenset(
    {"schema_version", "operation", "cluster", "request_id", "parameters"}
)
#
# Optional, and optional on purpose. A caller that holds stdin open as a
# lifeline has to say so, because the alternative is worse than it looks: a
# helper that simply watched stdin would read the immediate EOF from a caller
# that has not been rebuilt yet as "the caller let go", and abort every
# operation. Declaring it makes the old combination behave exactly as before.
#
OPTIONAL_REQUEST_FIELDS = frozenset({"lifeline"})
REQUEST_FIELDS = REQUIRED_REQUEST_FIELDS | OPTIONAL_REQUEST_FIELDS

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
    lifeline: bool = False


class Lifeline:
    """The caller's stdin, watched for the moment the caller lets go.

    Why a flag and not a signal
    ---------------------------
    This exists because the caller cannot stop us. The helper runs as root
    through sudo and the worker does not, so `kill` answers EPERM - and no
    amount of privilege would make killing the right answer anyway. A signal
    arrives at an arbitrary instant, which for a reconcile loop means an
    arbitrary half-applied cluster. A flag is read where the code already knows
    what it has done and what it has not.

    So this never stops anything. It answers one question - has the caller let
    go - and the loop that owns the mutation decides where to act on it.

    Two things end the watch, and both mean the same thing here:

    - EOF, which is the caller closing the stream, dying, or being torn out of
      its cgroup. Three of those need no code to run anywhere.
    - anything arriving on the stream, which the request framing says cannot
      happen. A caller that sends more is not the caller this helper agreed to
      run for, and continuing on its behalf is not defensible.
    """

    __slots__ = ("_reason", "_stream", "_thread")

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._reason: str | None = None
        self._thread: threading.Thread | None = None

    def watch(self) -> None:
        """Start watching. Daemon, so it can never hold the helper's exit."""

        thread = threading.Thread(target=self._read_until_gone, name="lifeline", daemon=True)
        self._thread = thread
        thread.start()

    def _read_until_gone(self) -> None:
        try:
            extra = self._stream.read(1)
        except OSError:
            #
            # The stream failing IS the caller being gone. Reporting it as an
            # error would leave the helper running for a caller it can no longer
            # hear, which is the situation this class exists to end.
            #
            self._reason = "the lifeline could not be read"
            return
        self._reason = (
            "unexpected input arrived on the lifeline"
            if extra
            else "the caller closed the lifeline"
        )

    @property
    def released(self) -> bool:
        """Whether the caller has let go. Cheap enough to ask every iteration."""

        return self._reason is not None

    @property
    def reason(self) -> str:
        if self._reason is None:
            raise RuntimeError("the lifeline is still held")
        return self._reason


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

    Two separate questions decide what stdin is for afterwards, and keeping them
    apart is what makes the rollout safe.

    `lifeline` here is the helper's own answer: whether this helper is one that
    can be interrupted at a checkpoint. A helper that says no and is handed a
    request asking for a lifeline refuses it rather than accepting a promise it
    cannot keep.

    The request's own `lifeline` field is the caller's answer: whether it is
    holding stdin open. Absent - which is every caller that has not been rebuilt
    - the stream must be at its end, and anything after the request is refused
    exactly as before.

    Both true is the only case where the stream is left open, and the helper
    then owns the duty of refusing anything that arrives on it.
    """

    if not OPERATION.fullmatch(expected_operation):
        raise ValueError("expected_operation is invalid")

    document = _read_document(stream, max_bytes=max_bytes)
    missing = sorted(REQUIRED_REQUEST_FIELDS - document.keys())
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

    requested_lifeline = document.get("lifeline", False)
    if type(requested_lifeline) is not bool:
        raise HelperProtocolError("lifeline must be true or false", exit_code=65)
    if requested_lifeline and not lifeline:
        raise HelperProtocolError("this helper does not support a lifeline", exit_code=65)

    if not requested_lifeline and stream.read(1):
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
        lifeline=requested_lifeline,
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
