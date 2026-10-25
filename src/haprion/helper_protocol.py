from __future__ import annotations

import json
import math
import os
import re
import signal
import sys
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, BinaryIO, TextIO, cast

from haprion import exit_codes, labels
from haprion.config import CLUSTER_ID
from haprion.envelope import failure

MAX_REQUEST_BYTES = 64 * 1024
#
# How deeply a request may nest arrays and objects. A real one goes nine deep;
# the limit is the protocol's own, counted before the document is parsed,
# rather than whatever depth Python's parser happens to survive - which
# differs between patch releases and machines (CI's Python 3.14 parsed 100 000
# levels that 3.13 refused, 26-10-24).
#
MAX_NESTING = 64
_NESTING_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]')
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

    def __init__(self, message: str, *, exit_code: int = exit_codes.USAGE):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class HelperRequest:
    operation: str
    cluster: str
    request_id: str
    parameters: Mapping[str, JsonValue]
    lifeline: bool = False


@dataclass(frozen=True, slots=True)
class ClusterlessRequest:
    """A request for an operation that acts on no particular cluster.

    A separate type rather than an optional field on `HelperRequest`, and the
    reason is the same one `ClaimedJob` gives for not being an optional `Job`:
    the difference is real, not a convenience. Every cluster helper reads
    `request.cluster` and hands it to something that needs a cluster - seventeen
    files of them - and widening that one field to `str | None` would push the
    absence into all of them so that three helpers could express it.

    The three that need it are the certificate operations, whose scope is the
    registry: one certificate may name two clusters, another only receivers
    and none. `cluster` is kept here, always null, because the envelope they answer
    with still has the field and reads better beside the request that produced
    it.
    """

    operation: str
    request_id: str
    parameters: Mapping[str, JsonValue]
    cluster: None = None


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

    __slots__ = ("_fd", "_reason", "_thread")

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._reason: str | None = None
        self._thread: threading.Thread | None = None

    @classmethod
    def take(cls, stream: BinaryIO) -> Lifeline:
        """Move the lifeline off descriptor 0, and put /dev/null there instead.

        This is the part that is easy to get wrong by doing nothing. A helper
        spawns children - ssh to every node, git, the validator - and a child
        inherits descriptor 0 unless it is told otherwise. Left as stdin, the
        lifeline is handed to every one of them: ssh forwards it to the far end,
        where the remote command waits for an end of input that will not come
        until the worker lets go. Measured on 2026-08-31 as a no-op deploy going
        from 0.58s to 3.42s, which was the cheap symptom of it.

        The alternative is a `stdin=DEVNULL` on twenty call sites and on every
        one written later. Moving the descriptor once is the same guarantee
        without depending on anyone remembering it: after this, the lifeline is
        a private descriptor and stdin is empty, which is what a helper that has
        already read its request should have anyway.
        """

        duplicate = os.dup(stream.fileno())
        empty = os.open(os.devnull, os.O_RDONLY)
        try:
            os.dup2(empty, 0)
        finally:
            os.close(empty)
        return cls(duplicate)

    def watch(self) -> None:
        """Start watching. Daemon, so it can never hold the helper's exit."""

        thread = threading.Thread(target=self._read_until_gone, name="lifeline", daemon=True)
        self._thread = thread
        thread.start()

    def _read_until_gone(self) -> None:
        try:
            extra = os.read(self._fd, 1)
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
            raise HelperProtocolError(f"duplicate JSON field: {key}", exit_code=exit_codes.REFUSED)
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise HelperProtocolError(
        f"non-finite JSON number is not allowed: {value}", exit_code=exit_codes.REFUSED
    )


def _finite_float(value: str) -> float:
    """A number written as a float, refused when it overflows to infinity (`1e999`)."""

    number = float(value)
    if not math.isfinite(number):
        _reject_non_finite_number(value)
    return number


def _refuse_deep_nesting(text: str) -> None:
    """Refuse a document nested deeper than `MAX_NESTING`, counting outside strings."""

    depth = 0
    for match in _NESTING_TOKEN.finditer(text):
        bracket = match.group()
        if bracket in "[{":
            depth += 1
            if depth > MAX_NESTING:
                raise HelperProtocolError(
                    "helper request is not one valid JSON document",
                    exit_code=exit_codes.REFUSED,
                )
        elif bracket in "]}":
            depth -= 1


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
        raise HelperProtocolError(
            "helper request exceeds the size limit", exit_code=exit_codes.REFUSED
        )
    if not raw:
        raise HelperProtocolError("helper request is empty", exit_code=exit_codes.REFUSED)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HelperProtocolError(
            "helper request is not valid UTF-8", exit_code=exit_codes.REFUSED
        ) from exc

    _refuse_deep_nesting(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_finite_float,
        )
    except HelperProtocolError:
        raise
    #
    # Python's own limits are refusals too: an integer past its digit limit
    # raises ValueError and a document nested past the stack RecursionError,
    # and either escaped as a traceback instead of the protocol's refusal
    # (review 2026-10-22, 5-15).
    #
    except (ValueError, RecursionError) as exc:
        raise HelperProtocolError(
            "helper request is not one valid JSON document", exit_code=exit_codes.REFUSED
        ) from exc

    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise HelperProtocolError(
            "helper request must be a JSON object", exit_code=exit_codes.REFUSED
        )
    return cast(dict[str, JsonValue], value)


def _required_string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise HelperProtocolError(
            f"{field} must be a non-empty string", exit_code=exit_codes.REFUSED
        )
    return value


@dataclass(frozen=True, slots=True)
class _Common:
    """What every request has, before the two kinds differ over the cluster."""

    operation: str
    request_id: str
    parameters: Mapping[str, JsonValue]
    lifeline: bool
    document: Mapping[str, JsonValue]


#
# How long a caller has to hand over its request - the line, and for a caller
# that holds no lifeline the end of its input. A byte limit is not a time
# limit: a caller that connected to a socket and said nothing held one of the
# few connections a helper takes, for as long as it liked (security review
# 26-10-13, S08). Every caller writes its request at once; this is for the one
# that does not.
#
REQUEST_DEADLINE_SECONDS = 30


class _RequestTimedOut(Exception):
    pass


@contextmanager
def _request_deadline(seconds: float) -> Iterator[None]:
    """Raise HelperProtocolError if the block is still reading after `seconds`.

    A timer signal, because the request is read through a buffered stream that
    must stay blocking - it may be the lifeline afterwards. Signals reach the
    main thread only; read anywhere else, there is no deadline to set.
    """

    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def expired(_signum: int, _frame: object) -> None:
        raise _RequestTimedOut

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    except _RequestTimedOut as exc:
        raise HelperProtocolError(
            f"no complete request arrived within {seconds:g} s", exit_code=exit_codes.REFUSED
        ) from exc
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _read_common(
    stream: BinaryIO,
    *,
    expected_operation: str,
    allowed_parameter_keys: frozenset[str] = frozenset(),
    validate_parameters: ParameterValidator | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
    lifeline: bool = False,
) -> _Common:
    """`_read_request`, within the time a caller has to send it (S08)."""

    with _request_deadline(REQUEST_DEADLINE_SECONDS):
        return _read_request(
            stream,
            expected_operation=expected_operation,
            allowed_parameter_keys=allowed_parameter_keys,
            validate_parameters=validate_parameters,
            max_bytes=max_bytes,
            lifeline=lifeline,
        )


def read_raw_request(stream: BinaryIO, *, max_bytes: int = MAX_REQUEST_BYTES) -> bytes:
    """A request read whole before it is parsed, within the time a caller has to send it (S08).

    For a helper that answers several operations on one socket, and has to see
    which one a request names before it can hold it to that operation's
    parameters. Read to the end of the input, which those callers close; a
    caller that never does is refused at the deadline instead of holding one of
    the helper's few connections for as long as it likes (review 2026-10-22,
    5-10: the read stood outside the deadline in three helpers).
    """

    with _request_deadline(REQUEST_DEADLINE_SECONDS):
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise HelperProtocolError(
            "helper request is larger than allowed", exit_code=exit_codes.REFUSED
        )
    return raw


def _read_request(
    stream: BinaryIO,
    *,
    expected_operation: str,
    allowed_parameter_keys: frozenset[str] = frozenset(),
    validate_parameters: ParameterValidator | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
    lifeline: bool = False,
) -> _Common:
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
            f"helper request is missing {labels.noun(len(missing), 'field')}: {', '.join(missing)}",
            exit_code=exit_codes.REFUSED,
        )
    if unknown:
        raise HelperProtocolError(
            f"helper request contains unknown {labels.noun(len(unknown), 'field')}: {', '.join(unknown)}",
            exit_code=exit_codes.REFUSED,
        )

    schema_version = document["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise HelperProtocolError("schema_version must be 1", exit_code=exit_codes.REFUSED)

    operation = _required_string(document, "operation")
    if operation != expected_operation:
        raise HelperProtocolError("operation is not allowed by this helper")

    request_id = _required_string(document, "request_id")
    try:
        parsed_request_id = uuid.UUID(request_id)
    except ValueError as exc:
        raise HelperProtocolError(
            "request_id must be a UUID", exit_code=exit_codes.REFUSED
        ) from exc
    if str(parsed_request_id) != request_id:
        raise HelperProtocolError(
            "request_id must use canonical UUID form", exit_code=exit_codes.REFUSED
        )

    requested_lifeline = document.get("lifeline", False)
    if type(requested_lifeline) is not bool:
        raise HelperProtocolError("lifeline must be true or false", exit_code=exit_codes.REFUSED)
    if requested_lifeline and not lifeline:
        raise HelperProtocolError(
            "this helper does not support a lifeline", exit_code=exit_codes.REFUSED
        )

    if not requested_lifeline and stream.read(1):
        #
        # Nothing may follow the request when stdin is not a lifeline. The line
        # framing ends the document, so trailing bytes are no longer a JSON
        # error the parser happens to catch - they are a second request, or a
        # caller that does not agree with this one about what it is sending.
        #
        raise HelperProtocolError(
            "helper request is followed by more input", exit_code=exit_codes.REFUSED
        )

    raw_parameters = document["parameters"]
    if not isinstance(raw_parameters, dict) or not all(
        isinstance(key, str) for key in raw_parameters
    ):
        raise HelperProtocolError("parameters must be a JSON object", exit_code=exit_codes.REFUSED)
    parameters = raw_parameters
    unknown_parameters = sorted(parameters.keys() - allowed_parameter_keys)
    if unknown_parameters:
        raise HelperProtocolError(
            f"parameters contains unknown {labels.noun(len(unknown_parameters), 'field')}: "
            f"{', '.join(unknown_parameters)}",
            exit_code=exit_codes.REFUSED,
        )
    if validate_parameters is not None:
        validate_parameters(parameters)

    return _Common(
        operation=operation,
        request_id=request_id,
        parameters=parameters,
        lifeline=requested_lifeline,
        document=document,
    )


def read_helper_request(
    stream: BinaryIO,
    *,
    expected_operation: str,
    allowed_parameter_keys: frozenset[str] = frozenset(),
    validate_parameters: ParameterValidator | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
    lifeline: bool = False,
) -> HelperRequest:
    """One request for a helper that acts on one cluster, which is most of them."""

    common = _read_common(
        stream,
        expected_operation=expected_operation,
        allowed_parameter_keys=allowed_parameter_keys,
        validate_parameters=validate_parameters,
        max_bytes=max_bytes,
        lifeline=lifeline,
    )
    cluster = _required_string(common.document, "cluster")
    if not CLUSTER_ID.fullmatch(cluster):
        raise HelperProtocolError("cluster is not a valid cluster ID")
    return HelperRequest(
        operation=common.operation,
        cluster=cluster,
        request_id=common.request_id,
        parameters=common.parameters,
        lifeline=common.lifeline,
    )


def read_clusterless_request(
    stream: BinaryIO,
    *,
    expected_operation: str,
    allowed_parameter_keys: frozenset[str] = frozenset(),
    validate_parameters: ParameterValidator | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
) -> ClusterlessRequest:
    """One request for an operation with no cluster, which is the certificate three.

    The `cluster` field is still required and must be explicitly null. A caller
    that states the absence has decided; one that omits the field has forgotten,
    and only the first is accepted - the same reason every other field here is
    required rather than defaulted.

    No lifeline. These helpers have no checkpoint to notice a released caller
    at: a certbot run is one external call, and a publish abandoned halfway
    would leave a target holding a file from a run that did not finish.
    """

    common = _read_common(
        stream,
        expected_operation=expected_operation,
        allowed_parameter_keys=allowed_parameter_keys,
        validate_parameters=validate_parameters,
        max_bytes=max_bytes,
        lifeline=False,
    )
    if common.document["cluster"] is not None:
        raise HelperProtocolError("this operation acts on no cluster; cluster must be null")
    return ClusterlessRequest(
        operation=common.operation,
        request_id=common.request_id,
        parameters=common.parameters,
    )


def read_scoped_request(
    stream: BinaryIO,
    *,
    expected_operation: str,
    allowed_parameter_keys: frozenset[str] = frozenset(),
    validate_parameters: ParameterValidator | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
) -> HelperRequest | ClusterlessRequest:
    """One request for an operation that reads either a cluster or the manager.

    `cert_list` and the readings helper that carries it: with a cluster, what
    that cluster is given; with an explicit null, what the manager holds, which
    a manager with no cluster yet must be able to read too (B304). The two
    types stay apart, as `ClusterlessRequest` says why; the caller branches
    once, on which one came back.
    """

    common = _read_common(
        stream,
        expected_operation=expected_operation,
        allowed_parameter_keys=allowed_parameter_keys,
        validate_parameters=validate_parameters,
        max_bytes=max_bytes,
        lifeline=False,
    )
    if common.document["cluster"] is None:
        return ClusterlessRequest(
            operation=common.operation,
            request_id=common.request_id,
            parameters=common.parameters,
        )
    cluster = _required_string(common.document, "cluster")
    if not CLUSTER_ID.fullmatch(cluster):
        raise HelperProtocolError("cluster is not a valid cluster ID")
    return HelperRequest(
        operation=common.operation,
        cluster=cluster,
        request_id=common.request_id,
        parameters=common.parameters,
    )


#
# Set by `run-tests` for both suites: there a contradiction between a
# document's outcome and its exit code stops the test, as it is a bug.
#
STRICT_VARIABLE = "HAPRION_EXIT_STRICT"


def write_document(stream: TextIO, document: Mapping[str, Any], exit_code: int) -> int:
    """Write one helper result to stdout in the one form every helper uses, and hand back its exit.

    Sorted keys and no incidental whitespace, so two helpers answering the same
    question produce byte-identical documents and a diff between a fixture and a
    real run is a difference in content rather than in formatting.

    The exit code is checked against the document's outcome (`exit_codes.check`):
    a `blocked` that exited 65 and a `partial` that exited 0 were two answers to
    one question (review 2026-10-22, 4-1). A contradiction is a bug, and the
    test suites refuse it. In use it no longer costs the document: refusing it
    after the work was done left no answer at all - a backup whose second node
    was down, a deploy that could not read its status (review 26-10-24, part
    06's own point). The outcome decides the code for `done`, `partial` and
    `blocked`; `failed` keeps a failure code of its own, or `FAILED`; and the
    contradiction is said on stderr. The text is made before a byte is written,
    so a document that cannot be serialised leaves none half written.
    """

    stated = document.get("outcome")
    try:
        code = exit_codes.check(stated, exit_code)
    except ValueError as contradiction:
        if os.environ.get(STRICT_VARIABLE) == "1":
            raise
        if stated in ("done", "partial", "blocked"):
            code = exit_codes.for_outcome(stated)
        elif exit_code in exit_codes.MEANINGS and exit_codes.outcome(exit_code) == "failed":
            code = exit_code
        else:
            code = exit_codes.FAILED
        sys.stderr.write(f"haprion: {contradiction}; exiting {code}\n")
    text = json.dumps(document, separators=(",", ":"), sort_keys=True)
    stream.write(text + "\n")
    return code


def config_error_code(exit_code: int) -> str:
    """The stable code a configuration failure is reported under.

    64 is the caller's mistake - a cluster this installation does not have.
    Anything else means the configuration a helper depends on could not be read
    or used, which is the installation's problem and not the request's.
    """

    return "bad_input" if exit_code == exit_codes.USAGE else "dependency_unavailable"


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

    return write_document(
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
        exit_code,
    )
