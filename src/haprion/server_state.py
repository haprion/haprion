"""Drain, maintenance and ready for one object's servers, on every node (Fas 20, B263).

The manager's half. The node keeps the state - `haprion-server-state` on the
node sets it on HAProxy's admin socket and holds it across reloads and restarts
- and this module decides what to ask for and who to ask.

What a request names
--------------------
An object and servers in it, written the way the object's editor writes them:
`host:port`, or `pool/host:port` where one object has the same server in two
pools. Never a GUID. A GUID is the node's key, and a caller that could name one
could name a server of an object it was not looking at; here every server is
found in the object first, in the cluster's newest version, and its GUID is
computed by the same function the generator writes it with.

The newest version and not the running one: a server that was published but
not yet deployed is a server the node does not have, and the node says so
(`server_not_on_node`). That is the honest answer - "this node is behind" - and
it does not need a second reading of what each node runs.

Why every node, and why a half is a half
----------------------------------------
Either node can be the one with the VIP the next minute, so a server drained on
one of them is not drained. Both are asked at once, and one that did not answer
is reported by name: the job is `partial`, the state on the other node holds,
and pressing the button again finishes it - the node helper is idempotent.

Nothing here takes the cluster lock. A deploy may run at the same time: the
node serialises its own reload and this call with a lock of its own, and puts
every kept state back after the reload, so the two cannot undo each other.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from haprion.config import DeployIdentity, Node
from haprion.guid import server_guid
from haprion.proxy_model import NAME, Proxy

OPERATION = "server_state"

STATES = ("ready", "drain", "maint")

#
# The forced command's one verb, and the words it takes after it
# (`haprion-server-state-trigger` on the node).
#
NODE_VERB = "server-state"

#
# The node helper's own exit codes (`install/node/haprion-server-state`).
#
NODE_UNKNOWN_SERVER = 65

#
# A bound, not a working figure: a pool of this many servers is one nobody
# drains by ticking boxes. Each server is one SSH call per node.
#
MAX_SERVERS = 64

#
# One call sets one server, and the node waits at most fifteen seconds for a
# reload in progress before it does. Thirty is a stop, not a schedule.
#
CALL_TIMEOUT_SECONDS = 30

MAX_ANSWER_BYTES = 16 * 1024

#
# `pool/host:port`, with the pool optional. The host is what the object model
# accepts on a server line - a name or an address, IPv6 in brackets or bare.
#
SERVER = re.compile(
    r"^(?:(?P<pool>[a-z][a-z0-9_-]{0,39})/)?(?P<host>[^\s/]{1,253}):(?P<port>\d{1,5})$"
)


class ServerStateError(Exception):
    """The request cannot be carried out as written. Nothing was sent to a node."""

    def __init__(self, code: str, message: str, *, exit_code: int = 65):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class Target:
    """One server of the object, as the node knows it."""

    pool: str
    host: str
    port: int
    guid: str

    @property
    def written(self) -> str:
        return f"{self.pool}/{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class Answer:
    """What one node said about one server."""

    node: str
    target: Target
    outcome: str
    """`done`, `refused` (the node does not run this server) or `failed`."""

    message: str | None = None
    reached: bool = True
    """False when nothing came back from the node: no connection, or no answer in time."""


def _host(value: str) -> str:
    return value[1:-1] if value.startswith("[") and value.endswith("]") else value


def resolve(proxy: Proxy, written: Sequence[str]) -> tuple[Target, ...]:
    """The servers a request names, found in the object or refused.

    Every one is resolved before any node is asked, so a request with one typo
    in it changes nothing anywhere rather than half of what was meant.
    """

    if proxy.listen.protocol in ("dns", "syslog"):
        engine = "dnsdist" if proxy.listen.protocol == "dns" else "keepalived"
        raise ServerStateError(
            "bad_input",
            f"{proxy.name} is a {proxy.listen.protocol} object; its servers are run by {engine}, "
            "not by HAProxy, and have no drain or maintenance",
        )
    if not written:
        raise ServerStateError("bad_input", "name at least one server")
    if len(written) > MAX_SERVERS:
        raise ServerStateError("bad_input", f"at most {MAX_SERVERS} servers in one request")

    found: list[Target] = []
    for entry in written:
        match = SERVER.match(entry) if isinstance(entry, str) else None
        if match is None:
            raise ServerStateError(
                "bad_input", f"{entry!r} is not a server; write host:port or pool/host:port"
            )
        host, port, pool = _host(match["host"]), int(match["port"]), match["pool"]
        candidates = [
            Target(
                pool=name,
                host=server.host,
                port=server.port,
                guid=server_guid(proxy.name, name, server),
            )
            for name, backend in sorted(proxy.backends.items())
            if pool in (None, name)
            for server in backend.servers
            if server.host == host and server.port == port
        ]
        if not candidates:
            raise ServerStateError(
                "server_not_found",
                f"{proxy.name} has no server {entry} in its newest version",
            )
        if len(candidates) > 1:
            choices = " or ".join(candidate.written for candidate in candidates)
            raise ServerStateError(
                "bad_input",
                f"{entry} is in more than one pool of {proxy.name}; write {choices}",
            )
        if candidates[0] not in found:
            found.append(candidates[0])
    return tuple(found)


def object_name(value: object) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ServerStateError("bad_input", "object must be an object name")
    return value


def find_object(proxies: Iterable[Proxy], name: str) -> Proxy:
    for proxy in proxies:
        if proxy.name == name:
            return proxy
    raise ServerStateError("server_not_found", f"there is no object {name} in the newest version")


type NodeCall = Callable[[Node, DeployIdentity, str, str], subprocess.CompletedProcess[str]]


def ask_node(
    node: Node, identity: DeployIdentity, guid: str, state: str
) -> subprocess.CompletedProcess[str]:
    """One server on one node, over the node's forced command."""

    from haprion.cli.deploy_helper import SSH, SSH_ENVIRONMENT, SSH_OPTIONS

    return subprocess.run(  # noqa: S603 - fixed path; host from configuration, words validated
        [
            SSH,
            *SSH_OPTIONS,
            "-i",
            str(identity.key),
            f"{identity.user}@{node.mgmt_host}",
            f"{NODE_VERB} {guid} {state}",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=SSH_ENVIRONMENT,
        timeout=CALL_TIMEOUT_SECONDS,
    )


def read_answer(node: str, target: Target, completed: subprocess.CompletedProcess[str]) -> Answer:
    """What the node said, or why nothing usable came back.

    The node answers one JSON line on every path it reaches. Nothing on stdout
    means the call never got that far - the connection, the key, the forced
    command or sudo - and that is "could not be reached", never a refusal.
    """

    document: object = None
    if completed.stdout and len(completed.stdout) <= MAX_ANSWER_BYTES:
        try:
            document = json.loads(completed.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            document = None
    if not isinstance(document, Mapping):
        stderr = (completed.stderr or "").strip().splitlines()
        reason = stderr[-1][:300] if stderr else "no answer"
        return Answer(
            node, target, "failed", f"the node could not be reached ({reason})", reached=False
        )

    said = document.get("message")
    message = said[:300] if isinstance(said, str) and said else None
    if completed.returncode == 0 and document.get("outcome") == "done":
        return Answer(node, target, "done")
    if completed.returncode == NODE_UNKNOWN_SERVER:
        return Answer(
            node,
            target,
            "refused",
            "the node does not run this server yet; deploy the newest version to it",
        )
    return Answer(
        node, target, "failed", message or f"the node answered with exit {completed.returncode}"
    )


def apply(
    nodes: Sequence[Node],
    identity: DeployIdentity,
    targets: Sequence[Target],
    state: str,
    *,
    ask: NodeCall = ask_node,
) -> tuple[Answer, ...]:
    """Every node's answer for every server, nodes at once and servers in order.

    One node failing is not the cluster failing: both are asked whatever the
    first one said. A node that could not be reached, or did not answer in
    time, is not asked for the servers after it (review 26-10-09, F4): each
    call waits up to CALL_TIMEOUT_SECONDS, and a node that hangs would hold
    the job for that long per server - past the worker's limit for a large
    pool, which would leave a job the other node finished as `unknown`.
    """

    if state not in STATES:
        raise ServerStateError("bad_input", f"state must be one of {', '.join(STATES)}")

    def one(node: Node) -> list[Answer]:
        answers: list[Answer] = []
        for target in targets:
            silent = next((answer for answer in answers if not answer.reached), None)
            if silent is not None:
                answers.append(
                    Answer(
                        node.name,
                        target,
                        "failed",
                        f"not asked: the node did not answer for {silent.target.written}",
                        reached=False,
                    )
                )
                continue
            try:
                completed = ask(node, identity, target.guid, state)
            except subprocess.TimeoutExpired:
                answers.append(
                    Answer(
                        node.name,
                        target,
                        "failed",
                        "the node did not answer in time",
                        reached=False,
                    )
                )
                continue
            answers.append(read_answer(node.name, target, completed))
        return answers

    if not nodes:
        return ()
    with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        return tuple(answer for answers in pool.map(one, nodes) for answer in answers)
