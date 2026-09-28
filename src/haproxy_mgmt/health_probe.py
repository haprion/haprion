"""Asking the nodes whether a health check would reach a pool.

The question is worth asking from a node and nowhere else. A node is what
connects to a pool - from the address the object leaves from, through whatever
firewall stands between the two - and a probe run on the management host proves
a path no traffic takes. So this module builds a request, hands it to each node
over SSH, and reports what came back without believing any of it too readily.

Which nodes
-----------
Both, unless the object names a source address, in which case the node that
carries that address is still both of them: the source is a cluster-wide
address that either node may hold, and asking both is what shows the difference
between "the pool is reachable" and "the pool is reachable from the node that
happens to own the address today". Two answers are the answer.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.config import DeployIdentity, Node
from haproxy_mgmt.tls_policy import DEFAULT_MIN_VERSION

SCHEMA_VERSION = 1

SSH = "/usr/bin/ssh"
SSH_OPTIONS = (
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "LogLevel=ERROR",
)
SSH_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}

#
# The node bounds these as well, and that is not redundant. This bound protects
# the node from a manager that asks for too much; the node's bound protects it
# from a client holding the key, which may not be this code.
#
MAX_TARGETS = 20
MAX_ANSWER_BYTES = 256 * 1024
DEFAULT_TIMEOUT_MS = 2000


@dataclass(frozen=True, slots=True)
class Target:
    """One server, and what a check against it would be."""

    host: str
    port: int
    type: str = "tcp"
    tls: bool = False
    verify: bool = False
    path: str = "/"
    host_header: str = ""
    min_version: str = DEFAULT_MIN_VERSION
    """The oldest handshake this check may use, as HAProxy would name it.

    The object's policy, not the probe's own. HAProxy will reach the pool under
    what the object says, so a probe holding a different floor would answer a
    question nobody asked - and the answer people act on is "the pool is down"
    when it is only unreachable from here.
    """

    def request(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "type": self.type,
            "tls": self.tls,
            "verify": self.verify,
            "path": self.path,
            "host_header": self.host_header,
            "min_version": self.min_version,
        }


@dataclass(frozen=True, slots=True)
class Reached:
    """What one node said about one server."""

    host: str
    port: int
    ok: bool
    status: int | None
    error: str | None
    ms: int | None


@dataclass(frozen=True, slots=True)
class NodeAnswer:
    """One node's whole answer, including its failure to give one."""

    node: str
    reachable: bool
    error: str | None
    results: tuple[Reached, ...]
    #
    # Whether this node carries the source address the object leaves from, and
    # could therefore answer at all. `None` is a node whose script predates the
    # field: it said nothing, which is never read as "no".
    #
    source_held: bool | None = None


def build_request(
    targets: Sequence[Target], *, source: str = "", timeout_ms: int = DEFAULT_TIMEOUT_MS
) -> str:
    """The JSON one node is handed. Refuses here what the node would refuse."""

    if not targets:
        raise ValueError("a probe needs at least one target")
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"at most {MAX_TARGETS} targets may be probed at once")
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "source": source,
            "timeout_ms": timeout_ms,
            "targets": [target.request() for target in targets],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def ask_node(
    node: Node, identity: DeployIdentity, request: str
) -> subprocess.CompletedProcess[str]:
    """One node, asked over its forced command. The request is stdin."""

    return subprocess.run(  # noqa: S603 - fixed path, host from validated configuration
        [SSH, *SSH_OPTIONS, "-i", str(identity.key), f"{identity.user}@{node.mgmt_host}"],
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        env=SSH_ENVIRONMENT,
        timeout=30,
    )


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def read_answer(node: str, completed: subprocess.CompletedProcess[str]) -> NodeAnswer:
    """What the node said, or why nothing usable came back.

    A node that could not be reached, answered nothing, or answered something
    this cannot read is one node with no answer - never an answer that the pool
    is unreachable. The two look identical on a page that does not separate
    them, and they lead to opposite actions.
    """

    if completed.returncode != 0 and not completed.stdout.strip():
        return NodeAnswer(
            node=node, reachable=False, error="the node could not be reached", results=()
        )
    if len(completed.stdout) > MAX_ANSWER_BYTES:
        return NodeAnswer(
            node=node, reachable=False, error="the node answered with too much", results=()
        )
    try:
        payload = json.loads(completed.stdout)
    except ValueError:
        return NodeAnswer(
            node=node, reachable=False, error="the node did not answer with JSON", results=()
        )
    if not isinstance(payload, Mapping):
        return NodeAnswer(
            node=node, reachable=False, error="the node's answer is not an object", results=()
        )
    if payload.get("ok") is not True:
        refusal = _text(payload.get("error")) or "the node refused the request"
        return NodeAnswer(node=node, reachable=True, error=refusal, results=())

    entries = payload.get("results")
    results = []
    for entry in entries if isinstance(entries, list) else ():
        if not isinstance(entry, Mapping):
            continue
        host = _text(entry.get("host"))
        port = _count(entry.get("port"))
        if host is None or port is None:
            continue
        results.append(
            Reached(
                host=host,
                port=port,
                ok=entry.get("ok") is True,
                status=_count(entry.get("status")),
                error=_text(entry.get("error")),
                ms=_count(entry.get("ms")),
            )
        )
    held = payload.get("source_held")
    return NodeAnswer(
        node=node,
        reachable=True,
        error=None,
        results=tuple(results),
        source_held=held if isinstance(held, bool) else None,
    )


def probe(
    nodes: Iterable[Node],
    identity: DeployIdentity,
    targets: Sequence[Target],
    *,
    source: str = "",
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ask: object = None,
) -> tuple[NodeAnswer, ...]:
    """Every node's answer, in configured order.

    One node failing is not the cluster failing. Both are asked whatever the
    first one said, because "reachable from one node and not the other" is the
    answer somebody is looking for often enough to be worth the second call.
    """

    request = build_request(targets, source=source, timeout_ms=timeout_ms)
    caller = ask if ask is not None else ask_node

    def one(node: Node) -> NodeAnswer:
        try:
            completed = caller(node, identity, request)  # type: ignore[operator]
        except subprocess.TimeoutExpired:
            return NodeAnswer(
                node=node.name,
                reachable=False,
                error="the node did not answer in time",
                results=(),
            )
        return read_answer(node.name, completed)

    #
    # The nodes at once rather than one after the other: two SSH calls of up
    # to 30 s each in a row met the web's 60 s, and nginx's, exactly (review
    # 2026-09-28). `map` keeps the configured order.
    #
    listed = list(nodes)
    if not listed:
        return ()
    with ThreadPoolExecutor(max_workers=len(listed)) as pool:
        return tuple(pool.map(one, listed))
