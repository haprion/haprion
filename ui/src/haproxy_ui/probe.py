"""Turning the object form into a probe, and the answer into something to read.

The form is the question. What a health check would do is spelled out across
half a dozen fields - the servers, the check's type and path, its own port, the
host header, whether the pool is reached over TLS, and which address the object
leaves from - and every one of them changes what the node should try. Building
the request anywhere else would mean reading those fields twice.

Nothing here reaches a node, and nothing here is privileged. It builds a
request, writes it to the socket the probe service answers on, and reads what
came back. The privilege sits on the other end of that socket and stays there;
this service could not sudo if it tried, which is deliberate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from haproxy_mgmt.probe_socket import ProbeUnavailable, ask, build_request

#
# The same bound the helper and the node hold. Named here so a pool with more
# servers than this is refused with a sentence instead of by whichever of the
# three happens to see it first.
#
MAX_TARGETS = 20


@dataclass(frozen=True, slots=True)
class Reached:
    host: str
    port: int
    ok: bool
    status: int | None
    error: str | None
    ms: int | None


@dataclass(frozen=True, slots=True)
class NodeReport:
    node: str
    reachable: bool
    error: str | None
    results: tuple[Reached, ...]
    #
    # False when this node does not carry the object's source address, and so
    # probed nothing. Not a failure and not a node that went missing: the
    # question simply belongs to the node that holds the address. `None` is a
    # node whose script predates the field.
    #
    source_held: bool | None = None


@dataclass(frozen=True, slots=True)
class ProbeReport:
    """What the probe found, or why there is nothing to show."""

    ran: bool
    source: str
    nodes: tuple[NodeReport, ...]
    problem: str | None = None

    @property
    def failing(self) -> int:
        return sum(not entry.ok for node in self.nodes for entry in node.results)


def targets_from(form: Mapping[str, Any]) -> list[dict[str, Any]]:
    """What a check against this object's pool would be, per server.

    The check's own port replaces each server's traffic port where one is set,
    which is what HAProxy does. TLS follows the pool: a check to a server that
    is reached over TLS is a TLS check, and `verify: none` here means the same
    thing it means in the object - the certificate is not judged.
    """

    def text(key: str) -> str:
        return str(form.get(key, "") or "").strip()

    kind = "http" if text("health_type") == "http" else "tcp"
    tls = bool(text("backend_tls"))
    check_port = text("health_port")

    targets: list[dict[str, Any]] = []
    for line in text("servers").splitlines():
        entry = line.strip()
        if not entry:
            continue
        host, separator, port = entry.rpartition(":")
        if not separator or not port.isdigit():
            continue
        targets.append(
            {
                "host": host,
                "port": int(check_port) if check_port.isdigit() else int(port),
                "type": kind,
                "tls": tls,
                "verify": text("backend_tls") == "system",
                "path": text("health_path") or "/",
                "host_header": text("health_host"),
            }
        )
    return targets[:MAX_TARGETS]


def source_address(form: Mapping[str, Any], choices: Mapping[str, Any]) -> str:
    """The address this object leaves from, as an address rather than a name.

    An object names a source from the cluster's table, or names none and takes
    the VIP's own. The node is asked to bind exactly that, because leaving from
    a different address is the thing a firewall notices - and a probe from the
    wrong address answers a question nobody asked.
    """

    named = str(form.get("source", "") or "").strip()
    if named:
        for entry in choices.get("sources", ()):
            if entry.get("name") == named:
                return str(entry.get("address", "") or "")
        return ""
    vip = str(form.get("vip", "") or "").strip() or str(choices.get("default_vip", "") or "")
    return str((choices.get("vip_sources") or {}).get(vip, "") or "")


def _read(payload: Any) -> tuple[str, tuple[NodeReport, ...]]:
    result = payload.get("result") if isinstance(payload, Mapping) else None
    result = result if isinstance(result, Mapping) else {}
    entries = result.get("nodes")
    nodes = []
    for entry in entries if isinstance(entries, list) else ():
        if not isinstance(entry, Mapping):
            continue
        rows = entry.get("results")
        nodes.append(
            NodeReport(
                node=str(entry.get("node", "")),
                reachable=entry.get("reachable") is True,
                error=str(entry.get("error")) if entry.get("error") else None,
                source_held=(
                    entry.get("source_held") if isinstance(entry.get("source_held"), bool) else None
                ),
                results=tuple(
                    Reached(
                        host=str(row.get("host", "")),
                        port=int(row.get("port", 0) or 0),
                        ok=row.get("ok") is True,
                        status=row.get("status") if isinstance(row.get("status"), int) else None,
                        error=str(row.get("error")) if row.get("error") else None,
                        ms=row.get("ms") if isinstance(row.get("ms"), int) else None,
                    )
                    for row in (rows if isinstance(rows, list) else ())
                    if isinstance(row, Mapping)
                ),
            )
        )
    return str(result.get("source", "") or ""), tuple(nodes)


def run(
    cluster: str,
    form: Mapping[str, Any],
    choices: Mapping[str, Any],
    *,
    call: Any = None,
) -> ProbeReport:
    """One probe, and a report that says plainly when it did not happen.

    A socket nothing is listening on, an account not in its group, a policy
    without a probe identity: all of them have to read as "the probe did not
    run" rather than as a pool that failed. The two look the same to a reader
    who is only shown a red mark, so each says which it was.
    """

    targets = targets_from(form)
    if not targets:
        return ProbeReport(
            ran=False, source="", nodes=(), problem="This pool names no server to check."
        )

    request = build_request(
        cluster,
        str(uuid4()),
        targets,
        source=source_address(form, choices),
    )
    caller = call if call is not None else ask
    try:
        answer = caller(request)
    except ProbeUnavailable as unavailable:
        return ProbeReport(ran=False, source="", nodes=(), problem=str(unavailable))

    if not answer.strip():
        return ProbeReport(
            ran=False,
            source="",
            nodes=(),
            problem="The probe service answered with nothing at all.",
        )
    try:
        payload = json.loads(answer)
    except ValueError:
        return ProbeReport(
            ran=False, source="", nodes=(), problem="The probe helper did not answer with JSON."
        )

    error = payload.get("error") if isinstance(payload, Mapping) else None
    if isinstance(error, Mapping) and error.get("message"):
        return ProbeReport(ran=False, source="", nodes=(), problem=str(error["message"]))

    source, nodes = _read(payload)
    return ProbeReport(ran=True, source=source, nodes=nodes)
