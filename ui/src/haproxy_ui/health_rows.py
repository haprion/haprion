"""One table for a backend's health: what the nodes report, and what was just tried.

The editor used to draw two. HAProxy's own verdict from the nodes, and below
or above it what the nodes answered when somebody pressed Test health check -
the same servers, the same columns, twice. To the reader they are one question,
"is this pool answering", and the second table read as a second opinion rather
than as the first one asked again (2026-09-30).

So a test writes its answers into the rows the nodes report: a server the test
reached shows what the test got, marked as tested, and one the nodes do not
know yet - a check never deployed, a server just typed - gets a row of its own.
The next reading from the poller takes the rows back. What the test could not
reproduce is said under the table, not in the colour of a row.
"""

from __future__ import annotations

from dataclasses import dataclass

from haproxy_ui.health import BackendHealth, check_phrase
from haproxy_ui.probe import ProbeReport


@dataclass(frozen=True, slots=True)
class HealthRow:
    node: str
    server: str
    #
    # None for a node that could not be asked at all: the row then carries the
    # reason in `state` and has no server to name.
    #
    up: bool | None
    state: str
    last: str
    code: str = ""
    tested: bool = False


def _duration(ms: int | None) -> str:
    return f" · {ms} ms" if ms is not None else ""


def health_rows(backend: BackendHealth | None, probe: ProbeReport | None) -> list[HealthRow]:
    rows: dict[tuple[str, str], HealthRow] = {}
    if backend is not None and backend.known:
        for node in backend.nodes:
            for member in node.members:
                server = backend.address(member.server) or member.server
                code = " ".join(part for part in (member.check_status, member.check_code) if part)
                rows[(node.node, server)] = HealthRow(
                    node=node.node,
                    server=server,
                    up=member.up,
                    state=member.status or "unknown",
                    last=(check_phrase(member.check_status or "", member.check_code or "") or "—")
                    + _duration(member.check_duration_ms),
                    code=code,
                )
    if probe is not None and probe.ran:
        for report in probe.nodes:
            #
            # A node without the source address tried nothing; its row is the
            # nodes' own and stays as it was.
            #
            if report.source_held is False:
                continue
            if not report.reachable or report.error:
                rows[(report.node, "")] = HealthRow(
                    node=report.node,
                    server="",
                    up=None,
                    state=report.error or "The node could not be reached",
                    last="",
                    tested=True,
                )
                continue
            for entry in report.results:
                server = f"{entry.host}:{entry.port}"
                rows[(report.node, server)] = HealthRow(
                    node=report.node,
                    server=server,
                    up=entry.ok,
                    state="UP" if entry.ok else "DOWN",
                    last=f"{entry.phrase}{_duration(entry.ms)} · tested",
                    tested=True,
                )
    return list(rows.values())
