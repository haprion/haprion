"""Running the object's health check by hand, before the object is saved.

This is not a second opinion about the backend. It is the check on the screen,
triggered once from the node that would run it, so somebody configuring a check
can see the answer before pressing Save rather than after a publish. Every
divergence from what HAProxy would do is therefore a defect, not a feature -
what the form says the check is, is what gets asked.

The form is the question. What a health check would do is spelled out across
half a dozen fields - the servers, the check's type and path, its own port, the
host header, whether the check speaks TLS, what answer counts as good, and which
address the object leaves from - and every one of them changes what the node
should try. Building the request anywhere else would mean reading those fields
twice.

Two things a check does that this cannot reproduce from here, and each is said
on the page rather than passed over: a tcp check's send/expect exchange, and an
expected body (the node never reads a body, deliberately - a key on a proxy
node that returned one would be a way to read pages through it). Silence about
either would be the probe answering a question it was not asked. The TLS
handshake is HAProxy's own since 2026-09-30: no SNI, the chain verified and
the host name not, as `haprion-health-probe` on the node says.

Nothing here reaches a node, and nothing here is privileged. It builds a
request, writes it to the socket the probe service answers on, and reads what
came back. The privilege sits on the other end of that socket and stays there;
this service could not sudo if it tried, which is deliberate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from haprion.check_policy import EffectiveCheck, effective_checks
from haprion.health_probe import DEFAULT_TIMEOUT_MS, UDP_WAIT_MS
from haprion.probe_socket import ProbeUnavailable, ask, build_request
from haprion.proxy_model import (
    DEFAULT_EXPECT_STATUS,
    SENDERS_ADDRESS,
    STATUS_RANGE,
    ModelError,
    load_proxy,
)

from haprion_ui.preview import build_document

#
# The same bound the helper and the node hold. Named here so a backend with more
# servers than this is refused with a sentence instead of by whichever of the
# three happens to see it first.
#
MAX_TARGETS = 20


#
# A dns check's answer is a response code (B253), named as dnsdist and every
# resolver tool name it.
#
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass(frozen=True, slots=True)
class Reached:
    host: str
    port: int
    ok: bool
    status: int | None
    error: str | None
    ms: int | None
    dns: bool = False
    #
    # A udp check hears only a refusal (Fas 19b B5): silence is what a
    # receiver that is up sends, and is said as what it is.
    #
    udp: bool = False

    @property
    def phrase(self) -> str:
        """What happened, in the words the nodes' own card uses.

        The two tables sit one above the other and describe the same check, so
        they say it the same way. `answered 200` there is `L7OK 200`
        translated; here it is what this run actually got.
        """

        if self.udp and self.ok:
            return "not refused"
        if self.status is not None and self.dns:
            return f"answered {RCODES.get(self.status, f'code {self.status}')}"
        if self.status is not None:
            return f"answered {self.status}"
        if self.error:
            return self.error
        return "connected"


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
    #
    # Where this run is narrower than the check it stands in for. Carried with
    # the result rather than written into the page, because which ones apply
    # depends on the object: a green row under an unsaid caveat is the failure
    # this whole card exists to prevent.
    #
    caveats: tuple[str, ...] = ()
    #
    # When the nodes were asked, so the one table the card draws can say which
    # of its rows were just tried and which the nodes have been reporting.
    #
    tested_at: datetime | None = None

    @property
    def complete(self) -> bool:
        """Whether this run was the whole check or only the part it can do.

        The caveats are the answer, so this is not a second judgement: each one
        is a condition of the check that the node did not reproduce, and a run
        carrying any of them proved less than HAProxy will ask for.

        It exists because the reading is what matters. A green row saying `UP`
        beside the nodes' own `UP` reads as the same verdict, and it is not one
        - the backend may answer this and still be marked down for a body, a tcp
        exchange, or a name it was never asked for. The row says which of the
        two it is now, and the sentences below say what was left out.
        """

        return not self.caveats

    @property
    def failing(self) -> int:
        return sum(not entry.ok for node in self.nodes for entry in node.results)

    @property
    def held_by(self) -> tuple[str, ...]:
        """The nodes that carry the source address, and so could answer.

        Named rather than left implicit. Once the nodes that do not hold it are
        off the page, a single row would otherwise read as a cluster with one
        node - and which node it was is the part worth knowing, because it is
        the one carrying the VIP at this moment.

        More than one is not filtered out. Two nodes claiming the same address
        is a real thing that can happen to a keepalived pair, and hiding it here
        would be this page deciding what the reader is allowed to notice.
        """

        return tuple(node.node for node in self.nodes if node.source_held is True)


def targets_from(checks: Sequence[EffectiveCheck]) -> list[dict[str, Any]]:
    """The request, from the object's effective checks.

    Nothing is decided here any more. What the check does - its port, whether
    it speaks TLS, what the backend's certificate is held to - is decided once in
    `check_policy` and read by the generator from the same call, so the run and
    the configuration cannot disagree about what was asked for. This turns that
    answer into the field names the node's script expects, and does no more.

    Reading it from the form's fields instead is what this used to do, and it
    is how the two drifted: B92 found four fields read wrongly here, so ticking
    the check's own TLS box changed the configuration and changed nothing about
    what was probed.
    """

    return [
        {
            "host": check.host,
            "port": check.port,
            "type": check.type,
            "tls": check.encrypted,
            "verify": check.verify,
            "path": check.path or "/",
            "host_header": check.host_header or "",
            "min_version": check.min_version,
            #
            # The pool's own CA (B276): the probe trusts the file HAProxy does.
            #
            **({"ca": check.authority} if check.authority else {}),
            #
            # A dns check's question (B253); the probe helper looks a named
            # server up on the manager, as the publish does for dnsdist.
            #
            **(
                {"query_name": check.query_name or "", "query_type": check.query_type or ""}
                if check.type == "dns"
                else {}
            ),
        }
        for check in checks[:MAX_TARGETS]
    ]


def accepted_status(checks: Sequence[EffectiveCheck]) -> tuple[int, int]:
    """Which answers this check calls good, as the object states it.

    The node cannot be asked to decide this. It holds one range for every
    request it has ever been sent, and the object's is a field on the form -
    so the status comes back from the node and the verdict is reached here,
    against the same value `http-check expect status` is written from.

    An unwritten range is HAProxy's own, which is why the model's default is
    the one used rather than a number repeated here. Anything unparseable falls
    back to it too: the form is validated elsewhere and this is a report, not
    the place to refuse a document.
    """

    asked = next(
        (check.expect_status for check in checks if check.expect_status), DEFAULT_EXPECT_STATUS
    )
    if not STATUS_RANGE.match(asked):
        asked = DEFAULT_EXPECT_STATUS
    low, _, high = asked.partition("-")
    return int(low), int(high or low)


def caveats_for(checks: Sequence[EffectiveCheck]) -> tuple[str, ...]:
    """What this run does not reproduce about the check it stands in for.

    Said rather than silently passed. Each of these is a way for the probe to
    answer "Reached" where HAProxy would mark the server down, and a reader who
    is shown a green row and no sentence has been told something untrue. The
    row itself says so too, in one word - see `ProbeReport.complete` - and
    these name which conditions it means.

    Read from the effective checks and not from the form, for the reason the
    request is: a caveat about a condition the object does not actually have,
    or a missing one about a condition it does, is the same defect as probing
    the wrong port.
    """

    notes: list[str] = []
    if any(check.type == "tcp" and check.send for check in checks):
        notes.append(
            "The send and expect exchange is not run here. This opens the connection "
            "and stops there, so a server that answers the wrong thing still reads as reached."
        )
    if any(check.type == "udp" for check in checks):
        notes.append(
            "A udp check hears only a refusal. A receiver whose datagrams are dropped on the "
            "way - by a firewall, say - reads as not refused, here and in keepalived."
        )
    if any(check.type == "http" and check.expect_body for check in checks):
        notes.append(
            "The expected body is not checked here. The node reads the status line and "
            "no more of the answer, so a page with the wrong contents still reads as reached."
        )
    return tuple(notes)


def source_address(form: Mapping[str, Any], choices: Mapping[str, Any]) -> str:
    """The address this object leaves from, as an address rather than a name.

    An object names a source from the cluster's table, or names none and takes
    the VIP's own. The node is asked to bind exactly that, because leaving from
    a different address is the thing a firewall notices - and a probe from the
    wrong address answers a question nobody asked.
    """

    #
    # A syslog object leaves from none (Fas 19b B4): IPVS forwards with the
    # sender's address, and keepalived on every node checks from its own. Empty
    # here, so the editor's table is not held to the node carrying the VIP.
    #
    if str(form.get("protocol", "") or "").strip() in SENDERS_ADDRESS:
        return ""
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


def _judged(nodes: tuple[NodeReport, ...], expected: tuple[int, int]) -> tuple[NodeReport, ...]:
    """The node's answers, judged by the object's range instead of the node's.

    The node marks anything from 200 to 399 as reached, which is HAProxy's
    default and right until an object says otherwise. An object expecting 204
    was then told a 200 was fine here and watched the same server go down on
    the nodes - the one outcome this card is meant to catch before a publish.

    Only rows that carry a status are touched. A handshake that failed or a
    connection that timed out has no status to judge, and its own sentence is
    the answer.
    """

    low, high = expected
    wanted = str(low) if low == high else f"{low}-{high}"

    def row(entry: Reached) -> Reached:
        if entry.status is None:
            return entry
        ok = low <= entry.status <= high
        return replace(entry, ok=ok, error=None if ok else f"answered {entry.status}, not {wanted}")

    return tuple(
        replace(node, results=tuple(row(entry) for entry in node.results)) for node in nodes
    )


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
    run" rather than as a backend that failed. The two look the same to a reader
    who is only shown a red mark, so each says which it was.
    """

    #
    # The object as it stands on the screen, read by the engine. Unsaved on
    # purpose - the question is whether the check *would* work, and the change
    # somebody is testing has not been saved yet - but read the same way a
    # publish would read it, so the check that runs is the check that would be
    # written.
    #
    try:
        proxy = load_proxy(
            str(form.get("name", "") or "").strip() or "object",
            build_document(dict(form)).encode(),
        )
    except (ValueError, ModelError) as refusal:
        #
        # Not a backend that failed. An object this version cannot read has no
        # check to run, and probing an approximation of it would answer for a
        # connection HAProxy will never make.
        #
        return ProbeReport(
            ran=False,
            source="",
            nodes=(),
            problem=f"This object cannot be read as written, so its check cannot be run: {refusal}",
        )

    checks = effective_checks(proxy)
    #
    # Nothing to trigger. The button runs the object's check early, and an
    # object without one has no check to run - probing anyway would answer for
    # a connection HAProxy will never make, and read as a healthy backend that is
    # in fact unchecked.
    #
    if not any(check.runs for check in checks):
        return ProbeReport(
            ran=False,
            source="",
            nodes=(),
            problem="This object has no health check. Choose a type above, then test it.",
        )

    targets = targets_from(checks)
    if not targets:
        return ProbeReport(
            ran=False, source="", nodes=(), problem="This backend names no server to check."
        )

    request = build_request(
        cluster,
        str(uuid4()),
        targets,
        source=source_address(form, choices),
        #
        # keepalived's wait for a refusal, so a host that is gone is said
        # here as it will be there (Fas 19b B5).
        #
        timeout_ms=(
            UDP_WAIT_MS if any(check.type == "udp" for check in checks) else DEFAULT_TIMEOUT_MS
        ),
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
    if any(check.type == "http" for check in checks):
        nodes = _judged(nodes, accepted_status(checks))
    if any(check.type == "udp" for check in checks):
        nodes = tuple(
            replace(node, results=tuple(replace(entry, udp=True) for entry in node.results))
            for node in nodes
        )
    if any(check.type == "dns" for check in checks):
        nodes = tuple(
            replace(node, results=tuple(replace(entry, dns=True) for entry in node.results))
            for node in nodes
        )
    return ProbeReport(
        ran=True,
        source=source,
        nodes=nodes,
        caveats=caveats_for(checks),
        tested_at=datetime.now(UTC),
    )
