"""Running the object's health check by hand, before the object is saved.

This is not a second opinion about the pool. It is the check on the screen,
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

Three things a check does that this cannot reproduce from here, and each is
said on the page rather than passed over: a tcp check's send/expect exchange,
an expected body (the node never reads a body, deliberately - a key on a proxy
node that returned one would be a way to read pages through it), and SNI, which
HAProxy's own check does not send and this does. Silence about any of them
would be the probe answering a question it was not asked.

Nothing here reaches a node, and nothing here is privileged. It builds a
request, writes it to the socket the probe service answers on, and reads what
came back. The privilege sits on the other end of that socket and stays there;
this service could not sudo if it tried, which is deliberate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any
from uuid import uuid4

from haproxy_mgmt.probe_socket import ProbeUnavailable, ask, build_request
from haproxy_mgmt.proxy_model import DEFAULT_EXPECT_STATUS, STATUS_RANGE
from haproxy_mgmt.tls_policy import (
    BACKEND_MIN_VERSION,
    DEFAULT_BACKEND_POLICY,
    DEFAULT_MIN_VERSION,
)

from haproxy_ui.preview import check_kind, check_tls

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

    @property
    def phrase(self) -> str:
        """What happened, in the words the nodes' own card uses.

        The two tables sit one above the other and describe the same check, so
        they say it the same way. `answered 200` there is `L7OK 200`
        translated; here it is what this run actually got.
        """

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


def check_is_encrypted(form: Mapping[str, Any]) -> bool:
    """Whether this object's check speaks TLS, read from the box that says so.

    The Type box carries both halves - `https` is an http check over TLS - so
    this is the same reading `build_document` makes before the generator ever
    sees it. `tcp` and `http` on a pool reached over TLS are the plaintext
    answers, which is what `no-check-ssl` says in the configuration.

    Rebuilt from the form rather than from the saved object, because that is
    the question the button exists for: what this check will do once it is
    saved.
    """

    chosen = str(form.get("health_type", "") or "").strip()
    written = check_tls(chosen, str(form.get("backend_tls", "") or "").strip())
    if written is not None:
        return written
    return bool(str(form.get("backend_tls", "") or "").strip())


def targets_from(form: Mapping[str, Any]) -> list[dict[str, Any]]:
    """What this object's check is, per server, as HAProxy would run it.

    The check's own port replaces each server's traffic port where one is set,
    which is what HAProxy does.

    Whether the check is encrypted is read from both places the generator reads
    it, because either one alone is a wrong answer. A pool reached over TLS is
    checked over TLS - inherited when the check goes to the traffic port, and
    written as `check-ssl` when a check port breaks that inheritance. On top of
    that the check has a TLS box of its own, for a plain pool whose health
    endpoint speaks TLS; that one writes `http-check connect ssl`. Reading only
    the pool's box, as this did, meant ticking the check's own box changed the
    configuration and changed nothing here.

    `verify: none` means the same thing it means in the object - the
    certificate is not judged.
    """

    def text(key: str) -> str:
        return str(form.get(key, "") or "").strip()

    kind = check_kind(text("health_type"))
    tls = check_is_encrypted(form)
    check_port = text("health_port")
    #
    # The floor the object asks for, as it stands on the screen. Taken from the
    # form rather than from what is published, for the reason the whole card
    # exists: the question is whether the check *would* work, and an unsaved
    # `legacy` is exactly the change somebody is trying to test.
    #
    policy = text("backend_tls_policy") or DEFAULT_BACKEND_POLICY
    min_version = BACKEND_MIN_VERSION.get(policy, DEFAULT_MIN_VERSION)

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
                "min_version": min_version,
            }
        )
    return targets[:MAX_TARGETS]


def accepted_status(form: Mapping[str, Any]) -> tuple[int, int]:
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

    asked = str(form.get("health_expect_status", "") or "").strip() or DEFAULT_EXPECT_STATUS
    if not STATUS_RANGE.match(asked):
        asked = DEFAULT_EXPECT_STATUS
    low, _, high = asked.partition("-")
    return int(low), int(high or low)


def caveats_for(form: Mapping[str, Any]) -> tuple[str, ...]:
    """What this run does not reproduce about the check on the screen.

    Said rather than silently passed. Each of these is a way for the probe to
    answer "Reached" where HAProxy would mark the server down, and a reader who
    is shown a green row and no sentence has been told something untrue.
    """

    def text(key: str) -> str:
        return str(form.get(key, "") or "").strip()

    notes: list[str] = []
    if check_kind(text("health_type")) == "tcp" and text("health_send"):
        notes.append(
            "The send and expect exchange is not run here. This opens the connection "
            "and stops there, so a server that answers the wrong thing still reads as reached."
        )
    if check_kind(text("health_type")) == "http" and text("health_expect_body"):
        notes.append(
            "The expected body is not checked here. The node reads the status line and "
            "no more of the answer, so a page with the wrong contents still reads as reached."
        )
    if check_is_encrypted(form):
        notes.append(
            "This sends the server name in the TLS handshake as SNI, and HAProxy's own check "
            "does not. The Host header is a different name and is sent by both. A pool that "
            "needs SNI can pass here and still be marked down on the nodes."
        )
    return tuple(notes)


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
    run" rather than as a pool that failed. The two look the same to a reader
    who is only shown a red mark, so each says which it was.
    """

    #
    # Nothing to trigger. The button runs the object's check early, and an
    # object without one has no check to run - probing anyway would answer for
    # a connection HAProxy will never make, and read as a healthy pool that is
    # in fact unchecked.
    #
    if check_kind(str(form.get("health_type", "") or "").strip()) == "disabled":
        return ProbeReport(
            ran=False,
            source="",
            nodes=(),
            problem="This object has no health check. Choose a type above, then test it.",
        )

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
    if check_kind(str(form.get("health_type", "") or "").strip()) == "http":
        nodes = _judged(nodes, accepted_status(form))
    return ProbeReport(ran=True, source=source, nodes=nodes, caveats=caveats_for(form))
