"""The reconcile loop: observe, decide, act, verify, observe again.

Everything that touches the world enters through two callables - read the
cluster status, trigger one node - and nothing else here runs a command or opens
a connection. That is what lets the whole loop, including every failure branch,
be driven by a harness instead of by a real pair of nodes.

The shape of the loop is the plan's, not a convenience:

  * the status is re-read after EVERY mutation, and the order is re-decided from
    what came back. Verifying only the node that was just touched is explicitly
    not enough
  * a node that reports success is not believed on its word. When the target is
    known, the re-read has to show the node actually running it, and a node that
    reports success while still running the old release is a failure
  * a hard failure on one node stops before the next is touched
  * the run ends in exactly one of four outcomes, and both the exit code and the
    JSON result follow the outcome rather than the last thing that happened

Why the whole loop belongs on one side of the privilege boundary
----------------------------------------------------------------
Publishing splits cleanly - the caller previews, root writes once. Deploy does
not: it is privileged read, decide, privileged mutate, privileged read, decide
again. Split per step, an operator would be asked for a password several times
in the middle of a rollout, which is both worse to operate and worse for safety,
because the tempting fix is a blanket NOPASSWD rule. So the loop runs as one
privileged unit and streams its progress out, and the caller stays thin.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TextIO

from haprion import exit_codes
from haprion.cluster_status import ClusterStatus, NodeStatus, StatusError
from haprion.deploy_plan import (
    NOTHING_DONE,
    Action,
    CertificateTarget,
    Outcome,
    Progress,
    Step,
    Target,
    VipState,
    certificate_gaps,
    next_step,
    record,
    served_nothing,
    unverified_certificates,
    warnings_for,
)
from haprion.envelope import Message, envelope
from haprion.helper_protocol import Lifeline

type ReadStatus = Callable[[], ClusterStatus]
type TriggerNode = Callable[[NodeStatus], int]

#
# The default operation name in the envelope. Certificate runs pass their own:
# the loop is shared, the two frozen contracts are not, and a cert_deploy result
# that announced itself as a deploy would validate against the wrong schema.
#
OPERATION = "deploy"
CERT_OPERATION = "cert_deploy"


@dataclass
class NodeReport:
    """One node's line in the result, in the shape the frozen contract wants."""

    name: str
    reachable: bool
    current_before: bool | None
    action: str = "none"
    outcome: str = "not_attempted"
    verified: bool = False
    error: Message | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "reachable": self.reachable,
            "current_before": self.current_before,
            "action": self.action,
            "outcome": self.outcome,
            "verified": self.verified,
            "error": self.error.as_dict() if self.error is not None else None,
        }


@dataclass
class DeployReport:
    """What happened, assembled as it happens rather than reconstructed."""

    target: Target | None
    override_used: bool
    initial_summary: Mapping[str, Any]
    operation: str = OPERATION
    final_summary: Mapping[str, Any] | None = None
    nodes: dict[str, NodeReport] = field(default_factory=dict)
    warnings: list[Message] = field(default_factory=list)
    error: Message | None = None
    outcome: Outcome = Outcome.DONE

    def result(self) -> dict[str, Any] | None:
        if self.target is None:
            return None
        return {
            **self.target.result_fields(),
            "converged": self.outcome is Outcome.DONE,
            "override_used": self.override_used,
            "initial_summary": dict(self.initial_summary),
            "final_summary": dict(self.final_summary) if self.final_summary is not None else None,
            "nodes": [report.as_dict() for report in self.nodes.values()],
        }

    def as_envelope(self, cluster: str | None, *, request_id: str | None = None) -> dict[str, Any]:
        """The frozen `haprion-deploy` envelope.

        A partial run must carry at least one warning and a blocked or failed one
        must carry an error; the envelope helper enforces both, so an incomplete
        report fails here rather than reaching a reader as a valid-looking lie.
        """

        warnings = tuple(self.warnings)
        error = self.error
        #
        # A block or a released caller after a node already carries the target
        # is partial, and partial carries no top-level error: the reason is
        # named among the warnings instead (review 2026-10-24).
        #
        if self.outcome is Outcome.PARTIAL and error is not None:
            warnings = (*warnings, error)
            error = None
        if self.outcome is Outcome.PARTIAL and not warnings:
            warnings = (
                Message(
                    code="cluster_not_converged",
                    message="the cluster was not fully reconciled",
                ),
            )
        return envelope(
            operation=self.operation,
            outcome=self.outcome.value,
            cluster=cluster,
            result=self.result(),
            request_id=request_id,
            warnings=warnings,
            error=error,
        )


@dataclass(frozen=True, slots=True)
class DeployRun:
    exit_code: int
    report: DeployReport


#
# The error code a configuration deploy blocks with when a readable node does
# not carry the certificates the release references. Named here because the
# jobs page reads it back: it is the one refusal the interface can offer to fix
# with a button, and the two sides have to agree on the string.
#
CERTIFICATES_NOT_DEPLOYED = "certificates_not_deployed"


@dataclass(frozen=True, slots=True)
class CertificatePreflight:
    """What a configuration deploy checks the nodes against before it starts.

    `target` is the cluster's referenced certificates as the manager published
    them - the same object `cert-deploy` reconciles towards, so the two commands
    cannot disagree about what "the node has the certificate" means. It is None
    when the manager has no certificate root to read them from; the check is
    then not made, and the run says so instead of staying quiet about it.
    `referenced` is the IDs by name, for that warning. `next_command` is what
    the refusal tells the operator to run; the loop does not know the cluster's
    name and should not have to.
    """

    target: CertificateTarget | None
    referenced: tuple[str, ...]
    next_command: str


def _state_line(prefix: str, status: ClusterStatus) -> str:
    owners = ", ".join(status.vip_owners) if status.vip_owners else "-"
    usable = sum(1 for node in status.nodes if node.status_ok)
    return (
        f"{prefix}: VIP={status.vip_state.value}, "
        f"owner={owners}, status={usable}/{len(status.nodes)}\n"
    )


def _initial_reports(status: ClusterStatus, target: Target | None) -> dict[str, NodeReport]:
    """Every configured node starts in the result, before anything is done.

    A node that is never touched still belongs in the answer - "not attempted"
    is information, and a result that simply omits it reads as if the cluster
    had fewer nodes than it has.
    """

    reports: dict[str, NodeReport] = {}
    observed = {node.name: node for node in status.observation().nodes}
    for node in status.nodes:
        #
        # Unknown rather than False when there is nothing to compare against:
        # no target given, a node whose status could not be read, or a target
        # the node did not answer about.
        #
        current = (
            None if target is None or not node.status_ok else target.is_current(observed[node.name])
        )
        reports[node.name] = NodeReport(
            name=node.name,
            reachable=node.reachable,
            current_before=current,
            outcome="unavailable" if not node.status_ok else "not_attempted",
            error=None
            if node.status_ok
            else Message(
                code=node.error_code or "node_status_unavailable",
                message="node status is unavailable",
                node=node.name,
            ),
        )
    return reports


@dataclass(frozen=True, slots=True)
class Budget:
    """The whole run's time, and what one node and one reading may take of it (6-9).

    Each step had its own limit and none had the run's: a trigger of 300 s a
    node, one after the other, and waits of fifteen readings of up to 60 s,
    went past the worker's 900 s while every step was within its own - and
    the job read `unknown` while the helper carried on (review 2026-10-22,
    6-9; logic review L4 for the backup). Within this the run answers itself:
    a node it has no time left for is named, not started.
    """

    seconds: float
    node_step: float
    reading: float


def run(
    read_status: ReadStatus,
    trigger: TriggerNode,
    writer: TextIO,
    *,
    target: Target | None = None,
    allow_vip_unknown: bool = False,
    operation: str = OPERATION,
    lifeline: Lifeline | None = None,
    preflight: CertificatePreflight | None = None,
    pause: Callable[[float], None] = time.sleep,
    budget: Budget | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> DeployRun:
    """Reconcile the cluster and report, in text as it goes and in a result.

    `preflight` is the certificate check a configuration deploy runs once, after
    the first status read and before any node is touched. It is given rather
    than derived because the loop is shared with `cert-deploy`, which is the
    command that fixes what the check finds and must not be blocked by it.
    """

    deadline = clock() + budget.seconds if budget is not None else None

    def time_left() -> float:
        return deadline - clock() if deadline is not None else float("inf")

    reading = budget.reading if budget is not None else 0.0

    try:
        status = read_status()
    except StatusError as exc:
        report = DeployReport(
            target=target,
            override_used=allow_vip_unknown,
            initial_summary={},
            operation=operation,
            outcome=Outcome.BLOCKED,
            error=Message(code="status_unavailable", message=str(exc)),
        )
        writer.write(f"ERROR: {exc}\n")
        # The exit the outcome is, not the reading's: `blocked` beside 68 was
        # refused when the envelope was written (review 26-10-24, 06-04).
        return DeployRun(exit_codes.BLOCKED, report)

    report = DeployReport(
        target=target,
        override_used=allow_vip_unknown,
        initial_summary=status.summary,
        operation=operation,
        nodes=_initial_reports(status, target),
    )
    writer.write(_state_line("Initial status", status))

    progress = NOTHING_DONE
    announced: tuple[str, ...] = ()
    first_deploy = served_nothing(status.observation())
    certificates_checked = preflight is None

    while True:
        #
        # The checkpoint. Asked before a step is chosen, which is the only place
        # in this loop where what has happened and what has not are both known
        # exactly: every node is either handled or untouched, and none is
        # half-handled. Stopping here therefore produces a state the contract
        # already has a word for, rather than the arbitrary instant a signal
        # would have produced.
        #
        if lifeline is not None and lifeline.released:
            _settle(status, report, target)
            return _released(writer, status, report, progress, lifeline.reason)

        #
        # Warnings are statements about the cluster, so they are printed when
        # they change rather than once at the start or once per step. A picture
        # that becomes worse mid-run must say so; one that stays the same must
        # not repeat itself into noise.
        #
        warnings = warnings_for(
            status.observation(),
            allow_vip_unknown=allow_vip_unknown,
            nothing_served=first_deploy,
        )
        if warnings != announced:
            writer.write("\n")
            for warning in warnings:
                writer.write(f"WARNING: {warning}\n")
                report.warnings.append(Message(code="cluster_state", message=warning))
            announced = warnings

        step = next_step(
            status.observation(),
            progress,
            target=target,
            allow_vip_unknown=allow_vip_unknown,
        )

        if step.action is Action.BLOCKED:
            return _blocked(writer, status, step, report, target)

        #
        # After the cluster-wide blocks and before the first node. Split brain
        # and an unreadable cluster are the graver faults and the ones with
        # nothing to press, so they are what the operator hears about first;
        # a missing certificate is only worth naming once the cluster is in a
        # state where fixing it would let the deploy through.
        #
        if not certificates_checked:
            certificates_checked = True
            assert preflight is not None  # noqa: S101 - the flag starts true without one
            blocked = _certificate_preflight(writer, status, report, preflight)
            if blocked is not None:
                return blocked

        if step.action is Action.FINISHED:
            if any(entry.outcome == "updated" for entry in report.nodes.values()):
                try:
                    status = _await_vip_owner(
                        status,
                        read_status,
                        writer,
                        report,
                        pause,
                        lambda: time_left() > reading,
                    )
                except StatusError as exc:
                    writer.write(f"\nERROR: {exc}\n")
                    writer.write(
                        "The nodes were deployed, but the cluster could not be read while "
                        "waiting for a node to take the VIP.\n"
                    )
                    report.outcome = Outcome.FAILED
                    report.error = Message(code="status_unavailable", message=str(exc))
                    _settle(status, report, target)
                    return DeployRun(exc.exit_code, report)
                #
                # Judged again on the reading the wait ended with: a node that
                # went back to its old release meanwhile is not converged
                # (review 26-10-24, 13-03). The VIP's own state is said by the
                # final status, as the wait's docstring has it, not judged here.
                #
                again = next_step(
                    status.observation(),
                    progress,
                    target=target,
                    allow_vip_unknown=allow_vip_unknown,
                )
                if again.action is Action.FINISHED:
                    step = again
                elif again.action is Action.BLOCKED:
                    #
                    # Split brain, or a VIP nobody holds, when the wait ended:
                    # what a reading before the first node is refused on is no
                    # done after the last (review 26-10-25, 13-03).
                    #
                    return _blocked(writer, status, again, report, target)
            _settle(status, report, target)
            return DeployRun(_report(writer, status, step, report), report)

        if step.action is Action.SKIP:
            writer.write(f"\n{step.reason}.\n")
            _record_skip(report, step)
            progress = record(progress, step)
            continue

        node_name = step.node
        if node_name is None:
            #
            # Unreachable by construction - a deploy step always names a node -
            # and stated rather than assumed, because a silent fallback here
            # would deploy nothing while reporting success.
            #
            raise RuntimeError("a deploy step must name a node")

        if budget is not None and time_left() < budget.node_step:
            _settle(status, report, target)
            return _out_of_time(writer, status, report, node_name, budget)

        writer.write(f"\n=== Deploy: {node_name} ===\n")
        code = trigger(status.node(node_name))
        entry = report.nodes[node_name]
        entry.action = "deploy"

        #
        # Mandatory, and mandatory even when the trigger failed: the failure has
        # already changed the cluster, and reporting a state from before it would
        # describe something that is no longer true.
        #
        try:
            status = read_status()
        except StatusError as exc:
            writer.write(f"\nERROR: {exc}\n")
            writer.write(
                f"The deploy of {node_name} finished with exit {code}, "
                "but the cluster could not be read afterwards.\n"
            )
            # Attempted either way; whether it took is what could not be read.
            entry.outcome = "failed"
            entry.error = Message(code="status_unavailable", message=str(exc), node=node_name)
            report.outcome = Outcome.FAILED
            report.error = Message(code="status_unavailable", message=str(exc))
            return DeployRun(exc.exit_code, report)

        writer.write(_state_line("Post-deploy status", status))

        landed = _verify(status, node_name, target)
        if code == 0 and landed is None and target is not None:
            status, landed = _await_node(
                status,
                node_name,
                target,
                read_status,
                writer,
                pause,
                lambda: time_left() > reading,
                clock,
            )
            if landed is None and not _readable(status, node_name):
                return _node_lost(writer, status, report, node_name, target)
        failed = code != 0 or landed is False
        progress = record(progress, step, failed=failed)

        if code != 0:
            entry.outcome = "failed"
            #
            # Said when the reading afterwards shows the node on the target
            # anyway: the failure is then in what it did besides, and the
            # operator should not go looking for a release that did not land.
            #
            runs_target = " (the node nonetheless runs the target release)" if landed else ""
            entry.error = Message(
                code="trigger_failed",
                message=f"the deploy trigger failed with exit {code}{runs_target}",
                node=node_name,
            )
            writer.write(
                f"\nERROR: the deploy trigger failed on {node_name} with exit {code}"
                f"{runs_target}.\n"
                "The status was read again and the remaining nodes were not touched.\n"
            )
        elif landed is False:
            #
            # Reported success and is still not running the target. Believing the
            # exit code here would mark a node updated that never changed, and
            # the next command would be run against a cluster nobody knows the
            # true state of.
            #
            entry.outcome = "failed"
            entry.error = Message(
                code="target_not_reached",
                message="the node reported success but is not running the target release",
                node=node_name,
            )
            writer.write(
                f"\nERROR: {node_name} reported success but is not running the target release.\n"
                "The remaining nodes were not touched.\n"
            )
        else:
            entry.outcome = "updated"
            entry.verified = bool(landed)
            try:
                status = _await_peers(
                    status,
                    node_name,
                    read_status,
                    writer,
                    report,
                    pause,
                    lambda: time_left() > reading,
                )
            except StatusError as exc:
                #
                # The next node would otherwise be chosen from the reading
                # before this one failed - possibly the VIP owner, touched by a
                # manager that has just lost sight of the cluster (review
                # 26-10-13, L1). Stopped as the reading after a trigger is.
                #
                writer.write(f"\nERROR: {exc}\n")
                writer.write(
                    f"{node_name} was deployed, but the cluster could not be read while "
                    "waiting for its peers. The remaining nodes were not touched.\n"
                )
                report.outcome = Outcome.FAILED
                report.error = Message(code="status_unavailable", message=str(exc))
                return DeployRun(exc.exit_code, report)


#
# How long, on the clock, a node that answered 0 to its deploy and then cannot be
# read is waited for (review 26-10-30, D2). A reading of a node that is down costs
# its connect timeout and one of a node that hangs far more, so the limit is time
# and not a count of readings. A node that is slow to answer after a heavy reload
# gets this; one that does not come back stops the rollout,
# because the next node may be the VIP owner and the release is then the likely
# reason the last one went silent.
#
NODE_WAIT_SECONDS = 30


def _readable(status: ClusterStatus, node_name: str) -> bool:
    return any(node.name == node_name and node.status_ok for node in status.observation().nodes)


def _await_node(
    status: ClusterStatus,
    node_name: str,
    target: Target,
    read_status: ReadStatus,
    writer: TextIO,
    pause: Callable[[float], None],
    may_read: Callable[[], bool],
    clock: Callable[[], float],
) -> tuple[ClusterStatus, bool | None]:
    """The status, and whether the node landed, once it can be read again or the wait ends.

    Waited only while the node cannot be read: one that answers is judged on
    its answer as it always was. A reading that fails altogether counts as the
    node not answering; the next full reading decides what the run does about
    the cluster.
    """

    writer.write(f"{node_name} cannot be read after its deploy; waiting for it...\n")
    wait_end = clock() + NODE_WAIT_SECONDS
    while not _readable(status, node_name) and may_read() and clock() < wait_end:
        pause(1.0)
        try:
            status = read_status()
        except StatusError:
            continue
    return status, _verify(status, node_name, target)


def _node_lost(
    writer: TextIO,
    status: ClusterStatus,
    report: DeployReport,
    node_name: str,
    target: Target | None,
) -> DeployRun:
    """The deployed node stayed unreadable: stop before the next node can be touched.

    The remaining nodes may include the VIP owner, and a release that has just
    made one node go silent is not one to put on it too.
    """

    others_waiting = any(
        entry.outcome == "not_attempted"
        for name, entry in report.nodes.items()
        if name != node_name
    )
    message = f"{node_name} could not be read after its deploy" + (
        "; the remaining nodes were not touched" if others_waiting else ""
    )
    writer.write(f"\nERROR: {message}.\n")
    entry = report.nodes[node_name]
    entry.outcome = "failed"
    entry.error = Message(code="node_lost_after_deploy", message=message, node=node_name)
    _settle(status, report, target)
    report.final_summary = status.summary
    report.outcome = Outcome.PARTIAL
    report.warnings.append(Message(code="node_lost_after_deploy", message=message, node=node_name))
    return DeployRun(exit_codes.PARTIAL, report)


#
# How long a node that has just reloaded is given to reach the nodes it shares
# its tables with before the next one is touched (B270). It takes its counts
# back from them on connecting, and HAProxy retries a peer every five seconds
# (measured on 3.4.6: back after 5.3 s). Reloading the next node before then
# would leave neither with the counts.
#
PEERS_WAIT_SECONDS = 15


def _unconnected_peers(status: ClusterStatus, node_name: str) -> list[str]:
    """The peers of one node it is not connected to that report sharing themselves."""

    sharing = {node.name for node in status.nodes if node.peers}
    return [
        name
        for name, connected in status.node(node_name).peers or ()
        if not connected and name in sharing
    ]


def _await_peers(
    status: ClusterStatus,
    node_name: str,
    read_status: ReadStatus,
    writer: TextIO,
    report: DeployReport,
    pause: Callable[[float], None],
    may_read: Callable[[], bool] = lambda: True,
) -> ClusterStatus:
    """The status once the deployed node is connected to its peers, or after the wait.

    Only a peer that shares itself is waited for: one still on a release
    without `peers` - the other node, the first time sharing is turned on - or
    one that could not be read has nothing to connect to, and waiting for it
    only delayed the rollout and warned about nothing (review 26-10-10, F2).
    One that has not connected when the wait ends is named and the deploy goes
    on: the counts are a convenience, and holding a rollout for them would
    trade the release for them.

    A reading that fails is raised, not waited out: what comes next is
    another node, and it is chosen from the status returned here.
    """

    for _ in range(PEERS_WAIT_SECONDS):
        waiting = _unconnected_peers(status, node_name)
        if not waiting or not may_read():
            break
        pause(1.0)
        status = read_status()
    waiting = _unconnected_peers(status, node_name)
    if waiting:
        warning = (
            f"{node_name} has not reached {', '.join(waiting)} to share counters; "
            f"they were not shared within {PEERS_WAIT_SECONDS} s"
        )
        writer.write(f"WARNING: {warning}\n")
        report.warnings.append(Message(code="counters_not_shared", message=warning, node=node_name))
    return status


#
# How long a deploy that ends with no VIP owner waits for one (Fas 18,
# 26-10-16). Every node starts keepalived as BACKUP with `nopreempt`, so the
# first deploy - the one that starts it - ends before any node has stopped
# listening for a MASTER: about three advertisement intervals and the skew, a
# few seconds. Read then, the cluster says the VIP is down, and so did the
# dashboard, woken by the finished job.
#
VIP_WAIT_SECONDS = 15


def _await_vip_owner(
    status: ClusterStatus,
    read_status: ReadStatus,
    writer: TextIO,
    report: DeployReport,
    pause: Callable[[float], None],
    may_read: Callable[[], bool] = lambda: True,
) -> ClusterStatus:
    """The status once a node owns the VIP, or after the wait.

    Only `no_owner` is waited out: split brain, unknown and an unreadable node
    are not what a starting keepalived looks like, and the final status says
    them as they are. One that still has no owner when the wait ends is named
    and the deploy ends as it would have.
    """

    for _ in range(VIP_WAIT_SECONDS):
        if status.vip_state is not VipState.NO_OWNER or not may_read():
            break
        pause(1.0)
        status = read_status()
    if status.vip_state is VipState.NO_OWNER:
        warning = f"no node took the VIP within {VIP_WAIT_SECONDS} s of the deploy"
        writer.write(f"WARNING: {warning}\n")
        report.warnings.append(Message(code="vip_not_owned", message=warning))
    return status


def _out_of_time(
    writer: TextIO, status: ClusterStatus, report: DeployReport, node_name: str, budget: Budget
) -> DeployRun:
    """The run stopped before a node it had no time left for; the nodes before it stand."""

    message = (
        f"{node_name} was not started: less than {int(budget.node_step)} s of the deploy's "
        f"{int(budget.seconds)} s was left. Run the same command again to deploy the rest."
    )
    writer.write(f"\nERROR: {message}\n")
    entry = report.nodes[node_name]
    entry.outcome = "not_attempted"
    entry.error = Message(code="deploy_budget_exhausted", message=message, node=node_name)
    report.final_summary = status.summary
    #
    # Touched as `_released` counts it: a node deployed and then not readable
    # is `failed` after `_settle`, and still not a cluster left as it was.
    #
    if any(node.outcome in ("updated", "failed") for node in report.nodes.values()):
        report.outcome = Outcome.PARTIAL
        report.warnings.append(Message(code="deploy_budget_exhausted", message=message))
        return DeployRun(exit_codes.PARTIAL, report)
    report.outcome = Outcome.BLOCKED
    report.error = Message(code="deploy_budget_exhausted", message=message)
    return DeployRun(exit_codes.BLOCKED, report)


def _certificate_preflight(
    writer: TextIO, status: ClusterStatus, report: DeployReport, preflight: CertificatePreflight
) -> DeployRun | None:
    """Block before the first node if a readable node lacks a referenced certificate.

    Once, not before every step: the check is about whether the release can be
    activated at all, and a certificate does not appear on a node in the middle
    of a configuration rollout. Re-checking after each node would only turn a
    result that is already known into a later one.

    A node that said nothing about certificates is warned about and let through.
    The loop treats that silence as "unverified" everywhere else, and a
    preflight that read it as "missing" would refuse every deploy against a
    node whose status script predates the field - a refusal nobody could act on.
    """

    if preflight.target is None:
        warning = (
            f"no certificate root is configured; {', '.join(preflight.referenced)} "
            "not checked on the nodes"
        )
        writer.write(f"WARNING: {warning}\n")
        report.warnings.append(Message(code="certificates_unchecked", message=warning))
        return None

    if not preflight.target.certificates and not preflight.target.authorities:
        #
        # Nothing referenced, nothing to be behind on. Warning about nodes
        # that did not report certificates would then be noise about a
        # question nobody asked.
        #
        return None

    observation = status.observation()
    gaps = certificate_gaps(observation, preflight.target)
    if gaps:
        named = "; ".join(gap.describe() for gap in gaps)
        reason = (
            f"referenced certificates are not on every node: {named}. "
            f"Run {preflight.next_command} first, then deploy again"
        )
        writer.write(f"\nERROR: [{CERTIFICATES_NOT_DEPLOYED}] {reason}\n")
        report.outcome = Outcome.BLOCKED
        report.final_summary = status.summary
        report.error = Message(
            code=CERTIFICATES_NOT_DEPLOYED,
            message=reason,
            details={
                "nodes": [gap.as_dict() for gap in gaps],
                "next_command": preflight.next_command,
            },
        )
        return DeployRun(exit_codes.BLOCKED, report)

    for name, what in unverified_certificates(observation, preflight.target):
        warning = f"{name} did not report its {what}; they were not checked"
        writer.write(f"WARNING: {warning}\n")
        report.warnings.append(Message(code="certificates_unverified", message=warning, node=name))
    return None


def _released(
    writer: TextIO,
    status: ClusterStatus,
    report: DeployReport,
    progress: Progress,
    reason: str,
) -> DeployRun:
    """Stop because the caller let go, and say so in the report.

    `blocked` when no node was touched: nothing happened, the cluster is as it
    was found, and the job needs a person rather than a retry. `partial` once
    anything was deployed - some nodes carry the target and some do not, which
    is exactly what partial has always meant here.

    Never `failed`. Nothing failed. The caller stopped waiting, and a report
    that blamed the cluster for that would send the next reader looking for a
    fault that is not there.
    """

    writer.write("\n")
    writer.write(_state_line("Final status", status))
    report.final_summary = status.summary

    touched = bool(progress.deployed or progress.failed)
    report.outcome = Outcome.PARTIAL if touched else Outcome.BLOCKED
    report.error = Message(code="caller_released", message=reason)

    writer.write(
        f"\nRESULT: {report.outcome.value.upper()}  [{report.error.code}]\n"
        f"{reason}; stopped at a safe point.\n"
    )
    if touched:
        writer.write("Some nodes carry the target and some do not. Run the same command again.\n")
        return DeployRun(exit_codes.PARTIAL, report)
    writer.write("No node was touched.\n")
    return DeployRun(exit_codes.BLOCKED, report)


def _verify(status: ClusterStatus, node_name: str, target: Target | None) -> bool | None:
    """Did the node land on the target? None when it cannot be told.

    Cannot be told covers three cases that are all honest: no target was given,
    so there is nothing to compare against; the node stopped answering, so the
    answer is unknown rather than negative; and the node answered without
    mentioning what the target asks about.
    """

    if target is None:
        return None
    try:
        status.node(node_name)
    except StatusError:
        return None
    for node in status.observation().nodes:
        if node.name == node_name:
            return None if not node.status_ok else target.is_current(node)
    return None


def _settle(status: ClusterStatus, report: DeployReport, target: Target | None) -> None:
    """The node lines from the last reading, as the outcome is (CR-08).

    A deployed node is verified against the same reading the run's outcome is
    judged on: one that could not be read just after its deploy is verified now
    if it can be, and one that no longer runs the target is not called updated.
    A node skipped as current stays as it was found, as the contract has it;
    a warning says it moved since.
    """

    if target is None:
        return
    observed = {node.name: node for node in status.observation().nodes}
    for name, entry in report.nodes.items():
        node = observed.get(name)
        if node is None or entry.outcome not in ("current", "updated"):
            continue
        current = target.is_current(node) if node.status_ok else None
        if entry.outcome == "updated":
            if current is True:
                entry.verified = True
            elif current is False:
                entry.outcome, entry.verified = "failed", False
                entry.error = Message(
                    code="target_not_reached",
                    message="the node is not running the target at the end of the run",
                    node=name,
                )
            elif not entry.verified:
                entry.outcome = "failed"
                entry.error = Message(
                    code="node_unverified",
                    message="the node could not be read after its deploy; whether it runs "
                    "the target is unknown",
                    node=name,
                )
        if current is False and entry.outcome == "failed":
            report.warnings.append(
                Message(
                    code="target_not_reached",
                    message=f"{name} is not running the target at the end of the run",
                    node=name,
                )
            )
        elif current is False:
            report.warnings.append(
                Message(
                    code="target_not_reached",
                    message=f"{name} was current when it was passed over and is not any more",
                    node=name,
                )
            )
        elif entry.outcome == "failed":
            report.warnings.append(
                Message(
                    code="node_unverified",
                    message=f"{name} could not be read after its deploy",
                    node=name,
                )
            )


def _record_skip(report: DeployReport, step: Step) -> None:
    if step.node is None:
        return
    entry = report.nodes[step.node]
    entry.action = "skip"
    if step.warnings:
        entry.outcome = "unavailable"
        report.warnings.append(
            Message(code="node_unverified", message=step.warnings[0], node=step.node)
        )
    else:
        entry.outcome = "current"
        entry.verified = True


def _blocked(
    writer: TextIO, status: ClusterStatus, step: Step, report: DeployReport, target: Target | None
) -> DeployRun:
    """A reading the deploy may not go on from, before the first node or after the last."""

    writer.write(f"\nERROR: {step.reason}\n")
    # Partial when a node was deployed before the block; see next_step.
    report.outcome = step.outcome or Outcome.BLOCKED
    report.final_summary = status.summary
    report.error = Message(code="deploy_blocked", message=step.reason)
    if step.outcome is Outcome.PARTIAL:
        writer.write(
            "Some nodes carry the target and some do not. "
            "Run the same command again once the cluster allows it.\n"
        )
    _settle(status, report, target)
    return DeployRun(step.exit_code, report)


def _report(writer: TextIO, status: ClusterStatus, step: Step, report: DeployReport) -> int:
    writer.write("\n")
    writer.write(_state_line("Final status", status))
    report.final_summary = status.summary

    if step.outcome is Outcome.DONE:
        report.outcome = Outcome.DONE
        writer.write("\nRESULT: OK\n")
        return 0

    #
    # The stable code is written beside the prose from here on, because it is
    # what the jobs page and the audit trail record. A person comparing what
    # their terminal said with what the interface says should not have to guess
    # that "one node did not reach the target" and `target_not_reached` are the
    # same event. Added 2026-08-31 as F1b.
    #
    if step.outcome is Outcome.FAILED:
        report.outcome = Outcome.FAILED
        report.error = Message(code="deploy_failed", message=step.reason)
        writer.write(f"\nRESULT: FAILED  [{report.error.code}]\n{step.reason}.\n")
        return step.exit_code

    report.outcome = Outcome.PARTIAL
    #
    # Partial carries warnings rather than one top-level error, so the codes are
    # the warnings' - listed rather than invented, and skipped entirely when
    # there are none, so this never prints an empty pair of brackets.
    #
    codes = sorted({warning.code for warning in report.warnings})
    suffix = f"  [{', '.join(codes)}]" if codes else ""
    writer.write(f"\nRESULT: PARTIAL{suffix}\n{step.reason}.\n")
    writer.write("Run the same command again once every node can be read.\n")
    return exit_codes.PARTIAL
