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

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TextIO

from haproxy_mgmt.cluster_status import ClusterStatus, NodeStatus, StatusError
from haproxy_mgmt.deploy_plan import (
    NOTHING_DONE,
    Action,
    Outcome,
    Step,
    Target,
    next_step,
    record,
    warnings_for,
)
from haproxy_mgmt.envelope import Message, envelope

type ReadStatus = Callable[[], ClusterStatus]
type TriggerNode = Callable[[NodeStatus], int]

#
# The default operation name in the envelope. Certificate runs pass their own:
# the loop is shared, the two frozen contracts are not, and a cert_deploy result
# that announced itself as a deploy would validate against the wrong schema.
#
OPERATION = "deploy"
CERT_OPERATION = "cert_deploy"

#
# A stop that is not a refusal: the run did what it could and something is left
# for a human to come back to.
#
EXIT_INCOMPLETE = 69


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
        """The frozen `haproxy-deploy` envelope.

        A partial run must carry at least one warning and a blocked or failed one
        must carry an error; the envelope helper enforces both, so an incomplete
        report fails here rather than reaching a reader as a valid-looking lie.
        """

        warnings = tuple(self.warnings)
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
            error=self.error,
        )


@dataclass(frozen=True, slots=True)
class DeployRun:
    exit_code: int
    report: DeployReport


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


def run(
    read_status: ReadStatus,
    trigger: TriggerNode,
    writer: TextIO,
    *,
    target: Target | None = None,
    allow_vip_unknown: bool = False,
    operation: str = OPERATION,
) -> DeployRun:
    """Reconcile the cluster and report, in text as it goes and in a result."""

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
        return DeployRun(exc.exit_code, report)

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

    while True:
        #
        # Warnings are statements about the cluster, so they are printed when
        # they change rather than once at the start or once per step. A picture
        # that becomes worse mid-run must say so; one that stays the same must
        # not repeat itself into noise.
        #
        warnings = warnings_for(status.observation(), allow_vip_unknown=allow_vip_unknown)
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
            writer.write(f"\nERROR: {step.reason}\n")
            report.outcome = Outcome.BLOCKED
            report.final_summary = status.summary
            report.error = Message(code="deploy_blocked", message=step.reason)
            return DeployRun(step.exit_code, report)

        if step.action is Action.FINISHED:
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
            entry.outcome = "failed" if code else "not_attempted"
            entry.error = Message(code="status_unavailable", message=str(exc), node=node_name)
            report.outcome = Outcome.FAILED
            report.error = Message(code="status_unavailable", message=str(exc))
            return DeployRun(exc.exit_code, report)

        writer.write(_state_line("Post-deploy status", status))

        landed = _verify(status, node_name, target)
        failed = code != 0 or landed is False
        progress = record(progress, step, failed=failed)

        if code != 0:
            entry.outcome = "failed"
            entry.error = Message(
                code="trigger_failed",
                message=f"the deploy trigger failed with exit {code}",
                node=node_name,
            )
            writer.write(
                f"\nERROR: the deploy trigger failed on {node_name} with exit {code}.\n"
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


def _report(writer: TextIO, status: ClusterStatus, step: Step, report: DeployReport) -> int:
    writer.write("\n")
    writer.write(_state_line("Final status", status))
    report.final_summary = status.summary

    if step.outcome is Outcome.DONE:
        report.outcome = Outcome.DONE
        writer.write("\nRESULT: OK\n")
        return 0

    if step.outcome is Outcome.FAILED:
        report.outcome = Outcome.FAILED
        report.error = Message(code="deploy_failed", message=step.reason)
        writer.write(f"\nRESULT: FAILED\n{step.reason}.\n")
        return step.exit_code

    report.outcome = Outcome.PARTIAL
    writer.write(f"\nRESULT: PARTIAL\n{step.reason}.\n")
    writer.write("Run the same command again once every node can be read.\n")
    return step.exit_code or EXIT_INCOMPLETE
