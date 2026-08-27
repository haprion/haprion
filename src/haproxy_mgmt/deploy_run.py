"""The reconcile loop: observe, decide, act, observe again.

Everything that touches the world enters through two callables - read the
cluster status, trigger one node - and nothing else here runs a command or opens
a connection. That is what lets the whole loop, including every failure branch,
be driven by a harness instead of by a real pair of nodes.

The shape of the loop is the plan's, not a convenience:

  * the status is re-read after EVERY mutation, and the order is re-decided from
    what came back. Verifying only the node that was just touched is explicitly
    not enough
  * a hard failure on one node stops before the next is touched
  * the run ends in exactly one of four outcomes, and the exit code follows the
    outcome rather than the last thing that happened

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

from collections.abc import Callable
from typing import TextIO

from haproxy_mgmt.cluster_status import ClusterStatus, NodeStatus, StatusError
from haproxy_mgmt.deploy_plan import (
    NOTHING_DONE,
    Action,
    Outcome,
    Step,
    next_step,
    record,
    warnings_for,
)

type ReadStatus = Callable[[], ClusterStatus]
type TriggerNode = Callable[[NodeStatus], int]

#
# A stop that is not a refusal: the run did what it could and something is left
# for a human to come back to.
#
EXIT_INCOMPLETE = 69


def _state_line(prefix: str, status: ClusterStatus) -> str:
    owners = ", ".join(status.vip_owners) if status.vip_owners else "-"
    usable = sum(1 for node in status.nodes if node.status_ok)
    return f"{prefix}: VIP={status.vip_state.value}, owner={owners}, status={usable}/{len(status.nodes)}\n"


def run(
    read_status: ReadStatus,
    trigger: TriggerNode,
    writer: TextIO,
    *,
    expected_hash: str | None = None,
    allow_vip_unknown: bool = False,
) -> int:
    """Reconcile the cluster and report. Returns the exit code."""

    try:
        status = read_status()
    except StatusError as exc:
        writer.write(f"ERROR: {exc}\n")
        return exc.exit_code

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
            announced = warnings

        step = next_step(
            status.observation(),
            progress,
            expected_hash=expected_hash,
            allow_vip_unknown=allow_vip_unknown,
        )

        if step.action is Action.BLOCKED:
            writer.write(f"\nERROR: {step.reason}\n")
            return step.exit_code

        if step.action is Action.FINISHED:
            return _report(writer, status, step)

        if step.action is Action.SKIP:
            writer.write(f"\n{step.reason}.\n")
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
        progress = record(progress, step, failed=code != 0)

        #
        # Mandatory, and mandatory even when the trigger failed: the failure has
        # already changed the cluster, and reporting a state from before it would
        # describe something that is no longer true.
        #
        try:
            status = read_status()
        except StatusError as exc:
            writer.write(f"\nERROR: {exc}\n")
            writer.write(f"The deploy of {node_name} finished with exit {code}, ")
            writer.write("but the cluster could not be read afterwards.\n")
            return exc.exit_code

        writer.write(_state_line("Post-deploy status", status))

        if code != 0:
            writer.write(
                f"\nERROR: the deploy trigger failed on {node_name} with exit {code}.\n"
                "The status was read again and the remaining nodes were not touched.\n"
            )


def _report(writer: TextIO, status: ClusterStatus, step: Step) -> int:
    writer.write("\n")
    writer.write(_state_line("Final status", status))

    if step.outcome is Outcome.DONE:
        writer.write("\nRESULT: OK\n")
        return 0

    if step.outcome is Outcome.FAILED:
        writer.write(f"\nRESULT: FAILED\n{step.reason}.\n")
        return step.exit_code

    writer.write(f"\nRESULT: PARTIAL\n{step.reason}.\n")
    writer.write("Run the same command again once every node can be read.\n")
    return step.exit_code or EXIT_INCOMPLETE
