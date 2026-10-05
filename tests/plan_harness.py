"""Driving the deploy matrix: the pieces both target kinds are tested with.

`next_step` is asked one question at a time and must be fed a fresh observation
after every mutation, so the driver here always takes the next observation from
a list rather than reusing one. That is not a test convenience - feeding it a
stale observation is the single way to misuse the module, and a driver that
allowed it would hide exactly the bug the design exists to prevent.

Shared by the release matrix (§6.3) and the certificate matrix (§6.4), because
the plan says both obey the same rules and the frozen contract reuses the same
node result for both. Two drivers would let the two matrices drift apart
quietly, which is the thing that must not happen here.
"""

from __future__ import annotations

from haproxy_mgmt.deploy_plan import (
    Action,
    ClusterObservation,
    NodeObservation,
    Outcome,
    Progress,
    Target,
    VipState,
    next_step,
    record,
)

TARGET = "a" * 40
BEHIND = "b" * 40


def node(
    name: str,
    *,
    ok: bool = True,
    owner: bool | None = False,
    hash_: str | None = BEHIND,
    addresses: bool | None = True,
) -> NodeObservation:
    """One node as the status read saw it.

    `addresses` defaults to True - the node carries the address list its release
    publishes - so a case about ordering or ownership stays a case about
    ordering or ownership. The half-way node, where the release is live and the
    addresses are not, is asked for explicitly by the cases that are about it.
    """

    return NodeObservation(
        name=name,
        status_ok=ok,
        owns_vip=owner,
        release_hash=hash_,
        addresses_current=addresses,
    )


def pair(vip_state: VipState, *nodes: NodeObservation) -> ClusterObservation:
    return ClusterObservation(nodes=nodes, vip_state=vip_state)


def drive(
    observations: list[ClusterObservation],
    *,
    target: Target | None = None,
    allow_vip_unknown: bool = False,
    fail_on: str | None = None,
) -> tuple[list[str], Outcome, int]:
    """Run the loop to its end. Returns (what happened, outcome, exit code).

    Each entry is "deploy:<node>" or "skip:<node>", in the order decided - which
    is the thing most of these cases are actually asserting about.
    """

    progress = Progress()
    trace: list[str] = []
    index = 0

    while True:
        observation = observations[min(index, len(observations) - 1)]
        step = next_step(
            observation,
            progress,
            target=target,
            allow_vip_unknown=allow_vip_unknown,
        )

        if step.action in (Action.BLOCKED, Action.FINISHED):
            assert step.outcome is not None
            return trace, step.outcome, step.exit_code

        assert step.node is not None
        trace.append(f"{step.action.value}:{step.node}")
        failed = step.action is Action.DEPLOY and step.node == fail_on
        progress = record(progress, step, failed=failed)
        if step.action is Action.DEPLOY:
            #
            # A deploy is a mutation, so the next question is asked of a fresh
            # observation. A skip changed nothing and reuses this one.
            #
            index += 1
