"""What a deploy should do next, decided from what the cluster looks like now.

This module is the deploy matrix in §6.3 of the implementation plan, and nothing
else. It reads no files, opens no connections and runs no commands: it is given
one observation of the cluster and answers with one step. That is deliberate -
the matrix is normative, the states in it cannot be provoked on a real pair, and
a decision tangled up with SSH is a decision that can only be tested by breaking
production.

Asked one step at a time, on purpose
------------------------------------
The order is not computed once and then followed. It is re-decided after every
mutation, from a fresh observation, which is what the plan requires: a node that
takes the VIP after the first step changes the order of the remaining steps, and
verifying only the node that was just touched is not enough.

The shell-era command computed its order up front and kept it. That is the gap
this module closes; the loop that drives it simply asks again.

What "owner" means here
-----------------------
Ownership is what a node answers about holding the VIP address. Three answers
are possible and all three are different:

  * True  - it holds the address
  * False - it does not
  * None  - it is reachable but the question got no usable answer

None is not the same as unreachable. An unreachable node cannot be part of a
split brain that this manager could make worse by acting; an indeterminate one
might already be in one, which is why it blocks instead of degrading.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

#
# Exit codes, unchanged from the command this replaces: an operator and any
# wrapper around it have been reading these.
#
EXIT_BLOCKED = 65
EXIT_NO_STATUS = 68
EXIT_INCOMPLETE = 69


class VipState(StrEnum):
    """The cluster-wide ownership picture, as the status contract reports it."""

    SINGLE_OWNER = "single_owner"
    NO_OWNER = "no_owner"
    SPLIT_BRAIN = "split_brain"
    UNKNOWN = "unknown"
    INCOMPLETE = "incomplete"


class Action(StrEnum):
    DEPLOY = "deploy"
    SKIP = "skip"
    BLOCKED = "blocked"
    FINISHED = "finished"


class Outcome(StrEnum):
    DONE = "done"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class NodeObservation:
    """One node as the last status read saw it."""

    name: str
    status_ok: bool
    owns_vip: bool | None = None
    release_hash: str | None = None


@dataclass(frozen=True, slots=True)
class ClusterObservation:
    """One status read, in configured node order.

    `vip_state` is taken from the status result rather than recomputed here.
    Two readers deriving cluster-wide ownership from per-node answers is exactly
    the drift that makes the status command and the deploy command disagree
    about whether it is safe to act.
    """

    nodes: tuple[NodeObservation, ...]
    vip_state: VipState

    @property
    def configured(self) -> int:
        return len(self.nodes)

    @property
    def usable(self) -> tuple[NodeObservation, ...]:
        return tuple(node for node in self.nodes if node.status_ok)


@dataclass(frozen=True, slots=True)
class Progress:
    """What the loop has done so far. Empty on the first call."""

    deployed: frozenset[str] = frozenset()
    skipped: frozenset[str] = frozenset()
    failed: frozenset[str] = frozenset()
    #
    # Set once a node was passed over because it had no usable status. It
    # survives later observations, because a run that ignored a node is partial
    # even if that node comes back before the end.
    #
    degraded: bool = False

    @property
    def handled(self) -> frozenset[str]:
        return self.deployed | self.skipped | self.failed


@dataclass(frozen=True, slots=True)
class Step:
    """One answer: deploy this node, skip it, stop, or we are done."""

    action: Action
    node: str | None = None
    reason: str = ""
    outcome: Outcome | None = None
    exit_code: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)


def _blocking_reason(
    observation: ClusterObservation, *, allow_vip_unknown: bool
) -> tuple[str, int] | None:
    """Why nothing may be touched right now, or None when it may.

    Checked before every single step, not once at the start. Between two steps
    the picture can change into one of these, and the plan is explicit that the
    operation stops the moment it does.
    """

    if not observation.usable:
        return "no node returned usable status; deploy blocked", EXIT_NO_STATUS

    if observation.vip_state is VipState.SPLIT_BRAIN:
        #
        # No override exists for this one, deliberately. Two owners means the
        # pair is already damaged, and deploying can deepen the damage.
        #
        return "split brain detected; deploy blocked and cannot be overridden", EXIT_BLOCKED

    if observation.vip_state is VipState.UNKNOWN and not allow_vip_unknown:
        return (
            "VIP ownership is unknown; deploy blocked. CLI override: --allow-vip-unknown",
            EXIT_BLOCKED,
        )

    return None


#
# The starting point of a run: nothing deployed, nothing skipped, nothing
# failed. A module-level value rather than a call in a default argument, and
# safe to share because Progress is frozen - every step returns a new one.
#
NOTHING_DONE = Progress()


def warnings_for(
    observation: ClusterObservation, *, allow_vip_unknown: bool = False
) -> tuple[str, ...]:
    """What the run should say about this observation, once, before acting.

    Separate from the steps because these are statements about the cluster, not
    about a node. The plan requires two of them by name: zero owners always
    warns that the VIP is down, and an accepted override always says that it was
    accepted, so the audit trail shows a human chose to proceed.
    """

    if observation.vip_state is VipState.NO_OWNER:
        return (
            "no node currently owns the VIP; it is down",
            "deploying in configured cluster order",
        )

    if observation.vip_state is VipState.UNKNOWN and allow_vip_unknown:
        return (
            "VIP ownership is UNKNOWN",
            "explicit CLI override accepted",
            "deploying in configured cluster order",
        )

    if observation.vip_state is VipState.INCOMPLETE:
        unreadable = ", ".join(node.name for node in observation.nodes if not node.status_ok)
        return (
            "partial cluster status; only reachable nodes will be reconciled",
            f"unavailable: {unreadable}",
        )

    return ()


def _candidates(observation: ClusterObservation, progress: Progress) -> tuple[NodeObservation, ...]:
    """Nodes still to consider, in configured order."""

    return tuple(node for node in observation.nodes if node.name not in progress.handled)


def _ordered(
    candidates: tuple[NodeObservation, ...], vip_state: VipState
) -> tuple[NodeObservation, ...]:
    """Non-owner first, owner last - decided from the ownership seen just now.

    Every other state keeps configured order. With no owner there is no traffic
    order left to preserve, and with ownership overridden as unknown there is
    nothing trustworthy to order by; in both cases the stable order from the
    cluster configuration is the honest choice.
    """

    if vip_state is not VipState.SINGLE_OWNER:
        return candidates
    return tuple(node for node in candidates if not node.owns_vip) + tuple(
        node for node in candidates if node.owns_vip
    )


def next_step(
    observation: ClusterObservation,
    progress: Progress = NOTHING_DONE,
    *,
    expected_hash: str | None = None,
    allow_vip_unknown: bool = False,
    target_moved: bool = False,
) -> Step:
    """The single next thing to do, given the cluster as it looks right now.

    Call it, act on the answer, read the status again, call it again. Feeding it
    a stale observation is the one way to misuse it, and it is the thing the
    command this replaces got wrong.

    `expected_hash` is the release the deploy is for. A node already running it
    is skipped rather than redeployed, which is what makes a returning node cost
    one deploy instead of two, and what makes a re-run after a partial safe.
    """

    if progress.failed:
        failed = ", ".join(sorted(progress.failed))
        return Step(
            action=Action.FINISHED,
            reason=f"deploy failed on {failed}; the remaining nodes were not touched",
            outcome=Outcome.FAILED,
            exit_code=EXIT_INCOMPLETE,
        )

    if target_moved:
        #
        # Checked after the lock is held: if the published target changed under
        # the operation, the thing about to be rolled out is no longer the thing
        # that was asked for.
        #
        return Step(
            action=Action.BLOCKED,
            reason="the published target changed while the deploy was starting; nothing was deployed",
            outcome=Outcome.BLOCKED,
            exit_code=EXIT_BLOCKED,
        )

    blocked = _blocking_reason(observation, allow_vip_unknown=allow_vip_unknown)
    if blocked is not None:
        reason, code = blocked
        return Step(action=Action.BLOCKED, reason=reason, outcome=Outcome.BLOCKED, exit_code=code)

    for node in _ordered(_candidates(observation, progress), observation.vip_state):
        if not node.status_ok:
            #
            # Degraded mode, and the deliberate exception in the plan: with a
            # peer that cannot be read, the reachable node is still reconciled
            # and the result says so.
            #
            return Step(
                action=Action.SKIP,
                node=node.name,
                reason=f"{node.name} has no usable status; skipping it",
                warnings=(f"{node.name} could not be read; its state is unverified",),
            )

        if expected_hash is not None and node.release_hash == expected_hash:
            return Step(
                action=Action.SKIP,
                node=node.name,
                reason=f"{node.name} already runs this version; nothing to do",
            )

        return Step(action=Action.DEPLOY, node=node.name)

    return _finish(observation, progress)


def _finish(observation: ClusterObservation, progress: Progress) -> Step:
    """Nothing left to touch: say how it went.

    Partial is not failure. It means the cluster was left in a state the run
    could not fully verify - a node that could not be read, or one that was
    passed over earlier - and that someone should run the same command again
    when the missing node is back.
    """

    unverified = len(observation.usable) < observation.configured
    if progress.degraded or unverified:
        return Step(
            action=Action.FINISHED,
            reason="some nodes could not be verified",
            outcome=Outcome.PARTIAL,
            exit_code=EXIT_INCOMPLETE,
        )

    return Step(action=Action.FINISHED, outcome=Outcome.DONE, exit_code=0)


def record(progress: Progress, step: Step, *, failed: bool = False) -> Progress:
    """Progress after acting on `step`. The loop's only state."""

    if step.node is None:
        return progress
    if step.action is Action.SKIP:
        return Progress(
            deployed=progress.deployed,
            skipped=progress.skipped | {step.node},
            failed=progress.failed,
            degraded=progress.degraded or bool(step.warnings),
        )
    if failed:
        return Progress(
            deployed=progress.deployed,
            skipped=progress.skipped,
            failed=progress.failed | {step.node},
            degraded=progress.degraded,
        )
    return Progress(
        deployed=progress.deployed | {step.node},
        skipped=progress.skipped,
        failed=progress.failed,
        degraded=progress.degraded,
    )
