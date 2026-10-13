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
from typing import Protocol

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
    """One node as the last status read saw it.

    `certificates` is what the node says it currently carries, as (id,
    fingerprint) pairs in id order. `None` means the node did not report
    certificates at all, which is not the same as reporting none: the first
    cannot be compared against a target, the second compares as missing.
    """

    name: str
    status_ok: bool
    owns_vip: bool | None = None
    release_hash: str | None = None
    #
    # Whether the node carries the keepalived address list its release
    # publishes. None means nobody measured it, which is not the same as False.
    #
    addresses_current: bool | None = None
    #
    # The same for the syslog objects' IPVS file (B256). True where the node
    # does not report it: its bundle predates the file.
    #
    ipvs_current: bool | None = True
    #
    # The same for the log forwarding rsyslog reads (review 26-10-13, A1).
    #
    forwarding_current: bool | None = True
    certificates: tuple[tuple[str, str], ...] | None = None
    #
    # The CA files the node carries for its pools (B276), as (id, bundle
    # fingerprint) pairs. None when the node did not say - a node from
    # before authorities existed.
    #
    authorities: tuple[tuple[str, str], ...] | None = None


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


class Target(Protocol):
    """What this run is reconciling the nodes towards.

    The matrix in §6.3 does not care whether the thing being rolled out is a
    configuration release or a set of certificates: the ordering rules, the
    blocking rules, the skip-if-current rule and the partial semantics are the
    same, and §6.4 says so in as many words. The frozen contract agrees - the
    `cert_deploy` result reuses `node_reconcile_result` unchanged, and the
    contract validator runs the same semantic check over both.

    So the difference between the two operations is exactly this object: what
    "already current" means, and what the run is aiming at. Everything else is
    shared, which is the only way the two can be kept from drifting apart.
    """

    def is_current(self, node: NodeObservation) -> bool | None:
        """Is this node already where it should be? None when it cannot be told.

        None is deliberately distinct from False. False means the node is behind
        and must be acted on; None means the node did not answer the question,
        so it is neither skipped as current nor confirmed as verified.
        """

    def skip_reason(self, node: NodeObservation) -> str:
        """What to say when the node is passed over as already current."""

    def result_fields(self) -> dict[str, object]:
        """The target's own words for the result envelope. Plain data, no I/O."""


@dataclass(frozen=True, slots=True)
class ReleaseTarget:
    """The published configuration release this deploy is for.

    A release activates four things on a node, and they can end up in
    different states. The node installs and reloads HAProxy first, then the
    keepalived address list and the IPVS virtual servers (B256), then the log
    forwarding rsyslog reads (A1); when a later step fails its file is
    restored while the new configuration stays live, so the node reports the
    new release hash and the old addresses. The hash alone would then call that
    node current and skip the very node that needs the repair - and the node
    deploy's own unchanged-release branch, which re-syncs the addresses, would
    never be reached because nothing calls it.

    So current means every component this release owns is where it should be.
    A node left half-way is a node the next reconcile finishes.
    """

    version: int
    hash: str

    def is_current(self, node: NodeObservation) -> bool | None:
        if node.release_hash is None:
            #
            # The node did not say which release it runs. Not compared, and it
            # must not read as agreement in the status command either.
            #
            return None
        if node.release_hash != self.hash:
            return False
        parts = (node.addresses_current, node.ipvs_current, node.forwarding_current)
        if False in parts:
            return False
        if None in parts:
            return None
        return True

    def skip_reason(self, node: NodeObservation) -> str:
        return f"{node.name} already runs this version; nothing to do"

    def result_fields(self) -> dict[str, object]:
        return {"target": {"version": self.version, "hash": self.hash}}


@dataclass(frozen=True, slots=True)
class CertificateRef:
    """One certificate the cluster references, and the bytes it should be."""

    id: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class CertificateTarget:
    """The certificates this cluster references, and nothing else.

    Only referenced certificates are compared, and a certificate the node
    carries but the cluster does not reference is ignored rather than removed.
    That is §6.4's rule and it is a safety property, not an omission: the
    distribution directory is shared with other systems, so this command syncs
    the smallest set that makes the cluster correct. Deleting key material a
    node might still be serving on is a far worse failure than leaving a stale
    file behind, and nothing here can tell the difference from the outside.
    """

    certificates: tuple[CertificateRef, ...]
    #
    # The CA files the cluster's pools verify against (B276). Their
    # fingerprint is the whole bundle's, not the first certificate's: a root
    # added behind the one already there is a change the node must get.
    #
    authorities: tuple[CertificateRef, ...] = ()

    def is_current(self, node: NodeObservation) -> bool | None:
        if node.certificates is None:
            #
            # The node answered, but said nothing about certificates. Treated as
            # unknown rather than as "carries none", because the second would
            # make an unverifiable node look like a node that simply needs a
            # push - and the push would then be reported as verified.
            #
            return None
        if self.authorities and node.authorities is None:
            return None
        carried = dict(node.certificates)
        held = dict(node.authorities or ())
        return all(carried.get(ref.id) == ref.fingerprint for ref in self.certificates) and all(
            held.get(ref.id) == ref.fingerprint for ref in self.authorities
        )

    def skip_reason(self, node: NodeObservation) -> str:
        return f"{node.name} already has the referenced certificates; nothing to do"

    def result_fields(self) -> dict[str, object]:
        fields: dict[str, object] = {
            "target_certificates": [
                {"id": ref.id, "fingerprint_sha256": ref.fingerprint} for ref in self.certificates
            ]
        }
        if self.authorities:
            fields["target_authorities"] = [
                {"id": ref.id, "fingerprint_sha256": ref.fingerprint} for ref in self.authorities
            ]
        return fields


@dataclass(frozen=True, slots=True)
class CertificateGap:
    """One readable node whose referenced certificates are not the published bytes.

    `missing` names certificates the node does not carry at all; `stale` names
    the ones it carries as different bytes than the manager published. Both are
    IDs in the cluster's configured order, and both are told apart because they
    are read differently by the person who has to act: a missing file is a
    certificate that never reached the node, a stale one is a renewal that did
    not.
    """

    node: str
    missing: tuple[str, ...]
    stale: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"node": self.node, "missing": list(self.missing), "stale": list(self.stale)}

    def describe(self) -> str:
        parts = []
        if self.missing:
            parts.append(f"missing {', '.join(self.missing)}")
        if self.stale:
            parts.append(f"stale {', '.join(self.stale)}")
        return f"{self.node} ({'; '.join(parts)})"


def certificate_gaps(
    observation: ClusterObservation, certificates: CertificateTarget
) -> tuple[CertificateGap, ...]:
    """The readable nodes a configuration deploy must not be sent to yet.

    This is §6.4's preflight: a release that references a certificate a node
    does not carry would be installed and then refused by HAProxy on that node
    - a failure that was knowable before the first node was touched. So the
    comparison is made here, against the same fingerprints `cert-deploy` uses,
    and the deploy blocks and names the command that fixes it. Nothing chains
    the two operations together; that is the plan's rule, so that a certificate
    rollout is always something a person asked for by name.

    Only nodes that answered about certificates are judged. A node that said
    nothing cannot be shown to be behind, and blocking on silence would make a
    status script from before the field existed refuse every deploy. Such a
    node is reported as unverified instead, by `unverified_certificates`.
    """

    gaps = []
    for node in observation.usable:
        if node.certificates is None:
            continue
        carried = dict(node.certificates)
        missing = tuple(ref.id for ref in certificates.certificates if ref.id not in carried)
        stale = tuple(
            ref.id
            for ref in certificates.certificates
            if ref.id in carried and carried[ref.id] != ref.fingerprint
        )
        if missing or stale:
            gaps.append(CertificateGap(node=node.name, missing=missing, stale=stale))
    return tuple(gaps)


def unverified_certificates(observation: ClusterObservation) -> tuple[str, ...]:
    """The readable nodes that said nothing about the certificates they carry."""

    return tuple(node.name for node in observation.usable if node.certificates is None)


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

    #
    # Two owners among the nodes that answered, whatever the summary says: a
    # status from before the rule above, or one read as UNKNOWN and overridden,
    # must not carry a conflict past this point (review 2026-10-03, F1).
    #
    owners = sum(1 for node in observation.usable if node.owns_vip is True)
    if observation.vip_state is VipState.SPLIT_BRAIN or owners > 1:
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
    """Known standbys first, nodes of unknown ownership next, a known owner last.

    Decided from the ownership seen just now, and from what is known rather
    than from the cluster's summary: with one node unreadable the summary is
    INCOMPLETE, and the owner among the others is still the node whose traffic
    a deploy should touch last (review 2026-10-03, F1). Within each group the
    configured order holds, so with no owner, or with every node unknown, the
    order is the cluster configuration's as before. A node that could not be
    read is only ever skipped, never changed, and keeps its place.
    """

    del vip_state  # what is known about each node decides; kept for the callers
    rank = {False: 0, None: 1, True: 2}
    return tuple(sorted(candidates, key=lambda node: rank[node.owns_vip] if node.status_ok else 0))


def next_step(
    observation: ClusterObservation,
    progress: Progress = NOTHING_DONE,
    *,
    target: Target | None = None,
    allow_vip_unknown: bool = False,
    target_moved: bool = False,
) -> Step:
    """The single next thing to do, given the cluster as it looks right now.

    Call it, act on the answer, read the status again, call it again. Feeding it
    a stale observation is the one way to misuse it, and it is the thing the
    command this replaces got wrong.

    `target` is what the run is reconciling towards - a release or a set of
    certificates. A node already there is skipped rather than redeployed, which
    is what makes a returning node cost one deploy instead of two, and what
    makes a re-run after a partial safe. Passing none means nothing is ever
    skipped as current, because there is nothing to compare against.
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
        #
        # `blocked` says nothing was touched. Once a node carries the target it
        # is no longer true, whatever stopped the rest: the run is partial, as
        # a caller letting go after a deploy already is (review 2026-09-28 F4).
        #
        if progress.deployed:
            done = ", ".join(sorted(progress.deployed))
            return Step(
                action=Action.BLOCKED,
                reason=f"{reason}; {done} already carries the target",
                outcome=Outcome.PARTIAL,
                exit_code=EXIT_INCOMPLETE,
            )
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

        if target is not None and target.is_current(node):
            return Step(
                action=Action.SKIP,
                node=node.name,
                reason=target.skip_reason(node),
            )

        return Step(action=Action.DEPLOY, node=node.name)

    return _finish(observation, progress, target)


def _finish(
    observation: ClusterObservation, progress: Progress, target: Target | None = None
) -> Step:
    """Nothing left to touch: say how it went.

    Partial is not failure. It means the cluster was left in a state the run
    could not fully verify - a node that could not be read, or one that was
    passed over earlier - and that someone should run the same command again
    when the missing node is back.

    Judged on the last reading of every node against the target, not on what
    each node looked like when it was handled (review 2026-10-04, CR-08). A
    node handled early is never a candidate again, so one that fell back to an
    older release while a later node was deployed - or that could not be read
    right after its own deploy - used to end the run as converged.
    """

    if target is not None:
        behind = sorted(
            node.name for node in observation.usable if target.is_current(node) is False
        )
        if behind:
            return Step(
                action=Action.FINISHED,
                reason=f"{', '.join(behind)} is not on the target at the end of the run",
                outcome=Outcome.PARTIAL,
                exit_code=EXIT_INCOMPLETE,
            )
        if any(target.is_current(node) is None for node in observation.usable):
            return Step(
                action=Action.FINISHED,
                reason="some nodes could not be verified",
                outcome=Outcome.PARTIAL,
                exit_code=EXIT_INCOMPLETE,
            )

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
