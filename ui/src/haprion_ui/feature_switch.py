"""Turning a feature on or off: the one way both paths do it (B193, B231; Fas 23).

*Settings -> Features* and `haprion-settings apply` flip a switch through
this, so the refusals are the same sentences and the side effects the same
jobs: node backups off stops every running backup schedule through the
schedule job the backup page queues and remembers them, and on starts exactly
those again; the WAF engine is refused off while an object uses it; cluster
colours are refused on past six clusters.

What a flip needs to know besides the switch row - the clusters, their backup
readings, the stored objects, whether a node restore is waiting - comes from
`Readings`, so the web reads it through its own sources and the terminal from
the same tables. The writes are in the caller's transaction; the caller
commits, or rolls back on a refusal.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from haprion_ui import (
    cluster_identity,
    db,
    features,
    jobs,
    metrics,
    node_restores,
    operations,
    waf,
)


class UnknownFeature(Exception):
    """No switch by that name."""


@dataclass(frozen=True, slots=True)
class Readings:
    clusters: Callable[[], tuple[str, ...]]
    backup_overview: Callable[[], Any]
    objects: Callable[[], Iterable[Any]]
    restore_waiting: Callable[[], bool]


def locked(name: str, clusters: Iterable[str]) -> bool:
    """Whether a switch cannot be on here: cluster colours past six clusters."""

    return name == features.CLUSTER_COLOURS and not cluster_identity.fits(clusters)


def shown_on(name: str, stored: bool, clusters: Iterable[str]) -> bool:
    """Whether the interface shows `name` on: a locked switch shows off whatever its row says."""

    return stored and not locked(name, clusters)


def restore_waiting(connection: Any) -> bool:
    """Whether a node restore is running or waiting for an answer."""

    rows = [
        job
        for operation in node_restores.OPERATIONS
        for job in db.operation_jobs(connection, operation, limit=100)
    ]
    runs = node_restores.recent_runs(rows, shown=metrics.shown, now=datetime.now(UTC), writes=True)
    waiting = {
        node_restores.STAGE_LABELS[stage][0]
        for stage in ("working", "held", "fingerprint", "confirm")
    }
    return any(run.label in waiting for listed in runs.values() for run in listed)


def switch(
    connection: Any,
    *,
    name: str,
    want: bool,
    actor: str,
    via: str,
    readings: Readings,
) -> tuple[db.Job, ...] | None:
    """Flip `name` to `want`, and the schedule jobs that queued; None when it already was.

    Refusals raise `SwitchRefused`.
    """

    current = db.feature_switches(connection).get(name)
    if name not in features.BY_NAME or current is None:
        raise UnknownFeature(name)
    #
    # No change is no change, locked or not: only an attempt to turn a locked
    # switch on is refused, so a file that says what is stored applies.
    #
    if current.enabled == want:
        return None
    if want and locked(name, readings.clusters()):
        raise features.SwitchRefused(
            f"Cluster colours cover {cluster_identity.ACCENT_COUNT} clusters, "
            "and this installation lists more."
        )
    #
    # A WAF the interface no longer shows still filters traffic (B231).
    #
    if name == features.WAF_ENGINE and not want:
        using = waf.objects_using(readings.objects())
        if using:
            shown = ", ".join(using[:3]) + (f" and {len(using) - 3} more" if len(using) > 3 else "")
            raise features.SwitchRefused(
                f"The WAF engine inspects {shown}. Turn it off there first."
            )

    remembered: dict[str, Any] = {}
    schedules: dict[str, dict[str, Any]] = {}
    if name == features.NODE_BACKUPS and not want:
        if readings.restore_waiting():
            raise features.SwitchRefused(
                "A node restore is running or waiting. Finish or discard it first."
            )
        schedules = features.schedules_to_stop(readings.backup_overview())
        remembered = {"schedules": schedules}
    elif name == features.NODE_BACKUPS:
        schedules = features.remembered_schedules(current.remembered)
    asked = [
        (cluster, {**schedule, "enabled": want}) for cluster, schedule in sorted(schedules.items())
    ]
    try:
        for cluster, payload in asked:
            operations.prepare(
                operation="backup_schedule", cluster=cluster, request_id=uuid4(), payload=payload
            )
    except operations.BadPayload as error:
        raise features.SwitchRefused(
            "A remembered backup schedule could not be written back."
        ) from error

    if not db.set_feature_switch(
        connection, name=name, enabled=want, remembered=remembered, actor=actor
    ):
        return None
    try:
        queued = [
            db.queue_job(
                connection,
                operation="backup_schedule",
                cluster=cluster,
                payload=payload,
                idempotency_key=uuid4(),
            )
            for cluster, payload in asked
        ]
    except db.ClusterBusy as error:
        #
        # Said by the rule a busy queue is said by everywhere (review 26-10-29,
        # A3); merely busy, it names the clusters, since it queued on each.
        #
        raise features.SwitchRefused(
            jobs.not_finishing(error.active, datetime.now(UTC), writes=True)
            or "A job is running on one of the clusters. Try again when it has finished."
        ) from error
    db.record_audit_event(
        connection,
        actor=actor,
        action="feature_switched",
        detail={"feature": name, "enabled": want, "schedules": sorted(schedules), "via": via},
    )
    for job in queued:
        db.record_audit_event(
            connection,
            actor=actor,
            action="queue_job",
            cluster=job.cluster,
            request_id=job.request_id,
            detail={"operation": job.operation, "job": job.id},
        )
    return tuple(queued)
