"""Feature switches: what an installation has turned off (Fas 13 part 3, B193; B204).

Two capabilities are odd for an HAProxy interface in itself and may be turned
off under Settings. Off means the interface no longer offers them - the tab,
the pages and the operations that start them - and for node backups it also
stops the clusters' backup timers, through the same schedule job the backup
page queues. Receivers already registered go on getting their certificates;
archives already taken are kept.

Read once per signed-in request, beside the reader's clock, so every page and
the menu in the layout agree about what is off.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt import backup_schedule

CERT_RECEIVERS = "cert_receivers"
NODE_BACKUPS = "node_backups"
CLUSTER_COLOURS = "cluster_colours"


@dataclass(frozen=True, slots=True)
class Feature:
    name: str
    title: str
    #
    # Said once, in the question before it is turned off, when turning it off
    # does more than hide something.
    #
    consequence: str = ""


FEATURES = (
    Feature(CERT_RECEIVERS, "Certificate receivers"),
    Feature(
        NODE_BACKUPS,
        "Node backups",
        consequence="Scheduled backups stop on every cluster and no new ones are taken. "
        "Existing archives are kept, and restore is hidden until this is turned on again.",
    ),
    #
    # Not a capability but a way of drawing (B204): the rule down each cluster
    # card's edge. It hides nothing, and with more than six clusters it is off
    # whatever its row says - see `cluster_identity`.
    #
    Feature(CLUSTER_COLOURS, "Cluster colours"),
)
BY_NAME = {feature.name: feature for feature in FEATURES}

#
# The paths a switch hides, as prefixes. A page under one of them answers 404
# while its switch is off, whatever handler would have drawn it.
#
HIDDEN_PATHS = (
    ("/backups", NODE_BACKUPS),
    ("/certificates/receivers", CERT_RECEIVERS),
)

#
# The job operations a switch withholds from the web while it is off. The
# switch's own schedule jobs are queued by the switch, not through the form
# these guard.
#
HIDDEN_OPERATIONS = {
    "backup_run": NODE_BACKUPS,
    "backup_schedule": NODE_BACKUPS,
    "node_restore_prepare": NODE_BACKUPS,
    "node_restore_preview": NODE_BACKUPS,
    "node_restore": NODE_BACKUPS,
    "node_restore_discard": NODE_BACKUPS,
    "node_restore_status": NODE_BACKUPS,
    "cert_receiver": CERT_RECEIVERS,
}

_OFF: ContextVar[frozenset[str]] = ContextVar("feature_off", default=frozenset())


def read_in(switches: Mapping[str, Any]) -> None:
    """Take this request's switches, as `db.feature_switches` returned them."""

    _OFF.set(frozenset(name for name, switch in switches.items() if not switch.enabled))


def is_on(name: str) -> bool:
    return name not in _OFF.get()


def hiding(path: str) -> str | None:
    """The switch that hides this path, when it is off; else None."""

    for prefix, name in HIDDEN_PATHS:
        if (path == prefix or path.startswith(f"{prefix}/")) and not is_on(name):
            return name
    return None


class SwitchRefused(Exception):
    """Why a switch cannot be flipped now, said as the page says it."""


def schedules_to_stop(overview: Any) -> dict[str, dict[str, Any]]:
    """Every cluster's running backup schedule, as the job that wrote it would ask.

    `overview` is `backups.build_backup_overview`. What comes back is kept in
    the switch's `remembered`, and turning it on again queues exactly these
    with `enabled: true`. A cluster whose timer is already off is not in it,
    so on leaves it off.

    Refused rather than guessed: a schedule job writes the whole schedule, so
    a stale reading, an unknown retention or a calendar the form cannot say
    would rewrite a cluster's schedule into something nobody asked for.
    """

    stopping: dict[str, dict[str, Any]] = {}
    for cluster in overview.clusters:
        schedule = cluster.schedule
        if cluster.stale or schedule is None:
            raise SwitchRefused(
                f"{cluster.cluster} has no fresh backup reading. Try again after the next poll."
            )
        if not schedule.enabled:
            continue
        if backup_schedule.describe(schedule.calendar) is None:
            raise SwitchRefused(
                f"{cluster.cluster}'s timer runs on {schedule.calendar}, which the schedule form "
                "cannot write back. Save its schedule from the backup page first."
            )
        if schedule.retention is None:
            raise SwitchRefused(f"{cluster.cluster}'s retention could not be read.")
        stopping[cluster.cluster] = {
            "time": schedule.time,
            "frequency": schedule.frequency,
            "weekdays": list(schedule.weekdays),
            "day_of_month": schedule.day_of_month,
            "retention": schedule.retention,
        }
    return stopping


def remembered_schedules(remembered: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """What turning node backups on starts again: the schedules off stopped."""

    kept = remembered.get("schedules")
    if not isinstance(kept, Mapping):
        return {}
    return {
        str(cluster): dict(schedule)
        for cluster, schedule in kept.items()
        if isinstance(schedule, Mapping)
    }
