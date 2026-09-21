"""Whether the state backup is on a schedule, and when it last ran.

The listing next to this answers "what is on the nodes". It cannot answer the
question an operator actually asks first - *is anything taking these, or am I
looking at archives that stopped arriving in June* - because a directory of old
files looks exactly like a directory of files a broken timer stopped adding to.

So the timer is read as well, from systemd, which is the thing that actually
knows. Nothing here schedules, enables or triggers anything: it runs
``systemctl show``, which reports properties and changes nothing. The timer's
name comes from the root-owned runtime policy rather than from code, because it
is an installation fact, and it is checked against a strict pattern anyway - a
unit name reaches an argv, and "it came from a root-owned file" is a weaker
guarantee than a form that cannot be anything else.

An installation that has not declared a timer gets ``null`` and no error. Not
every deployment backs up on a schedule, and a command that failed because a
key it does not need is absent would be worse than one that says nothing.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from haproxy_mgmt.config import CLUSTER_ID, TIMER_UNIT

SYSTEMCTL = "/usr/bin/systemctl"
#
# The policy's own timer name refuses template instances on purpose (see
# TIMER_UNIT). The per-cluster instance is the one exception, and only in the
# exact shape `timer_unit` derives it in: the project's template, an `@`, and
# a cluster ID that passed the same check the configuration applies.
#
SCHEDULE_DROPIN = "schedule.conf"
TIMER_INSTANCE = re.compile(rf"^haproxy-state-backup@{CLUSTER_ID.pattern[1:-1]}\.timer$")

#
# `systemctl show` never blocks on anything, but a hung dbus would otherwise
# hold a poll open for as long as it liked. Short, because the answer is local
# and the page it feeds is read every few minutes.
#
TIMEOUT_SECONDS = 5

#
# The one calendar expression from `TimersCalendar={ OnCalendar=... ; ... }`.
# The property carries a next_elapse too, which is read from its own property
# instead - one parser for one fact.
#
CALENDAR = re.compile(r"OnCalendar=(?P<calendar>[^;}]+?)\s*[;}]")


class ScheduleError(ValueError):
    """The configured timer name is not a name this may put in an argv."""


def _run(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    """Ask systemd for exactly these properties of exactly this unit.

    `--timestamp=unix` because the default format is a localised string that
    would have to be parsed back through the manager's timezone, twice a year
    ambiguously. Epoch seconds are an instant, and the envelope wants one.
    """

    command = [SYSTEMCTL, "show", unit, "--timestamp=unix"]
    command.extend(f"--property={name}" for name in properties)
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary, pattern-checked unit
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def _moment(value: str | None) -> str | None:
    """A systemd `@<epoch>` timestamp as RFC 3339, or None for "never"."""

    if not value or not value.startswith("@"):
        return None
    try:
        seconds = int(value[1:])
    except ValueError:
        return None
    if seconds <= 0:
        # systemd reports an event that has not happened as epoch zero rather
        # than as an empty value.
        return None
    return datetime.fromtimestamp(seconds, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


type ShowProperties = Callable[[str, tuple[str, ...]], dict[str, str]]


def schedule_result(unit: str | None, *, show: ShowProperties = _run) -> dict[str, Any] | None:
    """What systemd says about the backup timer, or None if none is configured.

    Never raises for a state of the machine: a timer that systemd does not know
    is reported as `known: false` with empty fields rather than as a failure,
    because that is a true and useful answer - somebody removed the unit, and
    the archives on the nodes are about to stop being replaced.
    """

    if unit is None:
        return None
    if not (TIMER_UNIT.fullmatch(unit) or TIMER_INSTANCE.fullmatch(unit)):
        raise ScheduleError(f"backup_timer is not a valid systemd timer name: {unit}")

    timer = show(
        unit,
        (
            "LoadState",
            "UnitFileState",
            "ActiveState",
            "TimersCalendar",
            "NextElapseUSecRealtime",
            "LastTriggerUSec",
            "Unit",
            "DropInPaths",
        ),
    )
    known = timer.get("LoadState") == "loaded"
    if not known:
        return {
            "unit": unit,
            "known": False,
            "enabled": False,
            "active": False,
            "calendar": None,
            "next_run": None,
            "last_run": None,
            "last_result": None,
            "scheduled": False,
        }

    calendar = CALENDAR.search(timer.get("TimersCalendar", ""))
    service = timer.get("Unit") or ""
    #
    # The timer says when it fired; only the service it triggers knows how that
    # run ended. A timer that fires every night into a service that fails every
    # night is the failure mode this page exists to make visible.
    #
    outcome = show(service, ("Result",)) if service.endswith(".service") else {}
    return {
        "unit": unit,
        "known": True,
        "enabled": timer.get("UnitFileState", "") in ("enabled", "enabled-runtime", "static"),
        "active": timer.get("ActiveState") == "active",
        "calendar": calendar.group("calendar") if calendar else None,
        "next_run": _moment(timer.get("NextElapseUSecRealtime")),
        "last_run": _moment(timer.get("LastTriggerUSec")),
        "last_result": outcome.get("Result") or None,
        #
        # A cluster instance is born with the template's default calendar and
        # disabled. Only an administrator's schedule writes the drop-in, so its
        # presence is what separates "never scheduled" from "switched off".
        #
        "scheduled": any(
            path.endswith("/" + SCHEDULE_DROPIN) for path in timer.get("DropInPaths", "").split()
        ),
    }
