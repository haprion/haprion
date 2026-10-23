"""How a moment is written on a page: one format each for a full moment, a day and a time.

A full moment is `yy-mm-dd hh:mm:ss` on a 24-hour clock (`metrics.TIMESTAMP`);
a day alone `yy-mm-dd`, a time alone `hh:mm:ss`. All of them in the reader's
clock (`metrics.shown`). Versions and Node backups wrote a four-digit year,
Needs attention left out the seconds, and one row of it carried two clocks in
two formats (review 2026-10-22, 2-5, 2-6). A test refuses `strftime` and a
`%`-format anywhere else in the interface.
"""

from __future__ import annotations

from datetime import datetime

from haprion_ui import metrics

TIMESTAMP = metrics.TIMESTAMP
DAY = "%y-%m-%d"
TIME = "%H:%M:%S"
#
# What the date and time picker takes and offers: to the minute, which is what
# a person types into a filter. Its bounds are already in the reader's clock.
#
PICKED = "%y-%m-%d %H:%M"


def moment(at: datetime) -> str:
    """`yy-mm-dd hh:mm:ss`, in the reader's clock; as written when it carries no zone."""

    return (at if at.tzinfo is None else metrics.shown(at)).strftime(TIMESTAMP)


def day(at: datetime) -> str:
    """`yy-mm-dd`, in the reader's clock."""

    return metrics.shown(at).strftime(DAY)


def time_of_day(at: datetime) -> str:
    """`hh:mm:ss`, in the reader's clock."""

    return metrics.shown(at).strftime(TIME)


def picked(local: datetime) -> str:
    """A picker's bound, `yy-mm-dd hh:mm`, from a moment already in the reader's clock."""

    return local.strftime(PICKED)


def picked_midnight(local: datetime) -> str:
    """The start of that day, as the picker offers it."""

    return local.strftime(DAY) + " 00:00"
