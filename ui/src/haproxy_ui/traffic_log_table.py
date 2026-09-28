"""The traffic log page's sortable table (THEME.md, Sortable tables).

Kept apart from `traffic_logs`, which the engine's own suite loads by path in an
environment without this package: the reader must import nothing from it.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from haproxy_ui import sorting


def _address(value: str) -> tuple[Any, ...] | None:
    """An address as a reader orders it: by number, a name after the numbers.

    Text order would put 192.0.2.10 before 192.0.2.9. A destination may carry a
    port and may be a name rather than an address.
    """

    if not value:
        return None
    host, port = value, 0
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        head, _, tail = value.rpartition(":")
        if head and tail.isdigit():
            host, port = head.strip("[]"), int(tail)
        try:
            parsed = ipaddress.ip_address(host)
        except ValueError:
            return (1, 0, 0, host.casefold(), port)
    return (0, parsed.version, int(parsed), "", port)


#
# The page sorts the rows it read - the newest matches, at most `max_lines` -
# and never asks the database for another order: the query stays the one the
# primary key answers in milliseconds at any volume. Newest first is the
# default; a tie keeps it.
#
TABLE = sorting.Table(
    columns=(
        sorting.Column("time", lambda row, _: row.at, descending_first=True),
        sorting.Column("node", lambda row, _: (row.cluster.casefold(), row.node.casefold())),
        sorting.Column("client", lambda row, _: _address(row.client)),
        sorting.Column(
            "request",
            lambda row, _: (row.host.casefold(), row.path.casefold(), row.method.casefold()),
        ),
        sorting.Column("status", lambda row, _: row.status, descending_first=True),
        sorting.Column("destination", lambda row, _: _address(row.server)),
        sorting.Column("bytes", lambda row, _: row.bytes, descending_first=True),
    ),
    cookie="haproxy_ui_logs_sort",
    path="/logs",
)
