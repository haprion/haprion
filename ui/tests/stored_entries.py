"""Rows for the page's tests: a JSON record read as the database would hand it back.

The collector's import (`haprion.traffic_collector._database_row`) is what
decides what a row may hold; this only gives a test an `Entry` without a
database.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from haprion_ui.traffic_logs import Entry


def entry_of(line: bytes, cluster: str, node: str) -> Entry:
    value = json.loads(line)
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError("unsupported record")
    return Entry(
        cluster=cluster,
        node=node,
        at=datetime.fromtimestamp(value["at"], UTC),
        request=value.get("request", 0),
        client=value["client"],
        method=value["method"],
        host=value["host"],
        path=value["path"],
        frontend=value["frontend"],
        backend=value["backend"],
        server=value["server"],
        status=value["status"],
        request_time=value["request_time"],
        queue_time=value["queue_time"],
        connect_time=value["connect_time"],
        response_time=value["response_time"],
        total_time=value["total_time"],
        bytes=value["bytes"],
        rule=value.get("rule", ""),
    )
