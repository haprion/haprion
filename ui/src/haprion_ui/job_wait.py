"""Waiting from a root tool for a job the worker runs (Fas 23).

A command that queues a job and ends before the worker has run it leaves its
caller to find out later whether it worked - and, for the certificate jobs,
holds the queue against its own next change. `haprion-profiles` and
`haprion-settings` wait here instead, reading the job's row as the job page
does, and say why a job that did not end `done` ended as it did.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from haprion_ui import db

WAIT_SECONDS = 120.0


def finished(
    connection: Any, job_id: int, *, wait: float, sleep: Callable[[float], None]
) -> tuple[str, str]:
    """The job's final state and, when it did not apply, why."""

    deadline = time.monotonic() + wait
    while True:
        state = db.job_state(connection, job_id) or "unknown"
        connection.commit()
        if state not in ("pending", "running"):
            break
        if time.monotonic() >= deadline:
            return (
                state,
                f"job {job_id} is still {state} after {wait:.0f} s; is the worker running?",
            )
        sleep(0.5)
    if state == "done":
        return state, ""
    with connection.cursor() as cursor:
        cursor.execute(
            "select coalesce(result->'error'->>'message', stderr_excerpt, '') from job "
            " where id = %(id)s",
            {"id": job_id},
        )
        row = cursor.fetchone()
    return state, f"job {job_id} ended {state}: {row[0] if row else ''}".rstrip(": ")
