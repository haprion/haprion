"""Whether root's file for a list is what the database's row says (B534, PW02).

Shared by the path lists and the blocklists: both are saved in the database and
written by a job to a file only root reads, and both can drift apart - a
database restored from an older dump, an apply that did not finish, a file
changed by hand. The poller reads each file's revision and a digest of what it
says (`db.ListFile`); this compares them with the row.
"""

from __future__ import annotations

from datetime import datetime

from haprion_ui import db


def in_step(
    *,
    revision: int,
    digest: str | None,
    file: db.ListFile | None,
    job: db.Job | None,
    read_at: datetime | None,
) -> bool:
    """Whether the file is the row's: the same revision and the same digest.

    The reading is up to a poll old. An apply of this revision that finished
    after the reading was made is taken to have done its work, so a card does
    not say *Not applied* in the seconds before the next reading. Where
    nothing has been read at all (`read_at` None, the time of the poller's last
    reading), nothing is known and the row is let be. A reading that found no
    files still has a time: a row without its file is then not in step (review
    26-11-24, PW02). A row whose digest cannot be made (`None`) is never in step.
    """

    if (
        file is not None
        and digest is not None
        and file.revision == revision
        and file.digest == digest
    ):
        return True
    done = (
        job is not None
        and job.state == "done"
        and job.payload.get("revision") == revision
        and job.payload.get("remove") is not True
    )
    if done and job is not None:
        seen = file.seen_at if file is not None else read_at
        if seen is None or (job.finished_at is not None and seen < job.finished_at):
            return True
    return False
