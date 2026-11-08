"""A cluster's deploys, drawn as bands behind its traffic line (B496, 8; 26-11-08).

The question a traffic card is opened with is often "did this start when we
deployed?", and until now the answer meant holding the card beside the Jobs
page and lining up two clocks by eye. A band puts the deploy where it happened
on the line itself.

**A band is the job's time, not the moment a node switched.** The job runs from
the first status reading to the last node's verification, and somewhere inside
that a node reloaded HAProxy; nothing finer is recorded. So the band says when
the cluster was being changed, and a dip beside it is a correlation for the
reader to weigh, never a cause this page asserts.

**Drawn on the line's own bucket edges.** A deploy takes a minute or two, which
is a sliver of a 24-hour line and less than a pixel of a week; a band as wide as
its seconds would be invisible exactly where it is needed. So it covers every
bucket the job touched, from the bucket it started in to the bucket it ended
in, computed with the same `metrics.bucket_of` the line is bucketed with - the
band and the bucket under the pointer then always agree about where a moment is.

**A job that changed no node is not drawn.** A deploy that found every node
already on its version, or that was refused before the first node, did nothing
to the traffic, and a band for it would be a false lead on the very question
the band is for. Whether a node was touched is read from the job's own node
lines; a job whose answer cannot be read - still running, or an outcome nobody
recorded - is drawn, since hiding a deploy that did reach a node is the worse
mistake of the two.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

from haprion_ui import jobs, metrics, moments
from haprion_ui.db import Job

type BandTone = Literal["done", "warning", "failed", "running"]

#
# The operations that can end in a configuration deploy: the deploy itself, a
# *Publish & deploy* (B257) and a node change deployed in the same job (B321).
# A revert publishes and stops, and a certificate deploy has no configuration
# version to name; neither is a band. `db.deploy_jobs` asks for these.
#
OPERATIONS = ("deploy", "changes_publish", "cluster_node")

#
# A node line that says the deploy reached the node: it installed the release,
# or tried to and failed - a failed reload is the change most likely to show
# on the line. `current`, `not_attempted` and `unavailable` left it alone.
#
_TOUCHED = frozenset({"updated", "failed"})


@dataclass(frozen=True, slots=True)
class DeployBand:
    """One deploy, placed in the card's drawing and said in words."""

    #
    # In the drawing's own units (`metrics.SPARK_WIDTH` across), like the
    # line and its hover targets.
    #
    x: float
    width: float
    #
    # Where the band begins and ends across the card, as percentages, for the
    # box that names it: placed in the page rather than in the stretched SVG.
    #
    left: float
    right: float
    tone: BandTone
    #
    # "Deploy v25", and what happened in the reader's clock:
    # "failed on node-b · 07:41:12–07:43:40".
    #
    heading: str
    detail: str
    job_link: str
    version_link: str | None


def _envelope_result(job: Job) -> Mapping[str, Any] | None:
    envelope = job.result if isinstance(job.result, dict) else None
    body = envelope.get("result") if envelope is not None else None
    return body if isinstance(body, Mapping) else None


def _node_lines(job: Job) -> list[Mapping[str, Any]] | None:
    """The deploy's per-node lines, or None when the answer does not carry them."""

    body = _envelope_result(job)
    lines = body.get("nodes") if body is not None else None
    if not isinstance(lines, list):
        return None
    return [line for line in lines if isinstance(line, Mapping)]


def is_deploy(job: Job) -> bool:
    """Whether this job ran, or is running, a configuration deploy.

    A finished job is asked through `jobs.ending_step`, the one reading of
    which helper a job ended in: a *Publish & deploy* whose publish failed
    never deployed, and its state is the publish's. A running one has no
    answer yet and is judged by what it was asked to do.
    """

    if job.operation not in OPERATIONS:
        return False
    payload = job.payload if isinstance(job.payload, dict) else {}
    asked = job.operation == "deploy" or payload.get("deploy") is True
    if not asked:
        return False
    if job.state == "running":
        return True
    return jobs.ending_step(job) == "deploy"


def touched_a_node(job: Job) -> bool:
    """Whether the deploy reached a node, or nothing says it did not."""

    if job.state in ("running", "unknown"):
        return True
    lines = _node_lines(job)
    if lines is None:
        return True
    return any(line.get("outcome") in _TOUCHED for line in lines)


def _version(job: Job) -> tuple[int | None, str | None]:
    """The version the deploy was for, and its commit, when the job recorded them."""

    body = _envelope_result(job)
    target = body.get("target") if body is not None else None
    if isinstance(target, Mapping):
        number = target.get("version")
        commit = target.get("hash")
        return (
            number if isinstance(number, int) and not isinstance(number, bool) else None,
            commit if isinstance(commit, str) and commit else None,
        )
    payload = job.payload if isinstance(job.payload, dict) else {}
    asked = payload.get("expected_version")
    return (asked if isinstance(asked, int) and not isinstance(asked, bool) else None), None


def _failed_nodes(job: Job) -> tuple[str, ...]:
    named: list[str] = []
    for line in _node_lines(job) or ():
        name = line.get("name")
        if line.get("outcome") == "failed" and isinstance(name, str) and name not in named:
            named.append(name)
    return tuple(named)


def _outcome(job: Job) -> tuple[BandTone, str]:
    """The band's colour and the words for how the deploy ended."""

    if job.state == "running":
        return "running", "running"
    if job.state == "done":
        return "done", "done"
    if job.state == "partial":
        nodes = jobs.unreconciled_nodes(job)
        return "warning", "completed with gaps" + (f" on {', '.join(nodes)}" if nodes else "")
    if job.state == "blocked":
        return "warning", "stopped part-way"
    if job.state == "unknown":
        return "failed", "outcome unknown"
    nodes = _failed_nodes(job)
    return "failed", "failed" + (f" on {', '.join(nodes)}" if nodes else "")


def _span(began: datetime, ended: datetime | None, *, long_window: bool) -> str:
    """When, in the reader's clock and the app's one format: the day too once the window spans days."""

    start = moments.moment(began) if long_window else moments.time_of_day(began)
    if ended is None:
        return f"since {start}"
    same_day = metrics.shown(ended).date() == metrics.shown(began).date()
    end = moments.time_of_day(ended) if same_day else moments.moment(ended)
    return f"{start}–{end}"


def bands(
    found: Iterable[Job],
    *,
    start: datetime,
    end: datetime,
    bucket: timedelta,
    now: datetime,
    width: float = metrics.SPARK_WIDTH,
) -> tuple[DeployBand, ...]:
    """The deploys among `found` that fall in the window, oldest first."""

    seconds = (end - start).total_seconds()
    if seconds <= 0 or bucket <= timedelta(0):
        return ()
    long_window = end - start > timedelta(days=1)
    drawn: list[DeployBand] = []
    for job in sorted(found, key=lambda entry: (entry.started_at or now, entry.id)):
        if job.started_at is None or not is_deploy(job) or not touched_a_node(job):
            continue
        ended = job.finished_at if job.state != "running" else None
        last = ended or now
        if last < start or job.started_at > end:
            continue
        first_edge = metrics.BUCKET_EPOCH + bucket * metrics.bucket_of(job.started_at, bucket)
        last_edge = metrics.BUCKET_EPOCH + bucket * (metrics.bucket_of(last, bucket) + 1)
        left = max((first_edge - start).total_seconds() / seconds, 0.0)
        right = min((last_edge - start).total_seconds() / seconds, 1.0)
        if right <= left:
            continue
        tone, words = _outcome(job)
        number, commit = _version(job)
        cluster = job.cluster or ""
        drawn.append(
            DeployBand(
                x=left * width,
                width=(right - left) * width,
                left=round(left * 100, 2),
                right=round(right * 100, 2),
                tone=tone,
                heading=f"Deploy v{number}" if number is not None else "Deploy",
                detail=f"{words} · {_span(job.started_at, ended, long_window=long_window)}",
                job_link=f"/jobs?job={job.id}#job-{job.id}",
                version_link=(
                    f"/history/{quote(cluster, safe='')}/versions/{quote(commit, safe='')}"
                    if commit is not None and cluster
                    else None
                ),
            )
        )
    return tuple(drawn)


def by_cluster(
    found: Sequence[Job],
    clusters: Iterable[str],
    *,
    start: datetime,
    end: datetime,
    bucket: timedelta,
    now: datetime,
) -> dict[str, tuple[DeployBand, ...]]:
    """Each cluster's bands, for a page that draws more than one cluster's cards."""

    return {
        cluster: bands(
            (job for job in found if job.cluster == cluster),
            start=start,
            end=end,
            bucket=bucket,
            now=now,
        )
        for cluster in clusters
    }
