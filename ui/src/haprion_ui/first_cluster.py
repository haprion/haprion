"""The guide through the first cluster (B315, mock approved 26-10-15).

A new installation shows *Set up your first cluster* on the dashboard instead
of an empty page: *Name and address*, *First node*, *Second node*, *Deploy*,
*Done*. Each step is the operation that already exists - *Create cluster* with
the first node's block, *Add node*, the deploy - so the guide holds no state of
its own. Which step is shown is read from what the installation is: no
cluster, a cluster being created, one with one node or two and nothing
deployed, a deploy running. Two things the system cannot tell are carried in
the address: that the second node was skipped, and that the deploy was
started here, so its outcome is shown as *Done* rather than as the dashboard.

Only an admin on an installation that writes sees it, and only for the first
cluster: once a cluster has been deployed, or a second one exists, the
dashboard is the dashboard.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from haprion_ui import dashboard, jobs
from haprion_ui.cluster_nodes import Creating
from haprion_ui.db import Job
from haprion_ui.jobs import InFlight

STEPS = ("Name and address", "First node", "Second node", "Deploy", "Done")
#
# The node package the CLI release carries (B302), offered for download on the
# node steps under the name `apt` expects, with its version.
#
RELEASE = Path("/opt/haprion/current")
NODE_PACKAGE = RELEASE / "haprion-node.deb"


def node_package_name(release: Path | None = None) -> str:
    """`haprion-node_<version>_all.deb`, as the release records it; a plain name without one."""

    try:
        installation = (release or RELEASE) / "INSTALLATION.json"
        record = json.loads(installation.read_text()).get("node_package")
        version = record.get("version") if isinstance(record, dict) else None
    except (OSError, ValueError, AttributeError):
        version = None
    if isinstance(version, str) and VERSION.fullmatch(version):
        return f"haprion-node_{version}_all.deb"
    return "haprion-node_all.deb"


#
# What the address may say (above). Anything else is ignored.
#
SKIP = "skip"
VERSION = re.compile(r"^[0-9A-Za-z.+~-]{1,128}$")
DEPLOYING = "deploying"


@dataclass(frozen=True, slots=True)
class Joined:
    name: str
    host: str


@dataclass(frozen=True, slots=True)
class Guide:
    step: int
    cluster: str = ""
    joined: tuple[Joined, ...] = ()
    #
    # What runs now, in the words of the job's badge; while it does, the step
    # shows only that.
    #
    busy: InFlight | None = None
    problem: str | None = None
    vip: str = ""
    #
    # The deploy's outcome on *Done*: which node carries the address and which
    # stand by.
    #
    owner: str = ""
    standby: tuple[str, ...] = ()
    form: Mapping[str, str] = field(default_factory=dict)

    @property
    def current(self) -> tuple[int, str]:
        """The step shown, as its number and name, for the getting started row (B328)."""

        return self.step, STEPS[self.step - 1]

    @property
    def resumed(self) -> tuple[int, str, str]:
        """Where the getting started row's Continue leads: step, name and address (B328).

        The second node is the one step that may be skipped, and Skip is said
        only in the address - so Continue from the dashboard opened *Second
        node* again after it had been skipped (review 26-10-24, 12-11). Once
        the first node has joined, the deploy is what must still happen: the
        row leads there, and the deploy step's Back returns to the second node.
        """

        if self.step == 3 and self.busy is None:
            return 4, STEPS[3], "/first-cluster?first-cluster=" + SKIP
        return self.step, STEPS[self.step - 1], "/first-cluster"

    @property
    def steps(self) -> list[tuple[int, str, str]]:
        """(number, name, state) per step: `is-done`, `is-current` or ``."""

        return [
            (
                number,
                name,
                "is-done" if number < self.step else "is-current" if number == self.step else "",
            )
            for number, name in enumerate(STEPS, 1)
        ]


def _nodes(reading: Any | None) -> list[Mapping[str, Any]]:
    result = getattr(reading, "result", None)
    nodes = result.get("nodes") if isinstance(result, Mapping) else None
    return [node for node in nodes or () if isinstance(node, Mapping)]


def joined(reading: Any | None) -> tuple[Joined, ...]:
    return tuple(
        Joined(str(node.get("name", "")), str(node.get("mgmt_host", "")))
        for node in _nodes(reading)
        if node.get("name")
    )


def _owner(reading: Any | None) -> tuple[str, tuple[str, ...]]:
    owner, standby = "", []
    for node in _nodes(reading):
        status = node.get("status")
        vip = status.get("vip") if isinstance(status, Mapping) else None
        if isinstance(vip, Mapping) and vip.get("owner") is True:
            owner = str(node.get("name", ""))
        else:
            standby.append(str(node.get("name", "")))
    return owner, tuple(standby)


def guide(
    *,
    clusters: Collection[str],
    reading: Any | None,
    creations: Iterable[Creating],
    busy: Mapping[str, InFlight],
    vip: str,
    phase: str,
    deployed_recently: bool,
    failure: str | None = None,
) -> Guide | None:
    """The step to show, or None when the dashboard is the dashboard.

    `reading` is the one cluster's newest status, `busy` what each cluster's
    job is doing (`jobs.in_flight`), `vip` the cluster's address as the
    network says it, `phase` what the address carries. `deployed_recently`
    says the cluster's newest deploy finished, which is when *Done* may be
    shown for a deploy started from the guide; `failure` what the cluster's
    newest node change or deploy said when it did not work.
    """

    if not clusters:
        for creating in creations:
            if creating.running is not None:
                return Guide(step=2, cluster=creating.cluster, busy=creating.running)
            return Guide(
                step=2, cluster=creating.cluster, problem=creating.message, form=creating.asked
            )
        return Guide(step=1)
    if len(clusters) != 1:
        return None
    cluster = next(iter(clusters))
    nodes = joined(reading)
    running = busy.get(cluster)
    if reading is None:
        #
        # Not read by the poller yet: still the first node's step while its job
        # runs; otherwise the dashboard says it waits for the first reading.
        #
        return Guide(step=2, cluster=cluster, busy=running) if running else None
    if not dashboard.not_deployed(reading):
        if phase == DEPLOYING and deployed_recently and running is None:
            owner, standby = _owner(reading)
            return Guide(
                step=5, cluster=cluster, joined=nodes, vip=vip, owner=owner, standby=standby
            )
        return None
    if running is not None:
        step = 4 if phase == DEPLOYING else 3
        return Guide(step=step, cluster=cluster, joined=nodes, busy=running, vip=vip)
    if phase == DEPLOYING and deployed_recently:
        #
        # Deployed, and the poller has not read the nodes since.
        #
        return Guide(
            step=4, cluster=cluster, joined=nodes, busy=InFlight("Reading the nodes"), vip=vip
        )
    if len(nodes) < 2 and phase != SKIP:
        return Guide(step=3, cluster=cluster, joined=nodes, vip=vip, problem=failure)
    return Guide(step=4, cluster=cluster, joined=nodes, vip=vip, problem=failure)


def deployed_recently(recent: Iterable[Job], cluster: str) -> bool:
    """Whether the cluster's newest deploy has finished well."""

    for job in recent:
        if job.cluster == cluster and job.operation == "deploy":
            return job.state == "done"
    return False


def failure(recent: Iterable[Job], cluster: str) -> str | None:
    """What the cluster's newest node change or deploy said, when it did not work."""

    for job in recent:
        if job.cluster == cluster and job.operation in {"cluster_node", "deploy"}:
            if job.state in jobs.ATTENTION:
                return jobs.error_message(job) or jobs.failure_label(job)
            return None
    return None
