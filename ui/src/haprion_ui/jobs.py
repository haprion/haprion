"""The safe, reader-visible projection of queued management jobs.

The job table is an operation record, not a way to control an operation.  It
deliberately leaves out claim tokens, idempotency keys and payload internals:
none answers the question a reader has after pressing a button, and several
would make an implementation detail into part of the UI contract.

Two things a failure needs are here, and both were missing until 2026-08-31.

The **error code** is the stable, environment-independent string the helper
blamed. The worker already keeps it in the audit trail because it is the one
part of a failure a person can act on months later - it simply never reached a
page, so `failed / exit 65` was the whole of what a reader was told, and a
locked cluster, a moved target and a refused validation looked identical.

The **diagnostics** are the operation's redacted stderr, and they are shown to
an admin only. The frozen contract says raw stderr is never returned to a
*reader role*; hiding it from everyone was a habit rather than a decision, and
the cost of that habit fell on the one person who had to open an SSH session at
every failure. See B44.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from haprion import exit_codes, node_enrollment, server_names
from haprion.deploy_run import CERTIFICATES_NOT_DEPLOYED
from haprion.restore_agent import RUN_ID

from haprion_ui import diagnostics, moments
from haprion_ui.dashboard import relative_age
from haprion_ui.db import ClusterStatus, Job

type Tone = Literal["healthy", "warning", "critical", "info", "unknown"]


@dataclass(frozen=True, slots=True)
class JobView:
    id: int
    operation: str
    cluster: str
    state: str
    state_label: str
    tone: Tone
    requested: str
    requested_iso: str
    requested_at: str
    started: str
    finished: str
    exit_code: str
    exit_meaning: str
    #
    # What is still owed after a job that succeeded. A revert publishes but does
    # not roll out, so a job that reads `Completed` can leave the nodes on the
    # previous version - which is the one case where the state column alone is
    # actively misleading. The helper answers this in its result; until it was
    # projected here it was answered to nobody.
    #
    follow_up: str | None = None
    next_command: str | None = None
    #
    # Who queued it (B275), from the `queue_job` row beside it; empty for a
    # job nobody queued from the interface.
    #
    by: str = ""
    #
    # Verbatim, never translated. A table mapping codes to friendlier sentences
    # would be a second place that has to stay in step with the contract - the
    # drift the exit column's own table had until it read the engine's - and
    # the code says more to somebody with proxy experience than a paraphrase
    # would.
    #
    error_code: str | None = None
    #
    # The helper's own sentence beside the code, for an admin, as the
    # diagnostics are: the sentence can name paths and hosts, which is why
    # the page showed the code alone from 2026-08-31. Until 2026-09-21 that
    # left a `publish_failed` whose sentence said "the certificate expires in
    # 3 days" as a word nobody could act on, and the diagnostics panel was
    # no help - a refusal written as an envelope prints nothing on stderr.
    # Bounded by the contract (2048).
    #
    error_message: str | None = None
    #
    # A partial run's reason, and what a deploy that completed warned about
    # (review 26-10-24, 02-03): a partial deploy names its reason among the
    # warnings rather than as an error, and a deploy that left the VIP unowned
    # read as a clean `Completed`. The codes for everybody, the sentences on
    # the same terms as `error_message`.
    #
    warning_codes: str = ""
    warning_message: str | None = None
    #
    # Admin only, and empty for everyone else. Not merely hidden in the
    # template: the projection never carries it, so a role that may not see it
    # cannot be shown it by a later change to a page.
    #
    diagnostics: str | None = None
    #
    # What a batch operation did, row by row, in one line: a certificate
    # deletion's removed, refused and incomplete IDs with the reason beside
    # each refused one. Shown when a row did not go - a `partial` is the
    # normal shape of a cleanup with one refusal in it, and the person wants
    # to know which - and not for a `done`, where the job's own row says it.
    #
    note: str | None = None
    #
    # Queued before the manager last started, and waiting for an admin's Run
    # or Discard (0082). The worker takes nothing held until then.
    #
    held: bool = False
    #
    # Where the job belongs, when that is a page of its own: a node restore's
    # three jobs are steps of one run, and the run's page is the only place
    # its next step can be taken. Without this nothing led back to it.
    #
    link: str | None = None


RESTORE_OPERATIONS = frozenset(
    {
        "node_restore_prepare",
        "node_restore_preview",
        "node_restore",
        "node_restore_discard",
        "node_restore_status",
    }
)


def _link(job: Job) -> str | None:
    """The run's page for a node restore job, when its payload names a usable run."""

    run = job.payload.get("run") if job.operation in RESTORE_OPERATIONS else None
    if isinstance(run, str) and RUN_ID.fullmatch(run):
        return f"/backups/restore/{run}"
    return None


@dataclass(frozen=True, slots=True)
class JobOverview:
    jobs: tuple[JobView, ...]
    active_count: int
    attention_count: int
    completed_count: int


def _stamp(moment: datetime | None, now: datetime) -> str:
    return "—" if moment is None else relative_age(moment, now)


def _state(state: str) -> tuple[str, Tone]:
    """Turn database state into the small vocabulary the screen promises."""

    labels: dict[str, tuple[str, Tone]] = {
        "pending": ("Queued", "info"),
        "running": ("Running", "info"),
        "done": ("Completed", "healthy"),
        "partial": ("Completed with gaps", "warning"),
        "blocked": ("Blocked", "warning"),
        "failed": ("Failed", "critical"),
        "unknown": ("Outcome unknown", "critical"),
    }
    return labels.get(state, ("Unknown", "unknown"))


#
# Every operation the worker runs has a name here, and so do the three retired
# ones the jobs page still lists from history; the fallback turned the rest
# into "Cert scep" and "Dns profile apply" (review 2026-10-22, 2-2). A test
# holds this to `operations.OPERATIONS`.
#
OPERATION_LABELS = {
    "deploy": "Deploy configuration",
    "cert_deploy": "Deploy certificates",
    "revert": "Publish reverted version",
    "network_publish": "Publish network description",
    "cluster_settings_publish": "Publish cluster settings",
    "objects_publish": "Publish proxies",
    "changes_publish": "Publish saved changes",
    "cert_issue": "Issue certificate",
    "cert_scep": "Enroll certificate",
    "cert_import": "Import certificate",
    "cert_request": "Request certificate",
    "cert_publish": "Publish certificates",
    "cert_target": "Change certificate targets",
    "cert_delete": "Delete certificates",
    "cert_receiver": "Change certificate receiver",
    "dns_profile_apply": "Apply DNS profile",
    "ndes_profile_apply": "Apply NDES profile",
    "cluster_node": "Change cluster nodes",
    "cluster_define": "Create or remove cluster",
    "server_state": "Set server state",
    "dynamic_unblock": "Unblock addresses",
    "backup_run": "Back up cluster nodes",
    "backup_schedule": "Change backup schedule",
    "node_restore_prepare": "Prepare node restore",
    "node_restore_preview": "Preview node restore",
    "node_restore": "Restore node",
    "node_restore_discard": "Discard node restore",
    "node_restore_status": "Ask node restore outcome",
}


def _operation(value: str) -> str:
    return OPERATION_LABELS.get(value, value.replace("_", " ").capitalize())


def deploys(job: Job) -> bool:
    """Whether this job deploys a cluster's configuration.

    A deploy, and the *Publish & deploy* that runs one after its publish in the
    same job (B257). The job's state is then the deploy's, so a reader that
    asks "was this cluster deployed" asks it of both.
    """

    if job.operation == "deploy":
        return True
    payload = job.payload if isinstance(job.payload, dict) else {}
    return job.operation == "changes_publish" and payload.get("deploy") is True


def published(job: Job) -> bool:
    """Whether a publish job recorded its version.

    A finished job, or the publish half of a *Publish & deploy* whose deploy
    did not finish: the job then ends as the deploy ended and keeps the
    publish's own answer beside it (B257). Asked only of a publish; read
    defensively, as every stored helper document is.
    """

    if job.state == "done":
        return True
    embedded = job.result.get("publish") if isinstance(job.result, dict) else None
    return isinstance(embedded, dict) and embedded.get("outcome") == "done"


#
# Where a job that runs a second helper after its own keeps its own answer:
# a Publish & deploy (B257) under `publish`, a node change deployed in the
# same job (B321) under `node`.
#
_OWN_ANSWER = {"changes_publish": "publish", "cluster_node": "node"}
_LATER_STEPS = frozenset({"deploy", "cert_deploy"})


def ending_step(job: Job) -> str:
    """The operation whose run the job's state is the outcome of.

    The job's own, unless a second helper ran after it: then the job ended as
    that run ended, and its own step - the publish, the node change - stands.
    Every page that names a job's failure or groups it asks this, so the
    dashboard, Needs attention and the jobs page cannot tell one job three ways
    (review 2026-10-22, 1B-2). The worker names the later step under `step`;
    a job finished before it did is read by the helper's operation.
    """

    result = job.result if isinstance(job.result, dict) else {}
    payload = job.payload if isinstance(job.payload, dict) else {}
    key = _OWN_ANSWER.get(job.operation)
    if key is None or payload.get("deploy") is not True or not isinstance(result.get(key), dict):
        return job.operation
    step = result.get("step")
    if step in _LATER_STEPS:
        return str(step)
    return "cert_deploy" if result.get("operation") == "cert_deploy_cluster" else "deploy"


#
# The payload field that names what an operation acted on inside its cluster.
# Listed per operation rather than read from any payload that has the field:
# an operation left out is about the cluster itself, so a field a future
# operation adds for another purpose cannot keep its failures from settling.
#
SUBJECT_FIELDS = {
    "cert_issue": "domain",
    "cert_scep": "id",
    "cert_import": "id",
    "cert_request": "id",
    "cert_receiver": "receiver",
    "cert_publish": "certificates",
    "cert_target": "certificates",
    "cert_delete": "certificates",
    "server_state": "object",
    "dynamic_unblock": "object",
}


def subject(job: Job) -> str:
    """What a job acted on inside its cluster, or "" for the cluster itself.

    Two certificate issues for two names are two questions, and so are two
    servers' states on two objects: keyed on the cluster and the operation
    alone, a later success for one ended the other's failure (review 26-10-24,
    02-02). Certificate jobs have no cluster at all.
    """

    field = SUBJECT_FIELDS.get(job.operation)
    payload = job.payload if isinstance(job.payload, dict) else {}
    value = payload.get(field) if field else None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ",".join(sorted(value))
    return ""


def step_states(job: Job) -> tuple[tuple[str, str], ...]:
    """Each step the job ran and how it ended: its own, then the one after it, if any."""

    step = ending_step(job)
    if step == job.operation:
        return ((job.operation, job.state),)
    return ((job.operation, "done"), (step, job.state))


_STEP_NOUNS = {"deploy": "deploy", "cert_deploy": "certificate deploy"}
_STEP_ENDINGS = {
    "failed": "failed",
    "blocked": "was refused",
    "partial": "reached only some nodes",
    "unknown": "gave no answer",
}


def step_note(job: Job) -> str | None:
    """What stands when the step after the job's own ended it badly, or None.

    "Publish saved changes · Failed" said nothing of the version the publish
    recorded, and a node added before its deploy failed read as a node that
    was never added (review 2026-10-22, 1B-2). The CLI says the same:
    "Published as version N; deploying it now".
    """

    step = ending_step(job)
    if step == job.operation or job.state not in _STEP_ENDINGS:
        return None
    result = job.result if isinstance(job.result, dict) else {}
    if job.operation == "changes_publish":
        envelope = result.get("publish")
        body = envelope.get("result") if isinstance(envelope, dict) else None
        version = body.get("version") if isinstance(body, dict) else None
        stands = (
            f"Published as version {version}"
            if isinstance(version, int) and not isinstance(version, bool)
            else "Published"
        )
    else:
        action = job.payload.get("action") if isinstance(job.payload, dict) else None
        stands = "The node was added" if action == "add" else "The node was removed"
    return f"{stands}; the {_STEP_NOUNS[step]} {_STEP_ENDINGS[job.state]}."


def awaiting_deployment(statuses: list[ClusterStatus]) -> frozenset[str]:
    """Clusters whose newest reading says they are not on their target.

    Read defensively, like everything else that comes out of a stored helper
    document: a reading that is missing, malformed or simply unknown is not
    evidence that a cluster is behind, and a job should not be captioned on a
    guess.
    """

    pending = set()
    for status in statuses:
        result = status.result if isinstance(status.result, dict) else {}
        summary = result.get("summary")
        state = summary.get("release_state") if isinstance(summary, dict) else None
        #
        # `behind`, or `incomplete` with a node that answered and is off the
        # target. `unknown` and an `incomplete` whose answering nodes are all
        # current say nothing about a deploy being owed (review 26-10-24, 02-07).
        #
        nodes = result.get("nodes")
        if state == "behind" or (
            state == "incomplete"
            and isinstance(nodes, list)
            and any(isinstance(node, dict) and node.get("current") is False for node in nodes)
        ):
            pending.add(status.cluster)
    return frozenset(pending)


def _owes_deployment(job: Job) -> tuple[bool, str | None]:
    """Whether this job recorded that a deploy was still owed when it ran.

    Read defensively. The document is written by a privileged helper and stored
    as it arrived, so this asks it questions rather than assuming its shape.

    A certificate deploy that finished owes one too, by the plan's own order:
    the preflight sends somebody to `cert-deploy` "followed by a new deploy",
    and nothing chains the second step on. Its envelope does not say so - the
    reconcile result has no `deployment_required` - so the answer is given
    here, and the caller still checks that the cluster is actually behind.
    """

    if job.operation == "cert_deploy" and job.state == "done" and job.cluster:
        return True, f"haprion-deploy -c {job.cluster}"

    envelope = job.result
    if not isinstance(envelope, dict):
        return False, None
    body = envelope.get("result")
    if not isinstance(body, dict) or body.get("deployment_required") is not True:
        return False, None

    command = body.get("next_command")
    return True, command if isinstance(command, str) and command else None


def _owed_sentence(job: Job) -> str:
    if job.operation == "cert_deploy":
        return (
            f"Certificates deployed, configuration not. The nodes still run the previous "
            f"configuration until {job.cluster} is deployed."
        )
    return (
        f"Published, not deployed. The nodes still run the previous version "
        f"until {job.cluster} is deployed."
    )


@dataclass(frozen=True, slots=True)
class NodeGap:
    """One node the engine named, and the certificate and CA IDs it is behind on."""

    node: str
    missing: tuple[str, ...]
    stale: tuple[str, ...]
    missing_authorities: tuple[str, ...] = ()
    stale_authorities: tuple[str, ...] = ()

    @property
    def behind(self) -> bool:
        return bool(
            self.missing or self.stale or self.missing_authorities or self.stale_authorities
        )

    def describe(self) -> str:
        parts = []
        if self.missing:
            parts.append(f"is missing {', '.join(self.missing)}")
        if self.stale:
            parts.append(f"carries an older {', '.join(self.stale)}")
        if self.missing_authorities:
            parts.append(f"is missing the CA {', '.join(self.missing_authorities)}")
        if self.stale_authorities:
            parts.append(f"carries an older CA {', '.join(self.stale_authorities)}")
        return f"{self.node} {' and '.join(parts)}"


@dataclass(frozen=True, slots=True)
class CertificateBlock:
    """A configuration deploy the engine refused because a node lacks a certificate.

    This is the one refusal the interface can offer to fix with a button: the
    engine's preflight names `cert-deploy`, and `cert-deploy` is an operation
    the queue already takes. So the standing "deploy certificates" button went
    away and this took its place - offered where the block happened and only
    while it is the newest thing known about the cluster.
    """

    cluster: str
    job_id: int
    #
    # The nodes as the engine reported them, in its order, each with what it
    # lacks. Empty when the details were not the expected shape: the code
    # alone is enough to offer the button, and a malformed detail block should
    # cost the sentence, not the offer.
    #
    gaps: tuple[NodeGap, ...]
    next_command: str

    @property
    def headline(self) -> str:
        """What is wrong, node by node, in one line.

        Node by node rather than as one merged list, because a merged list
        would say things the engine did not: two nodes missing different
        certificates would read as both missing both.
        """

        if not self.gaps:
            return "Deploy blocked: a node does not carry every certificate the version references"
        return "Deploy blocked: " + "; ".join(gap.describe() for gap in self.gaps)

    @property
    def sentence(self) -> str:
        """The headline and what to do about it, for the jobs page."""

        return (
            f"{self.headline}. Deploy the certificates first, then deploy the configuration again."
        )


def _ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _gaps(value: object) -> tuple[NodeGap, ...]:
    """The engine's per-node detail, with anything half-described left out."""

    gaps = []
    if isinstance(value, list):
        for entry in value:
            if not isinstance(entry, dict):
                continue
            node = entry.get("node")
            gap = NodeGap(
                node=node if isinstance(node, str) else "",
                missing=_ids(entry.get("missing")),
                stale=_ids(entry.get("stale")),
                missing_authorities=_ids(entry.get("missing_authorities")),
                stale_authorities=_ids(entry.get("stale_authorities")),
            )
            if gap.node and gap.behind:
                gaps.append(gap)
    return tuple(gaps)


def certificate_block(job: Job) -> CertificateBlock | None:
    """The certificate block this job ended in, or nothing.

    Read defensively for the same reason `error_code` is: the document was
    written by a privileged helper and stored as it arrived.
    """

    if ending_step(job) != "deploy" or job.state != "blocked" or not job.cluster:
        return None
    if error_code(job) != CERTIFICATES_NOT_DEPLOYED:
        return None

    details: object = None
    if isinstance(job.result, dict):
        error = job.result.get("error")
        if isinstance(error, dict):
            details = error.get("details")
    nodes: object = details.get("nodes") if isinstance(details, dict) else None
    command = details.get("next_command") if isinstance(details, dict) else None
    return CertificateBlock(
        cluster=job.cluster,
        job_id=job.id,
        gaps=_gaps(nodes),
        next_command=(
            command
            if isinstance(command, str) and command
            else f"haprion-cert-deploy -c {job.cluster}"
        ),
    )


def _newest_finished(rows: Iterable[Job]) -> dict[str, int]:
    """The id of each cluster's newest finished job. Rows arrive newest first."""

    newest: dict[str, int] = {}
    for job in rows:
        if job.cluster is None or job.cluster in newest or not ran(job):
            continue
        newest[job.cluster] = job.id
    return newest


def certificate_blocks(rows: list[Job]) -> dict[str, CertificateBlock]:
    """Clusters whose newest finished job is a deploy the preflight blocked.

    Newest, for the same reason `last_failure` reads only the newest: a block
    that a later certificate deploy cleared is history, and offering to fix it
    again would send somebody after a problem that is already gone. The next
    attempt - whichever way it ends - replaces the verdict.
    """

    newest = _newest_finished(rows)
    blocks: dict[str, CertificateBlock] = {}
    for job in rows:
        if job.cluster is None or newest.get(job.cluster) != job.id:
            continue
        block = certificate_block(job)
        if block is not None:
            blocks[job.cluster] = block
    return blocks


#
# The states that mean "this did not work". Both the follow-up row under a job
# and the "Need review" tally read it, so the two cannot drift into disagreeing
# about what counts as a bad ending.
#
ATTENTION = frozenset({"partial", "blocked", "failed", "unknown"})
#
# Warning codes that end a job `partial` while it waits on something outside
# it, rather than because it went wrong (review 26-10-24, 02-08): a request the
# CA has yet to approve, and an import whose material has not arrived.
# `source_missing` among a publish's warnings is only ever that skipped import;
# material that is there and cannot be read fails the certificate instead.
#
WAITING = {
    "request_pending": "Certificate enrollment waits for the CA",
    "source_missing": "Certificate distribution waits for imported material",
}
#
# A held job an admin chose not to run (0082). It never started, so it neither
# fails nor ends an earlier failure.
#
DISCARDED = "held_discarded"


def ran(job: Job) -> bool:
    """Whether a job finished a run: not queued, not running, not held and discarded."""

    if job.state in {"pending", "running"}:
        return False
    return not (job.state == "blocked" and error_code(job) == DISCARDED)


def warnings_of(job: Job) -> tuple[tuple[str, str], ...]:
    """The code and sentence of each warning the job's result carries, in order."""

    envelope = job.result if isinstance(job.result, dict) else {}
    listed = envelope.get("warnings")
    found = []
    for entry in listed if isinstance(listed, list) else ():
        code = entry.get("code") if isinstance(entry, dict) else None
        if isinstance(code, str) and code:
            message = entry.get("message")
            found.append((code, message.strip() if isinstance(message, str) else ""))
    return tuple(found)


def waiting_for(job: Job) -> str | None:
    """What a `partial` job waits on, when every warning it carries is a wait."""

    codes = {code for code, _ in warnings_of(job)}
    if job.state != "partial" or not codes or not codes <= WAITING.keys():
        return None
    return "; ".join(WAITING[code] for code in sorted(codes))


def error_code(job: Job) -> str | None:
    """The stable code this job's result blamed, or nothing.

    Public because the proxies listing asks the same question about a publish
    that ended badly. Two readings of one envelope would be two chances to
    disagree about why something failed.

    Read defensively for the same reason `_owes_deployment` is: the document
    was written by a privileged helper and stored as it arrived, so this asks
    it questions rather than assuming its shape.
    """

    envelope = job.result
    if not isinstance(envelope, dict):
        return None
    error = envelope.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, str) and code else None


def error_message(job: Job) -> str | None:
    """The sentence the envelope's error carries, read as defensively as its code."""

    envelope = job.result
    if not isinstance(envelope, dict):
        return None
    error = envelope.get("error")
    if not isinstance(error, dict):
        return None
    message = error.get("message")
    return message.strip() if isinstance(message, str) and message.strip() else None


def diagnostics_of(job: Job) -> str | None:
    """What the operation said about why, at its most useful.

    A refusal carries its evidence in the envelope: `candidate_invalid` puts
    the whole `haproxy -c` output under `error.details.diagnostics`, which
    names the file and the line HAProxy would not accept. Until this read it,
    the page showed `stderr_excerpt` instead - and for a clean refusal that is
    the one line the helper prints, `ERROR: [code] message`. So the most
    important failure in the system, "this configuration does not compile",
    arrived without the compiler's answer, and somebody was left to guess which
    line was wrong.

    The excerpt stays as the fallback. A failure that is not a refusal - a
    helper that died, a timeout - has no envelope to read, and its stderr is
    then the only account there is.

    Read defensively for the same reason `error_code` is: the document was
    written by a privileged helper and stored as it arrived.
    """

    envelope = job.result
    if isinstance(envelope, dict):
        error = envelope.get("error")
        if isinstance(error, dict):
            details = error.get("details")
            if isinstance(details, dict):
                text = details.get("diagnostics")
                if isinstance(text, str) and text.strip():
                    #
                    # Again on the way out: a row stored before the worker
                    # redacted this field is shown masked all the same.
                    #
                    return diagnostics.redact(text)
    return job.stderr_excerpt or None


def publication_note(job: Job) -> str | None:
    """An unpublished node list (B318) or a removed node still running (B319), in the helper's words.

    The change itself stands, so the job is done; what it did not do is said
    here, or the cluster's release would quietly lack the node.
    """

    if job.operation not in {"cluster_node", "cluster_define"} or not isinstance(job.result, dict):
        return None
    #
    # A node change deployed in the same job (B321) ends as the deploy ended,
    # with its own answer beside it under `node`.
    #
    embedded = job.result.get("node")
    envelope = embedded if isinstance(embedded, dict) else job.result
    body = envelope.get("result")
    publication = body.get("publication") if isinstance(body, dict) else None
    error = publication.get("error") if isinstance(publication, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    #
    # A removed node that did not stop (B319): it takes the cluster's
    # addresses if it is started again, which is what the job must say.
    #
    step_down = body.get("step_down") if isinstance(body, dict) else None
    left = step_down.get("message") if isinstance(step_down, dict) else None
    notes = []
    if isinstance(message, str) and message.strip():
        notes.append(f"The node list was not published: {message.strip()}")
    if isinstance(left, str) and left.strip():
        notes.append(left.strip())
    #
    # A cloned machine (fynd 43, B335): the addition stands, and this says why
    # it should not stay that way. A creation carries it among its warnings.
    #
    answer: dict[str, Any] = body if isinstance(body, dict) else {}
    shared = answer.get("shares_host_key_with")
    if isinstance(shared, list) and shared:
        names = [str(name) for name in shared]
        notes.append(node_enrollment.shared_key_warning(str(answer.get("node", "")), names) + ".")
    warnings = answer.get("warnings")
    if isinstance(warnings, list):
        notes += [f"{text.strip()}." for text in warnings if isinstance(text, str) and text.strip()]
    return " ".join(notes) or None


def unresolved_note(job: Job) -> str | None:
    """A published server name the manager cannot resolve (finding 72), in the engine's words.

    The publish stands; a node that cannot resolve the name either stops the
    deploy, and this says so before somebody presses it. A *Publish & deploy*
    keeps the publish's own answer under `publish` (B257).
    """

    if job.operation != "changes_publish" or not isinstance(job.result, dict):
        return None
    embedded = job.result.get("publish")
    envelope = embedded if isinstance(embedded, dict) else job.result
    body = envelope.get("result")
    names = body.get("unresolved_servers") if isinstance(body, dict) else None
    if not isinstance(names, list):
        return None
    said = [server_names.warning(name) for name in names if isinstance(name, str) and name]
    return ". ".join(said) + "." if said else None


#
# What to look at before trying again, for a job whose outcome is unknown
# (review 2026-10-20, V1). The answer never came, so the operation may have
# taken effect; the sentence points at where that shows. No Retry button: a
# second certificate request issues a second certificate, and a second deploy
# is a different question from the first.
#
_DEPLOYED = (
    "It may have run on some nodes. Check the cluster on the Dashboard before deploying again."
)
_CERTIFICATE = (
    "It may have taken effect. Check the certificate under Certificates before trying again."
)
_ISSUED = (
    "A certificate may have been issued. Check Certificates before asking again:"
    " a second request issues a second certificate."
)
_RESTORE = "Check the restore's page for where the run stands before acting on it again."
UNKNOWN_NEXT: dict[str, str] = {
    "deploy": _DEPLOYED,
    "cert_deploy": _DEPLOYED,
    "changes_publish": "It may have been published. Check Versions before publishing again.",
    "revert": "It may have been published. Check Versions before publishing again.",
    "cluster_define": "It may have changed the cluster list. Check Settings before trying again.",
    "cluster_node": "It may have changed the cluster's nodes. Check Settings before trying again.",
    "server_state": "It may have taken effect. Check the server's state on its proxy before setting it again.",
    "dynamic_unblock": "It may have taken effect. Check the proxy's blocked addresses before unblocking again.",
    "backup_run": "An archive may have been taken. Check Node backups before running it again.",
    "backup_schedule": "Check the schedule on Node backups before changing it again.",
    "cert_issue": _ISSUED,
    "cert_request": _ISSUED,
    "cert_scep": _ISSUED,
    "cert_import": "It may have been imported. Check Certificates before importing again.",
    "cert_publish": _CERTIFICATE,
    "cert_delete": _CERTIFICATE,
    "cert_target": _CERTIFICATE,
    "cert_receiver": "It may have taken effect. Check the receiver under Certificates before trying again.",
    "dns_profile_apply": "Check the profile under Settings before applying it again.",
    "ndes_profile_apply": "Check the profile under Settings before applying it again.",
    "node_restore_prepare": _RESTORE,
    "node_restore_preview": _RESTORE,
    "node_restore": _RESTORE,
    "node_restore_discard": _RESTORE,
    "node_restore_status": _RESTORE,
}


def unknown_note(job: Job) -> str | None:
    if job.state != "unknown":
        return None
    #
    # Asked of the step that gave no answer: a Publish & deploy whose publish
    # never answered points at Versions, not at the nodes (1B-2).
    #
    return UNKNOWN_NEXT.get(
        ending_step(job), "It may have taken effect. Check what it changes before trying again."
    )


def deletion_note(job: Job) -> str | None:
    """One sentence per state for a `cert_delete` or `cert_target` result, or None.

    The two share a row shape - one certificate, one state, layers and node
    copies where something was removed - and so share the sentence.
    """

    if job.operation not in {"cert_delete", "cert_target"} or not isinstance(job.result, dict):
        return None
    body = job.result.get("result")
    if not isinstance(body, dict) or not isinstance(body.get("certificates"), list):
        return None
    removed: list[str] = []
    refused: list[str] = []
    incomplete: list[str] = []
    deleting = job.operation == "cert_delete"
    done_word = "Deleted" if deleting else "Changed"
    for entry in body["certificates"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("certificate"), str):
            continue
        identifier = entry["certificate"]
        state = entry.get("state")
        if state in {"removed", "changed"}:
            removed.append(identifier)
        elif state == "refused":
            refused.append(_with_reason(identifier, entry))
        elif state == "incomplete":
            kept = [
                f"{layer.get('layer')} {layer.get('state')}"
                for layer in entry.get("layers") or []
                if isinstance(layer, dict) and layer.get("state") in {"kept", "failed"}
            ]
            kept += [
                f"{node.get('node')} {node.get('state')}"
                for node in entry.get("nodes") or []
                if isinstance(node, dict) and node.get("state") != "removed"
            ]
            #
            # A deletion that stopped half-way says what it left standing; a
            # target change that stopped half-way has registered the target
            # and not published to it, and the helper's reason says why. The
            # reason is the useful half: the operator saw the state already.
            #
            if kept:
                incomplete.append(f"{identifier} ({', '.join(kept)})")
            else:
                incomplete.append(_with_reason(identifier, entry))
    if not refused and not incomplete:
        return None
    parts = []
    if removed:
        parts.append(f"{done_word}: " + ", ".join(removed))
    if refused:
        parts.append("Refused: " + "; ".join(refused))
    if incomplete:
        lead = (
            "Left; delete them again to finish: "
            if deleting
            else "Registered but not published; publish again once the cause is fixed: "
        )
        parts.append(lead + "; ".join(incomplete))
    return ". ".join(parts) + "."


def _with_reason(identifier: str, entry: dict[str, Any]) -> str:
    """`<id> (<code>) - <reason>`, with whichever halves the row carries.

    The code alone was what the page showed first, and an operator reading
    `https_receiver_isolated` beside a refused job had to go to the database
    for the sentence that explains it. The helper wrote that sentence for
    exactly this reader; it is shown as written.
    """

    code = entry.get("code")
    reason = entry.get("reason")
    text = f"{identifier} ({code})" if isinstance(code, str) and code else identifier
    if isinstance(reason, str) and reason.strip():
        text += " - " + reason.strip().rstrip(".")
    return text


def _view(
    job: Job,
    now: datetime,
    *,
    follow_up: str | None,
    next_command: str | None,
    diagnostics: bool,
) -> JobView:
    label, tone = _state(job.state)
    held = job.state == "pending" and job.held_since is not None and job.held_decision is None
    if held:
        label, tone = "Held", "warning"
    ended_badly = job.state in ATTENTION
    #
    # Every warning of a partial run; of a completed one only a deploy's, whose
    # warnings are each about the cluster (deploy_run). Other helpers' warnings
    # on success are not measured, and a note under every green row would bury
    # the ones that mean something, as the diagnostics comment below says.
    #
    warned = (
        warnings_of(job)
        if job.state == "partial"
        or (job.state == "done" and ending_step(job) in {"deploy", "cert_deploy"})
        else ()
    )
    return JobView(
        id=job.id,
        operation=named[0] if (named := action_names(job)) else _operation(job.operation),
        #
        # The same dash the other unknown cells use. A certificate job has no
        # cluster - its scope is the registry - and the column has to say that
        # rather than borrow a cluster name from somewhere to fill itself.
        #
        cluster=job.cluster or NO_CLUSTER,
        state=job.state,
        state_label=label,
        tone=tone,
        requested=_stamp(job.created_at, now),
        requested_iso=job.created_at.astimezone(UTC).isoformat(),
        requested_at=moments.moment(job.created_at),
        started=_stamp(job.started_at, now),
        finished=_stamp(job.finished_at, now),
        exit_code="—" if job.exit_code is None else str(job.exit_code),
        exit_meaning=_exit_meaning(job.exit_code),
        follow_up=follow_up,
        next_command=next_command,
        link=_link(job),
        error_code=error_code(job) if ended_badly else None,
        error_message=error_message(job) if diagnostics and ended_badly else None,
        warning_codes=", ".join(dict.fromkeys(code for code, _ in warned)),
        warning_message=(
            "; ".join(message for _, message in warned if message) or None if diagnostics else None
        ),
        #
        # Only for a job that ended badly. A successful operation's stderr is
        # progress output, and putting a diagnostics panel under every green
        # row would bury the ones that mean something.
        #
        diagnostics=diagnostics_of(job) if diagnostics and ended_badly else None,
        held=held,
        note=" ".join(
            text
            for text in (
                step_note(job),
                unknown_note(job)
                or deletion_note(job)
                or publication_note(job)
                or unresolved_note(job),
            )
            if text
        )
        or None,
    )


#
# What the number in the exit column means. It is shown because a maintainer
# reading a bad job wants the precise code, and explained because everyone else
# is being shown an implementation detail of a command they did not run. The
# words are the engine's table (review 2026-10-22, 4-1): this page kept its own,
# and 68 was "no usable status" for a certificate deploy refused for a missing
# certificate.
#
def _exit_meaning(code: int | None) -> str:
    if code is None:
        return "The job recorded no exit code."
    if code < 0:
        return f"Stopped by signal {-code}."
    return exit_codes.MEANINGS.get(code, f"The command exited with {code}.")


def _unresolved(rows: list[Job]) -> int:
    """Clusters whose newest finished job ended badly.

    Not a tally of every bad outcome in the list. That number only ever grows,
    cannot be cleared, and answers no question a reader can act on - a failure
    from yesterday that a later run replaced is history, not work. Asked on the
    page as "what needs review?", the honest answer is: the clusters where the
    last thing we did did not work.

    A queued or running job is skipped rather than counted, and the cluster is
    then judged on the newest job that did finish. So a re-run in flight neither
    clears the warning nor replaces it: what is still known about that cluster
    is that the last completed attempt failed, and it stays known until an
    attempt completes differently.

    That is deliberate, and it is the opposite of what this docstring claimed
    until 2026-08-31, when the code review measured the function against its own
    description. Counting only finished jobs and then letting a running one
    silence the tally would let an operation in progress hide a warning, which
    is the wrong direction to be wrong in.
    """

    latest: dict[str, str] = {}
    for job in rows:
        #
        # Skipped, not counted under a placeholder. This and the two summaries
        # below answer questions about clusters - what is busy, what last failed,
        # how many want attention - and a job with no cluster has no answer to
        # contribute. Letting one in would file it under a cluster that does not
        # exist, which is the shape of a warning nobody can act on.
        #
        if job.cluster is None:
            continue
        if job.cluster not in latest and ran(job):
            latest[job.cluster] = job.state
    return sum(state in ATTENTION for state in latest.values())


def build_job_overview(
    rows: list[Job],
    *,
    now: datetime | None = None,
    awaiting: frozenset[str] = frozenset(),
    diagnostics: bool = False,
) -> JobOverview:
    """Build one bounded, newest-first operation history from database rows.

    `awaiting` is what keeps the follow-up line honest. A job's result records
    what was still owed **when it ran**, which for anything but the newest such
    job is a statement about a moment that has passed - job 15 published, job 16
    deployed it, and captioning job 15 with "the nodes still run the previous
    version" was wrong within the hour. Found on 2026-08-31 by a reader looking
    at the page rather than at the row.

    So two things have to hold: the cluster has to be behind its target now, and
    this has to be the newest job that left it that way. Anything older is
    history, and history does not need a caption telling the reader to act.

    `diagnostics` says whether the caller is entitled to the operations' stderr.
    It defaults to false, so a page that forgets to ask the question gets the
    reader-safe projection rather than the privileged one.
    """

    current = now or datetime.now(UTC)
    captioned: set[str] = set()
    blocks = certificate_blocks(rows)
    views = []
    for job in rows:
        owes, command = _owes_deployment(job)
        #
        # The follow-up line names a cluster somebody has to deploy, so a job
        # without one can never carry it. Stated rather than left to the
        # membership test below, which would be false anyway but for a reason a
        # reader would have to work out.
        #
        cluster = job.cluster
        show = owes and cluster is not None and cluster in awaiting and cluster not in captioned
        if show and cluster is not None:
            captioned.add(cluster)
        #
        # A deploy the preflight refused is captioned on its own terms: the
        # cluster need not be behind its target for the block to be real, and
        # the button it gets queues the other operation. Only the job that is
        # the cluster's newest verdict carries it, which `certificate_blocks`
        # already decided.
        #
        block = blocks.get(cluster) if cluster is not None else None
        blocked = block is not None and block.job_id == job.id
        if blocked and cluster is not None:
            captioned.add(cluster)
        views.append(
            _view(
                job,
                current,
                follow_up=(
                    block.sentence
                    if blocked and block is not None
                    else _owed_sentence(job)
                    if show
                    else None
                ),
                next_command=(
                    block.next_command
                    if blocked and block is not None
                    else command
                    if show
                    else None
                ),
                diagnostics=diagnostics,
            )
        )
    jobs = tuple(views)
    return JobOverview(
        jobs=jobs,
        active_count=sum(job.state in {"pending", "running"} for job in jobs),
        attention_count=_unresolved(rows),
        completed_count=sum(job.state == "done" for job in jobs),
    )


#
# What each operation is called while it is happening. Present tense and short,
# because it is read inside a badge beside a spinner - and named here rather
# than in the template so the dashboard, the listing and anything built later
# say the same word for the same job.
#
# What the cluster column shows for an operation that has no cluster.
NO_CLUSTER = "—"

#
# One operation, several things a person did (Fas 18, 26-10-15): a node
# added, removed or moved, a cluster created or removed. Named by the action
# the job carries - the list, the running badge and the failure in the same
# words - and by the operation's own name when the payload has no action.
#
ACTION_NAMES: dict[tuple[str, str], tuple[str, str, str]] = {
    ("cluster_node", "add"): ("Add node", "Adding node", "Adding the node failed"),
    ("cluster_node", "remove"): ("Remove node", "Removing node", "Removing the node failed"),
    ("cluster_node", "host"): ("Change node host", "Changing node host", "Host change failed"),
    ("cluster_define", "add"): (
        "Create cluster",
        "Creating cluster",
        "Creating the cluster failed",
    ),
    ("cluster_define", "remove"): (
        "Remove cluster",
        "Removing cluster",
        "Removing the cluster failed",
    ),
}


def action_names(job: Job) -> tuple[str, str, str] | None:
    """The job's name, running label and failure label by its action, if it has one."""

    action = job.payload.get("action") if isinstance(job.payload, dict) else None
    return ACTION_NAMES.get((job.operation, action)) if isinstance(action, str) else None


def failure_label(job: Job, operation: str | None = None, state: str | None = None) -> str:
    """What a job that did not work is called: by the step that ended it, or by `operation`.

    `state` is how that step ended, the job's own state when left out.
    """

    operation = operation or ending_step(job)
    if operation == job.operation and (named := action_names(job)):
        return named[2]
    if (state or job.state) == "partial" and operation in PARTIAL_LABELS:
        return PARTIAL_LABELS[operation]
    return FAILURE_LABELS.get(operation, operation)


RUNNING_LABELS = {
    "backup_run": "Backing up nodes",
    "backup_schedule": "Changing backup schedule",
    "node_restore_prepare": "Preparing restore",
    "node_restore_preview": "Previewing restore",
    "node_restore": "Restoring node",
    "node_restore_discard": "Discarding restore",
    "node_restore_status": "Asking for the outcome",
    "deploy": "Deploying",
    "cert_deploy": "Deploying certificates",
    "revert": "Reverting",
    "network_publish": "Publishing addresses",
    "cluster_settings_publish": "Publishing settings",
    "objects_publish": "Publishing",
    "changes_publish": "Publishing",
    "cert_issue": "Issuing certificate",
    "cert_import": "Importing certificate",
    "cert_request": "Making signing request",
    "dns_profile_apply": "Applying DNS profile",
    "ndes_profile_apply": "Applying NDES profile",
    "cert_scep": "Enrolling certificate",
    "cert_delete": "Deleting certificates",
    "cert_publish": "Distributing certificates",
    "cert_target": "Changing certificate targets",
    "cert_receiver": "Changing receivers",
    "cluster_node": "Changing nodes",
    "cluster_define": "Changing clusters",
    "server_state": "Setting server state",
    "dynamic_unblock": "Unblocking addresses",
}


#
# What the follow-up button says, by the operation it queues. `{cluster}` is
# the cluster the job belongs to.
#


#
# What to call an operation that did not work. Past tense and short, beside the
# cluster it happened to. Named here with the running labels, so the badge that
# says a job is running and the badge that says it failed cannot come to use
# different words for the same operation.
#
#
# A run across the nodes that ended `partial` reached some of them, which is
# not what "failed" says (review 26-10-24, 02-03).
#
PARTIAL_LABELS = {
    "backup_run": "Backup reached only some nodes",
    "deploy": "Deploy reached only some nodes",
    "cert_deploy": "Certificate deploy reached only some nodes",
}
FAILURE_LABELS = {
    "backup_run": "Backup failed",
    "backup_schedule": "Schedule change failed",
    "node_restore_prepare": "Restore preparation failed",
    "node_restore_preview": "Restore preview failed",
    "node_restore": "Restore failed",
    "node_restore_discard": "Discarding the restore failed",
    "node_restore_status": "Asking for the outcome failed",
    "deploy": "Deploy failed",
    "cert_deploy": "Certificate deploy failed",
    "revert": "Revert failed",
    "network_publish": "Publish failed",
    "cluster_settings_publish": "Publish failed",
    "cluster_node": "Node change failed",
    "cluster_define": "Cluster change failed",
    "server_state": "Server state change failed",
    "dynamic_unblock": "Unblock failed",
    "objects_publish": "Publish failed",
    "changes_publish": "Publish failed",
    "cert_issue": "Certificate issue failed",
    "cert_import": "Certificate import failed",
    "cert_request": "Signing request failed",
    "dns_profile_apply": "DNS profile apply failed",
    "ndes_profile_apply": "NDES profile apply failed",
    "cert_scep": "Certificate enrollment failed",
    "cert_delete": "Certificate deletion failed",
    "cert_publish": "Certificate distribution failed",
    "cert_target": "Certificate target change failed",
    "cert_receiver": "Receiver change failed",
}


@dataclass(frozen=True, slots=True)
class Failure:
    """A cluster's newest job, when it ended badly."""

    label: str
    code: str | None


def last_failure(jobs: Iterable[Job]) -> dict[str, Failure]:
    """Clusters whose newest finished job failed, and what it blamed.

    The one thing a page describing the *machine* cannot read from the machine.
    A refused job changes nothing - the configuration is as it was, the nodes
    are content, and everything looks well precisely because nothing happened.
    So the failure is read from the jobs and it stays until a newer job for
    that cluster replaces it, which is what makes it correct itself.

    Newest first, one verdict per cluster: an older failure that the next
    attempt fixed is history, and showing it would send somebody after a
    problem that is already gone.

    A node restore neither sets nor ends the verdict. Its jobs carry the
    cluster only to hold the cluster's lock; they act on a VM, not on the
    cluster's configuration, and a preview blocked by a VM that is not empty
    is the check working. Their state is on the run's own page.
    """

    verdicts: dict[str, Failure] = {}
    for job in jobs:
        if job.cluster is None or job.cluster in verdicts or not ran(job):
            continue
        if job.operation in RESTORE_OPERATIONS:
            continue
        #
        # A Publish & deploy whose publish recorded its version and whose
        # deploy did not finish is a deploy that failed (review 26-10-08, F2):
        # the version is there, and publishing again finds nothing saved. A
        # node change deployed in its job likewise (1B-2).
        #
        verdicts[job.cluster] = (
            Failure(
                label=failure_label(job),
                code=error_code(job),
            )
            if job.state in ATTENTION
            else Failure("", None)
        )
    return {cluster: verdict for cluster, verdict in verdicts.items() if verdict.label}


def certificate_in_flight(jobs: Iterable[Job]) -> str | None:
    """What the one certificate slot is busy with, if anything.

    The counterpart of `in_flight` for jobs that belong to no cluster. The
    queue holds one active certificate job at a time, so this is a single
    label or nothing - and the form that would queue another can say so
    before the queue refuses it.
    """

    for job in jobs:
        if job.cluster is None and job.state in {"pending", "running"}:
            return RUNNING_LABELS.get(job.operation, job.operation)
    return None


def in_flight(jobs: Iterable[Job], operations: Collection[str] | None = None) -> dict[str, str]:
    """What each cluster is busy with, by cluster - or only with these operations.

    One entry at most per cluster, because the queue permits one pending job per
    cluster - which is what lets a page draw this as a single state rather than
    a list, and why the buttons can be replaced by it instead of sitting there
    offering an action the queue would refuse.

    An operation with no label still counts as busy. Falling back to the plain
    name is better than a cluster that looks idle while it is not.
    """

    busy: dict[str, str] = {}
    for job in jobs:
        if job.cluster is None:
            #
            # A certificate job does not make a cluster busy, and the queue
            # agrees: it holds no cluster's active-job slot, so a deploy for any
            # cluster may still be queued beside it. Marking one busy here would
            # grey out a button the queue would have accepted.
            #
            continue
        if job.state not in {"pending", "running"} or job.cluster in busy:
            continue
        if operations is not None and job.operation not in operations:
            continue
        busy[job.cluster] = running_label(job)
    return busy


#
# A Publish & deploy is one job that publishes and then deploys (B257). The
# worker records no phase in between, so the badge names both for the whole
# job rather than saying "Publishing" while the nodes are being deployed.
#
PUBLISH_AND_DEPLOY = "Publishing and deploying"


HELD = "Held"


def running_label(job: Job) -> str:
    """What a cluster's job is called while it is pending or running.

    A job held after a restart waits for an administrator's Run or Discard, and
    is not doing what its operation says; it was drawn as "Deploying" with a
    spinner for as long as nobody answered (review 2026-10-22, 1B-4).
    """

    if job.state == "pending" and job.held_since is not None and job.held_decision is None:
        return HELD
    if job.operation == "changes_publish" and deploys(job):
        return PUBLISH_AND_DEPLOY
    if named := action_names(job):
        return named[1]
    return RUNNING_LABELS.get(job.operation, job.operation)
