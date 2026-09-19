"""The receivers pages: who fetches from this manager, and what each host runs.

B142. Two pages, split by when the operator needs what. The list is the
*after*: every registered receiver and, under each, the exact commands its
host runs to fetch - the account, the manager's name and each certificate it
holds filled in, in the form each transport takes. The form at
`/certificates/receivers/new` is the *before*: the name, the transport, and
the key its own `ssh-keygen` wrote (or, for https, the addresses allowed to
fetch), with the key-making commands for the transport chosen. One page that
was both read backwards: the fetch commands stood above a form that had not
been sent yet (seen 2026-09-19). The operator copies; nothing here is typed
from memory. A receiver is removed from the list once nothing publishes to it.

A job's progress is said on the row it concerns - a spinner while it runs,
a badge with the job number when it fails - and a receiver that is being
registered has a row before the registry knows it. Not a notice at the top
of the page: the row is where the reader is looking.

The rows come from the registry block the poller already carries
(`receiver_records`, `manager`), so the page costs no new source. The
commands are derived from those records; they are the same commands the
reference scripts in `examples/receivers/` run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from haproxy_mgmt.config import RECEIVER_ID, RECEIVER_TRANSPORTS

# The key file the instructions name on the receiving host. A name, not a
# path the manager decides: the host's operator may keep it elsewhere and
# edits one line.
KEY_FILE = "/root/.ssh/certfetch"
WINDOWS_KEY_FILE = "C:\\certs\\certfetch"

TRANSPORT_LABELS = {
    "rsync": "rsync over ssh",
    "sftp": "sftp",
    "https": "https",
}

# What the form says beside each choice - the sentence that decides between
# them, in the words INSTALLATION.md 1.4.9 uses.
TRANSPORT_HELP = {
    "rsync": "Linux hosts with rsync. The key is locked to one read-only directory.",
    "sftp": "Any host with an OpenSSH client, Windows included. Chrooted, read-only.",
    "https": "No key: an address allowlist under the interface's own certificate. "
    "Can hold any certificate, wildcards included.",
}


class ReceiverProblem(ValueError):
    """A form the page draws again with this sentence."""


@dataclass(frozen=True, slots=True)
class Held:
    """One certificate a receiver holds, and the form it is published in."""

    certificate_id: str
    format: str


@dataclass(frozen=True, slots=True)
class ReceiverRow:
    identifier: str
    transport: str
    layout: str
    owner: str
    path: str
    allow: tuple[str, ...]
    holds: tuple[Held, ...]

    @property
    def legacy(self) -> bool:
        return self.layout == "flat"

    @property
    def transport_label(self) -> str:
        return TRANSPORT_LABELS.get(self.transport, self.transport)

    @property
    def removable(self) -> bool:
        return not self.holds and not self.legacy


@dataclass(frozen=True, slots=True)
class Step:
    """One thing the receiving host's operator runs or does.

    `windows_command` is the same step on Windows, where the transport allows
    Windows at all; the page shows the two as equals, not one as a footnote
    to the other.
    """

    title: str
    command: str = ""
    note: str = ""
    windows_command: str = ""


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def parse_receiver_rows(block: Mapping[str, Any]) -> tuple[str | None, tuple[ReceiverRow, ...]]:
    """The manager's name and one row per registered receiver, out of the registry block.

    The format a receiver holds a certificate in lives on the certificate's
    side of the registry (`targets.receivers[].format`, B159), so it is
    gathered from the certificate entries here and put beside the receiver.
    """

    manager = block.get("manager")
    formats: dict[tuple[str, str], str] = {}
    entries = block.get("certificates")
    for entry in entries if isinstance(entries, list) else []:
        certificate = _mapping(entry)
        certificate_id = _text(certificate.get("id"))
        targets = _mapping(certificate.get("targets")).get("receivers")
        for target in targets if isinstance(targets, list) else []:
            receiver = _mapping(target)
            receiver_id = _text(receiver.get("id"))
            if certificate_id and receiver_id:
                formats[(receiver_id, certificate_id)] = _text(receiver.get("format")) or "pem"

    rows: list[ReceiverRow] = []
    records = block.get("receiver_records")
    for value in records if isinstance(records, list) else []:
        record = _mapping(value)
        identifier = _text(record.get("id"))
        if not identifier:
            continue
        held = record.get("certificates")
        allow = record.get("allow")
        rows.append(
            ReceiverRow(
                identifier=identifier,
                transport=_text(record.get("transport")) or "rsync",
                layout=_text(record.get("layout")) or "flat",
                owner=_text(record.get("owner")),
                path=_text(record.get("path")),
                allow=tuple(item for item in allow if isinstance(item, str))
                if isinstance(allow, list)
                else (),
                holds=tuple(
                    Held(name, formats.get((identifier, name), "pem"))
                    for name in held
                    if isinstance(name, str)
                )
                if isinstance(held, list)
                else (),
            )
        )
    return (manager if isinstance(manager, str) and manager else None), tuple(rows)


# --- what the host runs ------------------------------------------------------


# The transports whose receiver may be a Windows host. There is no rsync on
# Windows; sftp is the Windows transport, and the transport's own help says so.
WINDOWS_TRANSPORTS = frozenset({"sftp"})


def key_steps(receiver_id: str) -> tuple[Step, ...]:
    """Before registering: the key pair is made on the receiver (B157).

    Linux and Windows as equals in each step. Which of the two the page
    shows is the transport's (`WINDOWS_TRANSPORTS`), decided where the
    transport is chosen, so the steps follow the radio without a round trip;
    https has no key and shows none of this.
    """

    name = receiver_id or "<receiver>"
    return (
        Step(
            "On the receiving host, make a key for fetching and nothing else",
            f"ssh-keygen -t ed25519 -N '' -C {name} -f {KEY_FILE}",
            "",
            f"ssh-keygen -t ed25519 -N '\"\"' -C {name} -f {WINDOWS_KEY_FILE}",
        ),
        Step(
            "Paste the public half below",
            f"cat {KEY_FILE}.pub",
            "One line, starting with ssh-ed25519. The private half never leaves the host.",
            f"Get-Content {WINDOWS_KEY_FILE}.pub",
        ),
    )


def _files(held: Held) -> tuple[str, ...]:
    if held.format == "pkcs12":
        return (f"{held.certificate_id}.pfx", f"{held.certificate_id}.password")
    return ("fullchain.pem", "privkey.pem")


def fetch_steps(row: ReceiverRow, manager: str | None) -> tuple[Step, ...]:
    """The commands this receiver's host runs, one block per certificate it holds.

    Written for the certificates the receiver holds today; a receiver that
    holds none gets the same commands with `<certificate>` in the name's
    place, so the page never goes blank between registering and publishing.
    """

    host = manager or "<manager>"
    holds = row.holds or (Held("<certificate>", "pem"),)
    steps: list[Step] = []

    if row.transport == "https":
        steps.append(
            Step(
                "Once: pin the interface's certificate",
                f"openssl s_client -connect {host}:443 -servername {host} </dev/null 2>/dev/null "
                f"| openssl x509 > manager-ui.pem",
                "Or copy it from the manager. The fetch below verifies against this file, "
                "not against the system store.",
            )
        )
        for held in holds:
            for name in _files(held):
                steps.append(
                    Step(
                        f"Fetch {name} for {held.certificate_id}",
                        f"curl --fail --cacert manager-ui.pem -o {name} "
                        f"https://{host}/certdist/{row.identifier}/{held.certificate_id}/{name}",
                        "Windows: curl.exe, same arguments." if name.endswith(".pfx") else "",
                    )
                )
        return tuple(steps)

    if row.transport == "sftp":
        for held in holds:
            gets = "\n".join(f"get /{held.certificate_id}/{name}" for name in _files(held))
            steps.append(
                Step(
                    f"Fetch {held.certificate_id} (Linux)",
                    f"sftp -b - -i {KEY_FILE} -o IdentitiesOnly=yes {row.owner}@{host} <<'EOF'\n"
                    f"{gets}\nEOF",
                    "The commands arrive on stdin, so nothing is typed at a prompt.",
                )
            )
            windows_gets = "\n".join(
                f"get /{held.certificate_id}/{name} C:\\certs\\{name}" for name in _files(held)
            )
            steps.append(
                Step(
                    f"Fetch {held.certificate_id} (Windows, PowerShell)",
                    f'@"\n{windows_gets}\n"@ | sftp -b - -i {WINDOWS_KEY_FILE} '
                    f"-o IdentitiesOnly=yes {row.owner}@{host}",
                    "A PKCS#12 pair is then imported with examples/receivers/install-pkcs12.ps1."
                    if held.format == "pkcs12"
                    else "",
                )
            )
        return tuple(steps)

    for held in holds:
        target = "/etc/ssl/" + held.certificate_id
        steps.append(
            Step(
                f"Fetch {held.certificate_id}",
                f'rsync -a -e "ssh -i {KEY_FILE} -o IdentitiesOnly=yes" '
                f"{row.owner}@{host}:{held.certificate_id}/ {target}/",
                "The key is locked to this receiver's directory; the path names the "
                "certificate inside it. examples/receivers/fetch-rsync checks the pair "
                "before installing it.",
            )
        )
    return tuple(steps)


# --- what the queue said ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Activity:
    """One recent `cert_receiver` job, as the page's activity line reads it."""

    job_id: int
    receiver: str
    action: str
    label: str
    tone: str
    message: str

    @property
    def busy(self) -> bool:
        return self.tone == "info"

    @property
    def badge(self) -> str:
        """The label on the row, where the receiver's name is already there."""

        registering = self.action == "add"
        if self.busy:
            return "Registering" if registering else "Removing"
        if self.tone == "healthy":
            return "Registered" if registering else "Removed"
        if self.tone == "warning":
            return "A layer was left"
        return "Registration failed" if registering else "Removal failed"


def on_the_rows(
    rows: Sequence[ReceiverRow], activity: Sequence[Activity]
) -> tuple[dict[str, Activity], tuple[Activity, ...]]:
    """Which rows carry a job's state, and which jobs have no row yet.

    A job that is running is always on its row. A job that failed is shown
    only while it is the newest receiver job: a failure from last week is on
    the jobs page, not a badge the row wears forever. A registration has no
    row in the registry until it succeeds, so its state is a row of its own
    at the top of the table - the second value - and a failed registration
    is there for as long as the same rule keeps it.
    """

    registered = {row.identifier for row in rows}
    on_rows: dict[str, Activity] = {}
    ghosts: list[Activity] = []
    for index, item in enumerate(activity):
        if item.tone == "healthy" or item.receiver in on_rows:
            continue
        if not item.busy and index != 0:
            continue
        if item.receiver in registered:
            on_rows[item.receiver] = item
        elif item.action == "add" and not any(g.receiver == item.receiver for g in ghosts):
            ghosts.append(item)
    return on_rows, tuple(ghosts)


def recent_activity(rows: Sequence[Any]) -> tuple[Activity, ...]:
    """The newest receiver jobs, newest first, with the helper's own sentence.

    Read defensively, as `jobs.error_code` is: the result was written by a
    privileged helper and stored as it arrived.
    """

    activity: list[Activity] = []
    for job in rows:
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        receiver = _text(payload.get("receiver"))
        action = _text(payload.get("action")) or "add"
        verb = "Registering" if action == "add" else "Removing"
        if job.state in {"pending", "running"}:
            activity.append(Activity(job.id, receiver, action, f"{verb} {receiver}", "info", ""))
            continue
        envelope = job.result if isinstance(job.result, Mapping) else {}
        error = _mapping(envelope.get("error"))
        message = _text(error.get("message"))
        if job.state == "done" and job.outcome == "done":
            label = f"{'Registered' if action == 'add' else 'Removed'} {receiver}"
            activity.append(Activity(job.id, receiver, action, label, "healthy", ""))
        elif job.state == "done" and job.outcome == "partial":
            failed = [
                _text(layer.get("detail"))
                for layer in _mapping(envelope.get("result")).get("layers", [])
                if isinstance(layer, Mapping) and layer.get("state") == "failed"
            ]
            activity.append(
                Activity(
                    job.id,
                    receiver,
                    action,
                    f"{verb} {receiver}: a layer was left",
                    "warning",
                    "; ".join(item for item in failed if item),
                )
            )
        else:
            activity.append(
                Activity(
                    job.id,
                    receiver,
                    action,
                    f"{verb} {receiver} failed",
                    "critical",
                    message or _text(job.stderr_excerpt),
                )
            )
    return tuple(activity)


# --- the form ----------------------------------------------------------------

PUBLIC_KEY_LINE = re.compile(
    r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^\r\n]{0,128})?"
)


def payload(
    receiver_id: str,
    transport: str,
    public_key: str,
    allow_text: str,
    existing: Sequence[ReceiverRow],
) -> dict[str, Any]:
    """The `cert_receiver` add payload, or a sentence about the form.

    The same refusals `haproxy-cert-receiver add` gives, said before the job
    is queued; the helper says them again in its own words for a payload
    that got past this.
    """

    name = receiver_id.strip().lower()
    if not name:
        raise ReceiverProblem("Name the receiver: the host's DNS name or address.")
    if not RECEIVER_ID.fullmatch(name):
        raise ReceiverProblem(
            "A receiver is named by the fetching host's DNS name or address: lowercase "
            "letters, digits, dots and dashes."
        )
    registered = next((row for row in existing if row.identifier == name), None)
    if registered is not None:
        raise ReceiverProblem(
            f"{name} already fetches over {registered.transport}. Publish more certificates "
            f"to it using the existing {registered.transport} way from the registry. To change "
            "the transport mode, remove it first."
        )
    if transport not in RECEIVER_TRANSPORTS:
        raise ReceiverProblem("Choose a transport.")
    result: dict[str, Any] = {"receiver": name, "action": "add", "transport": transport}
    if transport == "https":
        if public_key.strip():
            raise ReceiverProblem("An https receiver has no key; leave the key empty.")
        allow = tuple(item.strip() for item in re.split(r"[\s,]+", allow_text) if item.strip())
        if not allow:
            raise ReceiverProblem(
                "An https receiver fetches with no key, so the allowed addresses are what "
                "stands between its directory and everyone. Name at least one."
            )
        result["allow"] = list(allow)
        return result
    if allow_text.strip():
        raise ReceiverProblem("Allowed addresses belong to an https receiver only.")
    lines = [line.strip() for line in public_key.splitlines() if line.strip()]
    if not lines:
        raise ReceiverProblem("Paste the receiver's public key: one line from its .pub file.")
    if len(lines) != 1:
        raise ReceiverProblem(f"That is {len(lines)} lines; a receiver registers exactly one key.")
    if not PUBLIC_KEY_LINE.fullmatch(lines[0]):
        raise ReceiverProblem(
            "That is not a public key in OpenSSH's own form. Paste the .pub line the "
            "receiver's ssh-keygen wrote - not a private key and not a certificate."
        )
    result["public_key"] = lines[0]
    return result


def removal(receiver_id: str, existing: Sequence[ReceiverRow]) -> dict[str, Any]:
    """The `cert_receiver` remove payload, or why not."""

    row = next((row for row in existing if row.identifier == receiver_id), None)
    if row is None:
        raise ReceiverProblem(f"{receiver_id} is not a registered receiver.")
    if row.holds:
        names = ", ".join(held.certificate_id for held in row.holds)
        raise ReceiverProblem(
            f"{receiver_id} still receives {names}. Use Remove from… on the certificate "
            "first; that is the step that says what stops being fetched."
        )
    if row.legacy:
        raise ReceiverProblem(
            f"{receiver_id} was registered before this page and is migrated from the "
            "terminal (haproxy-cert-receiver migrate); it is not removed from here."
        )
    return {"receiver": receiver_id, "action": "remove"}
