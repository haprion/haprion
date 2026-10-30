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
from datetime import UTC, datetime, timedelta
from typing import Any

from haprion.cert_receiver import HTTPS_PREFIX
from haprion.config import RECEIVER_ID, RECEIVER_TRANSPORTS, check_allow_entries

from haprion_ui import jobs as queue

# The key file the instructions name on the receiving host. A name, not a
# path the manager decides: the host's operator may keep it elsewhere and
# edits one line.
KEY_FILE = "/root/.ssh/certfetch"
WINDOWS_CERT_DIR = "C:\\certs"
WINDOWS_KEY_FILE = WINDOWS_CERT_DIR + "\\certfetch"
# Every Windows command that writes under the directory starts with this, on
# its own line of the paste (`windows_prepared`): a throw ends that line, so
# nothing is written into a directory that could not be closed. C:\certs is
# made, owned by Administrators and given a protected DACL of Administrators
# and SYSTEM (by SID, so a localized system works), whatever was there before;
# what it already holds inherits it.
WINDOWS_MKDIR = (
    f"mkdir {WINDOWS_CERT_DIR} -Force -ErrorAction Stop | Out-Null; "
    "$acl = New-Object System.Security.AccessControl.DirectorySecurity; "
    "$acl.SetSecurityDescriptorSddlForm('O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'); "
    f"Set-Acl -Path {WINDOWS_CERT_DIR} -AclObject $acl -ErrorAction Stop; "
    f"if (Get-ChildItem {WINDOWS_CERT_DIR} -Force) {{ "
    f"icacls {WINDOWS_CERT_DIR}\\* /reset /T /C | Out-Null; "
    "if ($LASTEXITCODE -ne 0) { throw 'icacls failed' } }"
)


def windows_prepared(command: str) -> str:
    """The Windows command behind the directory preparation, on one line.

    Chained with `;` and not a new line: pasted lines run one by one, and a
    throw in the preparation stops only the line it is on.
    """

    return f"{WINDOWS_MKDIR}; {command}"


# The interface's own certificate as a file, served by its server block for a
# receiver that fetches over https to save and trust (05-platform-nginx).
UI_CERTIFICATE_FILE = "manager-ui.pem"
# Where an https receiver keeps its password (B306): a file curl reads with
# --netrc-file, so the password is in no command line, history or process list.
NETRC_FILE = "/root/.certfetch.netrc"
WINDOWS_NETRC_FILE = WINDOWS_CERT_DIR + "\\certfetch.netrc"

TRANSPORT_LABELS = {
    "rsync": "rsync over ssh",
    "sftp": "sftp",
    "https": "https",
}

# What the form says beside each choice - the sentence that decides between
# them, in the words user-manual.md, 'Registering a receiver', uses.
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
    def transport_label(self) -> str:
        return TRANSPORT_LABELS.get(self.transport, self.transport)

    @property
    def removable(self) -> bool:
        return not self.holds


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
                layout=_text(record.get("layout")) or "per-certificate",
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
            windows_prepared(f"ssh-keygen -t ed25519 -N '\"\"' -C {name} -f {WINDOWS_KEY_FILE}"),
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


def password_step(identifier: str, host: str, password: str) -> Step:
    """Where an https receiver's password goes on its host (B306), once.

    On the one page that shows it, with the password in the commands: a
    runnable line with a placeholder in it wrote the placeholder into the
    host's file, and the fetch was refused (26-10-14).
    """

    line = f"machine {host} login {identifier} password {password}"
    return Step(
        "Once: store this receiver's password",
        f"install -m 600 /dev/null {NETRC_FILE}\necho '{line}' > {NETRC_FILE}",
        "Copy it now: this page is the only place it is shown.",
        windows_prepared(f"Set-Content -Path {WINDOWS_NETRC_FILE} -Value '{line}'"),
    )


def _pair_check(certificate: str, key: str) -> str:
    """Shell that succeeds only when the key belongs to the certificate.

    Each public key is captured on its own so a failing openssl stops the
    line, and the first must not be empty: two failed calls print nothing,
    and nothing equals nothing.
    """

    return (
        f"pub_cert=$(openssl x509 -in {certificate} -pubkey -noout) && "
        f"pub_key=$(openssl pkey -in {key} -pubout) && "
        'test -n "$pub_cert" && test "$pub_cert" = "$pub_key"'
    )


def fetch_steps(row: ReceiverRow, manager: str | None) -> tuple[Step, ...]:
    """The commands this receiver's host runs, one block per certificate it holds.

    An https receiver's password is not among them: it is stored once, from
    the page that shows it (`password_step`), and the row has *New secret* for
    a lost one - a step here that could only say so was one step too many
    (26-10-14).

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
                "Once: decide what the fetches trust",
                f"curl -k -o manager-ui.pem https://{host}{HTTPS_PREFIX}/{UI_CERTIFICATE_FILE}",
                "Saves the manager's certificate for --cacert below (-k only on this first "
                "contact); redo it when the interface's certificate changes.\n"
                "If this host already trusts the CA that issued it, skip this step and drop "
                "--cacert.",
                windows_prepared(
                    f"curl.exe -k -o {WINDOWS_CERT_DIR}\\manager-ui.pem "
                    f"https://{host}{HTTPS_PREFIX}/{UI_CERTIFICATE_FILE}"
                ),
            )
        )
        for held in holds:
            for name in _files(held):
                url = f"https://{host}{HTTPS_PREFIX}/{row.identifier}/{held.certificate_id}/{name}"
                #
                # The private half is written under umask 077, in a directory
                # of the certificate's own: curl writes with the umask of the
                # shell (0644 under root's usual 022), and two certificates
                # would otherwise take the same file names. The key's step
                # ends by checking it against the certificate fetched before it.
                #
                fetch = (
                    f"(umask 077; curl --fail --create-dirs --netrc-file {NETRC_FILE} "
                    f"--cacert manager-ui.pem -o {held.certificate_id}/{name} {url})"
                )
                note = ""
                if name == "privkey.pem":
                    fetch += " && " + _pair_check(
                        f"{held.certificate_id}/fullchain.pem", f"{held.certificate_id}/privkey.pem"
                    )
                if name.endswith(".pfx"):
                    note = "A PKCS#12 pair is then imported with examples/receivers/install-pkcs12.ps1."
                steps.append(
                    Step(
                        f"Fetch {name} for {held.certificate_id}",
                        fetch,
                        note,
                        windows_prepared(
                            f"curl.exe --fail --create-dirs --netrc-file {WINDOWS_NETRC_FILE} "
                            f"--cacert {WINDOWS_CERT_DIR}\\manager-ui.pem "
                            f"-o {WINDOWS_CERT_DIR}\\{held.certificate_id}\\{name} {url}"
                        ),
                    )
                )
        return tuple(steps)

    if row.transport == "sftp":
        for held in holds:
            # A directory per certificate, as the https line has: two
            # certificates would otherwise take the same file names. The pair is
            # checked as the rsync and https lines check it, and the files are
            # written under umask 077 (sftp creates them with the remote mode,
            # 0600, but not the directory).
            directory = held.certificate_id
            gets = "\n".join(f"get /{directory}/{name} {directory}/{name}" for name in _files(held))
            windows_gets = "\n".join(
                f"get /{directory}/{name} {WINDOWS_CERT_DIR}\\{directory}\\{name}"
                for name in _files(held)
            )
            command = (
                f"(umask 077; mkdir -p {directory} && "
                f"sftp -b - -i {KEY_FILE} -o IdentitiesOnly=yes {row.owner}@{host} <<'EOF'\n"
                f"{gets}\nEOF\n)"
            )
            if held.format != "pkcs12":
                command += " && " + _pair_check(
                    f"{directory}/fullchain.pem", f"{directory}/privkey.pem"
                )
            steps.append(
                Step(
                    f"Fetch {held.certificate_id}",
                    command,
                    "The commands arrive on stdin, so nothing is typed at a prompt."
                    + (
                        " A PKCS#12 pair is then imported with examples/receivers/install-pkcs12.ps1."
                        if held.format == "pkcs12"
                        else ""
                    ),
                    windows_prepared(
                        f"New-Item -ItemType Directory -Force {WINDOWS_CERT_DIR}\\{directory} | Out-Null"
                    )
                    + "\n"
                    f'@"\n{windows_gets}\n"@ | sftp -b - -i {WINDOWS_KEY_FILE} '
                    f"-o IdentitiesOnly=yes {row.owner}@{host}",
                )
            )
        return tuple(steps)

    for held in holds:
        steps.append(
            Step(
                f"Fetch {held.certificate_id}",
                _rsync_command(row.owner, host, held),
                "The key is locked to this receiver's directory; the path names the "
                "certificate inside it.",
            )
        )
    return tuple(steps)


def _rsync_command(owner: str, host: str, held: Held) -> str:
    """The rsync fetch, in the shape of `examples/receivers/fetch-rsync`.

    Not `rsync -a`: it keeps the owner and group of the manager's side, and
    where no local account has that name the numeric id is used - which is
    some other service's on the receiving host. The files are fetched into a
    directory made for it and installed as root's, mode 600 for what is secret.
    """

    target = "/etc/ssl/" + held.certificate_id
    names = _files(held)
    # A subshell that cleans up with a trap: `...; rm -rf` ended with rm's exit
    # code, and a timer running the line saw success after a failed fetch.
    lines = [
        "( tmp=$(mktemp -d) && trap 'rm -rf \"$tmp\"' EXIT &&",
        f'rsync -rt --no-owner --no-group --chmod=D700,F600 -e "ssh -i {KEY_FILE} '
        f'-o IdentitiesOnly=yes" {owner}@{host}:{held.certificate_id}/ "$tmp"/ &&',
    ]
    if held.format != "pkcs12":
        lines.append(_pair_check('"$tmp"/fullchain.pem', '"$tmp"/privkey.pem') + " &&")
    lines.append(f"install -d -o root -g root -m 755 {target} &&")
    for name in names:
        mode = "644" if name == "fullchain.pem" else "600"
        lines.append(f'install -o root -g root -m {mode} "$tmp"/{name} {target}/{name} &&')
    lines[-1] = lines[-1].removesuffix(" &&") + " )"
    return "\n".join(lines)


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
    finished_at: datetime | None = None
    #
    # *Held* or *No worker* for a job that does not finish by itself; it holds
    # the row as a running one does, without the spinner (review 26-10-29).
    #
    stuck: str = ""

    @property
    def busy(self) -> bool:
        return self.tone == "info" or bool(self.stuck)

    @property
    def working(self) -> bool:
        return self.busy and not self.stuck

    @property
    def badge(self) -> str:
        """The label on the row, where the receiver's name is already there."""

        busy, done, failed = WORDS.get(self.action, WORDS["add"])
        if self.stuck:
            return self.stuck
        if self.busy:
            return busy
        if self.tone == "healthy":
            return done
        if self.tone == "warning":
            return "A layer was left"
        return failed


#
# What each job is called on its row: running, done, failed. A new secret
# was called *Removing* - the words knew two actions (26-10-14).
#
WORDS: Mapping[str, tuple[str, str, str]] = {
    "add": ("Registering", "Registered", "Registration failed"),
    "remove": ("Removing", "Removed", "Removal failed"),
    "secret": ("Setting a new secret", "New secret set", "New secret failed"),
    "key": ("Replacing the key", "Key replaced", "Key replacement failed"),
}


# How long a finished job's verdict stays on a row - the certificate rows'
# rule (certificate_activity.VERDICT_LIFETIME), applied here too. A failure
# from this morning is history, and the jobs page keeps it.
VERDICT_LIFETIME = timedelta(hours=1)


def on_the_rows(
    rows: Sequence[ReceiverRow],
    activity: Sequence[Activity],
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Activity], tuple[Activity, ...]]:
    """Which rows carry a job's state, and which jobs have no row yet.

    A job that is running is always on its row. A job that failed is shown
    only while it is the newest receiver job and for an hour after it ended:
    a failure from last week is on the jobs page, not a badge the row wears
    forever. A registration has no row in the registry until it succeeds,
    so its state is a row of its own at the top of the table - the second
    value - and a failed registration is there for as long as the same rule
    keeps it (and can be dismissed from the page before that).
    """

    moment = now or datetime.now(UTC)
    registered = {row.identifier for row in rows}
    on_rows: dict[str, Activity] = {}
    ghosts: list[Activity] = []
    for index, item in enumerate(activity):
        if item.tone == "healthy" or item.receiver in on_rows:
            continue
        if not item.busy and index != 0:
            continue
        if (
            not item.busy
            and item.finished_at is not None
            and moment - item.finished_at > VERDICT_LIFETIME
        ):
            continue
        if item.receiver in registered:
            on_rows[item.receiver] = item
        elif item.action == "add" and not any(g.receiver == item.receiver for g in ghosts):
            ghosts.append(item)
    return on_rows, tuple(ghosts)


def recent_activity(rows: Sequence[Any], *, writes: bool) -> tuple[Activity, ...]:
    """The newest receiver jobs, newest first, with the helper's own sentence.

    Read defensively, as `jobs.error_code` is: the result was written by a
    privileged helper and stored as it arrived.
    """

    activity: list[Activity] = []
    for job in rows:
        payload = job.payload if isinstance(job.payload, Mapping) else {}
        receiver = _text(payload.get("receiver"))
        action = _text(payload.get("action")) or "add"
        verb, done, _failed = WORDS.get(action, WORDS["add"])
        target = f"for {receiver}" if action in ("secret", "key") else receiver
        finished = getattr(job, "finished_at", None)
        if job.state in {"pending", "running"}:
            state = queue.busy_with(job, writes=writes)
            if not state.working:
                label = f"{state.label}: {verb} {target}"
                activity.append(
                    Activity(job.id, receiver, action, label, state.tone, "", stuck=state.label)
                )
                continue
            activity.append(Activity(job.id, receiver, action, f"{verb} {target}", "info", ""))
            continue
        envelope = job.result if isinstance(job.result, Mapping) else {}
        error = _mapping(envelope.get("error"))
        message = _text(error.get("message"))
        if job.state == "done" and job.outcome == "done":
            label = f"{done} {target}"
            activity.append(Activity(job.id, receiver, action, label, "healthy", "", finished))
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
                    f"{verb} {target}: a layer was left",
                    "warning",
                    "; ".join(item for item in failed if item),
                    finished,
                )
            )
        else:
            activity.append(
                Activity(
                    job.id,
                    receiver,
                    action,
                    f"{verb} {target} failed",
                    "critical",
                    message or _text(job.stderr_excerpt),
                    finished,
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

    The same refusals `haprion-cert-receiver add` gives, said before the job
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
        #
        # The engine's rule, said on the form: an entry that is not an address
        # or a network was a job failure about the registry until 2026-09-20.
        #
        try:
            check_allow_entries(allow)
        except ValueError as problem:
            raise ReceiverProblem(
                f"Allowed addresses{problem}. Each one is an IP address or a network "
                "in CIDR form, such as 192.0.2.7 or 192.0.2.0/24."
            ) from None
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
    return {"receiver": receiver_id, "action": "remove"}
