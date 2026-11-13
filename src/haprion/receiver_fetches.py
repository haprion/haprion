"""When each certificate receiver last fetched (B496, 10; B498).

A receiver fetches on its own schedule and tells the manager nothing, so the
manager's own logs are the only witness:

- an **rsync or sftp** receiver logs in with its key, and sshd writes
  `Accepted publickey for <account> from <address> ...` to the journal. The
  account can do nothing but read its own directory (`rrsync -ro`,
  `internal-sftp -R`), so a login is a fetch;
- an **https** receiver asks nginx for a file under `/certdist/<receiver>/`,
  and the interface's site writes each such request to a log of its own
  (`ACCESS_LOG`). A `200` is a fetch.

**Fetched is not installed.** Neither witness can say the receiver's host put
the file to use; the page says so beside the time.

Read as root, by the poller's `readings` helper: the journal is readable by
`systemd-journal`, and nginx's logs by `adm`, and the poller's account is in
neither. What leaves this module is one time per receiver, never a log line.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from haprion.config import Receiver
from haprion.digits import is_digits

OPERATION = "receiver_fetches"
JOURNAL = "journal"
ACCESS_LOG_SOURCE = "access_log"
WITNESSES = (JOURNAL, ACCESS_LOG_SOURCE)
"""The two places a fetch is read from, as `unread` names them."""
#
# Written by the interface's nginx site (`haprion.nginx.example`) for every
# request under `/certdist/<receiver>/`, in nginx's `combined` format. Rotated
# with nginx's other logs; the newest file and the one before it are read.
#
ACCESS_LOG = Path("/var/log/nginx/haprion-receivers.access.log")
JOURNALCTL = "/usr/bin/journalctl"
#
# OpenSSH 9.8 split the per-connection half off as `sshd-session`, which is
# what logs a login; older releases log it as `sshd`. Both are asked.
#
SSHD_IDENTIFIERS = ("sshd-session", "sshd")
#
# How far back a reading may ask. The poller asks from its last reading, and a
# first reading from a week and a day back - the *Needs attention* row's
# seven days and a margin.
#
MAX_LOOKBACK = timedelta(days=31)
DEFAULT_LOOKBACK = timedelta(days=8)
JOURNAL_TIMEOUT_SECONDS = 60
#
# A log line longer than this is not one nginx wrote in `combined` for a
# fetch, and is skipped rather than parsed.
#
MAX_LINE = 8192

_ACCEPTED = re.compile(r"^Accepted publickey for (?P<account>\S+) from (?P<address>\S+) port \d+ ")
_COMBINED = re.compile(
    r'^(?P<address>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) '
)
_NGINX_TIME = "%d/%b/%Y:%H:%M:%S %z"


class Unreadable(Exception):
    """One witness could not be read; the other is still answered."""


@dataclass(frozen=True, slots=True)
class Fetches:
    """The newest fetch per receiver ID, and the witnesses that could not be read."""

    found: Mapping[str, datetime]
    unread: tuple[tuple[str, str], ...]


def ssh_logins(lines: Iterable[str], accounts: Mapping[str, str]) -> dict[str, datetime]:
    """The newest login per receiver, from `journalctl -o json` lines.

    `accounts` maps an rsync or sftp receiver's account to its ID. A login
    by any other account - an operator's, a node's - is not a fetch.
    """

    newest: dict[str, datetime] = {}
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        #
        # `SYSLOG_IDENTIFIER` is the sender's to set, so any local account can
        # write a line that reads as a login. `_UID` and `_COMM` are the
        # journal's own: sshd's lines are root's, from sshd's own programs.
        #
        if entry.get("_UID") != "0" or entry.get("_COMM") not in SSHD_IDENTIFIERS:
            continue
        message = entry.get("MESSAGE")
        stamp = entry.get("__REALTIME_TIMESTAMP")
        if not isinstance(message, str) or not isinstance(stamp, str) or not is_digits(stamp):
            continue
        matched = _ACCEPTED.match(message)
        if matched is None or matched["account"] not in accounts:
            continue
        at = datetime.fromtimestamp(int(stamp) / 1_000_000, UTC)
        receiver = accounts[matched["account"]]
        if receiver not in newest or at > newest[receiver]:
            newest[receiver] = at
    return newest


def https_fetches(
    lines: Iterable[str], receivers: Iterable[str], prefix: str
) -> dict[str, datetime]:
    """The newest `200` per https receiver, from `combined` log lines.

    A request is the receiver's when its path is under `<prefix>/<id>/`: that
    location admits the receiver's addresses with the receiver's own password
    and nothing else, so a `200` there is that receiver.
    """

    wanted = set(receivers)
    newest: dict[str, datetime] = {}
    for line in lines:
        if len(line) > MAX_LINE:
            continue
        matched = _COMBINED.match(line)
        if (
            matched is None
            or matched["status"] != "200"
            or matched["method"] not in ("GET", "HEAD")
        ):
            continue
        rest = matched["path"].removeprefix(f"{prefix}/")
        if rest == matched["path"] or "/" not in rest:
            continue
        receiver = rest.split("/", 1)[0]
        if receiver not in wanted:
            continue
        try:
            at = datetime.strptime(matched["time"], _NGINX_TIME).astimezone(UTC)
        except ValueError:
            continue
        if receiver not in newest or at > newest[receiver]:
            newest[receiver] = at
    return newest


def journal_lines(since: datetime, *, journalctl: str = JOURNALCTL) -> list[str]:
    """sshd's accepted logins since `since`, as `journalctl -o json` lines."""

    argv = [
        journalctl,
        "--no-pager",
        "--quiet",
        "--output=json",
        f"--since=@{int(since.timestamp())}",
    ]
    for identifier in SSHD_IDENTIFIERS:
        argv.append(f"--identifier={identifier}")
    argv.append("--grep=^Accepted publickey for ")
    argv.append("_UID=0")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed program, no shell, fixed arguments
            argv,
            capture_output=True,
            text=True,
            timeout=JOURNAL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Unreadable(f"the journal could not be read: {exc}") from exc
    #
    # journalctl answers 1 when --grep matched nothing; that is an empty
    # answer, not a failure. Anything with an error on stderr is one.
    #
    if completed.returncode not in (0, 1) or (
        completed.returncode == 1 and completed.stderr.strip()
    ):
        raise Unreadable(
            f"the journal could not be read: journalctl exited {completed.returncode}: "
            f"{completed.stderr.strip()[:200]}"
        )
    return completed.stdout.splitlines()


def log_lines(log: Path = ACCESS_LOG) -> list[str]:
    """The receivers' access log and the file it was last rotated to, oldest first.

    A log that does not exist yet is an empty one: no https receiver has
    fetched since the site began writing it.
    """

    lines: list[str] = []
    for path in (log.with_name(log.name + ".1"), log):
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                lines.extend(handle.read().splitlines())
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise Unreadable(f"{path} could not be read: {exc}") from exc
    return lines


def read(
    receivers: Mapping[str, Receiver],
    *,
    since: datetime,
    prefix: str,
    journal: Callable[[datetime], list[str]] = journal_lines,
    access_log: Callable[[], list[str]] = log_lines,
) -> Fetches:
    """The newest fetch of each receiver since `since`, from both witnesses."""

    accounts = {
        receiver.owner: receiver.receiver_id
        for receiver in receivers.values()
        if receiver.transport in ("rsync", "sftp")
    }
    https = [
        receiver.receiver_id for receiver in receivers.values() if receiver.transport == "https"
    ]
    found: dict[str, datetime] = {}
    unread: list[tuple[str, str]] = []
    #
    # Both are read whether or not a receiver of that kind is registered: that
    # a witness could be read, and since when, is what a later receiver's
    # "has not fetched" rests on, and it cannot start on the day it is added.
    #
    try:
        found.update(ssh_logins(journal(since), accounts))
    except Unreadable as exc:
        unread.append((JOURNAL, str(exc)))
    try:
        found.update(
            {
                receiver: at
                for receiver, at in https_fetches(access_log(), https, prefix).items()
                if at >= since
            }
        )
    except Unreadable as exc:
        unread.append((ACCESS_LOG_SOURCE, str(exc)))
    return Fetches(found=found, unread=tuple(unread))


def result(receivers: Mapping[str, Receiver], fetches: Fetches) -> dict[str, Any]:
    """The reading's result: every registered receiver, with its fetch or null."""

    return {
        "receivers": [
            {
                "id": receiver_id,
                "transport": receivers[receiver_id].transport,
                "fetched_at": (
                    fetches.found[receiver_id].astimezone(UTC).isoformat().replace("+00:00", "Z")
                    if receiver_id in fetches.found
                    else None
                ),
            }
            for receiver_id in sorted(receivers)
        ],
        "unread": [
            {"source": source, "reason": reason[:1024]} for source, reason in fetches.unread
        ],
    }
