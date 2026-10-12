"""``haprion-backup-schedule`` - one cluster's node backup schedule (Fas 23).

The terminal's way to *Save* on the node backup page: when the cluster's
backup timer runs, how many archives each node keeps, and whether it runs at
all. The request goes to the same root service the interface's
`backup_schedule` job asks, which writes the timer and the retention and
reads systemd back. What systemd and the retention file hold now is read
first, and the service is asked only when it differs, so the same command
twice changes nothing.

    haprion-backup-schedule -c <cluster> --time HH:MM
                            [--weekly Mon,Thu | --monthly <day>]
                            [--retention <count>] [--disable] [--check] [--json]

Runs as root, like `haprion-state-backup`. *Node backups* under the
interface's Features is the interface's switch; this command works either way.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from typing import Any, TextIO

from haprion import backup_retention, backup_schedule_write, helper_socket
from haprion.backup_schedule import Schedule, schedule_result
from haprion.cli import backup_job_helper
from haprion.cli.backup_job_ask import SOCKET_PATH, TIMEOUT_SECONDS
from haprion.envelope import Message, envelope, failure, new_request_id

OPERATION = "backup_schedule"
EXIT_NOT_ROOT = 77
EXIT_USAGE = 64
EXIT_UNAVAILABLE = 69

type Ask = Callable[[dict[str, Any]], str]
type Current = Callable[[str], tuple[dict[str, Any] | None, int]]


def ask_service(request: dict[str, Any]) -> str:
    return helper_socket.ask(
        request, path=SOCKET_PATH, timeout=TIMEOUT_SECONDS, what="the backup job service"
    )


def current(cluster: str) -> tuple[dict[str, Any] | None, int]:
    """What systemd says about the cluster's timer, and the retention in force."""

    unit = backup_schedule_write.timer_unit(cluster)
    return schedule_result(unit), backup_retention.read(cluster)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-backup-schedule",
        description="Set one cluster's node backup schedule. Runs as root.",
    )
    parser.add_argument("-c", "--cluster", required=True)
    parser.add_argument("--time", required=True, help="HH:MM on the manager's clock")
    shape = parser.add_mutually_exclusive_group()
    shape.add_argument("--weekly", metavar="DAYS", help="weekdays, such as Mon,Thu")
    shape.add_argument("--monthly", type=int, metavar="DAY", help="day of the month, 1 to 28")
    parser.add_argument("--retention", type=int, default=backup_retention.DEFAULT_RETENTION)
    parser.add_argument("--disable", action="store_true", help="keep the schedule, stop the timer")
    parser.add_argument(
        "--check", action="store_true", help="say whether it would change; change nothing"
    )
    parser.add_argument("--json", action="store_true")
    return parser


def requested(args: argparse.Namespace) -> Schedule:
    parameters: dict[str, Any] = {"time": args.time, "retention": args.retention}
    if args.weekly:
        parameters.update(
            frequency="weekly", weekdays=[day.strip() for day in args.weekly.split(",")]
        )
    elif args.monthly is not None:
        parameters.update(frequency="monthly", day_of_month=args.monthly)
    return backup_schedule_write.schedule(parameters)


def differs(wanted: Schedule, enabled: bool, timer: dict[str, Any] | None, retention: int) -> bool:
    """Whether the service must be asked: the timer or the retention is not as asked.

    A disabled timer's calendar is not compared beyond the drop-in's readback:
    systemd reports the calendar of a loaded timer either way, which is what
    the service checks after a write, so a stopped timer keeps its schedule.
    """

    if timer is None or timer.get("known") is not True:
        return True
    return (
        timer.get("calendar") != wanted.calendar()
        or timer.get("enabled") is not enabled
        or timer.get("active") is not enabled
        or retention != wanted.retention
    )


def main(
    argv: list[str] | None = None,
    *,
    ask: Ask = ask_service,
    read: Current = current,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    require_root: bool = True,
) -> int:
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    request_id = new_request_id()

    def refuse(code: str, message: str, exit_code: int) -> int:
        if args.json:
            writer.write(
                json.dumps(
                    failure(
                        operation=OPERATION,
                        cluster=args.cluster,
                        request_id=request_id,
                        code=code,
                        message=message,
                        exit_code=exit_code,
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )
        errors.write(f"ERROR: [{code}] {message}\n")
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-backup-schedule must run as root", EXIT_NOT_ROOT)
    try:
        wanted = requested(args)
        timer, retention = read(args.cluster)
    except backup_schedule_write.ScheduleWriteError as exc:
        return refuse("bad_input", str(exc), EXIT_USAGE)
    except backup_retention.RetentionError as exc:
        return refuse("dependency_unavailable", str(exc), 78)
    enabled = not args.disable
    if not differs(wanted, enabled, timer, retention):
        result = {"cluster": args.cluster, **wanted.as_dict(), "enabled": enabled}
        document = envelope(
            operation=OPERATION,
            outcome="done",
            cluster=args.cluster,
            request_id=request_id,
            result={**result, "schedule": timer or {}, "changed": False},
        )
        if args.json:
            writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
        else:
            writer.write(f"{args.cluster}: the backup schedule is as asked; nothing to change.\n")
        return 0
    if args.check:
        document = envelope(
            operation=OPERATION,
            outcome="done",
            cluster=args.cluster,
            request_id=request_id,
            result={
                "cluster": args.cluster,
                **wanted.as_dict(),
                "enabled": enabled,
                "schedule": timer or {},
                "changed": True,
            },
            warnings=(Message(code="check", message="--check: nothing was changed"),),
        )
        if args.json:
            writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
        else:
            writer.write(f"{args.cluster}: would set the backup schedule to {wanted.calendar()}\n")
        return 0
    request = json.loads(
        backup_job_helper.build_schedule_request(
            args.cluster, request_id, schedule=wanted, enabled=enabled
        )
    )
    try:
        answer = json.loads(ask(request))
    except (helper_socket.HelperUnavailable, json.JSONDecodeError) as exc:
        return refuse("dependency_unavailable", str(exc) or "no answer", EXIT_UNAVAILABLE)
    if isinstance(answer.get("result"), dict):
        answer["result"]["changed"] = answer.get("ok") is True
    if args.json:
        writer.write(json.dumps(answer, separators=(",", ":"), sort_keys=True) + "\n")
    elif answer.get("ok") is True:
        state = "on" if enabled else "off"
        writer.write(f"{args.cluster}: backup schedule {wanted.calendar()}, timer {state}.\n")
    else:
        error = answer.get("error") or {}
        writer.write(f"ERROR: [{error.get('code')}] {error.get('message')}\n")
    return 0 if answer.get("ok") is True else int(answer.get("exit_code") or 1)
