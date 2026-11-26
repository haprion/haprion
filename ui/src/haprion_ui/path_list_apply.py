"""``haprion-path-lists`` - *Settings → Path lists* from a file, for automation (B527, B532).

`apply` stores each listed path list as the web's form stores it - checked by
the engine's rule - and applies it with the same `path_list_apply` job, waited
for before the next. `remove` takes one list away, as the page's *Remove*, and
is refused while an object, a saved change or a draft still names it under
*Denied paths*.

A stored list is replaced when its description or paths differ. A list whose
last apply did not finish for its revision is applied again. `--prune` removes
the stored lists the file does not name.

    path_lists:
      - name: scanners
        description: Paths only scanners ask for
        paths: [/.env, /.git, /wp-login.php]
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg
import yaml
from haprion import exit_codes, path_lists, safe_yaml
from haprion.cli import apply_common, arguments

from haprion_ui import config, db, job_wait, labels, list_sync, path_list_form, tool_answer
from haprion_ui.admin import AdminError, actor_name, connect, load_environment

OPERATION = "path_lists_apply"
LIST_OPERATION = "path_lists_list"
MAX_FILE_BYTES = 1024 * 1024
MAX_LISTS = path_lists.MAX_LISTS
WAIT_SECONDS = job_wait.WAIT_SECONDS
FIELDS = frozenset({"name", "description", "paths"})


class ApplyError(tool_answer.ToolError):
    """What is wrong with the file or the change, as the form would say it."""


@dataclass(frozen=True)
class Change:
    name: str
    action: str
    """`create`, `replace`, `apply` (the stored revision again) or `remove`."""
    wanted: path_lists.PathList | None = None


@dataclass(frozen=True)
class Plan:
    changes: tuple[Change, ...]
    unchanged: tuple[str, ...]


def read_file(path: Path) -> list[path_lists.PathList]:
    """The listed path lists, each checked by the engine's rule."""

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ApplyError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
        document = safe_yaml.load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ApplyError(
            f"{path}: {exc.strerror}",
            code=apply_common.unreadable_code(exc),
            exit_code=exit_codes.NOT_FOUND,
        ) from exc
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ApplyError(f"{path}: not UTF-8 YAML") from exc
    if not isinstance(document, Mapping) or set(document) != {"path_lists"}:
        raise ApplyError(f"{path}: the file holds one section, path_lists")
    entries = document["path_lists"] or []
    if not isinstance(entries, list) or len(entries) > MAX_LISTS:
        raise ApplyError(f"{path}: path_lists is a list of at most {MAX_LISTS} lists")
    found: list[path_lists.PathList] = []
    seen: set[str] = set()
    for number, entry in enumerate(entries, start=1):
        where = f"{path}: path_lists {number}"
        if not isinstance(entry, Mapping):
            raise ApplyError(f"{where} must be a mapping")
        extra = sorted(str(key) for key in entry if key not in FIELDS)
        if extra:
            raise ApplyError(
                f"{where} has unknown {labels.noun(len(extra), 'field')}: {', '.join(extra)}"
            )
        description = entry.get("description") or ""
        try:
            item = path_lists.path_list(entry.get("name"), entry.get("paths"), description)
        except path_lists.PathListError as exc:
            raise ApplyError(f"{where}: {exc}") from exc
        if item.name in seen:
            raise ApplyError(f"{where}: {item.name} is listed twice")
        seen.add(item.name)
        found.append(item)
    return found


def _applied(
    stored: db.PathList,
    latest: db.Job | None,
    files: Mapping[str, db.ListFile] | None,
    read_at: datetime | None,
) -> bool:
    """Whether root's file is the stored row: what the poller read of it, not the job history.

    A restored database says *done* for a list whose file is another
    (review 26-11-24, PW02). With no reading at all, the newest apply decides.
    """

    return list_sync.in_step(
        revision=stored.revision,
        digest=path_lists.content_digest(stored.description, stored.paths),
        file=(files or {}).get(stored.name),
        job=latest,
        read_at=read_at,
    )


def plan(
    found: Sequence[path_lists.PathList],
    stored: Mapping[str, db.PathList],
    latest: Mapping[str, db.Job],
    files: Mapping[str, db.ListFile] | None = None,
    read_at: datetime | None = None,
    *,
    prune: bool,
) -> Plan:
    changes: list[Change] = []
    unchanged: list[str] = []
    for item in found:
        current = stored.get(item.name)
        if current is None:
            changes.append(Change(item.name, "create", item))
        elif tuple(current.paths) != item.paths or current.description != item.description:
            changes.append(Change(item.name, "replace", item))
        elif _applied(current, latest.get(item.name), files, read_at):
            unchanged.append(item.name)
        else:
            changes.append(Change(item.name, "apply", item))
    if prune:
        named = {item.name for item in found}
        changes.extend(Change(name, "remove") for name in sorted(set(stored) - named))
    return Plan(tuple(changes), tuple(unchanged))


def _queue(connection: Any, change: Change, *, actor: str) -> db.Job:
    """One change, its row and its job committed together, as the web makes it."""

    existing = db.path_list(connection, change.name)
    try:
        if change.action == "remove":
            if existing is None:
                raise ApplyError(f"{change.name} is gone", code="expected_target_changed")
            return path_list_form.remove(
                connection, existing, actor=actor, key=uuid.uuid4(), via="cli"
            )
        if change.action == "apply":
            if existing is None:
                raise ApplyError(f"{change.name} is gone", code="expected_target_changed")
            return path_list_form.apply_again(connection, existing, actor=actor, via="cli")
        if change.wanted is None:
            raise ApplyError(f"{change.name}: nothing to store", code="internal_error")
        return path_list_form.save(
            connection, change.wanted, existing=existing, actor=actor, key=uuid.uuid4(), via="cli"
        )
    except path_list_form.FormProblem as problem:
        exit_code = exit_codes.BLOCKED if problem.code != "bad_input" else exit_codes.REFUSED
        raise ApplyError(
            f"{change.name}: {problem}", code=problem.code, exit_code=exit_code
        ) from None


def summary(the_plan: Plan, *, check: bool, applied: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "changed": bool(the_plan.changes),
        "check": check,
        "changes": [{"name": change.name, "action": change.action} for change in the_plan.changes],
        "jobs": list(applied),
        "unchanged": list(the_plan.unchanged),
    }


def _stopped(
    args: argparse.Namespace,
    the_plan: Plan | None,
    applied: Sequence[dict[str, Any]],
    code: str,
    message: str,
    exit_code: int,
) -> int:
    """A run that stopped: refused before anything, or after some lists were applied."""

    if the_plan is None or not applied:
        return tool_answer.refusal(args, OPERATION, code, message, exit_code)
    result = summary(the_plan, check=False, applied=applied)
    took = any(entry["state"] == "done" for entry in applied)
    print(f"ERROR: {message}", file=sys.stderr)
    if args.json:
        if took:
            return tool_answer.partial(OPERATION, result, code, message)
        return tool_answer.failed(OPERATION, code, message, exit_code, result)
    for entry in applied:
        print(f"{entry['name']}: job {entry['job']} {entry['state']}")
    return exit_codes.PARTIAL if took else exit_code


def _run(
    args: argparse.Namespace,
    make_plan: Callable[[Any], Plan],
    *,
    sleep: Callable[[float], None],
) -> int:
    applied: list[dict[str, Any]] = []
    the_plan: Plan | None = None
    try:
        with connect(load_environment()) as connection:
            the_plan = make_plan(connection)
            connection.commit()
            if not getattr(args, "check", False):
                actor = actor_name()
                for change in the_plan.changes:
                    job = _queue(connection, change, actor=actor)
                    state, problem = job_wait.finished(
                        connection, job.id, wait=args.wait, sleep=sleep
                    )
                    applied.append(
                        {
                            "name": change.name,
                            "action": change.action,
                            "job": job.id,
                            "state": state,
                        }
                    )
                    if problem:
                        raise ApplyError(
                            f"{change.name}: {problem}",
                            code="job_not_done",
                            exit_code=exit_codes.FAILED,
                        )
    except ApplyError as exc:
        return _stopped(args, the_plan, applied, exc.code, str(exc), exc.exit_code)
    except psycopg.Error as exc:
        code, exit_code = tool_answer.database_failure(exc)
        return _stopped(args, the_plan, applied, code, f"database: {exc}", exit_code)
    result = summary(the_plan, check=getattr(args, "check", False), applied=applied)
    if args.json:
        return tool_answer.done(OPERATION, result)
    if not the_plan.changes:
        print(
            f"nothing to change ({labels.counted(len(the_plan.unchanged), 'path list')} as listed)"
        )
    lead = "would" if getattr(args, "check", False) else "did"
    for change in the_plan.changes:
        again = " again" if change.action == "apply" else ""
        print(f"{lead} {change.action} path list {change.name}{again}")
    return 0


def command_apply(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    try:
        found = read_file(Path(args.file))
    except ApplyError as exc:
        return tool_answer.refusal(args, OPERATION, exc.code, str(exc), exc.exit_code)

    def make_plan(connection: Any) -> Plan:
        stored = {row.name: row for row in db.path_lists(connection)}
        files = {entry.name: entry for entry in db.list_files(connection, path_list_form.KIND)}
        read_at = db.list_files_read_at(connection)
        return plan(
            found, stored, db.latest_path_list_jobs(connection), files, read_at, prune=args.prune
        )

    return _run(args, make_plan, sleep=sleep)


def command_remove(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    """One list removed, as the page's *Remove*; one already gone is no change."""

    try:
        path_lists.checked_name(args.name)
    except path_lists.PathListError as exc:
        return tool_answer.refusal(
            args, OPERATION, "bad_input", f"{args.name!r}: {exc}", exit_codes.USAGE
        )

    def make_plan(connection: Any) -> Plan:
        if db.path_list(connection, args.name) is None:
            return Plan((), ())
        return Plan((Change(args.name, "remove"),), ())

    return _run(args, make_plan, sleep=sleep)


def document(connection: Any) -> dict[str, Any]:
    """The stored lists as the file `read_file` takes: applied to the installation they came from, nothing changes."""

    return {
        "path_lists": [
            {"name": row.name, "description": row.description, "paths": list(row.paths)}
            for row in db.path_lists(connection)
        ]
    }


def command_list(args: argparse.Namespace) -> int:
    """The card's rows: each list's paths, users and whether root's file is what the row says."""

    try:
        settings = config.load()
    except config.ConfigError as exc:
        return tool_answer.refusal(
            args, LIST_OPERATION, "dependency_unavailable", str(exc), exc.exit_code
        )
    with connect(load_environment()) as connection:
        files = {entry.name: entry for entry in db.list_files(connection, path_list_form.KIND)}
        read_at = db.list_files_read_at(connection)
        shown = path_list_form.rows(
            db.path_lists(connection),
            path_list_form.usage(connection),
            db.latest_path_list_jobs(connection),
            files,
            writes=settings.management_writes,
            read_at=read_at,
        )
    entries: list[dict[str, Any]] = [
        {
            "name": row.name,
            "revision": row.revision,
            "paths": row.count,
            "used_by": row.proxies,
            "status": row.status,
            "stored": row.stored,
        }
        for row in shown
    ]
    if args.json:
        return tool_answer.done(LIST_OPERATION, {"path_lists": entries})
    for entry in entries:
        paths = "?" if entry["paths"] is None else entry["paths"]
        print(
            f"{entry['name']:<42} {paths:>4} paths  "
            f"{labels.counted(int(entry['used_by']), 'proxy'):<12} {entry['status']}".rstrip()
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(
        prog="haprion-path-lists",
        description="Path lists under Settings, from a file. Root only.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    apply = subcommands.add_parser("apply", help="store and apply a file's path lists")
    apply.add_argument("file")
    apply.add_argument("--check", action="store_true", help="say what would change; change nothing")
    apply.add_argument("--json", action="store_true")
    apply.add_argument("--prune", action="store_true", help="remove stored lists not named")
    apply.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, help="seconds to wait for each job"
    )
    remove = subcommands.add_parser("remove", help="remove one path list")
    remove.add_argument("name")
    remove.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, help="seconds to wait for the job"
    )
    remove.add_argument("--json", action="store_true")
    listing = subcommands.add_parser("list", help="the stored lists as Settings shows them")
    listing.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    contract = LIST_OPERATION if args.command == "list" else OPERATION
    if os.geteuid() != 0:
        return tool_answer.refusal(
            args, contract, "not_root", "run this with sudo", exit_codes.NOT_ROOT
        )
    try:
        commands = {"apply": command_apply, "remove": command_remove, "list": command_list}
        return commands[args.command](args)
    except AdminError as exc:
        return tool_answer.refusal(args, contract, exc.code, str(exc), exc.exit_code)
    except psycopg.Error as exc:
        return tool_answer.database_refusal(args, contract, exc)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())
