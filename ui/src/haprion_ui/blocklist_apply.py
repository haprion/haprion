"""``haprion-blocklists`` - *Settings → Blocklists* from a file, for automation (B496, 13; B500).

`apply` stores each listed blocklist as the web's form stores it - checked by
the engine's rule, the password or token sealed against the installation's
DNS profile key - and applies it with the same `blocklist_apply` job, waited
for before the next. `remove` takes one list away, as the page's *Remove*,
and is refused while an object still names it under *Denied*.

A stored list is replaced when a field differs. The secret cannot be
compared: it is sealed and stored when the list is new, when its
authorization changes, or when `--replace-secret <name>` asks; otherwise the
stored one is kept. A list whose last apply did not finish for its revision
is applied again. `--prune` removes the stored lists the file does not name.
A file that carries a secret is refused unless only its owner may read it.

    blocklists:
      - name: community
        url: https://lists.example.com/community.txt
        every_hours: 24                 # 1, 6, 12 or 24
        authorization: basic            # none | basic | bearer
        username: svc-app
        secret: "..."
        description: Community list
        except: [192.0.2.10, partner-sites]
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
import yaml
from haprion import blocklists, exit_codes, safe_yaml
from haprion.cli import apply_common, arguments
from haprion.dns_profile_keys import DnsProfilePublicKey, KeyFileError, read_public_key

from haprion_ui import blocklist_form, config, db, job_wait, labels, tool_answer
from haprion_ui.admin import AdminError, actor_name, connect, load_environment

OPERATION = "blocklists_apply"
MAX_FILE_BYTES = 256 * 1024
MAX_LISTS = 64
WAIT_SECONDS = job_wait.WAIT_SECONDS
FIELDS = frozenset(
    {"name", "url", "every_hours", "authorization", "username", "secret", "description", "except"}
)


class ApplyError(tool_answer.ToolError):
    """What is wrong with the file or the change, as the form would say it."""


@dataclass(frozen=True)
class Wanted:
    definition: blocklists.Definition
    secret: str = field(default="", repr=False)


@dataclass(frozen=True)
class Change:
    name: str
    action: str
    """`create`, `replace`, `apply` (the stored revision again) or `remove`."""
    wanted: Wanted | None = None
    keep: bool = False


@dataclass(frozen=True)
class Plan:
    changes: tuple[Change, ...]
    unchanged: tuple[str, ...]


def _text(value: object, where: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ApplyError(f"{where} must be text")
    return value


def read_file(path: Path) -> list[Wanted]:
    """The listed blocklists, each checked by the engine's rule."""

    try:
        status = path.stat()
        if status.st_size > MAX_FILE_BYTES:
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
    if not isinstance(document, Mapping) or set(document) != {"blocklists"}:
        raise ApplyError(f"{path}: the file holds one section, blocklists")
    entries = document["blocklists"] or []
    if not isinstance(entries, list) or len(entries) > MAX_LISTS:
        raise ApplyError(f"{path}: blocklists is a list of at most {MAX_LISTS} lists")
    found: list[Wanted] = []
    seen: set[str] = set()
    for number, entry in enumerate(entries, start=1):
        where = f"{path}: blocklists {number}"
        if not isinstance(entry, Mapping):
            raise ApplyError(f"{where} must be a mapping")
        extra = sorted(str(key) for key in entry if key not in FIELDS)
        if extra:
            raise ApplyError(
                f"{where} has unknown {labels.noun(len(extra), 'field')}: {', '.join(extra)}"
            )
        excepts = entry.get("except") or []
        if not isinstance(excepts, list) or not all(isinstance(item, str) for item in excepts):
            raise ApplyError(f"{where}: except is a list of addresses, networks or groups")
        authorization = entry.get("authorization", "none")
        try:
            definition = blocklists.definition(
                name=entry.get("name"),
                url=entry.get("url"),
                every_hours=entry.get("every_hours"),
                authorization=authorization,
                username=_text(entry.get("username"), f"{where} username"),
                description=_text(entry.get("description"), f"{where} description"),
                excepts=excepts,
            )
        except ValueError as exc:
            raise ApplyError(f"{where}: {exc}") from exc
        if definition.name in seen:
            raise ApplyError(f"{where}: {definition.name} is listed twice")
        seen.add(definition.name)
        secret = _text(entry.get("secret"), f"{where} secret")
        if definition.authorization == "none" and secret:
            raise ApplyError(f"{where}: a secret goes with Basic or Bearer authorization")
        found.append(Wanted(definition, secret))
    if any(item.secret for item in found) and status.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ApplyError(
            f"{path} carries a secret and may be read by others than its owner; make it mode 0600"
        )
    return found


def _same(stored: db.Blocklist, wanted: blocklists.Definition) -> bool:
    return (
        stored.url == wanted.url
        and stored.every_hours == wanted.every_hours
        and stored.auth == wanted.authorization
        and stored.username == wanted.username
        and stored.description == wanted.description
        and tuple(stored.excepts) == wanted.excepts
    )


def _applied(stored: db.Blocklist, latest: db.Job | None) -> bool:
    """Whether the stored revision's newest apply finished."""

    return (
        latest is not None
        and latest.state == "done"
        and latest.payload.get("revision") == stored.revision
        and latest.payload.get("remove") is not True
    )


def plan(
    found: Sequence[Wanted],
    stored: Mapping[str, db.Blocklist],
    latest: Mapping[str, db.Job],
    *,
    replace_secret: Sequence[str],
    prune: bool,
) -> Plan:
    changes: list[Change] = []
    unchanged: list[str] = []
    named = {item.definition.name for item in found}
    unknown = sorted(set(replace_secret) - named)
    if unknown:
        raise ApplyError(f"--replace-secret names a list the file does not: {', '.join(unknown)}")
    for item in found:
        name = item.definition.name
        current = stored.get(name)
        form = blocklist_form.Form(auth=item.definition.authorization, secret=item.secret)
        if current is None:
            try:
                blocklist_form.secret_choice(form, None)
            except blocklist_form.FormProblem as problem:
                raise ApplyError(f"{name}: {problem}") from None
            changes.append(Change(name, "create", item))
            continue
        replacing = name in replace_secret
        if replacing and not item.secret and item.definition.authorization != "none":
            raise ApplyError(f"{name}: --replace-secret needs the secret in the file")
        if _same(current, item.definition) and not replacing:
            if _applied(current, latest.get(name)):
                unchanged.append(name)
            else:
                changes.append(Change(name, "apply"))
            continue
        #
        # The file's secret is sealed only when it must be: asked for, or a
        # new authorization. Otherwise the stored one is kept, since a secret
        # cannot be compared and sealing it again on every run would make
        # each run a change.
        #
        if not replacing and current.auth == item.definition.authorization:
            form = blocklist_form.Form(auth=item.definition.authorization)
        try:
            secret, keep = blocklist_form.secret_choice(form, current)
        except blocklist_form.FormProblem as problem:
            raise ApplyError(f"{name}: {problem}") from None
        changes.append(Change(name, "replace", Wanted(item.definition, secret), keep=keep))
    if prune:
        changes.extend(Change(name, "remove") for name in sorted(set(stored) - named))
    return Plan(tuple(changes), tuple(unchanged))


def _queue(
    connection: Any, change: Change, *, public_key: DnsProfilePublicKey, actor: str
) -> db.Job:
    """One change, its row and its job committed together, as the web makes it."""

    existing = db.blocklist(connection, change.name)
    try:
        if change.action == "remove":
            if existing is None:
                raise ApplyError(f"{change.name} is gone", code="expected_target_changed")
            return blocklist_form.remove(
                connection, existing, actor=actor, key=uuid.uuid4(), via="cli"
            )
        if change.action == "apply":
            if existing is None:
                raise ApplyError(f"{change.name} is gone", code="expected_target_changed")
            return blocklist_form.apply_again(connection, existing, actor=actor, via="cli")
        if change.wanted is None:
            raise ApplyError(f"{change.name}: nothing to store", code="internal_error")
        return blocklist_form.save(
            connection,
            change.wanted.definition,
            existing=existing,
            secret=change.wanted.secret,
            keep=change.keep,
            public_key=public_key,
            actor=actor,
            key=uuid.uuid4(),
            via="cli",
        )
    except blocklist_form.FormProblem as problem:
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


def _public_key() -> DnsProfilePublicKey:
    settings = config.load()
    if settings.dns_profiles_public_key is None:
        raise ApplyError("this installation has no profile key ([dns_profiles] public_key)")
    try:
        return read_public_key(settings.dns_profiles_public_key)
    except KeyFileError as exc:
        raise ApplyError(f"the profile key cannot be read: {exc}") from exc


def _run(
    args: argparse.Namespace,
    make_plan: Callable[[Any], Plan],
    *,
    sleep: Callable[[float], None],
) -> int:
    applied: list[dict[str, Any]] = []
    the_plan: Plan | None = None
    try:
        public_key = _public_key()
        with connect(load_environment()) as connection:
            the_plan = make_plan(connection)
            connection.commit()
            if not getattr(args, "check", False):
                actor = actor_name()
                for change in the_plan.changes:
                    job = _queue(connection, change, public_key=public_key, actor=actor)
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
    except config.ConfigError as exc:
        return _stopped(args, the_plan, applied, "dependency_unavailable", str(exc), exc.exit_code)
    except psycopg.Error as exc:
        code, exit_code = tool_answer.database_failure(exc)
        return _stopped(args, the_plan, applied, code, f"database: {exc}", exit_code)
    result = summary(the_plan, check=getattr(args, "check", False), applied=applied)
    if args.json:
        return tool_answer.done(OPERATION, result)
    if not the_plan.changes:
        print(
            f"nothing to change ({labels.counted(len(the_plan.unchanged), 'blocklist')} as listed)"
        )
    lead = "would" if getattr(args, "check", False) else "did"
    for change in the_plan.changes:
        again = " again" if change.action == "apply" else ""
        print(f"{lead} {change.action} blocklist {change.name}{again}")
    return 0


def command_apply(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    try:
        found = read_file(Path(args.file))
    except ApplyError as exc:
        return tool_answer.refusal(args, OPERATION, exc.code, str(exc), exc.exit_code)

    def make_plan(connection: Any) -> Plan:
        stored = {row.name: row for row in db.blocklists(connection)}
        return plan(
            found,
            stored,
            db.latest_blocklist_jobs(connection),
            replace_secret=args.replace_secret,
            prune=args.prune,
        )

    return _run(args, make_plan, sleep=sleep)


def command_remove(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    """One list removed, as the page's *Remove*; one already gone is no change."""

    if not blocklists.NAME.fullmatch(args.name):
        return tool_answer.refusal(
            args,
            OPERATION,
            "bad_input",
            f"{args.name!r} is not a blocklist's name: lowercase letters, digits and '-', "
            "starting with a letter, at most 40 characters",
            exit_codes.USAGE,
        )

    def make_plan(connection: Any) -> Plan:
        if db.blocklist(connection, args.name) is None:
            return Plan((), ())
        return Plan((Change(args.name, "remove"),), ())

    return _run(args, make_plan, sleep=sleep)


def build_parser() -> argparse.ArgumentParser:
    parser = arguments.ArgumentParser(
        prog="haprion-blocklists",
        description="Blocklists under Settings, from a file. Root only.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    apply = subcommands.add_parser("apply", help="store and apply a file's blocklists")
    apply.add_argument("file")
    apply.add_argument("--check", action="store_true", help="say what would change; change nothing")
    apply.add_argument("--json", action="store_true")
    apply.add_argument(
        "--replace-secret",
        action="append",
        default=[],
        metavar="NAME",
        help="seal and store this list's secret again; it cannot be compared",
    )
    apply.add_argument("--prune", action="store_true", help="remove stored lists not named")
    apply.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, help="seconds to wait for each job"
    )
    remove = subcommands.add_parser("remove", help="remove one blocklist")
    remove.add_argument("name")
    remove.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, help="seconds to wait for the job"
    )
    remove.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        return tool_answer.refusal(
            args, OPERATION, "not_root", "run this with sudo", exit_codes.NOT_ROOT
        )
    try:
        commands = {"apply": command_apply, "remove": command_remove}
        return commands[args.command](args)
    except AdminError as exc:
        return tool_answer.refusal(args, OPERATION, exc.code, str(exc), exc.exit_code)
    except psycopg.Error as exc:
        return tool_answer.database_refusal(args, OPERATION, exc)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())
