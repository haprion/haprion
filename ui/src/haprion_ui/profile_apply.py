"""``haprion-profiles apply`` - DNS and NDES profiles from a file (Fas 23, B293).

The terminal's way to the certificate profiles: the DNS provider credentials
`dns-01` issuance reads, and the NDES endpoints and challenges SCEP reads.
Each listed profile is sealed by the form's own code against the
installation's profile key, stored as the web stores it, and made real by the
same `*_profile_apply` job, which the worker runs through the root helper.

The credentials are sealed and cannot be compared, so a stored profile is
left as it is unless it must change - an NDES endpoint that differs - or
`--replace <id>` asks; the same file twice changes nothing. A DNS profile's
provider is fixed once stored, as in the interface: another provider is
another profile. `--prune` removes the stored profiles of a kind the file
lists and does not name; a kind the file leaves out is left alone.

Only one certificate job may be queued at a time (the queue's rule, the
publisher's lock), so each change is queued, then waited for, before the
next: the command ends when the worker has applied the last of them, or
says which one did not apply and stops there.

    dns_profiles:
      - id: cloudflare-main
        provider: cloudflare
        fields: {api_token: "..."}
    ndes_profiles:
      - id: corp-ca
        endpoint: https://ndes.example.com/certsrv/mscep/mscep.dll
        challenge: "..."
"""

from __future__ import annotations

import argparse
import json
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
from haprion import ndes_profiles
from haprion.dns_profile_keys import DnsProfilePublicKey, KeyFileError, read_public_key
from haprion.dns_profiles import ProfileError

from haprion_ui import config, db, dns_profile_form, job_wait, ndes_profile_form
from haprion_ui.admin import AdminError, actor_name, connect, load_environment, refused

OPERATION = "profiles_apply"
MAX_FILE_BYTES = 256 * 1024
MAX_PROFILES = 64
WAIT_SECONDS = job_wait.WAIT_SECONDS
EXIT_REFUSED = 65


class ApplyError(Exception):
    """What is wrong with the file or the change, as the form would say it."""


@dataclass(frozen=True, slots=True)
class Kind:
    name: str
    section: str
    operation: str
    listed: Callable[[Any], list[db.DnsProfile]]
    create: Callable[..., db.DnsProfile]
    replace: Callable[..., db.DnsProfile]


DNS = Kind(
    "dns",
    "dns_profiles",
    "dns_profile_apply",
    db.dns_profiles,
    db.create_dns_profile,
    db.replace_dns_profile,
)
NDES = Kind(
    "ndes",
    "ndes_profiles",
    "ndes_profile_apply",
    db.ndes_profiles,
    db.create_ndes_profile,
    db.replace_ndes_profile,
)
KINDS = (DNS, NDES)
BY_SECTION = {kind.section: kind for kind in KINDS}


@dataclass(frozen=True, slots=True)
class Wanted:
    kind: Kind
    profile_id: str
    provider_id: str
    values: dict[str, str] = field(repr=False)


@dataclass(frozen=True, slots=True)
class Change:
    kind: Kind
    profile_id: str
    action: str
    """`create`, `replace` or `remove`."""

    revision: int
    sealed: dns_profile_form.Sealed | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class Plan:
    changes: tuple[Change, ...]
    unchanged: tuple[str, ...]


def _text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ApplyError(f"{where} must be text")
    return value


def _field_text(value: object, where: str) -> str:
    """One field as the form would have posted it: text, a number, or a list of lines.

    Anything else is refused rather than turned into its Python spelling: a
    YAML `null` must not be sealed as the word `None`, nor `true` as `True`.
    """

    if isinstance(value, str):
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return "\n".join(value)
    raise ApplyError(f"{where} must be text, a number or a list of text")


def read_file(path: Path) -> dict[str, list[Wanted]]:
    """The listed profiles by section; a section the file leaves out is absent."""

    try:
        status = path.stat()
        if status.st_size > MAX_FILE_BYTES:
            raise ApplyError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ApplyError(f"{path}: {exc.strerror}") from exc
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ApplyError(f"{path}: not UTF-8 YAML") from exc
    sections = BY_SECTION
    if not isinstance(document, Mapping) or not document:
        raise ApplyError(f"{path}: the file holds dns_profiles, ndes_profiles or both")
    unknown = sorted(str(key) for key in document if key not in sections)
    if unknown:
        raise ApplyError(f"{path}: unknown section(s): {', '.join(unknown)}")
    found: dict[str, list[Wanted]] = {}
    for section, entries in document.items():
        kind = sections[section]
        if entries is None:
            entries = []
        if not isinstance(entries, list) or len(entries) > MAX_PROFILES:
            raise ApplyError(f"{path}: {section} is a list of at most {MAX_PROFILES} profiles")
        wanted: list[Wanted] = []
        seen: set[str] = set()
        for number, entry in enumerate(entries, start=1):
            where = f"{path}: {section} {number}"
            if not isinstance(entry, Mapping):
                raise ApplyError(f"{where} must be a mapping")
            allowed = (
                {"id", "provider", "fields"} if kind is DNS else {"id", "endpoint", "challenge"}
            )
            extra = sorted(str(key) for key in entry if key not in allowed)
            if extra:
                raise ApplyError(f"{where} has unknown field(s): {', '.join(extra)}")
            profile_id = _text(entry.get("id"), f"{where} id").strip().lower()
            if profile_id in seen:
                raise ApplyError(f"{where}: {profile_id} is listed twice")
            seen.add(profile_id)
            if kind is DNS:
                given = entry.get("fields") or {}
                if not isinstance(given, Mapping):
                    raise ApplyError(f"{where}: fields maps a field to its value")
                values = {
                    str(name): _field_text(value, f"{where} fields.{name}")
                    for name, value in given.items()
                }
                provider_id = _text(entry.get("provider"), f"{where} provider")
            else:
                values = {
                    "endpoint": _text(entry.get("endpoint"), f"{where} endpoint"),
                    "challenge": _text(entry.get("challenge", ""), f"{where} challenge"),
                }
                provider_id = "ndes"
            wanted.append(Wanted(kind, profile_id, provider_id, values))
        found[section] = wanted
    if any(found.values()) and status.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ApplyError(
            f"{path} carries credentials and may be read by others than its owner; "
            "make it mode 0600"
        )
    return found


def _seal(
    wanted: Wanted, public_key: DnsProfilePublicKey, *, revision: int, taken: Sequence[str]
) -> dns_profile_form.Sealed:
    try:
        if wanted.kind is DNS:
            return dns_profile_form.seal_submission(
                dns_profile_form.ProfileForm(wanted.profile_id, wanted.provider_id, wanted.values),
                public_key,
                revision=revision,
                taken=taken,
            )
        return ndes_profile_form.seal_submission(
            ndes_profile_form.ProfileForm(wanted.profile_id, values=wanted.values),
            public_key,
            revision=revision,
            taken=taken,
        )
    except dns_profile_form.FormProblem as problem:
        raise ApplyError(f"{wanted.kind.section} {wanted.profile_id}: {problem}") from problem


def _endpoint(value: str) -> str:
    try:
        return ndes_profiles.check_endpoint(value)
    except ProfileError:
        return value


def plan(
    found: Mapping[str, Sequence[Wanted]],
    stored: Mapping[str, Sequence[db.DnsProfile]],
    public_key: DnsProfilePublicKey,
    *,
    replace: Sequence[str],
    prune: bool,
) -> Plan:
    """What would change, with every new box sealed: a bad entry is refused before any write."""

    changes: list[Change] = []
    unchanged: list[str] = []
    asked = set(replace)
    for section, wanted_list in found.items():
        rows = {row.id: row for row in stored.get(section, ())}
        taken = list(rows)
        for wanted in wanted_list:
            row = rows.get(wanted.profile_id)
            if row is None:
                sealed = _seal(wanted, public_key, revision=1, taken=taken)
                changes.append(Change(wanted.kind, wanted.profile_id, "create", 1, sealed))
                continue
            if wanted.kind is DNS and row.provider_id != wanted.provider_id:
                raise ApplyError(
                    f"dns_profiles {wanted.profile_id} is stored for {row.provider_id}; "
                    "a profile keeps its provider - give the new one another id"
                )
            moved = wanted.kind is NDES and _endpoint(wanted.values["endpoint"]) != row.endpoint
            if moved or wanted.profile_id in asked:
                sealed = _seal(wanted, public_key, revision=row.revision + 1, taken=taken)
                changes.append(
                    Change(wanted.kind, wanted.profile_id, "replace", row.revision + 1, sealed)
                )
            else:
                unchanged.append(f"{wanted.kind.name}/{wanted.profile_id}")
        if prune:
            named = {wanted.profile_id for wanted in wanted_list}
            kind = BY_SECTION[section]
            changes.extend(
                Change(kind, row.id, "remove", row.revision)
                for row in stored.get(section, ())
                if row.id not in named
            )
    unknown = asked - {
        wanted.profile_id for wanted_list in found.values() for wanted in wanted_list
    }
    if unknown:
        raise ApplyError(f"--replace names a profile the file does not list: {sorted(unknown)}")
    return Plan(tuple(changes), tuple(unchanged))


def _queue(connection: Any, change: Change, *, actor: str) -> db.Job:
    """The row and its job in one transaction, as the web saves a profile."""

    payload: dict[str, Any] = {"profile": change.profile_id, "revision": change.revision}
    sealed = change.sealed
    try:
        if change.action == "remove":
            payload["remove"] = True
        elif sealed is not None:
            extra = {"endpoint": sealed.endpoint} if change.kind is NDES else {}
            if change.action == "create":
                change.kind.create(
                    connection,
                    profile_id=sealed.profile_id,
                    name=sealed.name,
                    provider_id=sealed.provider_id,
                    key_id=sealed.key_id,
                    ciphertext=sealed.ciphertext,
                    actor=actor,
                    **extra,
                )
            else:
                change.kind.replace(
                    connection,
                    profile_id=sealed.profile_id,
                    revision=change.revision,
                    key_id=sealed.key_id,
                    ciphertext=sealed.ciphertext,
                    actor=actor,
                    name=sealed.name,
                    **extra,
                )
        job = db.queue_job(
            connection,
            operation=change.kind.operation,
            cluster=None,
            payload=payload,
            idempotency_key=uuid.uuid4(),
        )
    except (db.ProfileExists, db.ProfileMissing) as exc:
        raise ApplyError(
            f"{change.kind.section} {change.profile_id} changed while this ran; run it again"
        ) from exc
    except db.CertificateBusy as exc:
        raise ApplyError(
            "A certificate job is already running. Wait for it to finish, then run this again."
        ) from exc
    db.record_audit_event(
        connection,
        actor=actor,
        action="queue_job",
        cluster=None,
        request_id=job.request_id,
        detail={
            "operation": change.kind.operation,
            "job": job.id,
            "profile": change.profile_id,
            "revision": change.revision,
            "via": "cli",
            **({"remove": True} if change.action == "remove" else {}),
        },
    )
    return job


def summary(the_plan: Plan, *, check: bool, applied: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "changed": bool(the_plan.changes),
        "check": check,
        "changes": [
            {"kind": change.kind.name, "profile": change.profile_id, "action": change.action}
            for change in the_plan.changes
        ],
        "jobs": list(applied),
        "unchanged": list(the_plan.unchanged),
    }


def envelope(result: Any, error: str | None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": error is None,
        "outcome": "done" if error is None else "failed",
        "operation": OPERATION,
        "cluster": None,
        "request_id": str(uuid.uuid4()),
        "result": result,
        "warnings": [],
        "error": None if error is None else {"code": "refused", "message": error[:2048]},
    }


def command_apply(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    applied: list[dict[str, Any]] = []
    the_plan: Plan | None = None
    try:
        found = read_file(Path(args.file))
        settings = config.load()
        if settings.dns_profiles_public_key is None:
            raise ApplyError("this installation has no profile key ([dns_profiles] public_key)")
        try:
            public_key = read_public_key(settings.dns_profiles_public_key)
        except KeyFileError as exc:
            raise ApplyError(f"the profile key cannot be read: {exc}") from exc
        with connect(load_environment()) as connection:
            stored = {kind.section: kind.listed(connection) for kind in KINDS}
            connection.commit()
            the_plan = plan(found, stored, public_key, replace=args.replace, prune=args.prune)
            if not args.check:
                actor = actor_name()
                for change in the_plan.changes:
                    job = _queue(connection, change, actor=actor)
                    connection.commit()
                    state, problem = job_wait.finished(
                        connection, job.id, wait=args.wait, sleep=sleep
                    )
                    applied.append(
                        {
                            "kind": change.kind.name,
                            "profile": change.profile_id,
                            "job": job.id,
                            "state": state,
                        }
                    )
                    if problem:
                        raise ApplyError(f"{change.kind.section} {change.profile_id}: {problem}")
    except (ApplyError, config.ConfigError) as exc:
        if args.json:
            print(json.dumps(envelope(None, str(exc))))
            return EXIT_REFUSED
        for entry in applied:
            print(f"{entry['kind']} {entry['profile']}: job {entry['job']} {entry['state']}")
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    result = summary(the_plan, check=args.check, applied=applied)
    if args.json:
        print(json.dumps(envelope(result, None)))
        return 0
    if not the_plan.changes:
        print(f"nothing to change ({len(the_plan.unchanged)} profile(s) as listed)")
    lead = "would" if args.check else "did"
    for change in the_plan.changes:
        print(f"{lead} {change.action} {change.kind.name} profile {change.profile_id}")
    return 0


def command_remove(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    """One profile removed, as the page's *Remove*; one already gone is no change.

    `--json` answers as `apply` does (`profiles_apply`), with the one removal.
    """

    kind = DNS if args.kind == "dns" else NDES

    def refused(message: str) -> int:
        if args.json:
            print(json.dumps(envelope(None, message)))
        else:
            print(f"ERROR: {message}", file=sys.stderr)
        return EXIT_REFUSED

    with connect(load_environment()) as connection:
        row = next((row for row in kind.listed(connection) if row.id == args.profile), None)
        connection.commit()
        if row is None:
            if args.json:
                print(json.dumps(envelope(summary(Plan((), ()), check=False, applied=[]), None)))
            else:
                print(f"no {kind.name} profile {args.profile}; nothing to change")
            return 0
        change = Change(kind, row.id, "remove", row.revision)
        try:
            job = _queue(connection, change, actor=actor_name())
            connection.commit()
            state, problem = job_wait.finished(connection, job.id, wait=args.wait, sleep=sleep)
        except ApplyError as exc:
            return refused(str(exc))
    if problem:
        return refused(f"{kind.section} {row.id}: {problem}")
    if args.json:
        applied = [{"kind": kind.name, "profile": row.id, "job": job.id, "state": state}]
        print(
            json.dumps(envelope(summary(Plan((change,), ()), check=False, applied=applied), None))
        )
    else:
        print(f"removed {kind.name} profile {row.id} (job {job.id})")
    return 0


def command_list(args: argparse.Namespace) -> int:
    with connect(load_environment()) as connection:
        rows = {kind.name: kind.listed(connection) for kind in KINDS}
    shown = {
        name: [
            {
                "id": row.id,
                "provider": row.provider_id,
                "revision": row.revision,
                **({"endpoint": row.endpoint} if name == "ndes" else {}),
            }
            for row in listed
        ]
        for name, listed in rows.items()
    }
    if args.json:
        print(json.dumps(shown))
        return 0
    for name, listed in shown.items():
        for entry in listed:
            print(
                f"{name:<5} {entry['id']:<33} {entry['provider']:<16} revision {entry['revision']}"
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-profiles",
        description="DNS and NDES profiles for certificate issuance. Root only.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    apply = subcommands.add_parser("apply", help="store and apply a file's profiles where needed")
    apply.add_argument("file")
    apply.add_argument("--check", action="store_true", help="say what would change; change nothing")
    apply.add_argument("--json", action="store_true")
    apply.add_argument(
        "--replace",
        action="append",
        default=[],
        metavar="ID",
        help="seal and store this profile's credentials again; they cannot be compared",
    )
    apply.add_argument(
        "--prune", action="store_true", help="remove stored profiles of a listed kind not named"
    )
    apply.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, help="seconds to wait for each job"
    )
    remove = subcommands.add_parser("remove", help="remove one stored profile")
    remove.add_argument("kind", choices=("dns", "ndes"))
    remove.add_argument("profile")
    remove.add_argument(
        "--wait", type=float, default=WAIT_SECONDS, help="seconds to wait for the job"
    )
    remove.add_argument("--json", action="store_true")
    listing = subcommands.add_parser("list", help="the stored profiles; never a credential")
    listing.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    contract = envelope if args.command in ("apply", "remove") else None
    if os.geteuid() != 0:
        return refused(args, "run this with sudo", 77, contract)
    try:
        commands = {"apply": command_apply, "remove": command_remove, "list": command_list}
        return commands[args.command](args)
    except AdminError as exc:
        return refused(args, str(exc), 64, contract)
    except psycopg.Error as exc:
        return refused(args, f"database: {exc}", 74, contract)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())
