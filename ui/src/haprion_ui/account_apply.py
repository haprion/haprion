"""``haprion-user apply`` - the accounts from a file (Fas 23, B293).

The terminal's way to what *Settings -> Users* sets, for automation: each
listed account with its role, whether it is break-glass, whether it is
disabled, and its password. What is stored is compared first and only what
differs is written - a password is checked against the stored hash rather
than set again - so the same file twice changes nothing. Every change goes
through the functions the web's own page writes with, in one transaction,
under the same database guards: the last active admin, and the break-glass
admin sign-in through a provider needs, are refused here as there.

The file carries passwords, so it is refused when anybody but its owner may
read it. A listed account the provider created keeps the role and password
the provider and the interface give it; only `disabled` applies to it. An
account no entry names is left alone unless `--prune` asks for it to go, and
`--prune` never removes an account the provider created.

    accounts:
      - username: admin
        role: admin
        break_glass: true
        password: "..."        # set on creation, and wherever it no longer matches
      - username: viewer
        role: reader
        disabled: false
"""

from __future__ import annotations

import stat
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from haprion_ui import auth, db, users

OPERATION = "user_apply"
KEYS = frozenset({"username", "role", "break_glass", "disabled", "password"})
MAX_ACCOUNTS = 500
MAX_FILE_BYTES = 256 * 1024


class ApplyError(Exception):
    """What is wrong with the file or the change; nothing was written."""


@dataclass(frozen=True, slots=True)
class Wanted:
    username: str
    role: str
    break_glass: bool | None = None
    disabled: bool | None = None
    password: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class Stored:
    id: int
    username: str
    role: str
    disabled: bool
    source: str
    break_glass: bool
    password_hash: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class Plan:
    created: tuple[Wanted, ...] = ()
    #
    # Per account, the fields that change: role, password, break_glass, disabled.
    #
    updated: tuple[tuple[Stored, Wanted, tuple[str, ...]], ...] = ()
    deleted: tuple[Stored, ...] = ()
    unchanged: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.created or self.updated or self.deleted)


def _flag(entry: Mapping[str, Any], key: str, where: str) -> bool | None:
    value = entry.get(key)
    if value is None or isinstance(value, bool):
        return value
    raise ApplyError(f"{where}: {key} must be true or false")


def read_file(path: Path) -> list[Wanted]:
    try:
        status = path.stat()
        if status.st_size > MAX_FILE_BYTES:
            raise ApplyError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ApplyError(f"{path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise ApplyError(f"{path}: not UTF-8") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ApplyError(f"{path}: not valid YAML") from exc
    if not isinstance(document, Mapping) or set(document) != {"accounts"}:
        raise ApplyError(f"{path}: the file is one key, accounts, holding a list")
    entries = document["accounts"]
    if not isinstance(entries, list) or len(entries) > MAX_ACCOUNTS:
        raise ApplyError(f"{path}: accounts must be a list of at most {MAX_ACCOUNTS}")
    wanted: list[Wanted] = []
    seen: set[str] = set()
    for number, entry in enumerate(entries, start=1):
        where = f"{path}: account {number}"
        if not isinstance(entry, Mapping):
            raise ApplyError(f"{where} must be a mapping")
        unknown = sorted(str(key) for key in entry if key not in KEYS)
        if unknown:
            raise ApplyError(f"{where} has unknown field(s): {', '.join(unknown)}")
        username = entry.get("username")
        if not isinstance(username, str):
            raise ApplyError(f"{where} needs a username")
        problem = users.name_problem(username)
        if problem is not None:
            raise ApplyError(f"{where}: {problem}")
        if username.lower() in seen:
            raise ApplyError(f"{where}: {username} is listed twice")
        seen.add(username.lower())
        role = entry.get("role")
        if role not in users.ROLES:
            raise ApplyError(f"{where}: role must be one of {', '.join(users.ROLES)}")
        password = entry.get("password")
        if password is not None:
            if not isinstance(password, str):
                raise ApplyError(f"{where}: password must be text")
            problem = password_problem(password)
            if problem:
                raise ApplyError(f"{where}: {problem}")
        wanted.append(
            Wanted(
                username=username,
                role=str(role),
                break_glass=_flag(entry, "break_glass", where),
                disabled=_flag(entry, "disabled", where),
                password=password,
            )
        )
    if any(account.password is not None for account in wanted) and (
        status.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    ):
        raise ApplyError(
            f"{path} carries passwords and may be read by others than its owner; make it mode 0600"
        )
    return wanted


def password_problem(password: str) -> str:
    """The web's own rule for a new password, in the same words."""

    if len(password) < auth.MINIMUM_PASSWORD_LENGTH:
        return f"a password must be at least {auth.MINIMUM_PASSWORD_LENGTH} characters"
    if len(password.encode("utf-8")) > auth.MAX_PASSWORD_BYTES:
        return f"a password must be under {auth.MAX_PASSWORD_BYTES} bytes"
    return ""


def stored_accounts(connection: Any) -> list[Stored]:
    with connection.cursor() as cursor:
        cursor.execute(
            "select id, username, role, disabled, source, break_glass, password_hash "
            "  from app_user order by username_normalised"
        )
        return [Stored(*row) for row in cursor.fetchall()]


def document(connection: Any) -> dict[str, Any]:
    """The stored accounts as the file `read_file` takes: no passwords, which are never read back.

    A provider's account carries no `break_glass`, which the file may not set
    for it; applying this to the installation it came from changes nothing.
    """

    accounts: list[dict[str, Any]] = []
    for row in stored_accounts(connection):
        entry: dict[str, Any] = {
            "username": row.username,
            "role": row.role,
            "disabled": row.disabled,
        }
        if row.source == "local":
            entry["break_glass"] = row.break_glass
        accounts.append(entry)
    return {"accounts": accounts}


def plan(wanted: Sequence[Wanted], current: Sequence[Stored], *, prune: bool) -> Plan:
    by_name = {account.username.lower(): account for account in current}
    created: list[Wanted] = []
    updated: list[tuple[Stored, Wanted, tuple[str, ...]]] = []
    unchanged: list[str] = []
    for account in wanted:
        row = by_name.get(account.username.lower())
        if row is None:
            if account.password is None:
                raise ApplyError(f"{account.username} is new and needs a password")
            created.append(account)
            continue
        provider = row.source != "local"
        fields: list[str] = []
        if not provider and account.role != row.role:
            fields.append("role")
        if (
            not provider
            and account.password is not None
            and not (
                row.password_hash and auth.verify_password(row.password_hash, account.password)
            )
        ):
            fields.append("password")
        if (
            not provider
            and account.break_glass is not None
            and account.break_glass != row.break_glass
        ):
            fields.append("break_glass")
        if account.disabled is not None and account.disabled != row.disabled:
            fields.append("disabled")
        if provider and (account.role != row.role or account.password or account.break_glass):
            raise ApplyError(
                f"{account.username} signs in through the provider, which sets its role; "
                "only disabled applies to it"
            )
        if fields:
            updated.append((row, account, tuple(fields)))
        else:
            unchanged.append(row.username)
    listed = {account.username.lower() for account in wanted}
    deleted = (
        tuple(
            row for row in current if row.source == "local" and row.username.lower() not in listed
        )
        if prune
        else ()
    )
    return Plan(
        created=tuple(created), updated=tuple(updated), deleted=deleted, unchanged=tuple(unchanged)
    )


def write(connection: Any, the_plan: Plan, *, actor: str) -> None:
    """Every change of the plan, audited as the web audits it, in the caller's transaction."""

    def audit(action: str, account: str, **detail: object) -> None:
        db.record_audit_event(
            connection,
            actor=actor,
            action=action,
            detail={"account": account, "via": "cli", **detail},
        )

    try:
        for account in the_plan.created:
            if account.password is None:
                raise ApplyError(f"{account.username} is new and needs a password")
            db.create_account(
                connection,
                username=account.username,
                password_hash=auth.hash_password(account.password),
                role=account.role,
                break_glass=bool(account.break_glass),
            )
            audit(
                "account_created",
                account.username,
                role=account.role,
                break_glass=bool(account.break_glass),
            )
            if account.disabled:
                stored = {row.username.lower(): row for row in stored_accounts(connection)}
                db.set_disabled(
                    connection, user_id=stored[account.username.lower()].id, disabled=True
                )
                audit("account_disabled", account.username, sessions_revoked=0)
        for row, account, fields in the_plan.updated:
            if "role" in fields:
                db.set_role(connection, user_id=row.id, role=account.role)
                audit("role_changed", row.username, role=account.role, previous=row.role)
            if "password" in fields:
                if account.password is None:
                    raise ApplyError(f"{row.username}: no password to set")
                ended = db.reset_password(
                    connection, user_id=row.id, password_hash=auth.hash_password(account.password)
                )
                audit("password_reset", row.username, sessions_revoked=ended)
            if "break_glass" in fields:
                db.set_break_glass(
                    connection, user_id=row.id, break_glass=bool(account.break_glass)
                )
                audit("break_glass_changed", row.username, break_glass=bool(account.break_glass))
            if "disabled" in fields:
                ended = db.set_disabled(connection, user_id=row.id, disabled=bool(account.disabled))
                if account.disabled:
                    audit("account_disabled", row.username, sessions_revoked=ended)
                else:
                    audit("account_enabled", row.username)
        for row in the_plan.deleted:
            if db.delete_account(connection, user_id=row.id):
                audit("account_deleted", row.username, role=row.role, source=row.source)
    except db.NoBreakGlass as exc:
        raise ApplyError(
            "sign-in through the provider is on and needs an active break-glass admin"
        ) from exc
    except db.LastAdmin as exc:
        raise ApplyError("the last active admin cannot be demoted, disabled or deleted") from exc


def summary(the_plan: Plan, *, check: bool) -> dict[str, Any]:
    return {
        "changed": not the_plan.empty,
        "check": check,
        "created": [account.username for account in the_plan.created],
        "updated": [
            {"username": row.username, "fields": list(fields)}
            for row, _, fields in the_plan.updated
        ],
        "deleted": [row.username for row in the_plan.deleted],
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
