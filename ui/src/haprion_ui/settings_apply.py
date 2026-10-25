"""``haprion-settings apply`` - the interface's own settings from a file (Fas 23, B293).

The terminal's way to three things under *Settings*: who may ask `/status/`
(*External monitoring*), the feature switches, and sign-in through an OIDC
provider. Each section is optional, and a section the file leaves out is left
as it is. What is stored is read first and only what differs is written, so
the same file twice changes nothing.

Every write goes through the code the web's own pages use: the address list
through `attention.access_list` and `db.set_status_access`, a switch through
`feature_switch.switch` (with its refusals and its backup schedule jobs), and
the provider through `oidc_web.parse`, the OIDC helper's Verify and the
row's own guards - sign-in through the provider turns on only at settings that
passed Verify, and only with an active break-glass admin.

The client secret cannot be compared: the interface keeps it sealed against a
key only the OIDC helper holds. It is therefore sealed and stored when none is
stored, when the issuer or the client changes (the sealed secret is bound to
both), or when `--replace-oidc-secret` asks; otherwise the stored one is kept
and the answer says so. A file that carries it is refused unless only its
owner may read it.

    status_access: [192.0.2.10, 198.51.100.0/24]   # [] switches /status/ off
    features:
      node_backups: true
      waf_engine: false
    oidc:
      issuer: https://idp.example.com/realms/main
      client_id: haprion
      client_secret: "..."            # or --oidc-secret-stdin
      auth_method: client_secret_basic
      scopes: openid profile
      username_claim: preferred_username
      groups_claim: groups
      admin_group: haprion-admins
      reader_group: haprion-readers
      button_text: Sign in with SSO
      prompt_login: false
      logout_mode: app                # app | provider
      local_login: break_glass_only   # break_glass_only | all
      ca_pem: null
      enabled: true
      interface_url: https://mgr.example.com   # where people sign in; for Verify
"""

from __future__ import annotations

import contextlib
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml
from haprion import oidc, safe_yaml

from haprion_ui import attention, db, feature_switch, features, labels, oidc_web, tool_answer

OPERATION = "settings_apply"
SECTIONS = frozenset({"status_access", "features", "oidc"})
MAX_FILE_BYTES = 256 * 1024
#
# What the provider form has, as the file names it. `client_secret` is the
# typed secret, `enabled` the On/Off buttons and `interface_url` the address
# the web would have taken from the request; the rest are the row's columns.
#
OIDC_FLAGS = ("prompt_login",)
OIDC_TEXT = (
    "issuer",
    "client_id",
    "auth_method",
    "scopes",
    "username_claim",
    "groups_claim",
    "admin_group",
    "reader_group",
    "button_text",
    "logout_mode",
    "local_login",
    "ca_pem",
)
OIDC_KEYS = frozenset({*OIDC_FLAGS, *OIDC_TEXT, "client_secret", "enabled", "interface_url"})


class ApplyError(tool_answer.ToolError):
    """What is wrong with the file or the change; said as the page says it."""


@dataclass(frozen=True, slots=True)
class Wanted:
    status_access: tuple[str, ...] | None = None
    features: dict[str, bool] = field(default_factory=dict)
    oidc: dict[str, Any] | None = field(default=None, repr=False)


@dataclass(slots=True)
class Outcome:
    status_access: dict[str, list[str]] | None = None
    features: dict[str, bool] = field(default_factory=dict)
    oidc: dict[str, Any] | None = None

    @property
    def changed(self) -> bool:
        return bool(
            self.status_access
            or self.features
            or (self.oidc and (self.oidc["fields"] or self.oidc["enabled"] is not None))
        )


def read_file(path: Path) -> Wanted:
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
        document = safe_yaml.load(text)
    except yaml.YAMLError as exc:
        raise ApplyError(f"{path}: not valid YAML") from exc
    if not isinstance(document, Mapping) or not document:
        raise ApplyError(f"{path}: the file holds status_access, features, oidc or several")
    unknown = sorted(str(key) for key in document if key not in SECTIONS)
    if unknown:
        raise ApplyError(
            f"{path}: unknown {labels.noun(len(unknown), 'section')}: {', '.join(unknown)}"
        )

    access: tuple[str, ...] | None = None
    if "status_access" in document:
        listed = document["status_access"]
        if listed is None:
            listed = []
        if not isinstance(listed, list) or not all(isinstance(entry, str) for entry in listed):
            raise ApplyError(f"{path}: status_access is a list of addresses or networks")
        try:
            access = attention.access_list("\n".join(listed))
        except ValueError as exc:
            raise ApplyError(f"{path}: status_access: {exc}") from exc

    switches: dict[str, bool] = {}
    if "features" in document:
        given = document["features"]
        if not isinstance(given, Mapping):
            raise ApplyError(f"{path}: features maps a feature to true or false")
        for name, value in given.items():
            if name not in features.BY_NAME:
                raise ApplyError(
                    f"{path}: no feature {name}; there are {', '.join(features.BY_NAME)}"
                )
            if not isinstance(value, bool):
                raise ApplyError(f"{path}: features.{name} must be true or false")
            switches[str(name)] = value

    provider: dict[str, Any] | None = None
    if "oidc" in document:
        given = document["oidc"]
        if not isinstance(given, Mapping):
            raise ApplyError(f"{path}: oidc is a mapping of the provider's settings")
        if "auto_create" in given:
            raise ApplyError(
                f"{path}: oidc auto_create is gone: an account is made at the first sign-in, "
                "with the role the groups give; leave the key out"
            )
        unknown = sorted(str(key) for key in given if key not in OIDC_KEYS)
        if unknown:
            raise ApplyError(
                f"{path}: oidc has unknown {labels.noun(len(unknown), 'field')}: {', '.join(unknown)}"
            )
        for key in (*OIDC_FLAGS, "enabled"):
            if key in given and not isinstance(given[key], bool):
                raise ApplyError(f"{path}: oidc.{key} must be true or false")
        for key in (*OIDC_TEXT, "client_secret", "interface_url"):
            if given.get(key) is not None and not isinstance(given[key], str):
                raise ApplyError(f"{path}: oidc.{key} must be text")
        provider = dict(given)
        if provider.get("client_secret") and status.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ApplyError(
                f"{path} carries the client secret and may be read by others than its owner; "
                "make it mode 0600"
            )
    return Wanted(status_access=access, features=switches, oidc=provider)


def document(connection: Any) -> dict[str, Any]:
    """What is set now as the file `read_file` takes; the client secret never.

    The provider section only when an issuer is stored: a provider that was
    never configured has nothing a file could say. Without the secret, the
    file applies to the installation it came from - the stored secret is kept
    - and a new installation needs it added (`--oidc-secret-stdin`), and
    `interface_url` to turn sign-in on.
    """

    shown: dict[str, Any] = {
        "status_access": [entry.network for entry in db.status_access(connection)],
        "features": {
            name: switch.enabled for name, switch in sorted(db.feature_switches(connection).items())
        },
    }
    provider = db.oidc_provider(connection)
    if provider is not None and provider.issuer is not None:
        shown["oidc"] = provider_fields(provider)
    return shown


def provider_fields(provider: db.OidcProvider) -> dict[str, Any]:
    """The provider's settings by the file's names, and whether it is on; never the secret."""

    return {
        **{key: getattr(provider, key) for key in (*OIDC_TEXT, *OIDC_FLAGS)},
        "enabled": provider.enabled,
    }


# - External monitoring ---------------------------------------------------------


def apply_status_access(
    connection: Any, wanted: tuple[str, ...], *, actor: str
) -> dict[str, list[str]] | None:
    stored = [entry.network for entry in db.status_access(connection)]
    if set(stored) == set(wanted):
        return None
    db.set_status_access(connection, networks=wanted, actor=actor)
    db.record_audit_event(
        connection,
        actor=actor,
        action="status_access_changed",
        detail={"networks": list(wanted), "via": "cli"},
    )
    return {
        "added": sorted(set(wanted) - set(stored)),
        "removed": sorted(set(stored) - set(wanted)),
    }


# - feature switches -------------------------------------------------------------


def apply_features(
    connection: Any,
    wanted: Mapping[str, bool],
    *,
    actor: str,
    readings: feature_switch.Readings,
    queued: list[db.Job] | None = None,
) -> dict[str, bool]:
    """Each switch the file names, flipped where it differs, refused as the page refuses.

    Written in the caller's transaction, so `--check` runs the same refusals
    and rolls back rather than guessing which of them would apply. The backup
    schedule jobs a switch queued are added to `queued`, for the caller to
    wait for once it has committed.
    """

    flipped: dict[str, bool] = {}
    for name, want in sorted(wanted.items()):
        try:
            jobs = feature_switch.switch(
                connection, name=name, want=want, actor=actor, via="cli", readings=readings
            )
            if jobs is not None:
                flipped[name] = want
                if queued is not None:
                    queued.extend(jobs)
        except feature_switch.UnknownFeature as exc:
            raise ApplyError(f"no feature {name} in this database") from exc
        except features.SwitchRefused as exc:
            raise ApplyError(f"{name}: {exc}") from exc
    return flipped


# - the OIDC provider -------------------------------------------------------------


type Verify = Callable[[db.OidcProvider, str], tuple[bool, list[dict[str, Any]], str]]


def verify_with_helper(
    provider: db.OidcProvider, redirect: str
) -> tuple[bool, list[dict[str, Any]], str]:
    """The web's Verify: the helper asks the provider whether it accepts this client."""

    try:
        result = oidc_web.ask("verify", provider, redirect=redirect)
    except oidc_web.OidcProblem as error:
        return False, [], str(error)
    checks = [check for check in result.get("checks", []) if isinstance(check, dict)]
    return result.get("ok") is True, checks, ""


def _form(wanted: Mapping[str, Any], current: db.OidcProvider, *, secret: str) -> dict[str, str]:
    """The file over the stored row, as the settings form would post it."""

    form: dict[str, str] = {}
    for key in OIDC_TEXT:
        value = wanted[key] if key in wanted else getattr(current, key)
        form[key] = "" if value is None else str(value)
    for key in OIDC_FLAGS:
        value = wanted[key] if key in wanted else getattr(current, key)
        form[key] = "on" if value else ""
    form["client_secret"] = secret
    return form


def _identity(wanted: Mapping[str, Any], current: db.OidcProvider) -> tuple[str, str]:
    """The issuer and client the file names, as `oidc_web.parse` will store them.

    Compared before parsing, to know whether the sealed secret still fits: an
    issuer written with a trailing slash is the stored one, and must not ask
    for the secret again on every run.
    """

    issuer = str(wanted.get("issuer", current.issuer) or "").strip()
    with contextlib.suppress(oidc.OidcError):
        issuer = oidc.issuer_url(issuer)
    return issuer, str(wanted.get("client_id", current.client_id) or "").strip()


def _failed_verify(trouble: str, checks: list[dict[str, Any]]) -> str:
    failed = [
        f"{check.get('name')}: {check.get('message')}" for check in checks if not check.get("ok")
    ]
    return trouble or "Verify found a problem: " + "; ".join(failed or ["no check passed"])


def apply_oidc(
    connection: Any,
    wanted: Mapping[str, Any],
    *,
    actor: str,
    check: bool,
    public_key: Path | None,
    replace_secret: bool,
    piped_secret: str | None,
    verify: Verify | None = None,
) -> dict[str, Any] | None:
    """Save, Verify and On/Off as the provider page does them, where they differ.

    Commits as it goes, as the page does between its buttons: settings saved
    while off stay saved when Verify then fails, and the answer says why
    sign-in did not turn on.
    """

    verify = verify or verify_with_helper
    current = db.oidc_provider(connection)
    if current is None:
        raise ApplyError("this database has no OIDC provider row; is the schema current?")
    secret = piped_secret if piped_secret is not None else wanted.get("client_secret") or ""
    settings_given = any(key in wanted for key in (*OIDC_TEXT, *OIDC_FLAGS))
    fields: list[str] = []
    sealing: str | None = None
    parsed: oidc_web.Parsed | None = None
    if settings_given or secret:
        needs_secret = (
            replace_secret
            or current.client_secret_sealed is None
            or _identity(wanted, current) != (current.issuer, current.client_id)
        )
        parsed = oidc_web.parse(
            _form(wanted, current, secret=secret if needs_secret else ""),
            current,
            public_key=public_key,
        )
        if parsed.problem:
            raise ApplyError(f"oidc: {parsed.problem}")
        fields = [
            name
            for name, value in parsed.settings.items()
            if name not in ("client_secret_sealed", "key_id") and getattr(current, name) != value
        ]
        if "client_secret_sealed" in parsed.settings:
            sealing = "replaced"
            fields.append("client_secret")
        elif secret:
            sealing = "kept"
    want_on = wanted.get("enabled")
    turn: bool | None = None if want_on is None or want_on == current.enabled else bool(want_on)
    redirect = oidc_web.redirect_uri(str(wanted.get("interface_url") or ""))
    on_after = current.enabled if turn is None else turn
    must_verify = (fields and on_after) or (turn is True and not (current.verified and not fields))
    if must_verify and not wanted.get("interface_url"):
        raise ApplyError(
            "oidc: interface_url is needed to verify the settings with the provider "
            "(the address people sign in at, such as https://mgr.example.com)"
        )
    answer: dict[str, Any] = {"fields": fields, "enabled": turn, "sealing": sealing}
    if check or (not fields and turn is None):
        return answer if (fields or turn is not None or sealing) else None

    if turn is False:
        _set_enabled(connection, False, actor=actor, issuer=current.issuer)
    if fields and parsed is not None:
        verified = False
        if on_after and current.enabled and turn is None:
            #
            # On, the row accepts only verified settings: verified first, and
            # saved as verified in one statement - the page's Save while on.
            #
            ok, checks, trouble = verify(replace(current, **parsed.settings), redirect)
            if not ok:
                raise ApplyError(
                    "oidc: sign-in through the provider is on, and these settings did not "
                    f"pass Verify; nothing was saved. {_failed_verify(trouble, checks)}"
                )
            verified = True
        try:
            db.save_oidc_provider(
                connection, settings=parsed.settings, actor=actor, verified=verified
            )
        except db.ProviderRefused as error:
            raise ApplyError(f"oidc: {error}") from error
        db.record_audit_event(
            connection,
            actor=actor,
            action="oidc_configured",
            detail={
                "issuer": parsed.settings["issuer"],
                "client_id": parsed.settings["client_id"],
                "secret_replaced": "client_secret_sealed" in parsed.settings,
                "via": "cli",
            },
        )
        connection.commit()
    if turn is True:
        stored = db.oidc_provider(connection) or current
        if not stored.verified:
            ok, checks, trouble = verify(stored, redirect)
            recorded = ok and db.record_oidc_verified(connection, revision=stored.revision)
            db.record_audit_event(
                connection,
                actor=actor,
                action="oidc_verified",
                detail={
                    "issuer": stored.issuer,
                    "ok": ok,
                    "revision": stored.revision,
                    "via": "cli",
                },
            )
            connection.commit()
            if not recorded:
                raise ApplyError(
                    "oidc: the settings did not pass Verify, so sign-in through the provider "
                    f"stays off{'; the settings were saved' if fields else ''}. "
                    f"{_failed_verify(trouble, checks)}"
                )
        _set_enabled(connection, True, actor=actor, issuer=stored.issuer)
    connection.commit()
    return answer


def _set_enabled(connection: Any, enabled: bool, *, actor: str, issuer: str | None) -> None:
    try:
        ended = db.set_oidc_enabled(connection, enabled=enabled, actor=actor)
    except db.ProviderRefused as error:
        raise ApplyError(f"oidc: {error}") from error
    detail: dict[str, Any] = {"issuer": issuer, "via": "cli"}
    if not enabled:
        detail["sessions_ended"] = ended
    db.record_audit_event(
        connection,
        actor=actor,
        action="oidc_enabled" if enabled else "oidc_disabled",
        detail=detail,
    )


# - the answer -------------------------------------------------------------------


def summary(outcome: Outcome, *, check: bool) -> dict[str, Any]:
    return {
        "changed": outcome.changed,
        "check": check,
        "status_access": outcome.status_access,
        "features": outcome.features,
        "oidc": outcome.oidc,
    }
