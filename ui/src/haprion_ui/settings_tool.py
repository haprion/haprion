"""haprion-settings - the interface's own settings, from a root shell (Fas 23, B293).

What *Settings* sets for the interface itself - *External monitoring*, the
feature switches and sign-in through an OIDC provider - for automation:
`show` reads them and `apply` writes a file's worth of them where they
differ (see `settings_apply`). Root connects as `haprion-user` does, as the
migration role, and reads `ui.toml` for what the web would know: the cluster
list before the poller's, how old a backup reading may be, and the key the
client secret is sealed against.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import psycopg
from haprion import exit_codes

from haprion_ui import (
    backups,
    config,
    db,
    feature_switch,
    job_wait,
    labels,
    settings_apply,
    tool_answer,
)
from haprion_ui.admin import AdminError, actor_name, connect, load_environment


def known_clusters(connection: Any, settings: config.Config) -> tuple[tuple[str, ...], bool]:
    """The poller's list of clusters and True, or `ui.toml`'s and False before it has read one."""

    clusters = db.cluster_list(connection)
    # Empty is an answer (B302): no cluster yet, or the last one removed.
    return (clusters, True) if clusters is not None else (settings.clusters, False)


def _readings(connection: Any, settings: config.Config) -> feature_switch.Readings:
    """What a switch needs besides its row, read as the web's sources read it."""

    def listed() -> tuple[tuple[str, ...], bool]:
        return known_clusters(connection, settings)

    def kept(rows: list[Any]) -> list[Any]:
        clusters, polled = listed()
        return [row for row in rows if not polled or getattr(row, "cluster", None) in clusters]

    return feature_switch.Readings(
        clusters=lambda: listed()[0],
        backup_overview=lambda: backups.build_backup_overview(
            listed()[0],
            kept(db.cluster_backups(connection)),
            stale_after=settings.poller.stale_after,
        ),
        objects=lambda: kept(db.cluster_objects(connection)),
        restore_waiting=lambda: feature_switch.restore_waiting(connection),
    )


def _read_secret(args: argparse.Namespace) -> str | None:
    if not args.oidc_secret_stdin:
        return None
    line = sys.stdin.readline().removesuffix("\n").removesuffix("\r")
    if not line:
        raise settings_apply.ApplyError("--oidc-secret-stdin read an empty line")
    return line


def command_apply(args: argparse.Namespace, *, sleep: Callable[[float], None] = time.sleep) -> int:
    outcome = settings_apply.Outcome()
    queued: list[db.Job] = []
    saved = False
    try:
        wanted = settings_apply.read_file(Path(args.file))
        piped = _read_secret(args)
        if piped is not None and wanted.oidc is None:
            raise settings_apply.ApplyError("--oidc-secret-stdin given, but the file has no oidc")
        settings = config.load()
        with connect(load_environment()) as connection:
            actor = actor_name()
            if wanted.status_access is not None:
                outcome.status_access = settings_apply.apply_status_access(
                    connection, wanted.status_access, actor=actor
                )
            if wanted.features:
                outcome.features = settings_apply.apply_features(
                    connection,
                    wanted.features,
                    actor=actor,
                    readings=_readings(connection, settings),
                    queued=queued,
                )
            if args.check:
                #
                # The switches ran their refusals for real; nothing they wrote
                # is kept. The provider section is planned, not written.
                #
                connection.rollback()
            if wanted.oidc is not None:
                outcome.oidc = settings_apply.apply_oidc(
                    connection,
                    wanted.oidc,
                    actor=actor,
                    check=args.check,
                    public_key=settings.oidc_public_key,
                    replace_secret=args.replace_oidc_secret,
                    piped_secret=piped,
                )
            if args.check:
                connection.rollback()
            else:
                connection.commit()
                saved = True
                #
                # Node backups on starts the schedules it stopped as jobs. A
                # schedule set right after this (`haprion-backup-schedule`)
                # must not be overwritten by one of them running later, so
                # the command ends when they have run.
                #
                for job in queued:
                    _state, problem = job_wait.finished(
                        connection, job.id, wait=args.wait, sleep=sleep
                    )
                    if problem:
                        raise settings_apply.ApplyError(
                            f"backup schedule for {job.cluster}: {problem}", code="job_not_done"
                        )
    except settings_apply.ApplyError as exc:
        if saved:
            #
            # The settings are written; a backup schedule job they started did
            # not finish. That is what happened, not a refusal of the file
            # (review 2026-10-22, 1B-3).
            #
            return _saved_then_stopped(args, outcome, exc.code, str(exc))
        return tool_answer.refusal(
            args, settings_apply.OPERATION, exc.code, str(exc), exc.exit_code
        )
    except psycopg.Error as exc:
        if saved:
            #
            # Committed before the database went: the settings stand, as they
            # do when a schedule job does not finish (review 26-10-24, 07-07).
            #
            code, _exit = tool_answer.database_failure(exc)
            return _saved_then_stopped(args, outcome, code, f"database: {exc}")
        return tool_answer.database_refusal(args, settings_apply.OPERATION, exc)
    except config.ConfigError as exc:
        return tool_answer.refusal(
            args, settings_apply.OPERATION, "dependency_unavailable", str(exc), exc.exit_code
        )
    result = settings_apply.summary(outcome, check=args.check)
    if args.json:
        return tool_answer.done(settings_apply.OPERATION, result)
    lead = "would" if args.check else "did"
    if outcome.status_access:
        for network in outcome.status_access["added"]:
            print(f"{lead} allow {network} to ask /status/")
        for network in outcome.status_access["removed"]:
            print(f"{lead} stop {network} asking /status/")
    for name, enabled in outcome.features.items():
        print(f"{lead} turn {name} {'on' if enabled else 'off'}")
    if outcome.oidc:
        if outcome.oidc["fields"]:
            print(f"{lead} change the OIDC provider: {', '.join(outcome.oidc['fields'])}")
        if outcome.oidc["enabled"] is not None:
            state = "on" if outcome.oidc["enabled"] else "off"
            print(f"{lead} turn sign-in through the provider {state}")
        if outcome.oidc.get("sessions_ended"):
            print(f"{labels.counted(outcome.oidc['sessions_ended'], 'session')} ended")
        if outcome.oidc["sealing"] == "kept":
            print(
                "the stored client secret was kept: it cannot be compared; "
                "--replace-oidc-secret replaces it"
            )
    if not outcome.changed:
        print("nothing to change")
    return 0


def _saved_then_stopped(
    args: argparse.Namespace, outcome: settings_apply.Outcome, code: str, message: str
) -> int:
    result = settings_apply.summary(outcome, check=False)
    if args.json:
        return tool_answer.partial(settings_apply.OPERATION, result, code, message)
    print(f"ERROR: the settings were saved, but {message}", file=sys.stderr)
    return exit_codes.PARTIAL


def command_show(args: argparse.Namespace) -> int:
    with connect(load_environment()) as connection:
        shown = settings_apply.document(connection)
        provider = db.oidc_provider(connection)
    access: list[str] = shown["status_access"]
    switches: dict[str, bool] = shown["features"]
    shown["oidc"] = None
    if provider is not None:
        shown["oidc"] = {
            **settings_apply.provider_fields(provider),
            "client_secret": "set" if provider.client_secret_sealed else None,
            "verified": provider.verified,
        }
    if args.json:
        print(json.dumps(shown))
        return 0
    print("status_access: " + (", ".join(access) or "(off)"))
    for name, enabled in switches.items():
        print(f"feature {name}: {'on' if enabled else 'off'}")
    if shown["oidc"] is not None:
        oidc = shown["oidc"]
        state = "on" if oidc["enabled"] else "off"
        verified = "verified" if oidc["verified"] else "not verified"
        print(f"oidc: {state}, {verified}, issuer {oidc['issuer'] or '(none)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-settings",
        description="The interface's own settings: External monitoring, features, OIDC. Root only.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    apply = subcommands.add_parser("apply", help="write a file's settings where they differ")
    apply.add_argument("file")
    apply.add_argument("--check", action="store_true", help="say what would change; change nothing")
    apply.add_argument("--json", action="store_true")
    apply.add_argument(
        "--replace-oidc-secret",
        action="store_true",
        help="seal and store the client secret even though issuer and client are unchanged",
    )
    apply.add_argument(
        "--wait",
        type=float,
        default=job_wait.WAIT_SECONDS,
        help="seconds to wait for each backup schedule job a switch queues",
    )
    apply.add_argument(
        "--oidc-secret-stdin",
        action="store_true",
        help="read the client secret from one line on stdin instead of the file",
    )
    show = subcommands.add_parser("show", help="what is set now; the client secret never")
    show.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    contract = settings_apply.OPERATION if args.command == "apply" else None
    if os.geteuid() != 0:
        return tool_answer.refusal(
            args, contract, "not_root", "run this with sudo", exit_codes.NOT_ROOT
        )
    try:
        return command_apply(args) if args.command == "apply" else command_show(args)
    except AdminError as exc:
        return tool_answer.refusal(args, contract, exc.code, str(exc), exc.exit_code)
    except psycopg.Error as exc:
        return tool_answer.database_refusal(args, contract, exc)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())
