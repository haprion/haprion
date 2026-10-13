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
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg

from haprion_ui import backups, config, db, feature_switch, job_wait, settings_apply
from haprion_ui.admin import AdminError, actor_name, connect, load_environment, refused

EXIT_REFUSED = 65


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
            stale_after=timedelta(seconds=settings.poller.interval_seconds * 2),
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
                            f"backup schedule for {job.cluster}: {problem}"
                        )
    except (settings_apply.ApplyError, config.ConfigError) as exc:
        if args.json:
            print(json.dumps(settings_apply.envelope(None, str(exc))))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    result = settings_apply.summary(outcome, check=args.check)
    if args.json:
        print(json.dumps(settings_apply.envelope(result, None)))
        return 0
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
        if outcome.oidc["sealing"] == "kept":
            print(
                "the stored client secret was kept: it cannot be compared; "
                "--replace-oidc-secret replaces it"
            )
    if not outcome.changed:
        print("nothing to change")
    return 0


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
    contract = settings_apply.envelope if args.command in ("apply",) else None
    if os.geteuid() != 0:
        return refused(args, "run this with sudo", 77, contract)
    try:
        return command_apply(args) if args.command == "apply" else command_show(args)
    except AdminError as exc:
        return refused(args, str(exc), 64, contract)
    except psycopg.Error as exc:
        return refused(args, f"database: {exc}", 74, contract)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())
