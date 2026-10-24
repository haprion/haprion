"""haprion-export - what is set now, as the files the apply commands take (Fas 23, B293).

A playbook starts from the installation as it is: this writes every setting
the apply commands read, in their own formats, so that applying the export
to the installation it came from changes nothing. The layout:

    accounts.yaml                       haprion-user apply
    settings.yaml                       haprion-settings apply
    profiles.yaml                       haprion-profiles apply
    clusters/<id>/objects/<name>.yaml   haprion-objects apply -c <id>
    clusters/<id>/network.yaml          haprion-network apply -c <id>
    clusters/<id>/cluster-settings.yaml haprion-cluster-settings apply -c <id>
    clusters/<id>/backup-schedule.yaml  the flags of haprion-backup-schedule -c <id>

Nothing secret is written, because nothing secret is read back: passwords,
the OIDC client secret and the profiles' credentials are sealed or hashed.
What the export could not say is listed as `skipped` with the reason - an
object the generator refuses, a network derived from the cluster file.

Root connects as `haprion-user` does, for the interface's own settings, and
asks the engine's commands for the clusters'. The files are written below a
directory this command creates or finds empty, 0700 and 0600, and handed to
the person who ran sudo.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
import yaml
from haprion import backup_retention, backup_schedule, cluster_settings, exit_codes
from haprion.config import ConfigError
from haprion.digits import is_digits

from haprion_ui import (
    account_apply,
    config,
    profile_apply,
    settings_apply,
    settings_tool,
    tool_answer,
)
from haprion_ui.admin import AdminError, connect, load_environment

OPERATION = "export"
BIN = Path("/usr/bin")
TIMEOUT_SECONDS = 120

type ReadEngine = Callable[[Sequence[str]], Mapping[str, Any]]


class ExportError(tool_answer.ToolError):
    """A refusal, or an engine command that could not be read (`dependency_unavailable`)."""

    def __init__(self, message: str, exit_code: int = exit_codes.REFUSED) -> None:
        unavailable = exit_code == exit_codes.UNAVAILABLE
        super().__init__(
            message,
            code="dependency_unavailable" if unavailable else "bad_input",
            exit_code=exit_code,
        )


def read_engine(argv: Sequence[str]) -> Mapping[str, Any]:
    """One engine command's `--json` result; its refusal as an ExportError."""

    command = [str(BIN / argv[0]), *argv[1:], "--json"]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary directory, no caller argv
            command, capture_output=True, text=True, check=False, timeout=TIMEOUT_SECONDS
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ExportError(f"{argv[0]}: {exc}", exit_codes.UNAVAILABLE) from exc
    try:
        answer = json.loads(completed.stdout)
    except json.JSONDecodeError:
        said = completed.stderr.strip() or f"exit {completed.returncode}"
        raise ExportError(f"{' '.join(argv)}: {said}", exit_codes.UNAVAILABLE) from None
    error = answer.get("error") if isinstance(answer, Mapping) else None
    if isinstance(error, Mapping):
        raise ExportError(
            f"{' '.join(argv)}: {error.get('code')}: {error.get('message')}", exit_codes.UNAVAILABLE
        )
    result = answer.get("result") if isinstance(answer, Mapping) else None
    if not isinstance(result, Mapping):
        raise ExportError(f"{' '.join(argv)}: no result", exit_codes.UNAVAILABLE)
    return result


def _yaml(document: Any) -> str:
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False, allow_unicode=True)


@dataclass
class Written:
    """What one export holds, by path below its directory."""

    files: dict[str, str] = field(default_factory=dict)
    #
    # Written even when nothing goes in it: a cluster's `objects/` empty is
    # what `haprion-objects apply` reads as "no objects", where a missing one
    # is an error.
    #
    directories: set[str] = field(default_factory=set)
    skipped: list[dict[str, str]] = field(default_factory=list)

    def add(self, path: str, text: str) -> None:
        self.files[path] = text

    def skip(self, path: str, reason: str) -> None:
        self.skipped.append({"path": path, "reason": reason})


def cluster_settings_text(reading: Mapping[str, Any]) -> str:
    """The reading as `managed/cluster.yaml` is written: the file `apply` compares with."""

    document: dict[str, Any] = {}
    targets = reading.get("log_targets") or []
    if targets:
        document["log_targets"] = {
            target["name"]: {key: target[key] for key in ("address", "port", "disk_mib", "tls")}
            for target in targets
        }
    for key in ("not_logged_from", "metrics", "peers"):
        if reading.get(key):
            document[key] = reading[key]
    try:
        parsed = cluster_settings.load_mapping(document)
    except ConfigError as exc:
        raise ExportError(f"cluster settings: {exc}", exit_codes.UNAVAILABLE) from exc
    return cluster_settings.dump_document(parsed).decode("utf-8")


def schedule_document(schedule: Mapping[str, Any] | None) -> dict[str, Any] | str:
    """The backup schedule as the flags `haprion-backup-schedule` takes, or why not."""

    if schedule is None or not schedule.get("known"):
        return "the cluster has no backup timer"
    if not schedule.get("scheduled"):
        return "no schedule has been set"
    retention = int(schedule.get("retention") or backup_retention.DEFAULT_RETENTION)
    shown = backup_schedule.describe(schedule.get("calendar"), retention=retention)
    if shown is None:
        return f"the timer's calendar {schedule.get('calendar')!r} is not one the form can set"
    document: dict[str, Any] = {"time": shown.time}
    if shown.frequency == "weekly":
        document["weekly"] = ",".join(shown.weekdays)
    elif shown.frequency == "monthly":
        document["monthly"] = shown.day_of_month
    document["retention"] = shown.retention
    document["enabled"] = bool(schedule.get("enabled"))
    return document


def export_cluster(cluster: str, written: Written, read: ReadEngine) -> None:
    base = f"clusters/{cluster}"
    written.directories.add(f"{base}/objects")
    for entry in read(["haprion-objects", "-c", cluster])["objects"]:
        path = f"{base}/objects/{entry['name']}.yaml"
        if entry.get("readable"):
            written.add(path, str(entry["document"]))
        else:
            written.skip(path, str(entry.get("problem") or "not readable"))

    network = read(["haprion-network", "-c", cluster])
    if network.get("origin") == "repository" and network.get("document") is not None:
        written.add(f"{base}/network.yaml", str(network["document"]))
    else:
        written.skip(f"{base}/network.yaml", "derived from the cluster file; nothing to apply")

    reading = read(["haprion-cluster-settings", "-c", cluster])
    written.add(f"{base}/cluster-settings.yaml", cluster_settings_text(reading))

    backups = read(["haprion-list-backups", "-c", cluster])
    schedule = schedule_document(backups.get("schedule"))
    if isinstance(schedule, str):
        written.skip(f"{base}/backup-schedule.yaml", schedule)
    else:
        written.add(f"{base}/backup-schedule.yaml", _yaml(schedule))


def collect(
    connection: Any, settings: config.Config, chosen: Sequence[str], read: ReadEngine
) -> tuple[tuple[str, ...], Written]:
    written = Written()
    written.add("accounts.yaml", _yaml(account_apply.document(connection)))
    written.add("settings.yaml", _yaml(settings_apply.document(connection)))
    written.add("profiles.yaml", _yaml(profile_apply.document(connection)))
    known, _polled = settings_tool.known_clusters(connection, settings)
    unknown = sorted(set(chosen) - set(known))
    if unknown:
        raise ExportError(f"no such cluster: {', '.join(unknown)}")
    clusters = tuple(cluster for cluster in known if not chosen or cluster in chosen)
    for cluster in clusters:
        export_cluster(cluster, written, read)
    return clusters, written


def _owner() -> tuple[int, int] | None:
    """Whose the files become: the person behind sudo; root's own when there is none."""

    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid is None or gid is None or not is_digits(uid) or not is_digits(gid):
        return None
    return int(uid), int(gid)


def _open_directory(name: str, parent: int | None) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


def write_tree(
    directory: Path,
    files: Mapping[str, str],
    owner: tuple[int, int] | None,
    directories: Iterable[str] = (),
) -> None:
    """Write below a directory that is new or empty, without following a link inside it.

    Every step is relative to an open directory and refuses a symbolic link,
    so a name swapped for a link while this runs is an error, not a write
    somewhere else as root.

    A directory given with nothing in it holds an empty `.gitkeep`: Git keeps
    no empty directory, and an export is often kept in a repository (review
    26-10-24, 15-04).
    """

    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ExportError(f"{directory}: {exc.strerror}") from exc
    try:
        root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ExportError(f"{directory}: not a directory ({exc.strerror})") from exc
    opened: dict[str, int] = {"": root}
    try:
        if os.listdir(root):
            raise ExportError(f"{directory} is not empty; export into a new directory")
        os.fchmod(root, 0o700)

        def below(parts: Sequence[str]) -> str:
            parent = ""
            for part in parts:
                child = f"{parent}/{part}" if parent else part
                if child not in opened:
                    os.mkdir(part, mode=0o700, dir_fd=opened[parent])
                    opened[child] = _open_directory(part, opened[parent])
                parent = child
            return parent

        for path in sorted(directories):
            below(path.split("/"))
        kept = {
            f"{path}/.gitkeep": ""
            for path in directories
            if not any(name.startswith(f"{path}/") for name in files)
        }
        for path, text in sorted({**files, **kept}.items()):
            *parts, name = path.split("/")
            parent = below(parts)
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=opened[parent],
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text)
                if owner is not None:
                    os.fchown(stream.fileno(), *owner)
        if owner is not None:
            for descriptor in opened.values():
                os.fchown(descriptor, *owner)
    except OSError as exc:
        raise ExportError(f"{directory}: {exc.strerror}") from exc
    finally:
        for descriptor in opened.values():
            os.close(descriptor)


def command_export(args: argparse.Namespace, *, read: ReadEngine = read_engine) -> int:
    directory = Path(args.directory).absolute()
    try:
        settings = config.load()
        with connect(load_environment()) as connection:
            clusters, written = collect(connection, settings, args.cluster, read)
        write_tree(directory, written.files, _owner(), written.directories)
    except ExportError as exc:
        return tool_answer.refusal(args, OPERATION, exc.code, str(exc), exc.exit_code)
    except config.ConfigError as exc:
        return tool_answer.refusal(
            args, OPERATION, "dependency_unavailable", str(exc), exc.exit_code
        )
    result = {
        "directory": str(directory),
        "clusters": list(clusters),
        "files": sorted(written.files),
        "skipped": written.skipped,
    }
    if args.json:
        return tool_answer.done(OPERATION, result)
    print(f"wrote {len(written.files)} files to {directory}")
    for skipped in written.skipped:
        print(f"skipped {skipped['path']}: {skipped['reason']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haprion-export",
        description="Write what is set now as the files the apply commands take. Root only.",
    )
    parser.add_argument("directory", help="a new or empty directory")
    parser.add_argument(
        "-c",
        "--cluster",
        action="append",
        default=[],
        help="export this cluster only; repeat for more (default: every cluster)",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        return tool_answer.refusal(
            args, OPERATION, "not_root", "run this with sudo", exit_codes.NOT_ROOT
        )
    try:
        return command_export(args)
    except AdminError as exc:
        return tool_answer.refusal(args, OPERATION, exc.code, str(exc), exc.exit_code)
    except psycopg.Error as exc:
        return tool_answer.database_refusal(args, OPERATION, exc)


def _entry() -> None:  # pragma: no cover - console script shim
    sys.exit(main())
