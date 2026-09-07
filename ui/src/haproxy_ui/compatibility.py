"""Read the independently installed pieces as one compatibility report.

This command changes nothing. It reads the requirements shipped by the running
UI release, then checks the standalone engine, database, service processes,
sudo rules and node bundles against those requirements. Release identifiers are
reported for diagnosis; compatibility is capability-based so an unrelated UI
change does not force a CLI or node rollout.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess  # noqa: S404 - fixed diagnostic commands are the boundary here
import sys
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PSQL = "/usr/bin/psql"
SYSTEMCTL = "/usr/bin/systemctl"


class CompatibilityError(ValueError):
    """Installed metadata cannot be used to make a compatibility decision."""


@dataclass(frozen=True, slots=True)
class Requirements:
    engine_api: int
    node_api: int
    database_head: str
    database_revisions: tuple[str, ...]
    worker_helpers: tuple[str, ...]
    poller_helpers: tuple[str, ...]


class Report:
    def __init__(self) -> None:
        self.failures = 0

    def pass_(self, subject: str, detail: str) -> None:
        print(f"  PASS  {subject:<30} {detail}")

    def fail(self, subject: str, detail: str) -> None:
        self.failures += 1
        print(f"  FAIL  {subject:<30} {detail}")


def _positive_int(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise CompatibilityError(f"{name} must be a positive integer")
    return value


def load_requirements(path: Path, *, allow_legacy_database_head: bool = False) -> Requirements:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"cannot read UI compatibility metadata: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise CompatibilityError("UI compatibility metadata has an unsupported schema")
    required = document.get("requires")
    if not isinstance(required, dict):
        raise CompatibilityError("UI compatibility metadata has no requirements")

    def strings(name: str) -> tuple[str, ...]:
        values = required.get(name)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
        ):
            raise CompatibilityError(f"{name} must be a non-empty string list")
        return tuple(values)

    revisions = strings("database_revisions")
    database_head = required.get("database_head")
    if database_head is None and allow_legacy_database_head and len(revisions) == 1:
        # Compatibility metadata predating coordinated schema upgrades named
        # only the one revision it could run.  That singleton is unambiguous
        # when checking the installed release during the first bridge update.
        database_head = revisions[0]
    if not isinstance(database_head, str) or not database_head:
        raise CompatibilityError("database_head must be a non-empty string")
    if database_head not in revisions:
        raise CompatibilityError("database_head must be one of database_revisions")

    return Requirements(
        engine_api=_positive_int(required.get("engine_api"), "engine_api"),
        node_api=_positive_int(required.get("node_api"), "node_api"),
        database_head=database_head,
        database_revisions=revisions,
        worker_helpers=strings("worker_helpers"),
        poller_helpers=strings("poller_helpers"),
    )


def _one(paths: list[Path], what: str) -> Path:
    if len(paths) != 1:
        raise CompatibilityError(f"expected one {what}, found {len(paths)}")
    return paths[0]


def current_release(root: Path, what: str) -> Path:
    link = root / "current"
    if not link.is_symlink():
        raise CompatibilityError(f"{what} current is not a symlink")
    try:
        release = link.resolve(strict=True)
    except OSError as exc:
        raise CompatibilityError(f"{what} current cannot be resolved: {exc}") from exc
    releases = (root / "releases").resolve(strict=True)
    if release.parent != releases:
        raise CompatibilityError(f"{what} current points outside its release directory")
    return release


def named_release(root: Path, name: str, what: str) -> Path:
    """Resolve one prepared release without allowing a path outside releases/."""

    if not name or Path(name).name != name:
        raise CompatibilityError(f"invalid {what} release id")
    releases = (root / "releases").resolve(strict=True)
    try:
        release = (releases / name).resolve(strict=True)
    except OSError as exc:
        raise CompatibilityError(f"{what} release {name} cannot be resolved: {exc}") from exc
    if release.parent != releases or not release.is_dir():
        raise CompatibilityError(f"{what} release points outside its release directory")
    return release


def ui_requirements(release: Path, *, allow_legacy_database_head: bool = False) -> Requirements:
    metadata = _one(
        list(release.glob("venv/lib/python*/site-packages/haproxy_ui/compatibility.json")),
        "installed UI compatibility file",
    )
    return load_requirements(metadata, allow_legacy_database_head=allow_legacy_database_head)


def cli_metadata(release: Path) -> dict[str, Any]:
    try:
        document = json.loads((release / "INSTALLATION.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"cannot read CLI installation metadata: {exc}") from exc
    if not isinstance(document, dict):
        raise CompatibilityError("CLI installation metadata is not an object")
    return document


def engine_api(document: Mapping[str, Any]) -> int:
    value = document.get("engine_api", 0)
    return value if type(value) is int else 0


def installed_entry_points(document: Mapping[str, Any]) -> set[str]:
    value = document.get("entry_points")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return set()
    return set(value)


def schema_upgrade_failures(
    active: Requirements, candidate: Requirements, current_revision: str
) -> tuple[str, ...]:
    """Why migrating under the active UI would make service or rollback unsafe."""

    failures = []
    if current_revision not in active.database_revisions:
        failures.append(f"running UI does not accept current revision {current_revision}")
    if candidate.database_head not in active.database_revisions:
        failures.append(f"running UI does not accept candidate head {candidate.database_head}")
    return tuple(failures)


def active_sudo_rules(text: str) -> tuple[str, ...]:
    return tuple(
        " ".join(line.split())
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def expected_sudo_rules(user: str, helpers: tuple[str, ...], cli_root: Path) -> tuple[str, ...]:
    return tuple(
        f'{user} ALL=(root) NOPASSWD: {cli_root}/current/bin/{helper} ""' for helper in helpers
    )


def check_sudoers(
    report: Report,
    *,
    root: Path,
    user: str,
    helpers: tuple[str, ...],
    cli_root: Path,
    label: str,
) -> None:
    path = root / user
    try:
        actual = active_sudo_rules(path.read_text(encoding="utf-8"))
        status = path.stat()
    except OSError as exc:
        report.fail(label, f"cannot read {path}: {exc}")
        return
    expected = expected_sudo_rules(user, helpers, cli_root)
    secure = status.st_uid == 0 and stat.S_IMODE(status.st_mode) == 0o440
    if sorted(actual) == sorted(expected) and len(actual) == len(expected) and secure:
        report.pass_(label, f"{len(expected)} exact helper rule(s)")
    else:
        detail = f"expected {len(expected)} exact helper rule(s), found {len(actual)}"
        if not secure:
            detail += f"; owner/mode is {status.st_uid}:{stat.S_IMODE(status.st_mode):o}"
        report.fail(label, detail)


def _command(argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - every executable is fixed by the installation
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )


def check_service(report: Report, *, unit: str, release: Path) -> None:
    active = _command([SYSTEMCTL, "is-active", unit])
    if active.returncode != 0 or active.stdout.strip() != "active":
        report.fail(unit, "not active")
        return
    pid_result = _command([SYSTEMCTL, "show", unit, "--property=MainPID", "--value"])
    pid = pid_result.stdout.strip()
    if pid_result.returncode != 0 or not pid.isdigit() or pid == "0":
        report.fail(unit, "has no main process")
        return
    try:
        argv0 = (Path("/proc") / pid / "cmdline").read_bytes().split(b"\0", 1)[0].decode()
    except (OSError, UnicodeDecodeError) as exc:
        report.fail(unit, f"cannot read its command: {exc}")
        return
    prefix = f"{release}/"
    if argv0.startswith(prefix):
        report.pass_(unit, f"runs {release.name}")
    else:
        report.fail(unit, f"runs outside {release.name}")


def database_revision(role: str, database: str) -> str:
    completed = _command(
        [PSQL, "-U", role, "-d", database, "-qtAX", "-c", "select version_num from alembic_version"]
    )
    if completed.returncode != 0:
        raise CompatibilityError(completed.stderr.strip() or "database revision query failed")
    revision = completed.stdout.strip()
    if not revision or "\n" in revision:
        raise CompatibilityError("database did not report exactly one revision")
    return revision


def _node_installation(entry: object) -> tuple[str, int | None, bool]:
    if not isinstance(entry, dict):
        return "unknown", None, False
    name = entry.get("name")
    shown = name if isinstance(name, str) and name else "unknown"
    status = entry.get("status")
    if not isinstance(status, dict):
        return shown, None, False
    installation = status.get("installation")
    if not isinstance(installation, dict):
        return shown, None, False
    api = installation.get("node_api")
    parsed_api = api if type(api) is int else None
    return shown, parsed_api, installation.get("scripts_current") is True


def check_cluster_nodes(report: Report, *, cluster: str, helper: Path, required_api: int) -> None:
    request = json.dumps(
        {
            "schema_version": 1,
            "operation": "status",
            "cluster": cluster,
            "request_id": str(uuid.uuid4()),
            "parameters": {},
        },
        separators=(",", ":"),
    )
    completed = _command([str(helper)], input_text=request)
    try:
        envelope = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report.fail(f"nodes/{cluster}", "status helper returned no usable JSON")
        return
    result = envelope.get("result") if isinstance(envelope, dict) else None
    nodes = result.get("nodes") if isinstance(result, dict) else None
    if not isinstance(nodes, list) or not nodes:
        report.fail(f"nodes/{cluster}", "status result contains no nodes")
        return
    for entry in nodes:
        name, api, scripts_current = _node_installation(entry)
        subject = f"node/{cluster}/{name}"
        if api is None:
            report.fail(subject, "does not report node compatibility metadata")
        elif api < required_api:
            report.fail(subject, f"node API {api}, requires {required_api}")
        elif not scripts_current:
            report.fail(subject, f"node API {api}, installed script digests differ")
        else:
            report.pass_(subject, f"node API {api}, script digests current")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check all installed HAProxy Manager components")
    parser.add_argument("--platform-root", required=True, type=Path)
    parser.add_argument("--cli-root", required=True, type=Path)
    parser.add_argument("--database", required=True)
    parser.add_argument("--database-role", required=True)
    parser.add_argument("--web-user", required=True)
    parser.add_argument("--worker-user", required=True)
    parser.add_argument("--poller-user", required=True)
    parser.add_argument("--clusters", required=True, nargs="*")
    parser.add_argument("--environment", default="prod")
    parser.add_argument("--sudoers-root", type=Path, default=Path("/etc/sudoers.d"))
    parser.add_argument("--ui-release")
    parser.add_argument("--skip-database", action="store_true")
    parser.add_argument("--skip-services", action="store_true")
    parser.add_argument("--upgrade-from-current", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if os.geteuid() != 0:
        print("ERROR: run this with sudo", file=sys.stderr)
        return 1
    report = Report()
    try:
        ui_release = (
            named_release(args.platform_root, args.ui_release, "UI")
            if args.ui_release
            else current_release(args.platform_root, "UI")
        )
        requirements = ui_requirements(ui_release)
        cli_release = current_release(args.cli_root, "CLI") if args.environment == "prod" else None
        installed_cli = cli_metadata(cli_release) if cli_release is not None else None
    except CompatibilityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("\n== Releases")
    report.pass_("UI release", ui_release.name)
    if cli_release is None or installed_cli is None:
        report.pass_("development boundary", "no standalone CLI, helpers or nodes")
    else:
        installed_engine_api = engine_api(installed_cli)
        if installed_engine_api >= requirements.engine_api:
            report.pass_("CLI release", f"{cli_release.name}, engine API {installed_engine_api}")
        else:
            report.fail(
                "CLI release",
                f"{cli_release.name}, engine API {installed_engine_api}; "
                f"requires {requirements.engine_api}",
            )
        installed_helpers = installed_entry_points(installed_cli)
        required_helpers = set(requirements.worker_helpers + requirements.poller_helpers)
        missing = sorted(required_helpers - installed_helpers)
        if missing:
            report.fail("CLI helpers", f"missing: {', '.join(missing)}")
        else:
            missing_files = sorted(
                helper
                for helper in required_helpers
                if not (cli_release / "bin" / helper).is_file()
                or not os.access(cli_release / "bin" / helper, os.X_OK)
            )
            if missing_files:
                report.fail("CLI helpers", f"not executable: {', '.join(missing_files)}")
            else:
                report.pass_("CLI helpers", f"{len(required_helpers)} required helpers installed")

    if args.upgrade_from_current and not args.ui_release:
        print("ERROR: --upgrade-from-current requires --ui-release", file=sys.stderr)
        return 1

    if not args.skip_database:
        print("\n== Database")
        try:
            revision = database_revision(args.database_role, args.database)
        except CompatibilityError as exc:
            report.fail("schema revision", str(exc))
        else:
            if args.upgrade_from_current:
                try:
                    active_release = current_release(args.platform_root, "UI")
                    active_requirements = ui_requirements(
                        active_release, allow_legacy_database_head=True
                    )
                except CompatibilityError as exc:
                    report.fail("schema transition", str(exc))
                else:
                    transition_failures = schema_upgrade_failures(
                        active_requirements, requirements, revision
                    )
                    if not any("current revision" in failure for failure in transition_failures):
                        report.pass_(
                            "running schema", f"{revision}, accepted by {active_release.name}"
                        )
                    else:
                        report.fail(
                            "running schema",
                            f"{revision}; running {active_release.name} does not accept it",
                        )
                    if not any("candidate head" in failure for failure in transition_failures):
                        report.pass_(
                            "rollback schema",
                            f"{requirements.database_head}, accepted by {active_release.name}",
                        )
                    else:
                        report.fail(
                            "rollback schema",
                            f"candidate head {requirements.database_head}; running "
                            f"{active_release.name} does not accept it",
                        )
                revision = ""
            if revision in requirements.database_revisions:
                report.pass_("schema revision", revision)
            elif not args.upgrade_from_current:
                report.fail(
                    "schema revision",
                    f"{revision}; accepts {', '.join(requirements.database_revisions)}",
                )

    if not args.skip_services:
        print("\n== Services")
        service_users = (
            (args.worker_user, args.poller_user, args.web_user)
            if args.environment == "prod"
            else (args.web_user,)
        )
        for user in service_users:
            check_service(report, unit=f"{user}.service", release=ui_release)

    print("\n== Sudo rules")
    if args.environment == "prod":
        check_sudoers(
            report,
            root=args.sudoers_root,
            user=args.worker_user,
            helpers=requirements.worker_helpers,
            cli_root=args.cli_root,
            label="worker sudoers",
        )
        check_sudoers(
            report,
            root=args.sudoers_root,
            user=args.poller_user,
            helpers=requirements.poller_helpers,
            cli_root=args.cli_root,
            label="poller sudoers",
        )
    web_rule = args.sudoers_root / args.web_user
    if web_rule.exists():
        report.fail("web sudoers", f"unexpected rule file {web_rule}")
    else:
        report.pass_("web sudoers", "no rule file")

    print("\n== Nodes")
    if cli_release is not None:
        helper = cli_release / "bin/haproxy-status-helper"
        for cluster in args.clusters:
            check_cluster_nodes(
                report, cluster=cluster, helper=helper, required_api=requirements.node_api
            )

    print()
    if report.failures:
        print(f"INCOMPATIBLE: {report.failures} check(s) failed")
        return 1
    print("COMPATIBLE: every installed component satisfies the running UI release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
