"""Read the independently installed pieces as one compatibility report.

This command changes nothing. It reads the requirements shipped by the running
UI release, then checks the standalone engine, database, service processes,
sudo rules and node packages against those requirements. Release identifiers are
reported for diagnosis; compatibility is capability-based so an unrelated UI
change does not force a CLI or node rollout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # noqa: S404 - fixed diagnostic commands are the boundary here
import sys
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion import accounts
from haprion.config import (
    DEFAULT_POLICY_PATH,
    load_policy,
    load_runtime_config,
    worker_writable_paths,
)
from haprion.config import ConfigError as EngineConfigError
from haprion.digits import is_digits
from haprion.traffic_collector import CollectorError
from haprion.traffic_collector import load_config as load_collector_config

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
    #
    # Helpers the worker reaches over a socket rather than through sudo (B163):
    # `{helper: socket path}`. The CLI release must carry them like any other
    # helper; the sudoers file must not name them, because a rule for a helper
    # the worker's sandbox cannot run is a rule that grants a failure. What has
    # to exist instead is the socket, and that is checked where sudoers is.
    #
    socket_helpers: dict[str, str]
    #
    # The oldest schema revision a running UI may stand at for this release's
    # migrations to run under it, and for a rollback to it to work afterwards
    # (B262). Declared by the migrations themselves - every one after it says
    # it only adds - and derived from them by the test that holds this file.
    # None in metadata from before 2026-10-08: such a release needs the running
    # UI to accept its head, as every release did then (the bridge).
    #
    rollback_safe_from: str | None = None


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


def load_requirements(path: Path) -> Requirements:
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

    def sockets(name: str) -> dict[str, str]:
        values = required.get(name, {})
        if not isinstance(values, dict) or not all(
            isinstance(helper, str) and helper and isinstance(path, str) and path.startswith("/")
            for helper, path in values.items()
        ):
            raise CompatibilityError(f"{name} must map helper names to absolute socket paths")
        return dict(values)

    revisions = strings("database_revisions")
    database_head = required.get("database_head")
    if not isinstance(database_head, str) or not database_head:
        raise CompatibilityError("database_head must be a non-empty string")
    if database_head not in revisions:
        raise CompatibilityError("database_head must be one of database_revisions")
    rollback_safe_from = required.get("rollback_safe_from")
    if rollback_safe_from is not None and (
        not isinstance(rollback_safe_from, str)
        or not is_digits(rollback_safe_from)
        or rollback_safe_from > database_head
    ):
        raise CompatibilityError("rollback_safe_from must be a revision no later than the head")

    return Requirements(
        engine_api=_positive_int(required.get("engine_api"), "engine_api"),
        node_api=_positive_int(required.get("node_api"), "node_api"),
        database_head=database_head,
        database_revisions=revisions,
        worker_helpers=strings("worker_helpers"),
        poller_helpers=strings("poller_helpers"),
        socket_helpers=sockets("socket_helpers"),
        rollback_safe_from=rollback_safe_from,
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


#
# The command every UI release installs, and so the one that names the package
# the release's code lives in. Read from the distribution's metadata rather than
# assumed, because a release this one replaces or rolls back to may call its
# package something else - the distribution's name is what stays.
#
ANCHOR_COMMAND = "haprion-worker"
ENTRY_POINT = re.compile(r"^\s*(?P<name>[^\s=]+)\s*=\s*(?P<module>[A-Za-z_][\w.]*):")


def release_package(site_packages: Path) -> str:
    """The import package of the UI distribution installed in one release."""

    entry_points = _one(
        list(site_packages.glob("haprion_ui-*.dist-info/entry_points.txt")),
        "UI distribution metadata",
    )
    try:
        lines = entry_points.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CompatibilityError(f"cannot read UI distribution metadata: {exc}") from exc
    for line in lines:
        match = ENTRY_POINT.match(line)
        if match is not None and match["name"] == ANCHOR_COMMAND:
            return match["module"].partition(".")[0]
    raise CompatibilityError(f"the UI distribution has no {ANCHOR_COMMAND} command")


def ui_requirements(release: Path) -> Requirements:
    site_packages = _one(
        list(release.glob("venv/lib/python*/site-packages")), "UI release site-packages"
    )
    return load_requirements(site_packages / release_package(site_packages) / "compatibility.json")


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
    if candidate.database_head not in active.database_revisions and not declared_safe(
        active, candidate
    ):
        failures.append(f"running UI does not accept candidate head {candidate.database_head}")
    return tuple(failures)


def declared_safe(active: Requirements, candidate: Requirements) -> bool:
    """Whether the candidate's migrations say the running UI keeps working over them (B262).

    The running UI's own head at or after the revision the candidate declares
    rollback-safe from, and not past the candidate's head: every migration in
    between only adds, by its own declaration, so the running UI serves while
    they run and is a rollback target after. Revisions are numbered and
    zero-padded, so their text orders as their numbers do.
    """

    safe_from = candidate.rollback_safe_from
    return safe_from is not None and safe_from <= active.database_head <= candidate.database_head


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
    name: str,
    user: str,
    helpers: tuple[str, ...],
    cli_root: Path,
    label: str,
) -> None:
    path = root / name
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


def check_socket(report: Report, *, helper: str, socket_path: Path) -> None:
    """The socket a helper answers on is there, and is a socket.

    The sudoers check's counterpart for a helper reached this way: the worker
    has no rule for it, so nothing else on this list would notice the unit
    missing until the first job said `dependency_unavailable`.
    """

    try:
        status = socket_path.stat()
    except OSError as exc:
        report.fail(
            f"{helper} socket", f"{socket_path}: {exc.strerror}; is its .socket unit active?"
        )
        return
    if stat.S_ISSOCK(status.st_mode):
        report.pass_(f"{helper} socket", f"{socket_path}")
    else:
        report.fail(f"{helper} socket", f"{socket_path} is not a socket")


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
    if pid_result.returncode != 0 or not is_digits(pid) or pid == "0":
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


def opened_paths(unit_text: str) -> set[str]:
    """Every path a unit's `ReadWritePaths` lines open, without the optional dash."""

    opened: set[str] = set()
    for line in unit_text.splitlines():
        if line.startswith("ReadWritePaths="):
            opened.update(word.removeprefix("-") for word in line.partition("=")[2].split())
    return opened


def check_worker_sandbox(
    report: Report, *, unit_file: Path, policy_file: Path, require_secure: bool = True
) -> None:
    """Does the worker's unit open the roots the runtime policy names? (review 26-10-10, F4)

    Platform step 07 writes them in from the policy. A policy changed since -
    the registry moved - without the step run again is otherwise found by the
    first certificate job, on "Read-only file system".
    """

    subject = "worker sandbox"
    try:
        required = [
            str(path)
            for path in worker_writable_paths(
                load_policy(policy_file, require_secure=require_secure)
            )
        ]
    except (EngineConfigError, OSError) as exc:
        report.fail(subject, f"cannot read the runtime policy: {exc}")
        return
    try:
        opened = opened_paths(unit_file.read_text(encoding="utf-8"))
    except OSError as exc:
        report.fail(subject, f"cannot read {unit_file}: {exc}")
        return
    missing = [path for path in required if path not in opened]
    if missing:
        report.fail(
            subject,
            f"{unit_file.name} does not open {', '.join(missing)}; rerun platform step 07",
        )
    else:
        report.pass_(subject, f"opens the policy's {len(required)} roots")


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


def _inventory_differences(
    expected: Iterable[tuple[str, str, str]], actual: Iterable[tuple[str, str, str]]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    expected_by_name = {(cluster, node): host for cluster, node, host in expected}
    actual_by_name = {(cluster, node): host for cluster, node, host in actual}
    missing = tuple(
        f"{cluster}/{node}" for cluster, node in sorted(expected_by_name.keys() - actual_by_name)
    )
    extra = tuple(
        f"{cluster}/{node}" for cluster, node in sorted(actual_by_name.keys() - expected_by_name)
    )
    changed = tuple(
        f"{cluster}/{node}"
        for cluster, node in sorted(expected_by_name.keys() & actual_by_name)
        if expected_by_name[(cluster, node)] != actual_by_name[(cluster, node)]
    )
    return missing, extra, changed


def check_traffic_collector(report: Report, *, policy: Path, collector_config: Path) -> None:
    """Hold the collector's installed copy against the engine's live inventory."""

    try:
        runtime = load_runtime_config(load_policy(policy))
        collector = load_collector_config(collector_config)
    except (EngineConfigError, CollectorError, OSError) as exc:
        report.fail("traffic collector inventory", str(exc))
        return
    #
    # Checked before the inventory, because a mirror-only collector is the
    # failure that looks like calm. This release reads traffic records from the
    # database; a configuration still on schema 1 mirrors files and ingests
    # nothing, so the page renders an empty table with nothing to say why. A
    # current node list does not make that state correct.
    #
    if collector.database is None:
        report.fail(
            "traffic collector database",
            "the collector configuration predates database ingest; rerun platform step 13",
        )
        return
    report.pass_("traffic collector database", collector.database)
    expected = (
        (cluster.cluster_id, node.name, node.mgmt_host)
        for cluster in runtime.clusters.values()
        for node in cluster.nodes
    )
    actual = ((node.cluster, node.node, node.host) for node in collector.nodes)
    missing, extra, changed = _inventory_differences(expected, actual)
    if not (missing or extra or changed):
        report.pass_("traffic collector inventory", f"{len(collector.nodes)} node(s) current")
        return
    details = []
    if missing:
        details.append(f"missing {', '.join(missing)}")
    if extra:
        details.append(f"retired {', '.join(extra)}")
    if changed:
        details.append(f"management host changed for {', '.join(changed)}")
    report.fail("traffic collector inventory", "; ".join(details) + "; rerun platform step 13")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check all installed Haprion components")
    parser.add_argument("--platform-root", required=True, type=Path)
    parser.add_argument("--cli-root", required=True, type=Path)
    parser.add_argument("--database", required=True)
    parser.add_argument("--database-role", required=True)
    parser.add_argument("--clusters", required=True, nargs="*")
    parser.add_argument("--runtime-policy", type=Path)
    parser.add_argument("--collector-config", type=Path)
    parser.add_argument("--sudoers-root", type=Path, default=Path("/etc/sudoers.d"))
    parser.add_argument("--systemd-root", type=Path, default=Path("/etc/systemd/system"))
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
    if (args.runtime_policy is None) != (args.collector_config is None):
        print(
            "ERROR: --runtime-policy and --collector-config must be supplied together",
            file=sys.stderr,
        )
        return 1
    try:
        ui_release = (
            named_release(args.platform_root, args.ui_release, "UI")
            if args.ui_release
            else current_release(args.platform_root, "UI")
        )
        requirements = ui_requirements(ui_release)
        cli_release = current_release(args.cli_root, "CLI")
        installed_cli = cli_metadata(cli_release)
    except CompatibilityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("\n== Releases")
    report.pass_("UI release", ui_release.name)
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
    required_helpers = set(
        requirements.worker_helpers
        + requirements.poller_helpers
        + tuple(requirements.socket_helpers)
    )
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
                    active_requirements = ui_requirements(active_release)
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
                            f"{requirements.database_head}, accepted by {active_release.name}"
                            if requirements.database_head in active_requirements.database_revisions
                            else f"{requirements.database_head}, rollback-safe from "
                            f"{requirements.rollback_safe_from} by its migrations; "
                            f"{active_release.name} stands at {active_requirements.database_head}",
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
        for unit in (accounts.WORKER_UNIT, accounts.POLLER_UNIT, accounts.WEB_UNIT):
            check_service(report, unit=unit, release=ui_release)

    print("\n== Worker sandbox")
    check_worker_sandbox(
        report,
        unit_file=args.systemd_root / accounts.WORKER_UNIT,
        policy_file=args.runtime_policy or DEFAULT_POLICY_PATH,
    )

    print("\n== Sudo rules")
    check_sudoers(
        report,
        root=args.sudoers_root,
        name=accounts.WORKER_SUDOERS,
        user=accounts.WORKER,
        helpers=requirements.worker_helpers,
        cli_root=args.cli_root,
        label="worker sudoers",
    )
    check_sudoers(
        report,
        root=args.sudoers_root,
        name=accounts.POLLER_SUDOERS,
        user=accounts.POLLER,
        helpers=requirements.poller_helpers,
        cli_root=args.cli_root,
        label="poller sudoers",
    )
    web_rules = [
        path
        for path in (args.sudoers_root / accounts.WEB, args.sudoers_root / "haprion-web")
        if path.exists()
    ]
    if web_rules:
        report.fail("web sudoers", f"unexpected rule file {web_rules[0]}")
    else:
        report.pass_("web sudoers", "no rule file")
    for helper_name, socket_path in sorted(requirements.socket_helpers.items()):
        check_socket(report, helper=helper_name, socket_path=Path(socket_path))

    print("\n== Nodes")
    if args.runtime_policy is not None and args.collector_config is not None:
        check_traffic_collector(
            report,
            policy=args.runtime_policy,
            collector_config=args.collector_config,
        )
    helper = cli_release / "bin/haprion-status-helper"
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
