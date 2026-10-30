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
import subprocess  # fixed diagnostic commands are the boundary here
import sys
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haprion import accounts, haproxy_versions, node_package, node_ssh, status_collect
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

from haprion_ui import labels

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
    #
    # The revision this release's migrations begin at (B369): every migration
    # before it was folded into it. A database older than it is from an
    # installation from before the baseline, which is installed afresh rather
    # than migrated - there is nothing here that would carry it across. None in
    # metadata from before the baseline.
    #
    database_baseline: str | None = None


class Report:
    def __init__(self) -> None:
        self.failures = 0

    def pass_(self, subject: str, detail: str) -> None:
        print(f"  PASS  {subject:<30} {detail}")

    def fail(self, subject: str, detail: str) -> None:
        self.failures += 1
        print(f"  FAIL  {subject:<30} {detail}")

    def warn(self, subject: str, detail: str) -> None:
        """Said, and not a failure: a state the installation passes through on purpose."""

        print(f"  WARN  {subject:<30} {detail}")


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
    database_baseline = required.get("database_baseline")
    if database_baseline is not None and (
        not isinstance(database_baseline, str)
        or not is_digits(database_baseline)
        or database_baseline > database_head
    ):
        raise CompatibilityError("database_baseline must be a revision no later than the head")

    return Requirements(
        engine_api=_positive_int(required.get("engine_api"), "engine_api"),
        node_api=_positive_int(required.get("node_api"), "node_api"),
        database_head=database_head,
        database_revisions=revisions,
        worker_helpers=strings("worker_helpers"),
        poller_helpers=strings("poller_helpers"),
        socket_helpers=sockets("socket_helpers"),
        rollback_safe_from=rollback_safe_from,
        database_baseline=database_baseline,
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


def before_baseline(requirements: Requirements, revision: str) -> str | None:
    """Why a database at `revision` cannot be taken to this release at all, or None (B369)."""

    baseline = requirements.database_baseline
    if baseline is None or not is_digits(revision) or revision >= baseline:
        return None
    return (
        f"{revision} is from before this release's baseline {baseline}. Haprion 0.99 and later "
        "are installed afresh, not upgraded from an earlier release: see docs/install.md, "
        "'Removing'"
    )


def schema_upgrade_failures(
    active: Requirements, candidate: Requirements, current_revision: str
) -> tuple[str, ...]:
    """Why migrating under the active UI would make service or rollback unsafe."""

    failures = []
    #
    # The candidate carries its own migrations: a database already at its head
    # - an update run again after it migrated - is one the running UI runs on
    # when they are declared safe for it, by the rule a rollback uses
    # (review 26-10-29, A01).
    #
    if schema_problem(active, (candidate,), current_revision) is not None:
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


def schema_problem(
    target: Requirements, carriers: Iterable[Requirements], revision: str
) -> str | None:
    """Why the target cannot run on the database's schema; None when it can (26-10-20).

    A revision the target accepts is the plain case. A newer one is a rollback
    over migrations, safe only when a release that carries them - its head is
    the database's revision - declares them safe from the target's head or
    earlier. Nothing on the machine carrying them is no answer, and so a no:
    the web would start on that schema whether it can or not.

    The one rule for a release on a schema: `haprion-rollback` asks it before
    it switches, the check after it, and an update run again over its own
    migration (review 26-10-29, A01: three rules, and the check refused what
    the rollback had just allowed).
    """

    if revision in target.database_revisions:
        return None
    if revision < target.database_head:
        return f"schema {revision} is older than every revision the target runs on"
    for owner in carriers:
        if owner.database_head == revision and owner.rollback_safe_from is not None:
            if owner.rollback_safe_from <= target.database_head:
                return None
            return (
                f"schema {revision} is safe for a UI from {owner.rollback_safe_from} on; "
                f"the target stands at {target.database_head}"
            )
    return f"no release on this machine declares schema {revision} safe for the target"


def newest_first(name: str) -> tuple[int, ...]:
    """`0.99.10-<hash>` after `0.99.9-<hash>`; a name without a version last."""

    version = re.match(r"\d+(?:\.\d+)*", name)
    return tuple(int(part) for part in version.group().split(".")) if version else ()


def owners(root: Path, packaged: str | None) -> list[Requirements]:
    """Every UI release on disk that says its schema: the packaged one first, then the newest.

    A later release may correct an earlier one's declaration, as 0.99.4 did
    0.99.3's (26-10-28), and the release the package installed knows the
    newest migrations.
    """

    found = []
    releases = sorted((root / "releases").iterdir(), key=lambda path: newest_first(path.name))
    for release in sorted(releases[::-1], key=lambda path: path.name != packaged):
        try:
            found.append(ui_requirements(release))
        except CompatibilityError:
            continue  # a release that says nothing carries nothing
    return found


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


def extra_helper_rules(
    actual: tuple[str, ...], expected: tuple[str, ...], user: str, cli_root: Path
) -> tuple[str, ...] | None:
    """The helpers named by rules beyond the expected ones, when every rule expected is
    there once and each extra one is an exact helper rule of the same form; else None.

    The sudo rules follow the package and not the release: after a rollback on its
    own, the newer package's file may name a helper the older release does not run
    (review 26-10-24, 11-06).
    """

    if len(set(actual)) != len(actual) or not set(expected) <= set(actual):
        return None
    form = re.compile(
        rf"{re.escape(user)} ALL=\(root\) NOPASSWD: "
        rf'{re.escape(str(cli_root))}/current/bin/(haprion-[a-z0-9-]+) ""'
    )
    helpers = []
    for rule in sorted(set(actual) - set(expected)):
        found = form.fullmatch(rule)
        if found is None:
            return None
        helpers.append(found.group(1))
    return tuple(helpers) or None


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
    extra = extra_helper_rules(actual, expected, user, cli_root)
    if sorted(actual) == sorted(expected) and len(actual) == len(expected) and secure:
        report.pass_(label, labels.counted(len(expected), "exact helper rule"))
    elif extra is not None and secure:
        report.warn(
            label,
            f"{labels.counted(len(expected), 'exact helper rule')}, and {len(extra)} more "
            f"for what this release does not run ({', '.join(extra)}); "
            "the package's next update writes the file again",
        )
    else:
        detail = (
            f"expected {labels.counted(len(expected), 'exact helper rule')}, found {len(actual)}"
        )
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


#
# The status helper's own limits are the status read's (`STATUS_TIMEOUT_SECONDS`
# for the whole read of a node, and the connect wait before it); the call that
# waits for the helper waits longer, so that a slow node is the helper's answer
# - `reachable: false` - and not an exception here (review 26-10-30, U1).
#
NODE_CALL_MARGIN_SECONDS = 15
NODE_CALL_TIMEOUT_SECONDS = (
    status_collect.STATUS_TIMEOUT_SECONDS
    + node_ssh.STATUS_CONNECT_TIMEOUT_SECONDS
    + NODE_CALL_MARGIN_SECONDS
)
COMMAND_TIMEOUT_SECONDS = 30


class CommandTimedOut(Exception):
    """A command the check ran did not finish within its limit."""

    def __init__(self, argv: list[str], seconds: float) -> None:
        super().__init__(f"{Path(argv[0]).name} gave no answer within {seconds:g} seconds")
        self.seconds = seconds


def _command(
    argv: list[str],
    *,
    input_text: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    limit = COMMAND_TIMEOUT_SECONDS if timeout is None else timeout
    try:
        return subprocess.run(  # noqa: S603 - every executable is fixed by the installation
            argv,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=limit,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandTimedOut(argv, limit) from exc


def check_service(report: Report, *, unit: str, release: Path) -> None:
    try:
        active = _command([SYSTEMCTL, "is-active", unit])
    except CommandTimedOut as exc:
        report.fail(unit, str(exc))
        return
    if active.returncode != 0 or active.stdout.strip() != "active":
        report.fail(unit, "not active")
        return
    try:
        pid_result = _command([SYSTEMCTL, "show", unit, "--property=MainPID", "--value"])
    except CommandTimedOut as exc:
        report.fail(unit, str(exc))
        return
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
    try:
        completed = _command(
            [
                PSQL,
                "-U",
                role,
                "-d",
                database,
                "-qtAX",
                "-c",
                "select version_num from alembic_version",
            ]
        )
    except CommandTimedOut as exc:
        raise CompatibilityError(f"database revision query: {exc}") from exc
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


def _scripts_behind(entry: object, expected: Mapping[str, str]) -> list[str]:
    """The node's scripts whose installed bytes are not the release's node package's."""

    status = entry.get("status") if isinstance(entry, dict) else None
    installation = status.get("installation") if isinstance(status, dict) else None
    scripts = installation.get("scripts") if isinstance(installation, dict) else None
    if not isinstance(scripts, dict):
        return sorted(expected)
    behind = []
    for name, digest in sorted(expected.items()):
        reported = scripts.get(name)
        installed = reported.get("installed_sha256") if isinstance(reported, dict) else None
        if installed != digest:
            behind.append(name)
    return behind


def check_cluster_nodes(
    report: Report,
    *,
    cluster: str,
    helper: Path,
    required_api: int,
    expected_scripts: Mapping[str, str] | None = None,
    carried_version: str | None = None,
) -> None:
    """Each node's API and scripts, and whether they are the CLI release's node package.

    Whether they are is asked two ways, both warnings: the package's version
    against the carried one's, as the dashboard and `haprion-status` ask it,
    and each script's bytes against the carried package's - a script changed
    by hand under the right version (review 26-10-29, A07: the check knew only
    the bytes, and a release that changed no script left an older package
    current here and older on the dashboard).

    A node's own `scripts_current` compares its files with the record its own
    package left, so a node still on an older package looks current against
    itself (found 2026-09-10). `expected_scripts` are the digests of the node
    package the CLI release carries; a node behind them is a warning, not a
    failure, because the CLI and the interface are installed before the nodes
    on purpose, and that order would otherwise fail every update (B335).

    A node that does not answer is a warning too: what it runs is unknown, not
    wrong. As a failure it stopped the update, or rolled back a release that
    worked, just when a node was down and the interface was needed to bring
    it back (review 2026-10-22, 6-2). A node that answers without the metadata,
    or with an older API, still fails.
    """

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
    try:
        completed = _command([str(helper)], input_text=request, timeout=NODE_CALL_TIMEOUT_SECONDS)
    except CommandTimedOut as exc:
        report.warn(
            f"nodes/{cluster}",
            f"{exc}; what its nodes run is unknown - check again when they answer",
        )
        return
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
        if isinstance(entry, dict) and entry.get("reachable") is False:
            report.warn(
                subject,
                "did not answer; what it runs is unknown - check again when it is back",
            )
            continue
        if api is None:
            report.fail(subject, "does not report node compatibility metadata")
        elif api < required_api:
            report.fail(subject, f"node API {api}, requires {required_api}")
        elif not scripts_current:
            report.fail(subject, f"node API {api}, installed script digests differ")
        else:
            report.pass_(subject, f"node API {api}, script digests current")
        status = entry.get("status") if isinstance(entry, dict) else None
        installation = status.get("installation") if isinstance(status, dict) else None
        standing = haproxy_versions.node_package_standing(installation, carried_version)
        if standing is not None:
            installed = standing.installed
            shown = (
                f"haprion-node {node_package.short_version(installed)}"
                if installed
                else "haprion-node"
            )
            if standing.kind == "not configured":
                said = (
                    f"{shown} is installed but not configured - "
                    f"{haproxy_versions.CONFIGURE_ON_THE_NODE}"
                )
            else:
                carried = node_package.short_version(str(carried_version))
                if standing.kind == "newer":
                    said = f"{shown}, newer than the CLI release's {carried}"
                else:
                    said = (
                        f"{shown}, older than the CLI release's {carried} - install it on the node"
                    )
            report.warn(subject, said)
        #
        # The scripts, when the package is the release's: a package of another
        # version, or one not configured, has its own scripts, and the line
        # above already says what to do (review 26-10-29, AA03).
        #
        if expected_scripts and standing is None:
            behind = _scripts_behind(entry, expected_scripts)
            if behind:
                report.warn(
                    subject,
                    f"{labels.counted(len(behind), 'script')} not this release's node package: "
                    f"{', '.join(behind)} - install it on the node",
                )


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
    expected = (
        (cluster.cluster_id, node.name, node.mgmt_host)
        for cluster in runtime.clusters.values()
        for node in cluster.nodes
    )
    actual = ((node.cluster, node.node, node.host) for node in collector.nodes)
    missing, extra, changed = _inventory_differences(expected, actual)
    if not (missing or extra or changed):
        report.pass_(
            "traffic collector inventory", f"{labels.counted(len(collector.nodes), 'node')} current"
        )
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
    #
    # The release the haprion-ui package installed, asked first about a schema
    # past the checked release's head - as `haprion-rollback` asks it.
    #
    parser.add_argument("--packaged")
    parser.add_argument("--skip-database", action="store_true")
    parser.add_argument("--skip-services", action="store_true")
    parser.add_argument("--upgrade-from-current", action="store_true")
    #
    # The release an update goes back to when it is not the one running: the
    # release last proved, under an unproved one an earlier update left
    # (review 26-10-29, AA01).
    #
    parser.add_argument("--rollback-to")
    #
    # A first installation, checked before its release is activated: the worker
    # unit, the sudo rules and the helper sockets come from platform step 07,
    # which runs after activation, so they are left to the check after it.
    #
    parser.add_argument("--first-install", action="store_true")
    #
    # The nodes left unasked: the check after a switch or a restore, where the
    # interface's own release decides and the nodes were asked before the
    # migration (review 26-10-30, U1).
    #
    parser.add_argument("--skip-nodes", action="store_true")
    return parser.parse_args(argv)


def first_install_error(args: argparse.Namespace) -> str | None:
    """Why `--first-install` may not be used here, or None.

    Only before the first activation: with a release current, skipping the
    parts step 07 installs would weaken an upgrade's check instead.
    """

    if not args.first_install:
        return None
    if not args.ui_release or args.upgrade_from_current:
        return "--first-install requires --ui-release and excludes --upgrade-from-current"
    current = args.platform_root / "current"
    if current.exists() or current.is_symlink():
        return (
            f"--first-install is for an installation with no active release, and {current} exists"
        )
    return None


def past_head_refusal(
    name: str, candidate: Requirements, carriers: Iterable[Requirements], revision: str
) -> str | None:
    """Why an update cannot take the database back to `name`, or None (B388, review 26-10-29, A05).

    A schema past the candidate's head is one a newer release migrated to. No
    migration goes back (B360): the update would stop in the candidate's own
    alembic, which does not know the revision. The way back is a rollback when
    the candidate runs on that schema by the rollback's rule, and otherwise the
    dump taken before the update that migrated it.

    Said under apt, where the older package is unpacked over the newer one
    already: the newer package goes back first, and the rollback then switches
    the release with that package's files in place (review 26-10-29, AA07).
    """

    if revision in candidate.database_revisions or revision <= candidate.database_head:
        return None
    problem = schema_problem(candidate, carriers, revision)
    if problem is None:
        return (
            f"{revision}, past {name}'s head {candidate.database_head}; an update does not take "
            "the database back past a migration. Install the haprion-ui package that migrated "
            "it again - apt list -a haprion-ui lists the versions - then switch with: "
            f"sudo haprion-rollback --to {name}"
        )
    return (
        f"{revision}; {name} does not run on it ({problem}). An update does not take the "
        f"database back past a migration; the way back is the dump taken before the update "
        f"to {revision}"
    )


def check_schema_transition(
    report: Report,
    platform_root: Path,
    requirements: Requirements,
    revision: str,
    *,
    name: str,
    packaged: str | None,
    rollback_to: str | None = None,
) -> None:
    """The running UI over the schema now, and over this release's head after migrating.

    The release a failure after the switch goes back to is the running one,
    or `rollback_to` when the update goes on from an earlier release: the
    running release serves on the candidate's head until the switch, and the
    rollback target runs on it after.
    """

    try:
        refusal = past_head_refusal(name, requirements, owners(platform_root, packaged), revision)
    except OSError as exc:
        report.fail("candidate schema", f"cannot read the releases on disk: {exc}")
        return
    if refusal is not None:
        report.fail("candidate schema", refusal)
        return
    try:
        active_release = current_release(platform_root, "UI")
        active_requirements = ui_requirements(active_release)
    except CompatibilityError as exc:
        report.fail("schema transition", str(exc))
        return
    transition_failures = schema_upgrade_failures(active_requirements, requirements, revision)
    if not any("current revision" in failure for failure in transition_failures):
        report.pass_(
            "running schema",
            f"{revision}, accepted by {active_release.name}"
            if revision in active_requirements.database_revisions
            else f"{revision}, the candidate's head, declared safe for {active_release.name} "
            "by its migrations",
        )
    else:
        report.fail(
            "running schema",
            f"{revision}; running {active_release.name} does not accept it",
        )
    elsewhere = rollback_to is not None and rollback_to != active_release.name
    if not any("candidate head" in failure for failure in transition_failures):
        report.pass_(
            "migrated schema" if elsewhere else "rollback schema",
            head_accepted(requirements, active_release.name, active_requirements),
        )
    elif not elsewhere:
        report.fail(
            "rollback schema",
            f"candidate head {requirements.database_head}; running "
            f"{active_release.name} does not accept it",
        )
    else:
        report.fail(
            "migrated schema",
            f"candidate head {requirements.database_head}; {active_release.name}, which runs "
            "until the switch, does not accept it",
        )
    if elsewhere and rollback_to is not None:
        check_rollback_target(report, platform_root, requirements, rollback_to)


def head_accepted(candidate: Requirements, name: str, target: Requirements) -> str:
    """How the release `name` runs on the candidate's head, for a PASS line."""

    if candidate.database_head in target.database_revisions:
        return f"{candidate.database_head}, accepted by {name}"
    return (
        f"{candidate.database_head}, rollback-safe from {candidate.rollback_safe_from} by its "
        f"migrations; {name} stands at {target.database_head}"
    )


def check_rollback_target(
    report: Report, platform_root: Path, candidate: Requirements, name: str
) -> None:
    """The release last proved, where a failure after the switch goes back to, on the head."""

    try:
        target = ui_requirements(named_release(platform_root, name, "UI"))
    except CompatibilityError as exc:
        report.fail("rollback schema", f"{name}, the release last proved: {exc}")
        return
    if candidate.database_head in target.database_revisions or declared_safe(target, candidate):
        report.pass_("rollback schema", head_accepted(candidate, name, target))
    else:
        report.fail(
            "rollback schema",
            f"candidate head {candidate.database_head}; {name}, the release last proved, "
            "does not run on it",
        )


def check_schema_past_head(
    report: Report,
    platform_root: Path,
    packaged: str | None,
    requirements: Requirements,
    revision: str,
) -> None:
    """A schema the release does not list: a rollback over migrations, by the rollback's rule."""

    try:
        carriers = owners(platform_root, packaged)
    except OSError as exc:
        report.fail("schema revision", f"{revision}; cannot read the releases on disk: {exc}")
        return
    problem = schema_problem(requirements, carriers, revision)
    if problem is None:
        report.pass_(
            "schema revision",
            f"{revision}, past {requirements.database_head} over migrations declared safe for it",
        )
    else:
        report.fail("schema revision", f"{revision}; {problem}")


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
    refused = first_install_error(args)
    if refused is not None:
        print(f"ERROR: {refused}", file=sys.stderr)
        return 1

    if not args.skip_database:
        print("\n== Database")
        try:
            revision = database_revision(args.database_role, args.database)
        except CompatibilityError as exc:
            report.fail("schema revision", str(exc))
        else:
            refusal = before_baseline(requirements, revision)
            if refusal is not None:
                report.fail("schema revision", refusal)
            elif args.upgrade_from_current:
                check_schema_transition(
                    report,
                    args.platform_root,
                    requirements,
                    revision,
                    name=ui_release.name,
                    packaged=args.packaged,
                    rollback_to=args.rollback_to,
                )
            elif revision in requirements.database_revisions:
                report.pass_("schema revision", revision)
            else:
                check_schema_past_head(
                    report, args.platform_root, args.packaged, requirements, revision
                )

    if not args.skip_services:
        print("\n== Services")
        for unit in (accounts.WORKER_UNIT, accounts.POLLER_UNIT, accounts.WEB_UNIT):
            check_service(report, unit=unit, release=ui_release)

    if args.first_install:
        print("\n== Installed by platform step 07")
        print("  SKIP  worker sandbox, sudo rules, helper sockets   checked after step 07")
    else:
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
    if args.skip_nodes:
        print("  SKIP  node installations   asked before the switch")
        clusters: list[str] = []
    else:
        clusters = list(args.clusters)
    helper = cli_release / "bin/haprion-status-helper"
    carried = None
    if not args.skip_nodes:
        try:
            carried = node_package.release_package(cli_release)
        except node_package.PackageError as exc:
            report.warn("node package", f"the CLI release's node package cannot be read: {exc}")
    for cluster in clusters:
        check_cluster_nodes(
            report,
            cluster=cluster,
            helper=helper,
            required_api=requirements.node_api,
            expected_scripts=carried.scripts if carried is not None else None,
            carried_version=carried.version if carried is not None else None,
        )

    print()
    if report.failures:
        print(f"INCOMPATIBLE: {labels.counted(report.failures, 'check')} failed")
        return 1
    print("COMPATIBLE: every installed component satisfies the running UI release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
