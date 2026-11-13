"""haprion-blocklist-refresh: fetch the blocklists that are due and send them to the nodes (B500).

Run as root by `haprion-blocklist-refresh.timer`, the way certbot's renewal
runs: a pass fetches each list whose time has come, keeps the last good one
when a fetch fails, writes every cluster's files with that cluster's
exceptions taken out, and deploys the clusters whose files changed through
`haprion-cert-deploy`, which sends the lists with the certificates. A cluster
whose deploy did not finish is remembered and deployed again by the next pass.

Usage:
  haprion-blocklist-refresh [--list <name>]... [--force]

  --list <name>  Fetch this list now, whatever its interval says.
  --force        Fetch every list now.

The state the poller shows on Settings is in /var/lib/haprion/blocklists/.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TextIO

from haprion import (
    atomic_file,
    blocklist_refresh,
    blocklist_store,
    blocklists,
    cert_publish,
    exit_codes,
)
from haprion.cli.caller import help_asked
from haprion.cli.cert_publish import ClusterDeployer
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config

LOCK = Path("/run/haprion-blocklist-refresh.lock")
PENDING = "deploy-pending.json"

Deployer = Callable[[str], int]


def _usage(writer: TextIO) -> int:
    writer.write((__doc__ or "").split("Usage:\n", 1)[1].split("\n\n", 2)[0] + "\n")
    return exit_codes.USAGE


def _parse(argv: Sequence[str]) -> tuple[list[str], bool] | None:
    only: list[str] = []
    force = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--list" and index + 1 < len(argv):
            name = argv[index + 1]
            if not blocklists.NAME.fullmatch(name):
                return None
            only.append(name)
            index += 2
        elif argument == "--force":
            force = True
            index += 1
        else:
            return None
    return only, force


def read_pending(directory: Path) -> set[str]:
    """The clusters whose last deploy of their lists did not finish."""

    try:
        document = json.loads((directory / PENDING).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return set()
    except (OSError, ValueError):
        #
        # Unreadable is every cluster: deploying one that was current costs a
        # status read, and forgetting one that was not leaves its nodes behind.
        #
        return {"*"}
    clusters = document.get("clusters") if isinstance(document, dict) else None
    if not isinstance(clusters, list) or not all(isinstance(c, str) for c in clusters):
        return {"*"}
    return set(clusters)


def write_pending(directory: Path, clusters: Iterable[str]) -> None:
    content = json.dumps({"clusters": sorted(clusters)}, separators=(",", ":")) + "\n"
    atomic_file.write(directory / PENDING, content.encode("utf-8"), mode=0o600)


def remember(directory: Path, cluster: str) -> None:
    """Add a cluster to the pending file now: its files are about to change."""

    pending = read_pending(directory)
    if cluster not in pending and "*" not in pending:
        write_pending(directory, pending | {cluster})


def deploy(
    changed: Iterable[str],
    known: Sequence[str],
    *,
    directory: Path,
    deployer: Deployer,
    skip: Iterable[str] = (),
) -> dict[str, int]:
    """Deploy the changed clusters and those left over; what each answered.

    A cluster in `skip` was not written this pass: it stays pending if it was
    and is not deployed from files this pass did not make.
    """

    pending = read_pending(directory)
    if "*" in pending:
        pending = set(known)
    wanted = ((pending | set(changed)) & set(known)) - set(skip)
    answers: dict[str, int] = {}
    for cluster in sorted(wanted):
        answers[cluster] = deployer(cluster)
        if answers[cluster] == 0:
            pending.discard(cluster)
        else:
            pending.add(cluster)
    write_pending(directory, pending & set(known))
    return answers


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    definitions: Path = blocklist_store.DEFINITIONS,
    state: Path = blocklist_store.STATE,
    lock_path: Path = LOCK,
    deployer: Deployer | None = None,
    fetch: blocklist_refresh.Fetch = blocklists.fetch,
    now: dt.datetime | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    if help_asked(argv):
        writer.write(__doc__ or "")
        return exit_codes.OK
    parsed = _parse(argv)
    if parsed is None:
        return _usage(errors)
    only, force = parsed

    def refuse(message: str, code: int) -> int:
        errors.write(f"ERROR: {message}\n")
        return code

    if require_root and os.geteuid() != 0:
        return refuse(
            "haprion-blocklist-refresh must run as root; run it with sudo", exit_codes.NOT_ROOT
        )
    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(str(exc), exc.exit_code)
    if policy.certificate_root is None or runtime.registry is None:
        return refuse(
            "blocklists go to the nodes with the certificates; the runtime policy names no "
            "certificate_root or certificate_registry",
            exit_codes.CONFIG,
        )
    try:
        stored = blocklist_store.read_all(directory=definitions)
    except blocklist_store.StoreError as exc:
        return refuse(str(exc), exit_codes.CONFIG)
    unknown = sorted(set(only) - {item.definition.name for item in stored})
    if unknown:
        return refuse(f"no blocklist is called {', '.join(unknown)}", exit_codes.USAGE)

    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return refuse("another blocklist refresh is still running", exit_codes.BLOCKED)
        try:
            targets = []
            skipped: dict[str, str] = {}
            for cluster_id in sorted(runtime.clusters):
                #
                # One cluster's network file that cannot be read, or whose
                # directory cannot be prepared, is that cluster's problem: it
                # is left out of this pass, said, and the others go on (review
                # 2026-11-13, BL14 and GH06).
                #
                try:
                    target = cert_publish.cluster_target(policy.certificate_root, cluster_id)
                except cert_publish.PublishError as exc:
                    skipped[cluster_id] = f"its certificate directory could not be prepared: {exc}"
                    continue
                try:
                    groups = runtime.clusters[cluster_id].network().networks
                except (ConfigError, OSError) as exc:
                    skipped[cluster_id] = f"its network description could not be read: {exc}"
                    continue
                targets.append(
                    blocklist_refresh.ClusterTarget(
                        cluster=cluster_id,
                        directory=target.directory,
                        groups=groups,
                        uid=target.uid,
                        gid=target.gid,
                        mode=target.mode,
                    )
                )
            state.mkdir(mode=0o755, exist_ok=True)
            result = blocklist_refresh.run(
                stored,
                targets,
                now or dt.datetime.now(dt.UTC),
                fetch=fetch,
                state_directory=state,
                only=only,
                force=force,
                before_change=lambda cluster: remember(state, cluster),
            )
            answers = deploy(
                result.changed_clusters(),
                sorted(runtime.clusters),
                directory=state,
                deployer=deployer or ClusterDeployer(errors),
                skip=skipped,
            )
        except (cert_publish.PublishError, blocklist_store.StoreError, ConfigError, OSError) as exc:
            return refuse(str(exc), exit_codes.FAILED)
    finally:
        os.close(descriptor)

    code = exit_codes.OK
    for name in sorted(result.states):
        item = result.states[name]
        if item.error and item.failed_at == item.attempted_at:
            kept = f"; kept the list of {item.fetched_at}" if item.fetched_at else ""
            writer.write(f"{name}: failed: {item.error}{kept}\n")
            code = exit_codes.PARTIAL
        else:
            writer.write(f"{name}: {item.entries} entries, fetched {item.fetched_at}\n")
    for written in result.written:
        if written.unknown_groups:
            writer.write(
                f"{written.name} in {written.cluster}: the exception names "
                f"{', '.join(written.unknown_groups)}, which the cluster does not define\n"
            )
    for cluster, reason in sorted(skipped.items()):
        writer.write(f"{cluster}: skipped, {' '.join(reason.split())}\n")
        code = exit_codes.PARTIAL
    for cluster, answer in sorted(answers.items()):
        writer.write(f"deploy {cluster}: {'ok' if answer == 0 else f'exit {answer}'}\n")
        if answer != 0:
            code = exit_codes.FAILED
    return code


if __name__ == "__main__":
    raise SystemExit(main())
