"""Write one path list across the root boundary (B527, B532).

The worker's `path_list_apply` job sends the list as Settings saved it. This
checks it as the engine reads it (`haprion.path_lists`) and writes it
root-only under /etc/haprion/path-lists, where every publish reads the lists
its objects name. Nothing reaches a node here: a cluster whose version carries
another copy of the list says so in *Needs attention* and takes the change with
its next publish. `remove` deletes the list; whether an object still names it
is the web's check before the job is queued, and this one: a list a cluster's
committed objects still name is not removed, whatever the web read a poll ago
(review 26-11-24, PW11).
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haprion import exit_codes, path_lists
from haprion.cli import cert_job
from haprion.config import (
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haprion.envelope import envelope
from haprion.git_command import GitError
from haprion.helper_protocol import HelperProtocolError, write_document
from haprion.managed_publish import PROXY_PREFIX, managed_proxies
from haprion.path_lists import PathListError
from haprion.proxy_model import ModelError
from haprion.repo_snapshot import PublishError, read_tree_files, resolve_head

OPERATION = path_lists.OPERATION
PARAMETERS = frozenset({"name", "revision", "description", "paths", "remove"})

type UsersReader = Callable[[str], list[str]]
"""The objects, as `cluster/object`, whose committed document names the list."""


def committed_users(name: str, runtime: Any) -> list[str]:
    """Every cluster's committed objects that name the list under *Denied paths*.

    Read from each cluster's HEAD, as a publish reads the lists its objects
    name (`path_lists.named`), and with every cluster read: one that cannot be
    is a removal refused, not a list assumed unused.
    """

    users: list[str] = []
    for cluster_id, cluster in sorted(runtime.clusters.items()):
        try:
            _branch, head = resolve_head(cluster.config_path)
            files = read_tree_files(cluster.config_path, head, (PROXY_PREFIX,))
            proxies = managed_proxies(files)
        except (ConfigError, GitError, PublishError, ModelError, OSError) as exc:
            raise PathListError(
                f"cannot read the committed objects of cluster {cluster_id!r}: {exc}"
            ) from exc
        users.extend(
            f"{cluster_id}/{proxy.name}" for proxy in proxies if name in path_lists.named([proxy])
        )
    return users


def _runtime_users(policy_path: Path, require_secure: bool) -> UsersReader:
    def read(name: str) -> list[str]:
        try:
            policy = load_policy(policy_path, require_secure=require_secure)
            runtime = load_runtime_config(policy, require_secure=require_secure)
        except ConfigError as exc:
            raise PathListError(str(exc)) from exc
        return committed_users(name, runtime)

    return read


def main(
    argv: list[str] | None = None,
    *,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    directory: Path = path_lists.DIRECTORY,
    policy_path: Path = DEFAULT_POLICY_PATH,
    users_reader: UsersReader | None = None,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-path-list-apply-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code
    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    parameters = request.parameters
    try:
        name = path_lists.checked_name(parameters.get("name"))
        revision = path_lists.check_revision(parameters.get("revision"))
        remove = parameters.get("remove", False)
        if not isinstance(remove, bool):
            raise PathListError("remove must be true or false")
        item = (
            None
            if remove
            else path_lists.path_list(
                name, parameters.get("paths"), parameters.get("description", ""), revision
            )
        )
    except PathListError as exc:
        return refuse("bad_input", str(exc), exit_codes.REFUSED)

    result: dict[str, object] = {"name": name, "revision": revision}
    try:
        if item is None:
            users = (users_reader or _runtime_users(policy_path, require_secure))(name)
            if users:
                return refuse(
                    "in_use",
                    f"{name} is named under Denied paths by {', '.join(users)}; "
                    "take it out there first",
                    exit_codes.REFUSED,
                )
            result["removed"] = path_lists.remove(
                name, directory=directory, require_secure=require_secure
            )
        else:
            notes: list[str] = []
            path_lists.write(
                item, directory=directory, require_secure=require_secure, warnings=notes
            )
            for note in notes:
                errors.write(f"WARNING: {note}\n")
            result["paths"] = len(item.paths)
    except PathListError as exc:
        return refuse("dependency_unavailable", str(exc), exit_codes.CONFIG)
    return write_document(
        writer,
        envelope(
            operation=OPERATION,
            outcome="done",
            cluster=None,
            request_id=request.request_id,
            result=result,
        ),
        0,
    )


if __name__ == "__main__":
    raise SystemExit(main())
