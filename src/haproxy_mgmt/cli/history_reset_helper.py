"""The privileged half of `haproxy-history-reset`.

Takes no arguments. The cluster and the operator's acknowledgement arrive as a
structured request on stdin, for the reason PRIVILEGE.md gives: a sudoers rule
that matched a cluster name would need a wildcard in argument matching, and
wildcards there are forbidden. One no-argument rule covers every cluster, and
adding a cluster does not touch sudoers.

The acknowledgement is a field in the request rather than a prompt in here. A
prompt inside a root helper would be a prompt on the wrong side of the boundary:
it could not be shown by a user interface, and anything driving the helper would
have to fake a terminal to get past it. Asking is the caller's job; requiring
that it was asked is this one's.

Nothing the caller says about the repository is believed. The version count, the
current commit and the paths are all read again here, from the cluster
configuration and the repository itself.
"""

from __future__ import annotations

import grp
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    read_helper_request,
    require_no_arguments,
)
from haproxy_mgmt.history_reset import (
    OWNER_GROUP,
    ChangeOwner,
    ResetError,
    chown,
    preview,
    reset_history,
)

OPERATION = "reset_history"

#
# The same phrase the caller asks the operator to type. It is repeated in the
# request so that this side can refuse a request that was never confirmed - not
# so that it can be guessed: anything able to send the request could send the
# phrase too. What it prevents is an accident, not an attacker, and the attacker
# case is handled by the sudoers rule that decides who may run this at all.
#
ACKNOWLEDGEMENT = "please reset me"

BASELINE_MESSAGE = "Baseline after the build phase"

type ResolveGroup = Callable[[str], int]


def _group_id(name: str) -> int:
    """Resolve the required group, failing before writing an unreadable tree."""

    try:
        return grp.getgrnam(name).gr_gid
    except KeyError as exc:
        raise ResetError(
            f"the group '{name}' does not exist. The new history would be "
            "unreadable to the management identity.",
            exit_code=78,
        ) from exc


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    change_owner: ChangeOwner = chown,
    resolve_group: ResolveGroup = _group_id,
) -> int:
    output = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    stream = input_stream or sys.stdin.buffer
    arguments = sys.argv[1:] if argv is None else argv

    try:
        require_no_arguments(arguments)
        if require_root and os.geteuid() != 0:
            raise HelperProtocolError("history reset helper must run as root", exit_code=77)

        request = read_helper_request(
            stream,
            expected_operation=OPERATION,
            allowed_parameter_keys=frozenset({"acknowledgement"}),
        )
        if request.parameters.get("acknowledgement") != ACKNOWLEDGEMENT:
            raise HelperProtocolError(
                "the request does not carry the operator's acknowledgement", exit_code=77
            )

        policy = load_policy(policy_path, require_secure=require_secure)
        cluster = load_runtime_config(policy, require_secure=require_secure).cluster(
            request.cluster
        )
        plan = preview(request.cluster, cluster.config_path)

        group_id = resolve_group(OWNER_GROUP)

        result = reset_history(
            plan,
            stamp=datetime.now(UTC).strftime("%Y%m%d-%H%M%S"),
            message=BASELINE_MESSAGE,
            group_id=group_id,
            change_owner=change_owner,
        )
    except (ConfigError, HelperProtocolError, ResetError) as exc:
        print(f"ERROR: {exc}", file=errors)
        return exc.exit_code

    json.dump(
        {
            "schema_version": 1,
            "operation": request.operation,
            "cluster": request.cluster,
            "request_id": request.request_id,
            "commit": result.commit,
            "versions_discarded": result.versions_discarded,
            "archived_history": str(result.archived_history),
            "archived_draft": str(result.archived_draft),
        },
        output,
    )
    output.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
