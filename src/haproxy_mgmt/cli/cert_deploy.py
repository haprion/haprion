"""`haproxy-cert-deploy` - put the cluster's referenced certificates on its nodes.

The thin half. Same shape as `haproxy-deploy` and for the same reasons: it
resolves the cluster, hands one structured request across the boundary, and
lets the privileged half stream the rollout straight to this process's stdout.

Which certificates a cluster gets is not a parameter here, and cannot be made
one. The referenced list comes from the cluster configuration, read on the other
side of the boundary. A caller that could name certificates would be a caller
that could put key material on a node the configuration never referenced.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid

from haproxy_mgmt.cli.caller import config_path as _config_path
from haproxy_mgmt.cli.caller import usage

OPERATION = "cert_deploy_cluster"

HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-cert-deploy-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haproxy-cert-deploy -c <cluster> [--allow-vip-unknown] [--json]\n"
    "\n"
    "Examples:\n"
    "  haproxy-cert-deploy -c internal\n"
    "  haproxy-cert-deploy -c external --json\n"
    "\n"
    "Options:\n"
    "  --allow-vip-unknown\n"
    "        Proceed when VIP ownership cannot be determined. Split brain is\n"
    "        never overridable.\n"
    "  --json\n"
    "        Print one result document instead of the rollout.\n"
)


def _parse(argv: list[str]) -> tuple[str, bool, bool]:
    if len(argv) < 2 or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)

    options = argv[2:]
    if any(option not in ("--allow-vip-unknown", "--json") for option in options):
        usage(USAGE)
    if len(set(options)) != len(options):
        usage(USAGE)

    return argv[1], "--allow-vip-unknown" in options, "--json" in options


def build_request(
    cluster_id: str,
    request_id: str,
    *,
    allow_vip_unknown: bool,
    json_mode: bool,
    lifeline: bool = False,
) -> str:
    """The exact request this operation sends, built in one place.

    Public because the interface's worker sends the same operation. It must not
    build the envelope itself: the helper validates it strictly, and two
    constructions of one request are two things to keep in step - the divergence
    that is hardest to find, because each side looks correct on its own.

    The request ID is a parameter rather than generated here. The command line
    has nobody to answer to and makes one up; the worker already holds the ID the
    job was queued with, and that ID is what makes "did this operation take
    effect?" answerable after a crash.

    `lifeline` says the caller is holding stdin open so it can let go later. The
    command line leaves it False and closes stdin as it always has: a person at
    a terminal has Ctrl-C and holds no lease, so there is nothing for a lifeline
    to express. The worker sets it, because it has both.
    """

    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "lifeline": lifeline,
            "parameters": {"allow_vip_unknown": allow_vip_unknown, "json": json_mode},
        }
    )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cluster_id, allow_vip_unknown, json_mode = _parse(argv)

    _config_path(cluster_id)

    request = build_request(
        cluster_id,
        str(uuid.uuid4()),
        allow_vip_unknown=allow_vip_unknown,
        json_mode=json_mode,
    ).encode()

    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=request,
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
