"""`haprion-deploy` - bring the cluster's nodes onto the published version.

The thin half, and thinner than the other callers by design. It resolves the
cluster, hands one structured request across the boundary, and gets out of the
way: the privileged half streams the rollout straight to this process's stdout,
so there is nothing to relay, buffer or reformat here.

That matters more than it sounds. A rollout is watched while it runs - the
operator is looking at which node is being touched and what it answered - and a
caller that collected the output to print it at the end would turn a live
operation into a silence followed by a wall of text.

What is NOT decided here
------------------------
Everything that matters: which nodes to touch, in what order, whether to touch
any at all. The caller does not read the cluster's status, does not resolve the
published target, and cannot influence either. It knows the cluster name and two
booleans; the rest is decided inside the boundary, from readings taken there.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid

from haprion.cli.caller import config_path as _config_path
from haprion.cli.caller import usage

OPERATION = "deploy_cluster"

HELPER = "/opt/haprion/current/bin/haprion-deploy-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haprion-deploy -c <cluster> [--allow-vip-unknown] [--json]\n"
    "\n"
    "Examples:\n"
    "  haprion-deploy -c alpha\n"
    "  haprion-deploy -c beta --json\n"
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
    expected_version: int | None = None,
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

    `expected_version` is the published version the caller saw. The helper
    deploys it or nothing: a job that waited in the queue while somebody
    published again must not roll out what nobody looked at. Left out, the
    request means "the published version, whichever it is" - which is what a
    person at a terminal who types the command is asking for.
    """

    parameters: dict[str, object] = {"allow_vip_unknown": allow_vip_unknown, "json": json_mode}
    if expected_version is not None:
        parameters["expected_version"] = expected_version
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": cluster_id,
            "request_id": request_id,
            "lifeline": lifeline,
            "parameters": parameters,
        }
    )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cluster_id, allow_vip_unknown, json_mode = _parse(argv)

    #
    # Looked up only to fail early and clearly on a cluster that does not exist.
    # The privileged half resolves it again and does not trust this answer.
    #
    _config_path(cluster_id)

    request = build_request(
        cluster_id,
        str(uuid.uuid4()),
        allow_vip_unknown=allow_vip_unknown,
        json_mode=json_mode,
    ).encode()

    #
    # stdout and stderr are inherited rather than captured, which is the whole
    # streaming mechanism: the helper's output is already going to the right
    # place, and anything this process did with it in between would only add
    # latency.
    #
    completed = subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=request,
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
