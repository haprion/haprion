"""`haproxy-status` - what the nodes are doing, and whether they run what you published.

The thin half. It runs as the calling user, checks the arguments, and hands a
structured request to the root helper. It decides nothing about the cluster: the
document it prints is the one the helper produced.

The question this command exists to answer
------------------------------------------
`haproxy-config-status` answers "what is published, and what have I not sent
yet", which is a question about the manager. This one answers "are the nodes
healthy", which is a question about the nodes. Between them sat a third question
that neither answered - *do the nodes run what is published* - and the only way
to find out was to start `haproxy-deploy` and read what it decided to skip.
Reaching for the mutating command in order to observe is exactly backwards
during an incident, so the answer is reported here, from the same comparison the
deploy matrix makes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from typing import Any, TextIO

from haproxy_mgmt import haproxy_versions
from haproxy_mgmt.cli.caller import usage
from haproxy_mgmt.cluster_status import StatusError, keepalived_state, parse_status
from haproxy_mgmt.envelope import new_request_id
from haproxy_mgmt.status_collect import EXIT_UNAVAILABLE, OPERATION

HELPER = "/opt/haproxy-mgmt/current/bin/haproxy-status-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haproxy-status -c <cluster> [--json]\n"
    "\n"
    "Examples:\n"
    "  haproxy-status -c alpha\n"
    "  haproxy-status -c beta --json\n"
)

#
# What the summary's release_state means to a person. Written out rather than
# printed as the enum value: "behind" alone does not say behind what, and the
# operator reading this is deciding whether to run a deploy.
#
RELEASE_STATE_TEXT = {
    "converged": "every node runs the published version",
    "behind": "at least one node is not running the published version",
    "incomplete": "a node could not be read, so this cannot be confirmed",
    "unknown": "nothing published, or no node said which release it runs",
}

type RunHelper = Callable[[str, str], subprocess.CompletedProcess[str]]


def run_status_helper(cluster_id: str, request_id: str) -> subprocess.CompletedProcess[str]:
    """Ask the privileged helper for one cluster's status.

    Public because the interface's poller calls it too. It must not build this
    request itself: the helper validates the envelope strictly, and two
    constructions of the same request are two things to keep in step - which is
    the divergence that is hardest to find, because each side looks correct on
    its own.
    """

    request = {
        "schema_version": 1,
        "operation": OPERATION,
        "cluster": cluster_id,
        "request_id": request_id,
        "parameters": {},
    }
    return subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "-n", HELPER],
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


def _parse(argv: list[str]) -> tuple[str, bool]:
    if len(argv) not in (2, 3) or argv[0] not in ("-c", "--cluster"):
        usage(USAGE)
    if len(argv) == 3 and argv[2] != "--json":
        usage(USAGE)
    return argv[1], len(argv) == 3


def _release_line(node: dict[str, Any]) -> str:
    """The node's own answer about which release it runs, and whether it matches.

    `current` is three-valued and each value is printed differently on purpose.
    False is the one an operator has to act on, so it says what to do; None is
    "not compared", which must never look like agreement.
    """

    status = node.get("status") or {}
    release = status.get("release") or {}
    version = release.get("version")
    shown = "unknown" if version is None else str(version)

    current = node.get("current")
    if current is True:
        return f"{shown}   (published)"
    if current is False:
        return f"{shown}   BEHIND - run haproxy-deploy"
    return f"{shown}   (not compared)"


def _addresses_line(status: dict[str, Any]) -> str | None:
    """What the node said about its keepalived address list, in one line.

    Printed only when the node reported it at all, and only as description: the
    verdict on the far right of the version line is the helper's, decided once
    by `ReleaseTarget.is_current`. Without this line a node whose version says
    BEHIND while matching the published version is unexplainable from the
    status output, because the half that is behind is the address list.
    """

    reported = status.get("keepalived", {}).get("addresses")
    if not isinstance(reported, dict):
        return None
    if reported.get("published") is False:
        return "not managed from here"

    published = reported.get("published_sha256")
    installed = reported.get("installed_sha256")
    if not isinstance(published, str) or not isinstance(installed, str):
        if reported.get("installed") is False:
            return "MISSING - run haproxy-deploy"
        return "unknown"
    if published != installed:
        return "BEHIND the release - run haproxy-deploy"
    if reported.get("included") is False:
        return "installed, not included in keepalived.conf"
    return "in use"


def _render(envelope: dict[str, Any], writer: TextIO) -> None:
    cluster = envelope.get("cluster")
    result = envelope.get("result") or {}
    summary = result.get("summary") or {}
    target = summary.get("target")

    writer.write(f"Cluster: {cluster}\n\n")

    behind = haproxy_versions.notes(
        {
            str(node.get("name")): ((node.get("status") or {}).get("runtime") or {}).get("version")
            for node in result.get("nodes") or []
            if node.get("status_ok")
        },
        summary.get("validator_version"),
    )
    for node in result.get("nodes") or []:
        writer.write(f"{node['name']} ({node['mgmt_host']})\n")
        if not node["reachable"]:
            writer.write("  Reachable:    NO\n  Status:       UNREACHABLE\n\n")
            continue
        if not node["status_ok"]:
            writer.write("  Reachable:    YES\n  Status:       INVALID\n\n")
            continue

        status = node["status"]
        writer.write("  Reachable:    YES\n")
        writer.write(f"  HAProxy:      {'ACTIVE' if status['haproxy']['active'] else 'INACTIVE'}\n")
        writer.write(
            f"  Keepalived:   {'ACTIVE' if status['keepalived']['active'] else 'INACTIVE'}\n"
        )
        writer.write(f"  KA state:     {keepalived_state(status['keepalived']) or 'UNKNOWN'}\n")
        writer.write(f"  VIP owner:    {status['vip']['owner']}\n")
        writer.write(f"  Runtime:      {'OK' if status['stats_ok'] else 'FAILED'}\n")
        running = (status.get("runtime") or {}).get("version") or "unknown"
        note = behind.get(str(node["name"]))
        writer.write(f"  HAProxy ver:  {running}{f'  ({note})' if note else ''}\n")
        writer.write(f"  Version:      {_release_line(node)}\n")
        addresses = _addresses_line(status)
        if addresses is not None:
            writer.write(f"  Addresses:    {addresses}\n")
        writer.write("\n")

    writer.write(f"VIP state:      {summary.get('vip_state')}\n")
    owners = summary.get("vip_owners") or []
    if owners:
        writer.write(f"VIP owner:      {', '.join(owners)}\n")

    published = "none" if not target else str(target.get("version"))
    writer.write(f"Published:      {published}\n")
    state = str(summary.get("release_state", "unknown"))
    writer.write(f"Nodes:          {RELEASE_STATE_TEXT.get(state, state)}\n")
    if "validator_version" in summary:
        writer.write(f"Validator:      {summary['validator_version'] or 'unknown'} (this host)\n")

    for warning in envelope.get("warnings") or []:
        writer.write(f"WARNING: {warning['message']}\n")


def main(
    argv: list[str] | None = None,
    *,
    stream_out: TextIO | None = None,
    stream_err: TextIO | None = None,
    run_helper: RunHelper = run_status_helper,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = stream_out or sys.stdout
    errors: TextIO = stream_err or sys.stderr
    cluster_id, json_mode = _parse(argv)

    completed = run_helper(cluster_id, new_request_id())

    try:
        envelope = json.loads(completed.stdout)
    except json.JSONDecodeError:
        #
        # The helper's own stderr is shown here and nowhere else. This is the
        # one failure it cannot describe in the envelope - it never got far
        # enough to write one - and it covers the ordinary causes: no sudo rule,
        # no helper installed, an unreadable runtime policy.
        #
        errors.write(completed.stderr.strip() or "ERROR: the status helper returned no result")
        errors.write("\n")
        return completed.returncode or EXIT_UNAVAILABLE

    if json_mode:
        writer.write(json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\n")
        return completed.returncode

    try:
        #
        # Parsed before it is printed, so a malformed envelope is refused rather
        # than rendered into a status report with blanks in it. The renderer
        # below reads the raw document, but only after this has confirmed it is
        # one.
        #
        parse_status(envelope)
    except StatusError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    _render(envelope, writer)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
