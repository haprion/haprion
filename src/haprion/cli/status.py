"""`haprion-status` - what the nodes are doing, and whether they run what you published.

The thin half. It runs as the calling user, checks the arguments, and hands a
structured request to the root helper. It decides nothing about the cluster: the
document it prints is the one the helper produced.

The question this command exists to answer
------------------------------------------
`haprion-config-status` answers "what is published, and what have I not sent
yet", which is a question about the manager. This one answers "are the nodes
healthy", which is a question about the nodes. Between them sat a third question
that neither answered - *do the nodes run what is published* - and the only way
to find out was to start `haprion-deploy` and read what it decided to skip.
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

from haprion import haproxy_versions, log_forwarding, node_package, node_resources
from haprion.cli.caller import usage, without_answer
from haprion.cluster_status import (
    StatusError,
    ahead_of,
    ahead_words,
    forwarding_current,
    keepalived_state,
    parse_status,
    release_complete,
    traffic_stream_problem,
    traffic_stream_unguarded,
)
from haprion.envelope import new_request_id
from haprion.helper_protocol import write_document
from haprion.status_collect import OPERATION

HELPER = "/opt/haprion/current/bin/haprion-status-helper"
SUDO = "/usr/bin/sudo"

USAGE = (
    "Usage:\n"
    "  haprion-status -c <cluster> [--json]\n"
    "\n"
    "Examples:\n"
    "  haprion-status -c alpha\n"
    "  haprion-status -c beta --json\n"
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


def _release_line(node: dict[str, Any], published: object = None) -> str:
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
    if current is False and (ahead := ahead_of(status, published)) is not None:
        return f"{shown}   AHEAD - {ahead_words(*ahead)}"
    if current is False:
        return f"{shown}   BEHIND - run haprion-deploy"
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
            return "MISSING - run haprion-deploy"
        return "unknown"
    if published != installed:
        return "BEHIND the release - run haprion-deploy"
    if reported.get("included") is False:
        return "installed, not included in keepalived.conf"
    return "in use"


def _ipvs_line(status: dict[str, Any]) -> str | None:
    """The syslog objects' IPVS virtual servers on this node (B256), or None from an older node.

    The address list's reading, plus what only this file has: whether
    `ipvsadm` is there to count with, and how many virtual servers the kernel
    holds.
    """

    reported = status.get("ipvs")
    if not isinstance(reported, dict):
        return None
    if reported.get("published") is False:
        return "not managed from here"
    published = reported.get("published_sha256")
    installed = reported.get("installed_sha256")
    if not isinstance(published, str) or not isinstance(installed, str):
        if reported.get("installed") is False:
            return "MISSING - run haprion-deploy"
        return "unknown"
    if published != installed:
        return "BEHIND the release - run haprion-deploy"
    if reported.get("included") is False:
        servers = reported.get("published_servers")
        if isinstance(servers, int) and not isinstance(servers, bool) and servers > 0:
            return (
                f"NOT FORWARDING {servers} virtual server{'' if servers == 1 else 's'} - "
                "keepalived.conf does not include the file at its top level"
            )
        return "installed, not included at the top of keepalived.conf"
    if reported.get("included") is not True:
        return "installed, include unknown"
    services = reported.get("services")
    if reported.get("ipvsadm") is not True or not isinstance(services, list):
        return "in use, not counted (ipvsadm missing or failed)"
    return f"in use, {len(services)} virtual server{'' if len(services) == 1 else 's'}"


def _forward_file_line(status: dict[str, Any]) -> str | None:
    """The log forwarding file, only when it is the half that is behind (review 26-10-13, A1).

    Without it a node whose version says BEHIND while matching the published
    version is unexplainable here. When the file is where it should be the
    `Log forward:` line already says where the node sends.
    """

    if forwarding_current(status) is not False:
        return None
    reported = status["forward_file"]
    if reported.get("published") is False:
        return "LEFT BEHIND - this release forwards nowhere; run haprion-deploy"
    if reported.get("installed") is False:
        return "MISSING - run haprion-deploy"
    return "BEHIND the release - run haprion-deploy"


def _node_package_line(installation: object, carried: object) -> str | None:
    """The node's haprion-node, read against the one this host's release carries (26-10-29).

    None for a node that reports no version while this host names none: there
    is nothing to say about it.
    """

    reported = installation.get("version") if isinstance(installation, dict) else None
    shown = node_package.short_version(reported) if isinstance(reported, str) else None
    standing = haproxy_versions.node_package_standing(installation, carried)
    if standing is None:
        if isinstance(installation, dict) and "version" in installation and reported is None:
            return "not installed"
        return shown
    if standing.kind == "not configured":
        return f"{shown}  NOT CONFIGURED - {haproxy_versions.CONFIGURE_ON_THE_NODE}"
    words = "OLDER" if standing.kind == "older" else "NEWER"
    said = f"{words} than this host's {node_package.short_version(str(carried))}"
    if standing.kind == "older":
        said += f" - {haproxy_versions.UPGRADE_ON_THE_NODE}"
    return f"{shown}  {said}" if shown else said


def _waf_engine_line(engine: object, published: object) -> str | None:
    """The node's WAF engine, read against whether the release has rules (review 2026-10-04 F3).

    Stopped is only a fault where the published release carries rules; on a
    cluster without them the engine is meant to be off, and says so.
    """

    if not isinstance(engine, dict):
        return None
    version = engine.get("version")
    if not isinstance(version, str):
        return "not installed"
    if engine.get("active") is True:
        return f"ACTIVE ({version})"
    if published is False:
        return f"not in use ({version})"
    return f"STOPPED ({version})"


def _dns_listener_line(listener: object, published: object) -> str | None:
    """The node's dnsdist, read against whether the release has a dns listener (B249)."""

    return _waf_engine_line(listener, published)


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
        {
            str(node.get("name")): (node.get("status") or {}).get("packages")
            for node in result.get("nodes") or []
            if node.get("status_ok")
        },
    )
    for node in result.get("nodes") or []:
        writer.write(f"{node['name']} ({node['mgmt_host']})\n")
        if not node["reachable"]:
            writer.write("  Reachable:    NO\n  Status:       UNREACHABLE\n\n")
            continue
        if not node["status_ok"]:
            writer.write("  Reachable:    YES\n  Status:       INVALID\n")
            error = node.get("error") or {}
            if error.get("message"):
                writer.write(f"  Reason:       {error['message']}\n")
            for line in str((error.get("details") or {}).get("stderr") or "").splitlines():
                writer.write(f"    {line}\n")
            writer.write("\n")
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
        writer.write(f"  Version:      {_release_line(node, (target or {}).get('version'))}\n")
        package = _node_package_line(
            status.get("installation"), summary.get("node_package_version")
        )
        if package is not None:
            writer.write(f"  Node package: {package}\n")
        addresses = _addresses_line(status)
        if addresses is not None:
            writer.write(f"  Addresses:    {addresses}\n")
        resources = status.get("resources")
        if isinstance(resources, dict):
            writer.write(f"  Memory:       {node_resources.memory_line(resources)}\n")
            writer.write(f"  Load:         {node_resources.load_line(resources)}\n")
        engine = _waf_engine_line(status.get("waf_engine"), summary.get("waf_published"))
        if engine is not None:
            writer.write(f"  WAF engine:   {engine}\n")
        listener = _dns_listener_line(status.get("dns_listener"), summary.get("dns_published"))
        if listener is not None:
            writer.write(f"  DNS listener: {listener}\n")
        ipvs = _ipvs_line(status)
        if ipvs is not None:
            writer.write(f"  Syslog IPVS:  {ipvs}\n")
        forward_file = _forward_file_line(status)
        if forward_file is not None:
            writer.write(f"  Forward file: {forward_file}\n")
        if release_complete(status) is False:
            writer.write(
                "  Release:      INCOMPLETE - a step after the reload failed; run haprion-deploy\n"
            )
        dropped = traffic_stream_problem(status)
        if dropped is not None:
            writer.write(f"  Traffic log:  DROPPED - {dropped}\n")
        unguarded = traffic_stream_unguarded(status)
        if unguarded is not None:
            writer.write(f"  Traffic log:  UNGUARDED - {unguarded}\n")
        forwarding = log_forwarding.status_line(status.get("log_forwarding"))
        if forwarding is not None:
            writer.write(f"  Log forward:  {forwarding}\n")
        #
        # Said only when there is something to do, as the interface's
        # Needs attention says it (B363).
        #
        preparation = status.get("preparation")
        if isinstance(preparation, dict) and preparation.get("current") is False:
            writer.write("  Preparation:  CHANGED - run  sudo haprion-node-prepare  on the node\n")
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
        # The one failure the helper cannot describe in its envelope - it
        # never got far enough to write one.
        #
        return without_answer(
            completed,
            operation=OPERATION,
            cluster=cluster_id,
            json_mode=json_mode,
            writer=writer,
            errors=errors,
            fallback="the status helper returned no result",
        )

    if json_mode:
        return write_document(writer, envelope, completed.returncode)

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
