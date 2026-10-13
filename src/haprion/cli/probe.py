"""`haprion-probe` - ask the nodes whether a health check would reach a pool.

The thin half. It runs as the calling user, turns arguments into a structured
request, and prints what the helper produced. It decides nothing: which nodes
are asked, and with which identity, is the helper's to know.

The question this command exists to answer
------------------------------------------
`haprion-status` says whether the nodes are healthy and `show stat` on a node
says what HAProxy currently thinks of a pool it is already serving. Neither
answers the question somebody has while writing an object: would this check,
against these servers, from this source address, actually work - before it is
published to anybody.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, TextIO

from haprion.cli.caller import usage
from haprion.digits import is_digits
from haprion.envelope import new_request_id
from haprion.health_probe import DEFAULT_TIMEOUT_MS, UDP_WAIT_MS
from haprion.probe_socket import build_request
from haprion.tls_policy import BACKEND_MIN_VERSION, DEFAULT_MIN_VERSION

HELPER = "/opt/haprion/current/bin/haprion-probe-helper"
SUDO = "/usr/bin/sudo"
OPERATION = "probe"
ALLOWED_MIN_VERSIONS = frozenset(BACKEND_MIN_VERSION.values())

USAGE = (
    "Usage:\n"
    "  haprion-probe -c <cluster> -t <host:port>[,<host:port>...] "
    "[--http <path>] [--host <name>] [--tls [--verify [--ca <id>]] [--min-version <version>]] "
    "[--source <address>] [--json]\n"
    "  haprion-probe -c <cluster> -t <address:port>[,...] --udp [--json]\n"
    "\n"
    "Examples:\n"
    "  haprion-probe -c alpha -t 198.51.100.10:8080\n"
    "  haprion-probe -c alpha -t 198.51.100.10:8443 --tls --http /healthz --json\n"
    "  haprion-probe -c alpha -t app.example.com:443 --tls --verify --ca example-ca\n"
    "  haprion-probe -c alpha -t 198.51.100.20:514 --udp\n"
)


def run_probe_helper(
    cluster_id: str,
    request_id: str,
    targets: list[dict[str, Any]],
    *,
    source: str = "",
    timeout_ms: int = 2000,
) -> subprocess.CompletedProcess[str]:
    """Ask the privileged helper to probe one cluster's pool.

    Through sudo, because a person running this command has a terminal and a
    `%sudo` rule - so sudo may ask for the password, on the terminal, as
    `haprion-cert-deploy` lets it. There is no NOPASSWD rule for this helper,
    and `-n` made the command fail for anyone without a cached sudo. The
    interface reaches the same helper over a socket instead - its account is
    built so that it cannot gain privilege at all - but both build the request
    in `build_request`, so the two cannot drift apart.
    """

    request = build_request(cluster_id, request_id, targets, source=source, timeout_ms=timeout_ms)
    return subprocess.run(  # noqa: S603 - fixed path, no caller-supplied arguments
        [SUDO, "--", HELPER],
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
    )


def _targets(
    written: str,
    *,
    path: str,
    host: str,
    tls: bool,
    verify: bool,
    min_version: str,
    ca: str = "",
    udp: bool = False,
) -> list[dict[str, Any]]:
    targets = []
    for entry in written.split(","):
        address = entry.strip()
        if not address:
            continue
        host_part, separator, port = address.rpartition(":")
        if not separator or not is_digits(port):
            usage(USAGE)
        targets.append(
            {
                #
                # A udp check's receiver is an address, and an IPv6 one may be
                # written in brackets to set its port apart.
                #
                "host": host_part.strip("[]") if udp else host_part,
                "port": int(port),
                "type": "udp" if udp else "http" if path else "tcp",
                "tls": tls,
                "verify": verify,
                "min_version": min_version,
                "path": path or "/",
                "host_header": host,
                **({"ca": ca} if ca else {}),
            }
        )
    if not targets:
        usage(USAGE)
    return targets


def _parse(argv: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {
        "cluster": "",
        "targets": "",
        "path": "",
        "host": "",
        "tls": False,
        "verify": False,
        "ca": "",
        "min_version": DEFAULT_MIN_VERSION,
        "source": "",
        "udp": False,
        "json": False,
    }
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in ("-c", "--cluster") and index + 1 < len(argv):
            options["cluster"] = argv[index + 1]
            index += 2
        elif argument in ("-t", "--targets") and index + 1 < len(argv):
            options["targets"] = argv[index + 1]
            index += 2
        elif argument == "--http" and index + 1 < len(argv):
            options["path"] = argv[index + 1]
            index += 2
        elif argument == "--host" and index + 1 < len(argv):
            options["host"] = argv[index + 1]
            index += 2
        elif argument == "--source" and index + 1 < len(argv):
            options["source"] = argv[index + 1]
            index += 2
        elif argument == "--tls":
            options["tls"] = True
            index += 1
        elif argument == "--verify":
            options["verify"] = True
            index += 1
        #
        # A pool verified against a CA imported under Certificates (B276). The
        # helper reads the manager's copy and sends it with the request, as it
        # does for the form's test; without it the node checks against its own
        # trust store and calls a healthy pool down.
        #
        elif argument == "--ca" and index + 1 < len(argv):
            options["ca"] = argv[index + 1]
            index += 2
        #
        # keepalived's check on a syslog pool (Fas 19b B5): a datagram, and a
        # refusal back or none. Nothing else of a check applies to it.
        #
        elif argument == "--udp":
            options["udp"] = True
            index += 1
        #
        # The same floor an object may name, so the command a person runs and
        # the button in the form ask the nodes the same question. A pool the
        # interface reports as reachable and the command reports as down would
        # be the two implementations disagreeing about the pool.
        #
        elif argument == "--min-version" and index + 1 < len(argv):
            asked = argv[index + 1]
            if asked not in ALLOWED_MIN_VERSIONS:
                usage(USAGE)
            options["min_version"] = asked
            index += 2
        elif argument == "--json":
            options["json"] = True
            index += 1
        else:
            usage(USAGE)
    if not options["cluster"] or not options["targets"]:
        usage(USAGE)
    if options["udp"] and (options["path"] or options["host"] or options["tls"]):
        usage(USAGE)
    if options["ca"] and not (options["tls"] and options["verify"]):
        usage(USAGE)
    return options


def _render(envelope: dict[str, Any], writer: TextIO) -> None:
    result = envelope.get("result") or {}
    source = result.get("source")
    writer.write(f"Cluster: {envelope.get('cluster')}\n")
    writer.write(f"From:    {source or 'the node itself'}\n\n")

    for node in result.get("nodes") or []:
        writer.write(f"{node.get('node')}\n")
        if not node.get("reachable"):
            writer.write(f"  UNREACHABLE   {node.get('error') or ''}\n\n")
            continue
        if node.get("error"):
            writer.write(f"  REFUSED       {node['error']}\n\n")
            continue
        #
        # Said, not left blank. This node carries no results because it does not
        # hold the address the object leaves from, and a bare node name with
        # nothing under it reads as a node that answered about an empty pool.
        #
        if node.get("source_held") is False:
            writer.write(f"  NOT HERE      does not hold {source or 'the source address'}\n\n")
            continue
        for entry in node.get("results") or []:
            verdict = "OK    " if entry.get("ok") else "FAILED"
            detail = entry.get("error") or (
                f"status {entry['status']}" if entry.get("status") else ""
            )
            timing = f"{entry['ms']} ms" if entry.get("ms") is not None else ""
            writer.write(
                f"  {verdict}  {entry.get('host')}:{entry.get('port')}   {detail}   {timing}\n"
            )
        writer.write("\n")


def main(argv: list[str] | None = None, *, writer: TextIO | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out: TextIO = writer or sys.stdout
    options = _parse(argv)

    completed = run_probe_helper(
        options["cluster"],
        new_request_id(),
        _targets(
            options["targets"],
            path=options["path"],
            host=options["host"],
            tls=options["tls"],
            verify=options["verify"],
            min_version=options["min_version"],
            ca=options["ca"],
            udp=options["udp"],
        ),
        source=options["source"],
        timeout_ms=UDP_WAIT_MS if options["udp"] else DEFAULT_TIMEOUT_MS,
    )
    if not completed.stdout.strip():
        sys.stderr.write(completed.stderr or "ERROR: the helper produced no answer\n")
        return completed.returncode or 70
    try:
        envelope = json.loads(completed.stdout)
    except ValueError:
        sys.stderr.write("ERROR: the helper did not answer with JSON\n")
        return 70

    if options["json"]:
        out.write(json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\n")
        return completed.returncode

    error = envelope.get("error")
    if error:
        sys.stderr.write(f"ERROR: [{error.get('code')}] {error.get('message')}\n")
        return completed.returncode
    _render(envelope, out)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
