"""`haproxy-cert-issue` - one ACME certificate, from nothing to its targets.

Runs as root. The command line carries a domain, a method and target names;
everything certbot is told beyond that is fixed in the engine or read from
the runtime policy. The clusters named are rolled out at the end, with the
same `haproxy-cert-deploy` the certbot hook uses.

The result carries how long it took, in two numbers: certbot alone, and the
whole run. Phase 11 lives or dies on the second one being under five minutes.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_issue import Certbot, IssueError, IssueResult, issue, run_certbot
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_publish import EXIT_NOT_ROOT, default_deployer
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope, failure, new_request_id
from haproxy_mgmt.helper_protocol import HelperProtocolError

OPERATION = "cert_issue"
EXIT_USAGE = 64

USAGE = (
    "Usage:\n"
    "  haproxy-cert-issue --domain <name> --method dns-01|http-01\n"
    "                     [--dns-profile <id>] [--cluster <id>]...\n"
    "                     [--receiver <id>]... [--format <id>=<form>]... [--json]\n"
    "\n"
    "Obtains a certificate from the ACME account this host already has, adds it\n"
    "to the certificate registry, publishes it to the named targets and rolls\n"
    "out the named clusters. Runs as root.\n"
    "\n"
    "  --domain <name>       example.com, or *.example.com for a wildcard that\n"
    "                        also covers example.com. The certificate ID is the\n"
    "                        name without the asterisk.\n"
    "  --method dns-01       DNS challenge through the credential file named by\n"
    "                        acme.dns_cloudflare_credentials in the runtime policy.\n"
    "  --dns-profile <id>    Materialized provider profile for DNS-01. Omit only\n"
    "                        for the legacy Cloudflare policy credential.\n"
    "  --method http-01      HTTP challenge through acme.webroot; the name must\n"
    "                        already reach that directory over port 80. Not for\n"
    "                        wildcards.\n"
    "  --cluster <id>        A cluster to publish to and roll out. May be repeated.\n"
    "  --receiver <id>       A registered receiver to publish to. May be repeated.\n"
    "  --format <id>=<form>  How that receiver is written: pem (default) or pkcs12.\n"
    "  --json                Print the result envelope on stdout.\n"
)


def _parse(
    argv: list[str], writer: TextIO
) -> tuple[str, str, str | None, list[str], list[str], list[str], bool]:
    domain: str | None = None
    method: str | None = None
    formats: list[str] = []
    dns_profile: str | None = None
    clusters: list[str] = []
    receivers: list[str] = []
    json_mode = False
    index = 0

    def value() -> str:
        if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
        return argv[index + 1]

    while index < len(argv):
        argument = argv[index]
        if argument == "--domain":
            domain = value()
            index += 2
        elif argument == "--method":
            method = value()
            index += 2
        elif argument == "--cluster":
            clusters.append(value())
            index += 2
        elif argument == "--dns-profile":
            dns_profile = value()
            index += 2
        elif argument == "--receiver":
            receivers.append(value())
            index += 2
        elif argument == "--format":
            formats.append(value())
            index += 2
        elif argument == "--json":
            json_mode = True
            index += 1
        else:
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
    if domain is None or method is None:
        writer.write(USAGE)
        raise SystemExit(EXIT_USAGE)
    return domain, method, dns_profile, clusters, receivers, formats, json_mode


def _summary(result: IssueResult, writer: TextIO) -> None:
    writer.write(
        f"issued {result.request.certificate_id} ({', '.join(result.request.domains)}) "
        f"via {result.request.method} in {result.certbot_seconds:.0f}s\n"
    )
    for entry in result.publish.certificates:
        targets = ", ".join(f"{t.kind} {t.name}" for t in entry.targets)
        writer.write(f"published: {entry.status} ({targets})\n")
    for deployment in result.publish.deployments:
        state = "ok" if deployment.exit_code == 0 else f"exit {deployment.exit_code}"
        writer.write(f"deploy {deployment.cluster}: {state}\n")
    writer.write(f"total {result.total_seconds:.0f}s\n")


def result_envelope(result: IssueResult, *, request_id: str) -> tuple[dict[str, Any], int]:
    """One issue result, turned into the one envelope and exit code it means.

    Shared with the helper rather than written twice. The certificate exists and
    is registered by the time this is reached - certbot succeeded and the
    registry was written - so a failure here is always the narrower sentence
    "issued and registered but not fully published", never "it did not work".

    No `partial`: the run publishes exactly the certificate it just issued, and
    that one cannot be skipped for missing material.
    """

    failed_publish = result.publish.failed
    failed_deploy = [d.cluster for d in result.publish.deployments if d.exit_code != 0]
    if not failed_publish and not failed_deploy:
        return (
            envelope(
                operation=OPERATION,
                outcome="done",
                cluster=None,
                result=result.as_dict(),
                request_id=request_id,
            ),
            0,
        )
    parts = []
    if failed_publish:
        parts.append("not published: " + "; ".join(e.error[1] for e in failed_publish if e.error))
    if failed_deploy:
        parts.append("not deployed: " + ", ".join(failed_deploy))
    return (
        envelope(
            operation=OPERATION,
            outcome="failed",
            cluster=None,
            result=result.as_dict(),
            request_id=request_id,
            error=Message(code="publish_failed", message="; ".join(parts)),
        ),
        1,
    )


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    certbot: Certbot | None = None,
    deployer: Deployer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    request_id = new_request_id()

    try:
        domain, method, dns_profile, clusters, receivers, format_flags, json_mode = _parse(
            argv, writer
        )
    except SystemExit as exc:
        return int(exc.code or 0)

    def refuse(
        code: str, message: str, exit_code: int, details: dict[str, Any] | None = None
    ) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        #
        # certbot's own words, after the sentence that names the code. In JSON
        # mode they are in the document; at a terminal they would otherwise be
        # nowhere, and the operator holding the terminal is the person who
        # needs them.
        #
        diagnostics = (details or {}).get("diagnostics")
        if isinstance(diagnostics, str) and diagnostics.strip():
            errors.write(diagnostics.rstrip("\n") + "\n")
        if json_mode:
            document = failure(
                operation=OPERATION,
                cluster=None,
                request_id=request_id,
                code=code,
                message=message,
                exit_code=exit_code,
                details=details,
            )
            writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haproxy-cert-issue must run as root", EXIT_NOT_ROOT)
    try:
        formats = cert_job.format_flags(format_flags, receivers)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), EXIT_USAGE)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(
            "bad_input" if exc.exit_code == 64 else "dependency_unavailable",
            str(exc),
            exc.exit_code,
        )

    try:
        result = issue(
            domain=domain,
            method=method,
            clusters=clusters,
            receivers=receivers,
            dns_profile=dns_profile,
            formats=formats,
            policy=policy,
            runtime=runtime,
            deployer=deployer or default_deployer(errors),
            live=live,
            store=store,
            lock_path=lock_path,
            require_secure=require_secure,
            certbot=certbot or run_certbot,
        )
    except IssueError as exc:
        return refuse(exc.code, str(exc), exc.exit_code, exc.details)

    document, exit_code = result_envelope(result, request_id=request_id)

    if json_mode:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    else:
        _summary(result, writer)
        if exit_code:
            errors.write(
                "ERROR: the certificate was issued and registered but not fully published\n"
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
