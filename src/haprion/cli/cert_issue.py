"""`haprion-cert-issue` - one ACME certificate, from nothing to its targets.

Runs as root. The command line carries a domain, a method and target names;
everything certbot is told beyond that is fixed in the engine or read from
the runtime policy. The clusters named are rolled out at the end, with the
same `haprion-cert-deploy` the certbot hook uses.

The result carries how long it took, in two numbers: certbot alone, and the
whole run. Phase 11 lives or dies on the second one being under five minutes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes, ui_interface
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_issue import (
    Certbot,
    IssueError,
    IssueResult,
    adopt,
    issue,
    renew,
    run_certbot,
)
from haprion.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haprion.cli import cert_job
from haprion.cli.cert_publish import default_deployer
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import Message, envelope, failure, new_request_id
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document

OPERATION = "cert_issue"
RENEW = "renew"
ADOPT = "adopt"

USAGE = (
    "Usage:\n"
    "  haprion-cert-issue --domain <name> --method dns-01|http-01\n"
    "                     [--dns-profile <id>] [--cluster <id>]...\n"
    "                     [--receiver <id>]... [--format <id>=<form>]...\n"
    "                     [--interface | --exportable] [--json]\n"
    "  haprion-cert-issue --domain <certificate id> --renew [--json]\n"
    "  haprion-cert-issue --domain <lineage> --adopt [--cluster <id>]...\n"
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
    "  --interface           This manager's own interface certificate: no targets,\n"
    "                        installed with haprion-tls. Takes the mark from the\n"
    "                        one that had it, which is deleted once this one serves.\n"
    "  --exportable          For a device never connected to this manager: one name,\n"
    "                        no targets, an RSA key that may be exported from the\n"
    "                        interface.\n"
    "  --adopt               Register a lineage certbot already has under that name,\n"
    "                        with its targets, and publish it. Nothing is issued;\n"
    "                        it renews with its own renewal configuration.\n"
    "  --json                Print the result envelope on stdout.\n"
)


def _parse(
    argv: list[str], writer: TextIO
) -> tuple[str, str, str | None, list[str], list[str], list[str], bool, bool, bool]:
    domain: str | None = None
    method: str | None = None
    formats: list[str] = []
    dns_profile: str | None = None
    clusters: list[str] = []
    receivers: list[str] = []
    json_mode = False
    interface = False
    exportable = False
    index = 0

    def value() -> str:
        if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
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
        elif argument == "--renew":
            #
            # What *Renew* on the certificates page queues for a certbot row:
            # the whole round again, now, for a lineage the registry holds.
            #
            method = RENEW
            index += 1
        elif argument == "--adopt":
            method = ADOPT
            index += 1
        elif argument == "--interface":
            interface = True
            index += 1
        elif argument == "--exportable":
            exportable = True
            index += 1
        else:
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
    if domain is None or method is None:
        writer.write(USAGE)
        raise SystemExit(exit_codes.USAGE)
    return (
        domain,
        method,
        dns_profile,
        clusters,
        receivers,
        formats,
        json_mode,
        interface,
        exportable,
    )


def _summary(result: IssueResult, writer: TextIO) -> None:
    if result.adopted:
        writer.write(
            f"registered {result.request.certificate_id} ({', '.join(result.request.domains)}) "
            "from certbot's lineage; nothing was issued\n"
        )
    else:
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

    #
    # Said in both answers: a note of what is due that could not be written
    # (`pending_unrecorded`) was lost on the way here (review 26-10-24, 13-06).
    #
    warnings = tuple(
        Message(code=code, message=message) for code, message in result.publish.warnings
    )
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
                warnings=warnings,
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
            warnings=warnings,
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
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr
    request_id = new_request_id()

    try:
        (
            domain,
            method,
            dns_profile,
            clusters,
            receivers,
            format_flags,
            json_mode,
            interface,
            exportable,
        ) = _parse(argv, writer)
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
            write_document(writer, document, exit_code)
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-cert-issue must run as root", exit_codes.NOT_ROOT)
    try:
        formats = cert_job.format_flags(format_flags, receivers)
    except HelperProtocolError as exc:
        return refuse("bad_input", str(exc), exit_codes.USAGE)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(
            config_error_code(exc.exit_code),
            str(exc),
            exc.exit_code,
        )

    if method == RENEW:
        if dns_profile or clusters or receivers or format_flags or interface or exportable:
            return refuse(
                "bad_input", "a renewal names the certificate and nothing else", exit_codes.USAGE
            )
        try:
            renewed = renew(
                certificate_id=domain,
                policy=policy,
                runtime=runtime,
                certbot=certbot or run_certbot,
                deployer=deployer or default_deployer(errors),
                installer=installer or ui_interface.install,
                live=live,
                store=store,
                lock_path=lock_path,
                require_secure=require_secure,
            )
        except IssueError as exc:
            return refuse(exc.code, str(exc), exc.exit_code, exc.details)
        return _answer(renewed, request_id, json_mode=json_mode, writer=writer, errors=errors)

    if method == ADOPT:
        if dns_profile or interface or exportable:
            return refuse(
                "bad_input",
                "a lineage is registered with its targets only; it renews as certbot has it",
                exit_codes.USAGE,
            )
        try:
            adopted = adopt(
                certificate_id=domain,
                clusters=clusters,
                receivers=receivers,
                formats=formats,
                policy=policy,
                runtime=runtime,
                deployer=deployer or default_deployer(errors),
                installer=installer or ui_interface.install,
                live=live,
                store=store,
                lock_path=lock_path,
                require_secure=require_secure,
            )
        except IssueError as exc:
            return refuse(exc.code, str(exc), exc.exit_code, exc.details)
        return _answer(adopted, request_id, json_mode=json_mode, writer=writer, errors=errors)

    try:
        result = issue(
            domain=domain,
            method=method,
            clusters=clusters,
            receivers=receivers,
            dns_profile=dns_profile,
            formats=formats,
            interface=interface,
            exportable=exportable,
            policy=policy,
            runtime=runtime,
            deployer=deployer or default_deployer(errors),
            # Root at a terminal, outside any sandbox: installed directly.
            installer=installer or ui_interface.install,
            live=live,
            store=store,
            lock_path=lock_path,
            require_secure=require_secure,
            certbot=certbot or run_certbot,
        )
    except IssueError as exc:
        return refuse(exc.code, str(exc), exc.exit_code, exc.details)

    return _answer(result, request_id, json_mode=json_mode, writer=writer, errors=errors)


def _answer(
    result: IssueResult, request_id: str, *, json_mode: bool, writer: TextIO, errors: TextIO
) -> int:
    document, exit_code = result_envelope(result, request_id=request_id)
    if json_mode:
        write_document(writer, document, exit_code)
    else:
        _summary(result, writer)
        if exit_code:
            errors.write(
                "ERROR: the certificate was issued and registered but not fully published\n"
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
