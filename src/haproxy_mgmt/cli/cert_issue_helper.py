"""The privileged half of `haprion-cert-issue` - one ACME certificate, from a job.

Calls the same `issue` the terminal command calls, so the five-minute gate C3
measured is the same code path the interface will use. What this half adds is
the boundary: a bounded request in, one envelope out, and no way to name a
file, a directory, an account or a certbot flag.

What the caller may decide: a domain, a challenge method, and targets that the
registry already knows. Everything certbot is told beyond that is fixed in the
engine or read from the runtime policy.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from haproxy_mgmt import dns_profiles, ui_interface
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_issue import (
    RENEWAL_DIRECTORY,
    Certbot,
    IssueError,
    issue,
    renew,
    run_certbot,
)
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_issue import result_envelope
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.helper_protocol import (
    HelperProtocolError,
    config_error_code,
    write_document,
)

OPERATION = "cert_issue"
PARAMETERS = frozenset(
    {
        "domain",
        "method",
        "clusters",
        "receivers",
        "formats",
        "dns_profile",
        "renew",
        "interface",
        "exportable",
    }
)
MAX_DOMAIN_BYTES = 255
HELPER = "/opt/haprion/current/bin/haprion-cert-issue-helper"
SUDO = "/usr/bin/sudo"


def build_request(
    request_id: str,
    *,
    domain: str,
    method: str,
    clusters: tuple[str, ...] = (),
    receivers: tuple[str, ...] = (),
    formats: Mapping[str, str] | None = None,
    dns_profile: str | None = None,
    renew: bool = False,
    interface: bool = False,
    exportable: bool = False,
) -> str:
    """The exact bounded request the worker sends. Null cluster, by contract.

    A renewal (C9c) names the certificate and nothing else: the lineage, its
    names, its challenge and its targets are what the registry and certbot
    already hold, and the helper reads them there.
    """

    if renew:
        parameters: dict[str, Any] = {"domain": domain, "renew": True}
    else:
        parameters = {
            "domain": domain,
            "method": method,
            "clusters": list(clusters),
            "receivers": list(receivers),
            "dns_profile": dns_profile,
        }
        if formats:
            parameters["formats"] = dict(formats)
        if interface:
            parameters["interface"] = True
        if exportable:
            parameters["exportable"] = True
    return json.dumps(
        {
            "schema_version": 1,
            "operation": OPERATION,
            "cluster": None,
            "request_id": request_id,
            "parameters": parameters,
        },
        separators=(",", ":"),
    )


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    input_stream: BinaryIO | None = None,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    certbot: Certbot = run_certbot,
    deployer: Deployer | None = None,
    installer: Installer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
    renewal_directory: Path = RENEWAL_DIRECTORY,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    writer: TextIO = output_stream or sys.stdout
    errors: TextIO = error_stream or sys.stderr

    try:
        request = cert_job.read_request(
            OPERATION,
            parameters=PARAMETERS,
            input_stream=input_stream,
            argv=argv,
            require_root=require_root,
            helper_name="haprion-cert-issue-helper",
        )
    except HelperProtocolError as exc:
        errors.write(f"ERROR: {exc}\n")
        return exc.exit_code

    refuse = cert_job.Refuse(OPERATION, request, writer, errors)
    try:
        domain = request.parameters.get("domain")
        if (
            not isinstance(domain, str)
            or not domain
            or len(domain.encode("utf-8")) > MAX_DOMAIN_BYTES
        ):
            raise HelperProtocolError("parameters.domain must be a domain name", exit_code=65)
        renew_flag = request.parameters.get("renew", False)
        if not isinstance(renew_flag, bool):
            raise HelperProtocolError("parameters.renew must be true or false", exit_code=65)
        if renew_flag and set(request.parameters) - {"domain", "renew"}:
            raise HelperProtocolError(
                "a renewal names the certificate and nothing else", exit_code=65
            )
        method = request.parameters.get("method", "renew" if renew_flag else None)
        if not isinstance(method, str) or not method:
            raise HelperProtocolError("parameters.method must be a string", exit_code=65)
        clusters = cert_job.clusters(request.parameters)
        receivers = cert_job.receivers(request.parameters)
        formats = cert_job.formats(request.parameters, receivers)
        interface = cert_job.interface(request.parameters)
        exportable = cert_job.exportable(request.parameters)
        dns_profile_value = request.parameters.get("dns_profile")
        dns_profile = None
        if dns_profile_value is not None:
            dns_profile = dns_profiles.check_profile_id(dns_profile_value)
    except (HelperProtocolError, dns_profiles.ProfileError) as exc:
        return refuse("bad_input", str(exc), 65)

    try:
        policy = load_policy(policy_path, require_secure=require_secure)
        runtime = load_runtime_config(policy, require_secure=require_secure)
    except ConfigError as exc:
        return refuse(config_error_code(exc.exit_code), str(exc), exc.exit_code)

    #
    # Rolled out at the end, with the same `haprion-cert-deploy` the hook uses.
    # A certificate that is published but not deployed is one the nodes do not
    # have, and the gate this phase lives or dies on is measured from the click
    # to a certificate that actually answers.
    #
    #
    # Inside the worker's sandbox, so the interface certificate (B188) is
    # installed by the root service on its socket, not here.
    #
    install = installer if installer is not None else ui_interface.socket_installer()
    try:
        if renew_flag:
            result = renew(
                certificate_id=domain,
                policy=policy,
                runtime=runtime,
                certbot=certbot,
                deployer=deployer if deployer is not None else default_deployer(errors),
                installer=install,
                live=live,
                store=store,
                lock_path=lock_path,
                renewal_directory=renewal_directory,
                require_secure=require_secure,
            )
        else:
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
                certbot=certbot,
                deployer=deployer if deployer is not None else default_deployer(errors),
                installer=install,
                live=live,
                store=store,
                lock_path=lock_path,
                require_secure=require_secure,
            )
    except IssueError as exc:
        return refuse(exc.code, str(exc), exc.exit_code, exc.details)

    document, exit_code = result_envelope(result, request_id=request.request_id)
    write_document(writer, document)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
