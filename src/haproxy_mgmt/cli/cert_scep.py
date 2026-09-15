"""Root CLI for NDES enrollment through a materialized provider profile."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import TextIO

from haproxy_mgmt import cert_import, ndes, ndes_profiles
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer
from haproxy_mgmt.cli.cert_import import result_envelope
from haproxy_mgmt.cli.cert_publish import default_deployer
from haproxy_mgmt.config import (
    CERTIFICATE_ID,
    DEFAULT_POLICY_PATH,
    ConfigError,
    load_policy,
    load_runtime_config,
)
from haproxy_mgmt.dns_profiles import ProfileError
from haproxy_mgmt.envelope import Message, envelope, failure, new_request_id

OPERATION = "cert_scep"


def main(
    argv: list[str] | None = None,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    output_stream: TextIO | None = None,
    error_stream: TextIO | None = None,
    require_secure: bool = True,
    require_root: bool = True,
    deployer: Deployer | None = None,
    live: Path = LETSENCRYPT_LIVE,
    store: Path = IMPORT_STORE,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> int:
    writer = output_stream or sys.stdout
    errors = error_stream or sys.stderr
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument(
        "--domain",
        required=True,
        action="append",
        help="primary CN first, then additional DNS SANs",
    )
    parser.add_argument("--cluster", action="append", default=[])
    parser.add_argument("--receiver", action="append", default=[])
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    request_id = new_request_id()

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        if args.json:
            writer.write(
                json.dumps(
                    failure(
                        operation=OPERATION,
                        cluster=None,
                        request_id=request_id,
                        code=code,
                        message=message,
                        exit_code=exit_code,
                    )
                )
                + "\n"
            )
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haproxy-cert-scep must run as root", 77)
    try:
        if not CERTIFICATE_ID.fullmatch(args.id):
            return refuse("bad_input", "invalid certificate ID", 65)
        domains = ndes.names(args.domain)
        policy = load_policy(policy_path, require_secure=require_secure)
        if policy.ndes is None or policy.certificate_registry is None:
            return refuse(
                "dependency_unavailable",
                "NDES policy and certificate registry must be configured",
                78,
            )
        runtime = load_runtime_config(policy, require_secure=require_secure)
        if any(name not in runtime.clusters for name in args.cluster):
            return refuse("bad_input", "unknown target cluster", 65)
        if runtime.registry is None or any(
            name not in runtime.registry.receivers for name in args.receiver
        ):
            return refuse("bad_input", "certificate registry or target receiver is unavailable", 65)
        existing = runtime.registry.certificates.get(args.id)
        if existing is not None and existing.source.kind != "import":
            return refuse("bad_input", "certificate ID already belongs to another source kind", 65)
        if (live / args.id).exists():
            return refuse("bad_input", "certificate ID already belongs to an ACME lineage", 65)
        profile = ndes_profiles.resolve(policy.ndes, args.profile, require_secure=require_secure)
        with ndes.enroll(
            policy.ndes,
            certificate_id=args.id,
            profile=profile,
            domains=domains,
            resume=args.resume,
            require_secure=require_secure,
        ) as enrolled:
            if enrolled.state == "pending":
                doc = envelope(
                    operation=OPERATION,
                    outcome="partial",
                    cluster=None,
                    request_id=request_id,
                    result={
                        "id": args.id,
                        "profile": profile.profile_id,
                        "domains": list(domains),
                        "state": "pending",
                    },
                    warnings=(
                        Message(
                            code="request_pending",
                            message="CA approval is pending; resume the same request to retain its key",
                        ),
                    ),
                )
                exit_code = 0
            else:
                if enrolled.material is None:
                    raise ndes.NdesError(
                        "scep_failed", "issued request has no certificate material", exit_code=1
                    )
                ndes.validate_certificate(enrolled.material, domains, enrolled.directory)
                imported = cert_import.import_certificate(
                    certificate_id=args.id,
                    material=enrolled.material,
                    clusters=args.cluster,
                    receivers=args.receiver,
                    policy=policy,
                    runtime=runtime,
                    deployer=deployer or default_deployer(errors),
                    live=live,
                    store=store,
                    lock_path=lock_path,
                    require_secure=require_secure,
                )
                doc, exit_code = result_envelope(imported, request_id=request_id)
                doc["operation"] = OPERATION
                doc["result"] = {
                    "id": args.id,
                    "profile": profile.profile_id,
                    "domains": list(domains),
                    "state": "issued",
                    "publication": doc["result"],
                }
                if exit_code == 0:
                    shutil.rmtree(enrolled.directory)
    except ConfigError as exc:
        return refuse("dependency_unavailable", str(exc), exc.exit_code)
    except ProfileError as exc:
        return refuse("profile_unavailable", str(exc), 78)
    except (ndes.NdesError, cert_import.ImportError_) as exc:
        return refuse(exc.code, str(exc), exc.exit_code)
    if args.json:
        writer.write(json.dumps(doc, separators=(",", ":")) + "\n")
    else:
        writer.write(f"{args.id}: {doc['result']['state']}\n")
        if exit_code:
            errors.write(
                "ERROR: issued and imported, but publication or deployment did not finish\n"
            )
    return exit_code
