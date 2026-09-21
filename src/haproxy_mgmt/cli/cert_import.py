"""`haproxy-cert-import` - a certificate issued elsewhere, into the registry and out to its targets.

Runs as root. The command line names the files and the targets; what the
material is - which block is the leaf, what the chain is, whether the key
belongs to it - is decided in `cert_import` from the files, and a pair that
does not fit leaves nothing behind. The clusters named are rolled out at the
end with the same `haproxy-cert-deploy` the certbot hook uses.

The other way in is a signing request made here (`haproxy-cert-request`,
C9b), where the key never exists anywhere but the manager; the signed
certificate then comes back through this command without `--key`. With
`--key` this is for the case where the key already exists elsewhere: a
wildcard exported from an internal CA, a purchased certificate, a pair
handed over from another system.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haproxy_mgmt.cert_import import (
    OPERATION,
    ImportError_,
    ImportResult,
    import_certificate,
    read_material,
    stored_key,
)
from haproxy_mgmt.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haproxy_mgmt.cert_publish import DEFAULT_LOCK_PATH, Deployer
from haproxy_mgmt.cli import cert_job
from haproxy_mgmt.cli.cert_publish import EXIT_NOT_ROOT, default_deployer
from haproxy_mgmt.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haproxy_mgmt.envelope import Message, envelope, failure, new_request_id
from haproxy_mgmt.helper_protocol import HelperProtocolError

EXIT_USAGE = 64

USAGE = (
    "Usage:\n"
    "  haproxy-cert-import --id <id> --certificate <pem> [--key <pem>] [--chain <pem>]\n"
    "                      [--cluster <id>]... [--receiver <id>]...\n"
    "                      [--format <id>=<form>]... [--json]\n"
    "  haproxy-cert-import --id <id> --pkcs12 <file> [--password-file <path>]\n"
    "                      [--cluster <id>]... [--receiver <id>]...\n"
    "                      [--format <id>=<form>]... [--json]\n"
    "\n"
    "Imports a certificate issued elsewhere: writes it to the import store,\n"
    "registers it, publishes it to the named targets and rolls out the named\n"
    "clusters. Runs as root. An ID already imported is replaced - the new\n"
    "material, the targets it had unless new ones are named.\n"
    "\n"
    "  --id <id>             The certificate ID; proxy objects name it. Lower-case\n"
    "                        letters, digits, dots, dashes.\n"
    "  --certificate <pem>   The leaf, or the leaf followed by its chain.\n"
    "  --key <pem>           The unencrypted private key. Omitted, the key the manager\n"
    "                        already holds for the ID is used: a signing request made\n"
    "                        here (haproxy-cert-request), or an earlier import.\n"
    "  --chain <pem>         The issuing CA certificate(s), if not in --certificate.\n"
    "  --pkcs12 <file>       Everything in one PKCS#12 (.pfx/.p12) instead.\n"
    "  --password-file <p>   A file whose first line is the PKCS#12 password.\n"
    "                        Never on the command line.\n"
    "  --cluster <id>        A cluster to publish to and roll out. May be repeated.\n"
    "  --receiver <id>       A registered receiver to publish to. May be repeated.\n"
    "  --format <id>=<form>  How that receiver is written: pem (default) or pkcs12.\n"
    "  --json                Print the result envelope on stdout.\n"
)


class Arguments:
    def __init__(self) -> None:
        self.certificate_id: str | None = None
        self.certificate: Path | None = None
        self.key: Path | None = None
        self.chain: Path | None = None
        self.pkcs12: Path | None = None
        self.password_file: Path | None = None
        self.clusters: list[str] = []
        self.receivers: list[str] = []
        self.formats: list[str] = []
        self.json_mode = False


def _parse(argv: list[str], writer: TextIO) -> Arguments:
    parsed = Arguments()
    index = 0

    def value() -> str:
        if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
        return argv[index + 1]

    paths = {
        "--certificate": "certificate",
        "--key": "key",
        "--chain": "chain",
        "--pkcs12": "pkcs12",
        "--password-file": "password_file",
    }
    while index < len(argv):
        argument = argv[index]
        if argument == "--id":
            parsed.certificate_id = value()
            index += 2
        elif argument in paths:
            setattr(parsed, paths[argument], Path(value()))
            index += 2
        elif argument == "--cluster":
            parsed.clusters.append(value())
            index += 2
        elif argument == "--receiver":
            parsed.receivers.append(value())
            index += 2
        elif argument == "--format":
            parsed.formats.append(value())
            index += 2
        elif argument == "--json":
            parsed.json_mode = True
            index += 1
        else:
            writer.write(USAGE)
            raise SystemExit(EXIT_USAGE)
    if parsed.certificate_id is None or (parsed.pkcs12 is None and parsed.certificate is None):
        writer.write(USAGE)
        raise SystemExit(EXIT_USAGE)
    return parsed


def _summary(result: ImportResult, writer: TextIO) -> None:
    names = ", ".join(result.facts.sans) or (result.facts.common_name or "?")
    verb = "replaced" if result.replaced else "imported"
    writer.write(
        f"{verb} {result.certificate_id} ({names}), issued by {result.facts.issuer}, "
        f"valid until {result.facts.not_after.isoformat(timespec='seconds')}, "
        f"chain of {result.chain_length}\n"
    )
    for entry in result.publish.certificates:
        targets = ", ".join(f"{t.kind} {t.name}" for t in entry.targets)
        writer.write(f"published: {entry.status} ({targets})\n")
    for deployment in result.publish.deployments:
        state = "ok" if deployment.exit_code == 0 else f"exit {deployment.exit_code}"
        writer.write(f"deploy {deployment.cluster}: {state}\n")


def result_envelope(result: ImportResult, *, request_id: str) -> tuple[dict[str, Any], int]:
    """`done`, or `failed` with the narrow sentence: imported and registered, not fully published."""

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
        arguments = _parse(argv, writer)
    except SystemExit as exc:
        return int(exc.code or 0)

    def refuse(code: str, message: str, exit_code: int) -> int:
        errors.write(f"ERROR: [{code}] {message}\n")
        if arguments.json_mode:
            document = failure(
                operation=OPERATION,
                cluster=None,
                request_id=request_id,
                code=code,
                message=message,
                exit_code=exit_code,
            )
            writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haproxy-cert-import must run as root", EXIT_NOT_ROOT)
    try:
        formats = cert_job.format_flags(arguments.formats, arguments.receivers)
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
        assert arguments.certificate_id is not None  # noqa: S101 - _parse required it
        material = read_material(
            certificate=arguments.certificate,
            key=arguments.key,
            chain=arguments.chain,
            pkcs12=arguments.pkcs12,
            password_file=arguments.password_file,
            stored=(
                stored_key(store, arguments.certificate_id)
                if arguments.key is None and arguments.pkcs12 is None
                else None
            ),
        )
        result = import_certificate(
            certificate_id=arguments.certificate_id,
            material=material,
            clusters=arguments.clusters,
            receivers=arguments.receivers,
            formats=formats,
            policy=policy,
            runtime=runtime,
            deployer=deployer or default_deployer(errors),
            live=live,
            store=store,
            lock_path=lock_path,
            require_secure=require_secure,
        )
    except ImportError_ as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    document, exit_code = result_envelope(result, request_id=request_id)
    if arguments.json_mode:
        writer.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    else:
        _summary(result, writer)
        if exit_code:
            errors.write(
                "ERROR: the certificate was imported and registered but not fully published\n"
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
