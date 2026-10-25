"""`haprion-cert-import` - a certificate issued elsewhere, into the registry and out to its targets.

Runs as root. The command line names the files and the targets; what the
material is - which block is the leaf, what the chain is, whether the key
belongs to it - is decided in `cert_import` from the files, and a pair that
does not fit leaves nothing behind. The clusters named are rolled out at the
end with the same `haprion-cert-deploy` the certbot hook uses.

The other way in is a signing request made here (`haprion-cert-request`,
C9b), where the key never exists anywhere but the manager; the signed
certificate then comes back through this command without `--key`. With
`--key` this is for the case where the key already exists elsewhere: a
wildcard exported from an internal CA, a purchased certificate, a pair
handed over from another system.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, TextIO

from haprion import exit_codes, labels, ui_interface
from haprion.cert_import import (
    OPERATION,
    ImportError_,
    ImportResult,
    import_authority,
    import_certificate,
    read_authority_file,
    read_material,
    stored_key,
)
from haprion.cert_inventory import IMPORT_STORE, LETSENCRYPT_LIVE
from haprion.cert_publish import DEFAULT_LOCK_PATH, Deployer, Installer
from haprion.cli import cert_job
from haprion.cli.cert_publish import default_deployer
from haprion.config import DEFAULT_POLICY_PATH, ConfigError, load_policy, load_runtime_config
from haprion.envelope import Message, envelope, failure, new_request_id
from haprion.helper_protocol import HelperProtocolError, config_error_code, write_document

USAGE = (
    "Usage:\n"
    "  haprion-cert-import --id <id> --certificate <pem> [--key <pem>] [--chain <pem>]\n"
    "                      [--cluster <id>]... [--receiver <id>]...\n"
    "                      [--format <id>=<form>]... [--interface] [--json]\n"
    "  haprion-cert-import --id <id> --pkcs12 <file> [--password-file <path>]\n"
    "                      [--cluster <id>]... [--receiver <id>]...\n"
    "                      [--format <id>=<form>]... [--interface] [--json]\n"
    "  haprion-cert-import --id <id> (--authority <file> | --ndes-ca)\n"
    "                      [--cluster <id>]... [--json]\n"
    "\n"
    "Imports a certificate issued elsewhere: writes it to the import store,\n"
    "registers it, publishes it to the named targets and rolls out the named\n"
    "clusters. Runs as root. An ID already imported is replaced - the new\n"
    "material, the targets it had and any named now added to them.\n"
    "\n"
    "  --id <id>             The certificate ID; proxy objects name it. Lower-case\n"
    "                        letters, digits, dots, dashes.\n"
    "  --certificate <pem>   The leaf, or the leaf followed by its chain.\n"
    "  --key <pem>           The unencrypted private key. Omitted, the key the manager\n"
    "                        already holds for the ID is used: a signing request made\n"
    "                        here (haprion-cert-request), or an earlier import.\n"
    "  --chain <pem>         The issuing CA certificates, if not in --certificate.\n"
    "  --pkcs12 <file>       Everything in one PKCS#12 (.pfx/.p12) instead.\n"
    "  --password-file <p>   A file whose first line is the PKCS#12 password.\n"
    "                        Never on the command line.\n"
    "  --cluster <id>        A cluster to publish to and roll out. May be repeated.\n"
    "  --receiver <id>       A registered receiver to publish to. May be repeated.\n"
    "  --format <id>=<form>  How that receiver is written: pem (default) or pkcs12.\n"
    "  --interface           This manager's own interface certificate: no targets,\n"
    "                        installed with haprion-tls. Takes the mark from the\n"
    "                        one that had it, which is deleted once this one serves.\n"
    "  --authority <file>    A CA certificate - or several, a root and its\n"
    "                        intermediates - without a key, for the clusters' pools to\n"
    "                        verify their servers against (tls verify: ca).\n"
    "  --ndes-ca             The same, from the NDES issuing CA the runtime policy names.\n"
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
        self.interface = False
        self.authority: Path | None = None
        self.ndes_ca = False


def _parse(argv: list[str], writer: TextIO) -> Arguments:
    parsed = Arguments()
    index = 0

    def value() -> str:
        if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
        return argv[index + 1]

    paths = {
        "--certificate": "certificate",
        "--key": "key",
        "--chain": "chain",
        "--pkcs12": "pkcs12",
        "--password-file": "password_file",
        "--authority": "authority",
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
        elif argument == "--interface":
            parsed.interface = True
            index += 1
        elif argument == "--ndes-ca":
            parsed.ndes_ca = True
            index += 1
        else:
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
    if parsed.authority is not None or parsed.ndes_ca:
        #
        # A CA file goes to clusters and nowhere else, and carries nothing
        # but itself (B276).
        #
        others = (
            parsed.certificate,
            parsed.key,
            parsed.chain,
            parsed.pkcs12,
            parsed.password_file,
        )
        if (
            parsed.certificate_id is None
            or (parsed.authority is not None and parsed.ndes_ca)
            or any(item is not None for item in others)
            or parsed.receivers
            or parsed.formats
            or parsed.interface
        ):
            writer.write(USAGE)
            raise SystemExit(exit_codes.USAGE)
        return parsed
    if parsed.certificate_id is None or (parsed.pkcs12 is None and parsed.certificate is None):
        writer.write(USAGE)
        raise SystemExit(exit_codes.USAGE)
    return parsed


def _summary(result: ImportResult, writer: TextIO) -> None:
    if result.authority:
        verb = "replaced" if result.replaced else "imported"
        writer.write(
            f"{verb} CA {result.certificate_id} ({result.facts.subject}), "
            f"{labels.counted(result.chain_length + 1, 'certificate')}, first valid until "
            f"{result.facts.not_after.isoformat(timespec='seconds')}\n"
        )
        for entry in result.publish.certificates:
            targets = ", ".join(f"{t.kind} {t.name}" for t in entry.targets)
            writer.write(f"published: {entry.status} ({targets})\n")
        for deployment in result.publish.deployments:
            state = "ok" if deployment.exit_code == 0 else f"exit {deployment.exit_code}"
            writer.write(f"deploy {deployment.cluster}: {state}\n")
        return
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
            write_document(writer, document, exit_code)
        return exit_code

    if require_root and os.geteuid() != 0:
        return refuse("not_root", "haprion-cert-import must run as root", exit_codes.NOT_ROOT)
    try:
        formats = cert_job.format_flags(arguments.formats, arguments.receivers)
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

    assert arguments.certificate_id is not None  # noqa: S101 - _parse required it
    if arguments.authority is not None or arguments.ndes_ca:
        try:
            if arguments.ndes_ca:
                if policy.ndes is None:
                    return refuse(
                        "dependency_unavailable",
                        "runtime policy.ndes is not configured",
                        exit_codes.CONFIG,
                    )
                source = policy.ndes.issuing_ca
            else:
                assert arguments.authority is not None  # noqa: S101 - the branch says so
                source = arguments.authority
            result = import_authority(
                certificate_id=arguments.certificate_id,
                blocks=read_authority_file(source),
                clusters=arguments.clusters,
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
            write_document(writer, document, exit_code)
        else:
            _summary(result, writer)
        return exit_code

    try:
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
            interface=arguments.interface,
            policy=policy,
            runtime=runtime,
            deployer=deployer or default_deployer(errors),
            # Root at a terminal, outside any sandbox: installed directly.
            installer=installer or ui_interface.install,
            live=live,
            store=store,
            lock_path=lock_path,
            require_secure=require_secure,
        )
    except ImportError_ as exc:
        return refuse(exc.code, str(exc), exc.exit_code)

    document, exit_code = result_envelope(result, request_id=request_id)
    if arguments.json_mode:
        write_document(writer, document, exit_code)
    else:
        _summary(result, writer)
        if exit_code:
            errors.write(
                "ERROR: the certificate was imported and registered but not fully published\n"
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
